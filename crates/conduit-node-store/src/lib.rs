//! Device-local durable custody for Conduit.
//!
//! This crate deliberately owns canonical paths, runtime/process identities,
//! encrypted credential material, and raw trace content. None of these records
//! are suitable for direct replication to the control plane.

mod credential;
mod identity;
mod storage;

pub use credential::{CredentialMetadata, CredentialProjection, CredentialStore, ProjectionKind};
pub use identity::DeviceIdentity;
pub use storage::{StorageClass, StorageManager, StorageObject};

use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_EVENT_BYTES: usize = 60_000;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("journal unavailable: {0}")]
    Unavailable(String),
    #[error("journal corrupt: {0}")]
    Corrupt(String),
    #[error("storage exhausted")]
    Exhausted,
    #[error("journal is read-only")]
    ReadOnly,
    #[error("bounded value exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("idempotency conflict")]
    IdempotencyConflict,
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("sequence conflict")]
    SequenceConflict,
    #[error("sequence gap: expected {expected}, received {received}")]
    SequenceGap { expected: u64, received: u64 },
    #[error("record not found")]
    NotFound,
    #[error("invalid record: {0}")]
    Invalid(String),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

fn map_sql(error: rusqlite::Error) -> StoreError {
    match &error {
        rusqlite::Error::SqliteFailure(code, _) => match code.code {
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => {
                StoreError::Corrupt(error.to_string())
            }
            ErrorCode::ReadOnly => StoreError::ReadOnly,
            ErrorCode::DiskFull => StoreError::Exhausted,
            _ => StoreError::Unavailable(error.to_string()),
        },
        _ => StoreError::Unavailable(error.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Reserved,
    Admitted,
    Starting,
    Running,
    WaitingInput,
    WaitingApproval,
    Finishing,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    Lost,
    Uncertain,
    RecoveryRequired,
    Rejected,
    Expired,
}

impl OperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Admitted => "admitted",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::WaitingInput => "waiting_input",
            Self::WaitingApproval => "waiting_approval",
            Self::Finishing => "finishing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Lost => "lost",
            Self::Uncertain => "uncertain",
            Self::RecoveryRequired => "recovery_required",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
    fn parse(value: &str) -> Result<Self, StoreError> {
        Ok(match value {
            "reserved" => Self::Reserved,
            "admitted" => Self::Admitted,
            "starting" => Self::Starting,
            "running" => Self::Running,
            "waiting_input" => Self::WaitingInput,
            "waiting_approval" => Self::WaitingApproval,
            "finishing" => Self::Finishing,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "timed_out" => Self::TimedOut,
            "lost" => Self::Lost,
            "uncertain" => Self::Uncertain,
            "recovery_required" => Self::RecoveryRequired,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            _ => return Err(StoreError::Corrupt("unknown operation state".into())),
        })
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::Cancelled
                | Self::TimedOut
                | Self::Lost
                | Self::Uncertain
                | Self::RecoveryRequired
                | Self::Rejected
                | Self::Expired
        )
    }
    fn permits(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Reserved,
                    Self::Admitted | Self::Rejected | Self::Expired
                ) | (
                    Self::Admitted,
                    Self::Starting | Self::Cancelled | Self::Expired
                ) | (
                    Self::Starting,
                    Self::Running | Self::Failed | Self::TimedOut | Self::Lost | Self::Uncertain
                ) | (
                    Self::Running,
                    Self::WaitingInput
                        | Self::WaitingApproval
                        | Self::Finishing
                        | Self::Cancelled
                        | Self::TimedOut
                        | Self::Lost
                        | Self::Uncertain
                        | Self::RecoveryRequired
                ) | (
                    Self::WaitingInput | Self::WaitingApproval,
                    Self::Running | Self::Cancelled | Self::TimedOut | Self::Lost | Self::Uncertain
                ) | (
                    Self::Finishing,
                    Self::Completed
                        | Self::Failed
                        | Self::Cancelled
                        | Self::TimedOut
                        | Self::Uncertain
                        | Self::RecoveryRequired
                )
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub manifest: Vec<u8>,
    pub local_policy_revision: u64,
    pub state: OperationState,
    pub runtime_id: Option<String>,
    pub process_identity: Option<String>,
    pub last_event_sequence: u64,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveResult {
    Reserved(OperationRecord),
    Replay(OperationRecord),
    Uncertain(OperationRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ControlToNode,
    NodeToControl,
}
impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::ControlToNode => "control_to_node",
            Self::NodeToControl => "node_to_control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFrame {
    pub sequence: u64,
    pub message_id: String,
    pub payload_digest: String,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveResult {
    Applied,
    Duplicate,
    Gap { expected: u64 },
}

#[derive(Clone)]
pub struct NodeStore {
    inner: Arc<Mutex<Connection>>,
    root: PathBuf,
}

impl NodeStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let db_path = root.join("node.sqlite3");
        let conn = Connection::open(&db_path).map_err(map_sql)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(map_sql)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA wal_autocheckpoint=1000;").map_err(map_sql)?;
        migrate(&conn)?;
        integrity(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            root,
        })
    }

    /// Open an existing journal for diagnostics without granting mutation.
    /// Admission through this handle deterministically returns `ReadOnly`.
    pub fn open_read_only(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(
            root.join("node.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(map_sql)?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;",
        )
        .map_err(map_sql)?;
        integrity(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            root,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    fn conn(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::Unavailable("database lock poisoned".into()))
    }

    pub fn integrity_check(&self) -> Result<(), StoreError> {
        let conn = self.conn()?;
        integrity(&conn)
    }

    pub fn reserve_operation(
        &self,
        operation_id: &str,
        key: &str,
        digest: &str,
        manifest: &[u8],
        policy_revision: u64,
    ) -> Result<ReserveResult, StoreError> {
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_MANIFEST_BYTES,
            });
        }
        validate_digest(digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(record) = query_operation(&tx, key)? {
            if record.request_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            tx.commit().map_err(map_sql)?;
            return Ok(if record.state == OperationState::Uncertain {
                ReserveResult::Uncertain(record)
            } else {
                ReserveResult::Replay(record)
            });
        }
        tx.execute("INSERT INTO operations(operation_id,idempotency_key,request_digest,manifest,local_policy_revision,state) VALUES(?1,?2,?3,?4,?5,'reserved')", params![operation_id,key,digest,manifest,policy_revision]).map_err(map_sql)?;
        let record = query_operation(&tx, key)?
            .ok_or_else(|| StoreError::Corrupt("reserved row missing".into()))?;
        tx.commit().map_err(map_sql)?;
        Ok(ReserveResult::Reserved(record))
    }

    pub fn transition_operation(
        &self,
        key: &str,
        expected: OperationState,
        next: OperationState,
        runtime_id: Option<&str>,
        process_identity: Option<&str>,
        receipt: Option<&[u8]>,
    ) -> Result<OperationRecord, StoreError> {
        if receipt.is_some_and(|v| v.len() > MAX_EVENT_BYTES) {
            return Err(StoreError::TooLarge {
                limit: MAX_EVENT_BYTES,
            });
        }
        if !expected.permits(next) {
            return Err(StoreError::InvalidTransition {
                from: expected.as_str().into(),
                to: next.as_str().into(),
            });
        }
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let changed = tx.execute("UPDATE operations SET state=?1,runtime_id=COALESCE(?2,runtime_id),process_identity=COALESCE(?3,process_identity),receipt=COALESCE(?4,receipt),updated_at=strftime('%s','now') WHERE idempotency_key=?5 AND state=?6", params![next.as_str(),runtime_id,process_identity,receipt,key,expected.as_str()]).map_err(map_sql)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition {
                from: expected.as_str().into(),
                to: next.as_str().into(),
            });
        }
        let row = query_operation(&tx, key)?.ok_or(StoreError::NotFound)?;
        tx.commit().map_err(map_sql)?;
        Ok(row)
    }

    pub fn operation(&self, key: &str) -> Result<Option<OperationRecord>, StoreError> {
        let conn = self.conn()?;
        query_operation(&conn, key)
    }

    pub fn append_outbound(
        &self,
        direction: Direction,
        message_id: &str,
        digest: &str,
        frame: &[u8],
        priority: u8,
    ) -> Result<u64, StoreError> {
        self.append_outbound_with(direction, message_id, digest, priority, |_| {
            Ok(frame.to_vec())
        })
        .map(|v| v.0)
    }

    /// Allocate the durable sequence and build the exact encoded frame inside
    /// one immediate transaction, so a crash can never retain a placeholder
    /// sequence in the replay outbox.
    pub fn append_outbound_with<F>(
        &self,
        direction: Direction,
        message_id: &str,
        digest: &str,
        priority: u8,
        build: F,
    ) -> Result<(u64, Vec<u8>), StoreError>
    where
        F: FnOnce(u64) -> Result<Vec<u8>, StoreError>,
    {
        validate_digest(digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let sequence: u64 = tx
            .query_row(
                "SELECT next_sequence FROM transport_positions WHERE direction=?1",
                [direction.as_str()],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        let frame = build(sequence)?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        tx.execute("INSERT INTO transport_outbox(direction,sequence,message_id,payload_digest,frame,priority) VALUES(?1,?2,?3,?4,?5,?6)", params![direction.as_str(),sequence,message_id,digest,frame,priority]).map_err(map_sql)?;
        tx.execute(
            "UPDATE transport_positions SET next_sequence=next_sequence+1 WHERE direction=?1",
            [direction.as_str()],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok((sequence, frame))
    }

    pub fn receive(
        &self,
        direction: Direction,
        item: &TransportFrame,
    ) -> Result<ReceiveResult, StoreError> {
        if item.frame.len() > MAX_FRAME_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        validate_digest(&item.payload_digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let expected: u64 = tx
            .query_row(
                "SELECT received_through+1 FROM transport_positions WHERE direction=?1",
                [direction.as_str()],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        if item.sequence < expected {
            let prior: Option<(String,String)> = tx.query_row("SELECT message_id,payload_digest FROM transport_inbox WHERE direction=?1 AND sequence=?2", params![direction.as_str(),item.sequence], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(map_sql)?;
            return match prior {
                Some((m, d)) if m == item.message_id && d == item.payload_digest => {
                    Ok(ReceiveResult::Duplicate)
                }
                _ => Err(StoreError::SequenceConflict),
            };
        }
        if item.sequence > expected {
            return Ok(ReceiveResult::Gap { expected });
        }
        tx.execute("INSERT INTO transport_inbox(direction,sequence,message_id,payload_digest,frame) VALUES(?1,?2,?3,?4,?5)", params![direction.as_str(),item.sequence,item.message_id,item.payload_digest,item.frame]).map_err(map_sql)?;
        tx.execute(
            "UPDATE transport_positions SET received_through=?2 WHERE direction=?1",
            params![direction.as_str(), item.sequence],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok(ReceiveResult::Applied)
    }

    pub fn ack_outbound(&self, direction: Direction, through: u64) -> Result<usize, StoreError> {
        let conn = self.conn()?;
        let sent_max: u64 = conn
            .query_row(
                "SELECT next_sequence-1 FROM transport_positions WHERE direction=?1",
                [direction.as_str()],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        if through > sent_max {
            return Err(StoreError::SequenceGap {
                expected: sent_max,
                received: through,
            });
        }
        conn.execute(
            "UPDATE transport_outbox SET acknowledged=1 WHERE direction=?1 AND sequence<=?2",
            params![direction.as_str(), through],
        )
        .map_err(map_sql)
    }

    pub fn replay_outbound(
        &self,
        direction: Direction,
        from: u64,
        limit: usize,
    ) -> Result<Vec<TransportFrame>, StoreError> {
        let limit = limit.min(512);
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT sequence,message_id,payload_digest,frame FROM transport_outbox WHERE direction=?1 AND sequence>=?2 ORDER BY sequence LIMIT ?3").map_err(map_sql)?;
        let rows = stmt
            .query_map(params![direction.as_str(), from, limit], |r| {
                Ok(TransportFrame {
                    sequence: r.get(0)?,
                    message_id: r.get(1)?,
                    payload_digest: r.get(2)?,
                    frame: r.get(3)?,
                })
            })
            .map_err(map_sql)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_sql)
    }

    pub fn set_connection_epoch(&self, epoch: u64) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let current: u64 = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='connection_epoch'",
                [],
                |r| r.get::<_, String>(0),
            )
            .map_err(map_sql)?
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid epoch".into()))?;
        if epoch <= current {
            return Err(StoreError::Invalid("connection_epoch_stale".into()));
        }
        conn.execute(
            "UPDATE metadata SET value=?1 WHERE key='connection_epoch'",
            [epoch.to_string()],
        )
        .map_err(map_sql)?;
        Ok(())
    }

    pub fn connection_epoch(&self) -> Result<u64, StoreError> {
        self.conn()?
            .query_row(
                "SELECT value FROM metadata WHERE key='connection_epoch'",
                [],
                |r| r.get::<_, String>(0),
            )
            .map_err(map_sql)?
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid epoch".into()))
    }

    pub fn persist_reconciliation_plan(
        &self,
        plan_id: &str,
        epoch: u64,
        digest: &str,
        plan: &[u8],
    ) -> Result<(), StoreError> {
        if plan.len() > MAX_MANIFEST_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_MANIFEST_BYTES,
            });
        }
        validate_digest(digest)?;
        self.conn()?.execute("INSERT INTO reconciliation_plans(plan_id,connection_epoch,payload_digest,plan,state) VALUES(?1,?2,?3,?4,'pending') ON CONFLICT(plan_id) DO UPDATE SET state=CASE WHEN payload_digest=excluded.payload_digest THEN state ELSE 'conflict' END",params![plan_id,epoch,digest,plan]).map_err(map_sql)?;
        Ok(())
    }
    pub fn complete_reconciliation(&self, plan_id: &str) -> Result<(), StoreError> {
        if self.conn()?.execute("UPDATE reconciliation_plans SET state='complete',completed_at=unixepoch() WHERE plan_id=?1 AND state='pending'",[plan_id]).map_err(map_sql)?!=1{return Err(StoreError::Invalid("reconciliation plan missing or conflicting".into()))}
        Ok(())
    }

    pub fn append_event(
        &self,
        run_id: &str,
        event_id: &str,
        digest: &str,
        payload: &[u8],
        priority: u8,
    ) -> Result<u64, StoreError> {
        if payload.len() > MAX_EVENT_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_EVENT_BYTES,
            });
        }
        validate_digest(digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let seq: u64 = tx
            .query_row(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM run_events WHERE run_id=?1",
                [run_id],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        tx.execute("INSERT INTO run_events(run_id,sequence,event_id,content_digest,payload,priority) VALUES(?1,?2,?3,?4,?5,?6)", params![run_id,seq,event_id,digest,payload,priority]).map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok(seq)
    }

    pub fn event_range(
        &self,
        run_id: &str,
        from: u64,
        through: u64,
    ) -> Result<Vec<TransportFrame>, StoreError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT sequence,event_id,content_digest,payload FROM run_events WHERE run_id=?1 AND sequence BETWEEN ?2 AND ?3 ORDER BY sequence LIMIT 128").map_err(map_sql)?;
        let values = stmt
            .query_map(params![run_id, from, through], |r| {
                Ok(TransportFrame {
                    sequence: r.get(0)?,
                    message_id: r.get(1)?,
                    payload_digest: r.get(2)?,
                    frame: r.get(3)?,
                })
            })
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        if values.first().is_none_or(|v| v.sequence != from) {
            return Err(StoreError::NotFound);
        }
        Ok(values)
    }

    pub fn put_content(&self, bytes: &[u8]) -> Result<(String, PathBuf), StoreError> {
        let digest = hex::encode(Sha256::digest(bytes));
        let dir = self.root.join("content").join(&digest[..2]);
        fs::create_dir_all(&dir)?;
        let path = dir.join(&digest);
        if !path.exists() {
            let temp = dir.join(format!(".{digest}.tmp-{}", std::process::id()));
            fs::write(&temp, bytes)?;
            let file = fs::OpenOptions::new().read(true).open(&temp)?;
            file.sync_all()?;
            fs::rename(&temp, &path)?;
        }
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO content_objects(digest,size_bytes,path) VALUES(?1,?2,?3)",
                params![digest, bytes.len(), path.as_os_str().as_encoded_bytes()],
            )
            .map_err(map_sql)?;
        Ok((digest, path))
    }
}

fn validate_digest(value: &str) -> Result<(), StoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(StoreError::Invalid("invalid SHA-256 digest".into()))
    }
}

fn query_operation(conn: &Connection, key: &str) -> Result<Option<OperationRecord>, StoreError> {
    conn.query_row("SELECT operation_id,idempotency_key,request_digest,manifest,local_policy_revision,state,runtime_id,process_identity,last_event_sequence,receipt FROM operations WHERE idempotency_key=?1", [key], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,u64>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,u64>(8)?,r.get::<_,Option<Vec<u8>>>(9)?)))
        .optional().map_err(map_sql)?.map(|v| Ok(OperationRecord { operation_id:v.0,idempotency_key:v.1,request_digest:v.2,manifest:v.3,local_policy_revision:v.4,state:OperationState::parse(&v.5)?,runtime_id:v.6,process_identity:v.7,last_event_sequence:v.8,receipt:v.9 })).transpose()
}

fn integrity(conn: &Connection) -> Result<(), StoreError> {
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(map_sql)?;
    if result == "ok" {
        Ok(())
    } else {
        Err(StoreError::Corrupt("SQLite quick_check failed".into()))
    }
}

fn migrate(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(r#"
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT(unixepoch()));
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO metadata(key,value) VALUES('connection_epoch','0'),('journal_generation','1');
CREATE TABLE IF NOT EXISTS operations(
 operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
 manifest BLOB NOT NULL, local_policy_revision INTEGER NOT NULL, state TEXT NOT NULL,
 runtime_id TEXT, process_identity TEXT, last_event_sequence INTEGER NOT NULL DEFAULT 0,
 receipt BLOB, updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(request_digest)=64), CHECK(length(manifest)<=262144));
CREATE TABLE IF NOT EXISTS transport_positions(direction TEXT PRIMARY KEY, next_sequence INTEGER NOT NULL DEFAULT 1, received_through INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO transport_positions(direction) VALUES('control_to_node'),('node_to_control');
CREATE TABLE IF NOT EXISTS transport_outbox(direction TEXT NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, payload_digest TEXT NOT NULL, frame BLOB NOT NULL, priority INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(direction,sequence));
CREATE TABLE IF NOT EXISTS transport_inbox(direction TEXT NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, payload_digest TEXT NOT NULL, frame BLOB NOT NULL, PRIMARY KEY(direction,sequence));
CREATE TABLE IF NOT EXISTS run_events(run_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL, content_digest TEXT NOT NULL, payload BLOB NOT NULL, priority INTEGER NOT NULL, PRIMARY KEY(run_id,sequence), UNIQUE(run_id,event_id));
CREATE TABLE IF NOT EXISTS runtime_records(runtime_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, provider_id TEXT NOT NULL, spec_digest TEXT NOT NULL, provider_object_id TEXT, generation INTEGER NOT NULL, state TEXT NOT NULL, process_identity TEXT, metadata BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS credential_profiles(profile_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, adapter_id TEXT NOT NULL, kind TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, metadata BLOB NOT NULL, UNIQUE(profile_id,revision));
CREATE TABLE IF NOT EXISTS storage_objects(object_id TEXT PRIMARY KEY, class TEXT NOT NULL, path BLOB NOT NULL, size_bytes INTEGER NOT NULL, pinned INTEGER NOT NULL DEFAULT 0, custody_count INTEGER NOT NULL DEFAULT 1, contains_credentials INTEGER NOT NULL DEFAULT 0, collected INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS content_objects(digest TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, path BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS reconciliation_plans(plan_id TEXT PRIMARY KEY, connection_epoch INTEGER NOT NULL, payload_digest TEXT NOT NULL, plan BLOB NOT NULL, state TEXT NOT NULL, completed_at INTEGER);
INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);
COMMIT;"#).map_err(map_sql)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn digest(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }
    #[test]
    fn exact_once_survives_reopen_and_conflicts() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        assert!(matches!(
            s.reserve_operation(
                "op_12345678",
                "a-long-idempotency-key",
                &digest(1),
                b"{}",
                1
            )
            .unwrap(),
            ReserveResult::Reserved(_)
        ));
        drop(s);
        let s = NodeStore::open(d.path()).unwrap();
        assert!(matches!(
            s.reserve_operation(
                "op_12345678",
                "a-long-idempotency-key",
                &digest(1),
                b"{}",
                1
            )
            .unwrap(),
            ReserveResult::Replay(_)
        ));
        assert!(matches!(
            s.reserve_operation(
                "op_87654321",
                "a-long-idempotency-key",
                &digest(2),
                b"{}",
                1
            ),
            Err(StoreError::IdempotencyConflict)
        ));
    }
    #[test]
    fn sequences_reject_gaps_conflicts_and_accept_exact_duplicates() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let one = TransportFrame {
            sequence: 1,
            message_id: "cmsg_12345678".into(),
            payload_digest: digest(1),
            frame: b"{}".to_vec(),
        };
        assert_eq!(
            s.receive(Direction::ControlToNode, &one).unwrap(),
            ReceiveResult::Applied
        );
        assert_eq!(
            s.receive(Direction::ControlToNode, &one).unwrap(),
            ReceiveResult::Duplicate
        );
        let mut conflict = one.clone();
        conflict.payload_digest = digest(2);
        assert!(matches!(
            s.receive(Direction::ControlToNode, &conflict),
            Err(StoreError::SequenceConflict)
        ));
        let gap = TransportFrame {
            sequence: 3,
            message_id: "cmsg_33333333".into(),
            payload_digest: digest(3),
            frame: b"{}".to_vec(),
        };
        assert_eq!(
            s.receive(Direction::ControlToNode, &gap).unwrap(),
            ReceiveResult::Gap { expected: 2 }
        );
    }
    #[test]
    fn terminal_receipt_is_durable_before_replay() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let key = "a-long-idempotency-key";
        s.reserve_operation("op_12345678", key, &digest(1), b"{}", 1)
            .unwrap();
        s.transition_operation(
            key,
            OperationState::Reserved,
            OperationState::Admitted,
            None,
            None,
            None,
        )
        .unwrap();
        s.transition_operation(
            key,
            OperationState::Admitted,
            OperationState::Starting,
            Some("rt_12345678"),
            None,
            None,
        )
        .unwrap();
        s.transition_operation(
            key,
            OperationState::Starting,
            OperationState::Running,
            None,
            Some("pid:1:start:2"),
            None,
        )
        .unwrap();
        s.transition_operation(
            key,
            OperationState::Running,
            OperationState::Finishing,
            None,
            None,
            None,
        )
        .unwrap();
        s.transition_operation(
            key,
            OperationState::Finishing,
            OperationState::Completed,
            None,
            None,
            Some(b"terminal"),
        )
        .unwrap();
        drop(s);
        let s = NodeStore::open(d.path()).unwrap();
        let r = s.operation(key).unwrap().unwrap();
        assert_eq!(r.state, OperationState::Completed);
        assert_eq!(r.receipt.unwrap(), b"terminal");
    }
    #[test]
    fn read_only_journal_refuses_new_custody() {
        let d = tempdir().unwrap();
        drop(NodeStore::open(d.path()).unwrap());
        let s = NodeStore::open_read_only(d.path()).unwrap();
        assert!(matches!(
            s.reserve_operation(
                "op_12345678",
                "a-long-idempotency-key",
                &digest(1),
                b"{}",
                1
            ),
            Err(StoreError::ReadOnly)
        ));
    }
    #[test]
    fn corrupt_database_fails_closed() {
        let d = tempdir().unwrap();
        std::fs::write(
            d.path().join("node.sqlite3"),
            b"not sqlite; SECRET_MUST_NOT_APPEAR",
        )
        .unwrap();
        assert!(matches!(
            NodeStore::open(d.path()),
            Err(StoreError::Corrupt(_)) | Err(StoreError::Unavailable(_))
        ));
    }
}
