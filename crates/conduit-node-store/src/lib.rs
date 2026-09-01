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
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_EVENT_BYTES: usize = 60_000;
const STORE_SCHEMA_VERSION: u32 = 3;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub operation: OperationRecord,
    pub provider_id: String,
    pub access_scope: String,
    pub approval_policy: String,
    pub runtime_request: Vec<u8>,
    pub launch_plan: Vec<u8>,
    pub admission_receipt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionResult {
    Admitted(AdmissionRecord),
    Replay(AdmissionRecord),
    Uncertain(AdmissionRecord),
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
    DuplicatePending,
    Gap { expected: u64 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPositions {
    pub control_received_through: u64,
    pub node_sent_through: u64,
    pub node_acknowledged_through: u64,
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
        secure_store_root(&root)?;
        let db_path = root.join("node.sqlite3");
        if db_path.exists() {
            secure_regular_file(&db_path)?;
        }
        let conn = Connection::open(&db_path).map_err(map_sql)?;
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(map_sql)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA wal_autocheckpoint=1000;").map_err(map_sql)?;
        migrate(&conn)?;
        integrity(&conn)?;
        for suffix in ["node.sqlite3-wal", "node.sqlite3-shm"] {
            let path = root.join(suffix);
            if path.exists() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            root,
        })
    }

    /// Open an existing journal for diagnostics without granting mutation.
    /// Admission through this handle deterministically returns `ReadOnly`.
    pub fn open_read_only(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        secure_store_root(&root)?;
        secure_regular_file(&root.join("node.sqlite3"))?;
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

    #[allow(clippy::too_many_arguments)]
    pub fn admit_operation(
        &self,
        operation_id: &str,
        key: &str,
        digest: &str,
        manifest: &[u8],
        policy_revision: u64,
        provider_id: &str,
        access_scope: &str,
        approval_policy: &str,
        runtime_request: &[u8],
        launch_plan: &[u8],
        admission_receipt: &[u8],
    ) -> Result<AdmissionResult, StoreError> {
        for value in [manifest, runtime_request, launch_plan, admission_receipt] {
            if value.len() > MAX_MANIFEST_BYTES {
                return Err(StoreError::TooLarge {
                    limit: MAX_MANIFEST_BYTES,
                });
            }
        }
        validate_digest(digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(existing) = query_admission(&tx, key)? {
            if existing.operation.request_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            tx.commit().map_err(map_sql)?;
            return Ok(if existing.operation.state == OperationState::Uncertain {
                AdmissionResult::Uncertain(existing)
            } else {
                AdmissionResult::Replay(existing)
            });
        }
        tx.execute("INSERT INTO operations(operation_id,idempotency_key,request_digest,manifest,local_policy_revision,state) VALUES(?1,?2,?3,?4,?5,'admitted')",params![operation_id,key,digest,manifest,policy_revision]).map_err(map_sql)?;
        tx.execute("INSERT INTO operation_admissions(idempotency_key,provider_id,access_scope,approval_policy,runtime_request,launch_plan,admission_receipt) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![key,provider_id,access_scope,approval_policy,runtime_request,launch_plan,admission_receipt]).map_err(map_sql)?;
        let result = query_admission(&tx, key)?
            .ok_or_else(|| StoreError::Corrupt("admission row missing".into()))?;
        tx.commit().map_err(map_sql)?;
        Ok(AdmissionResult::Admitted(result))
    }

    pub fn admission(&self, key: &str) -> Result<Option<AdmissionRecord>, StoreError> {
        let conn = self.conn()?;
        query_admission(&conn, key)
    }

    pub fn nonterminal_admissions(&self) -> Result<Vec<AdmissionRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare(
                "SELECT idempotency_key FROM operations WHERE state NOT IN ('completed','failed','cancelled','timed_out','lost','uncertain','recovery_required','rejected','expired') ORDER BY updated_at, operation_id",
            )
            .map_err(map_sql)?;
        let keys = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        drop(statement);
        keys.into_iter()
            .map(|key| {
                query_admission(&conn, &key)?.ok_or_else(|| {
                    StoreError::Corrupt("nonterminal operation lacks immutable admission".into())
                })
            })
            .collect()
    }

    pub fn admissions(&self) -> Result<Vec<AdmissionRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare(
                "SELECT o.idempotency_key FROM operations o JOIN operation_admissions a ON a.idempotency_key=o.idempotency_key ORDER BY o.updated_at DESC, o.operation_id",
            )
            .map_err(map_sql)?;
        let keys = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        keys.into_iter()
            .map(|key| query_admission(&conn, &key)?.ok_or(StoreError::NotFound))
            .collect()
    }

    pub fn admission_by_runtime_id(
        &self,
        runtime_id: &str,
    ) -> Result<Option<AdmissionRecord>, StoreError> {
        let conn = self.conn()?;
        let key = conn
            .query_row(
                "SELECT idempotency_key FROM operations WHERE runtime_id=?1",
                [runtime_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sql)?;
        key.map(|key| query_admission(&conn, &key))
            .transpose()
            .map(Option::flatten)
    }

    pub fn backup_database(&self, destination: &Path) -> Result<(), StoreError> {
        if !destination.is_absolute() || destination.exists() {
            return Err(StoreError::Invalid(
                "backup destination must be a new absolute path".into(),
            ));
        }
        let destination = destination
            .to_str()
            .ok_or_else(|| StoreError::Invalid("backup path must be UTF-8".into()))?;
        let escaped = destination.replace('\'', "''");
        self.conn()?
            .execute_batch(&format!("VACUUM INTO '{escaped}'"))
            .map_err(map_sql)
    }

    pub fn verify_database(path: &Path) -> Result<(), StoreError> {
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(map_sql)?;
        let result: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(map_sql)?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!(
                "backup integrity check failed: {result}"
            )))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_rejection(
        &self,
        operation_id: &str,
        key: &str,
        digest: &str,
        manifest: &[u8],
        policy_revision: u64,
        state: OperationState,
        receipt: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if !matches!(state, OperationState::Rejected | OperationState::Expired) {
            return Err(StoreError::Invalid("rejection state required".into()));
        }
        if manifest.len() > MAX_MANIFEST_BYTES || receipt.len() > MAX_EVENT_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_MANIFEST_BYTES,
            });
        }
        validate_digest(digest)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(existing) = query_operation(&tx, key)? {
            if existing.request_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            if !matches!(
                existing.state,
                OperationState::Rejected | OperationState::Expired
            ) {
                return Err(StoreError::Invalid(
                    "operation already has executable custody".into(),
                ));
            }
            let saved = existing
                .receipt
                .ok_or_else(|| StoreError::Corrupt("rejection receipt missing".into()))?;
            tx.commit().map_err(map_sql)?;
            return Ok(saved);
        }
        tx.execute(
            "INSERT INTO operations(operation_id,idempotency_key,request_digest,manifest,local_policy_revision,state,receipt) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![operation_id, key, digest, manifest, policy_revision, state.as_str(), receipt],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok(receipt.to_vec())
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
            let prior: Option<(String,String,String)> = tx.query_row("SELECT message_id,payload_digest,application_state FROM transport_inbox WHERE direction=?1 AND sequence=?2", params![direction.as_str(),item.sequence], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(map_sql)?;
            return match prior {
                Some((m, d, state)) if m == item.message_id && d == item.payload_digest => {
                    Ok(if state == "applied" {
                        ReceiveResult::Duplicate
                    } else {
                        ReceiveResult::DuplicatePending
                    })
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

    pub fn mark_inbound_applied(
        &self,
        direction: Direction,
        sequence: u64,
    ) -> Result<(), StoreError> {
        let changed = self
            .conn()?
            .execute(
                "UPDATE transport_inbox SET application_state='applied' WHERE direction=?1 AND sequence=?2 AND application_state='pending'",
                params![direction.as_str(), sequence],
            )
            .map_err(map_sql)?;
        if changed > 1 {
            return Err(StoreError::Corrupt("multiple inbox rows changed".into()));
        }
        Ok(())
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

    pub fn transport_positions(&self) -> Result<TransportPositions, StoreError> {
        let conn = self.conn()?;
        let control_received_through=conn.query_row("SELECT received_through FROM transport_positions WHERE direction='control_to_node'",[],|r|r.get(0)).map_err(map_sql)?;
        let node_sent_through = conn
            .query_row(
                "SELECT next_sequence-1 FROM transport_positions WHERE direction='node_to_control'",
                [],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        let node_acknowledged_through=conn.query_row("SELECT COALESCE(MAX(sequence),0) FROM transport_outbox WHERE direction='node_to_control' AND acknowledged=1",[],|r|r.get(0)).map_err(map_sql)?;
        Ok(TransportPositions {
            control_received_through,
            node_sent_through,
            node_acknowledged_through,
        })
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
    pub fn unacknowledged_outbound(
        &self,
        from: u64,
        limit: usize,
    ) -> Result<Vec<TransportFrame>, StoreError> {
        let conn = self.conn()?;
        let mut stmt=conn.prepare("SELECT sequence,message_id,payload_digest,frame FROM transport_outbox WHERE direction='node_to_control' AND acknowledged=0 AND sequence>=?1 ORDER BY sequence LIMIT ?2").map_err(map_sql)?;
        stmt.query_map(params![from, limit.min(512)], |r| {
            Ok(TransportFrame {
                sequence: r.get(0)?,
                message_id: r.get(1)?,
                payload_digest: r.get(2)?,
                frame: r.get(3)?,
            })
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)
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

    pub fn append_operation_event(
        &self,
        key: &str,
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
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let operation_sequence: u64 = transaction
            .query_row(
                "SELECT last_event_sequence+1 FROM operations WHERE idempotency_key=?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql)?
            .ok_or(StoreError::NotFound)?;
        let run_sequence: u64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM run_events WHERE run_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if operation_sequence != run_sequence {
            return Err(StoreError::Corrupt(
                "operation and Run event sequences diverged".into(),
            ));
        }
        transaction.execute("INSERT INTO run_events(run_id,sequence,event_id,content_digest,payload,priority) VALUES(?1,?2,?3,?4,?5,?6)", params![run_id,run_sequence,event_id,digest,payload,priority]).map_err(map_sql)?;
        transaction
            .execute(
                "UPDATE operations SET last_event_sequence=?2 WHERE idempotency_key=?1",
                params![key, run_sequence],
            )
            .map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        Ok(run_sequence)
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

fn secure_store_root(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(StoreError::Invalid(
            "journal root must be an owner-controlled directory".into(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn secure_regular_file(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(StoreError::Invalid(
            "journal file must be owner-only and regular".into(),
        ));
    }
    Ok(())
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

fn query_admission(conn: &Connection, key: &str) -> Result<Option<AdmissionRecord>, StoreError> {
    let operation = match query_operation(conn, key)? {
        Some(v) => v,
        None => return Ok(None),
    };
    conn.query_row("SELECT provider_id,access_scope,approval_policy,runtime_request,launch_plan,admission_receipt FROM operation_admissions WHERE idempotency_key=?1",[key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?)))
        .optional().map_err(map_sql)?.map(|v|AdmissionRecord{operation,provider_id:v.0,access_scope:v.1,approval_policy:v.2,runtime_request:v.3,launch_plan:v.4,admission_receipt:v.5}).map_or(Ok(None),|v|Ok(Some(v)))
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
    let has_migrations:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",[],|r|r.get(0)).map_err(map_sql)?;
    let version = if has_migrations {
        let version: u32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        if version > STORE_SCHEMA_VERSION {
            return Err(StoreError::Invalid(format!(
                "journal schema version {version} is newer than supported {STORE_SCHEMA_VERSION}"
            )));
        }
        version
    } else {
        0
    };
    if version > 0 && version < 3 {
        conn.execute(
            "ALTER TABLE transport_inbox ADD COLUMN application_state TEXT NOT NULL DEFAULT 'pending'",
            [],
        )
        .map_err(map_sql)?;
    }
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
CREATE TABLE IF NOT EXISTS operation_admissions(
 idempotency_key TEXT PRIMARY KEY REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 provider_id TEXT NOT NULL, access_scope TEXT NOT NULL, approval_policy TEXT NOT NULL,
 runtime_request BLOB NOT NULL, launch_plan BLOB NOT NULL, admission_receipt BLOB NOT NULL,
 CHECK(length(runtime_request)<=262144), CHECK(length(launch_plan)<=262144), CHECK(length(admission_receipt)<=262144));
CREATE TABLE IF NOT EXISTS transport_positions(direction TEXT PRIMARY KEY, next_sequence INTEGER NOT NULL DEFAULT 1, received_through INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO transport_positions(direction) VALUES('control_to_node'),('node_to_control');
CREATE TABLE IF NOT EXISTS transport_outbox(direction TEXT NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, payload_digest TEXT NOT NULL, frame BLOB NOT NULL, priority INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(direction,sequence));
CREATE TABLE IF NOT EXISTS transport_inbox(direction TEXT NOT NULL, sequence INTEGER NOT NULL, message_id TEXT NOT NULL, payload_digest TEXT NOT NULL, frame BLOB NOT NULL, application_state TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(direction,sequence));
CREATE TABLE IF NOT EXISTS run_events(run_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL, content_digest TEXT NOT NULL, payload BLOB NOT NULL, priority INTEGER NOT NULL, PRIMARY KEY(run_id,sequence), UNIQUE(run_id,event_id));
CREATE TABLE IF NOT EXISTS runtime_records(runtime_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, provider_id TEXT NOT NULL, spec_digest TEXT NOT NULL, provider_object_id TEXT, generation INTEGER NOT NULL, state TEXT NOT NULL, process_identity TEXT, metadata BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS credential_profiles(profile_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, adapter_id TEXT NOT NULL, kind TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, metadata BLOB NOT NULL, UNIQUE(profile_id,revision));
CREATE TABLE IF NOT EXISTS storage_objects(object_id TEXT PRIMARY KEY, class TEXT NOT NULL, path BLOB NOT NULL, size_bytes INTEGER NOT NULL, pinned INTEGER NOT NULL DEFAULT 0, custody_count INTEGER NOT NULL DEFAULT 1, contains_credentials INTEGER NOT NULL DEFAULT 0, collected INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS content_objects(digest TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, path BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS reconciliation_plans(plan_id TEXT PRIMARY KEY, connection_epoch INTEGER NOT NULL, payload_digest TEXT NOT NULL, plan BLOB NOT NULL, state TEXT NOT NULL, completed_at INTEGER);
INSERT OR IGNORE INTO schema_migrations(version) VALUES(1),(2),(3);
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
            ReceiveResult::DuplicatePending
        );
        s.mark_inbound_applied(Direction::ControlToNode, 1).unwrap();
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
            Err(StoreError::Corrupt(_))
                | Err(StoreError::Unavailable(_))
                | Err(StoreError::Invalid(_))
        ));
    }
    #[test]
    fn atomic_admission_replays_immutable_execution_inputs() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let key = "immutable-idempotency-key";
        let first = s
            .admit_operation(
                "op_12345678",
                key,
                &digest(4),
                b"manifest",
                7,
                "native",
                "project_full",
                "never",
                b"runtime-v1",
                b"launch-v1",
                b"receipt-v1",
            )
            .unwrap();
        assert!(matches!(first, AdmissionResult::Admitted(_)));
        drop(s);
        let s = NodeStore::open(d.path()).unwrap();
        let replay = s
            .admit_operation(
                "op_12345678",
                key,
                &digest(4),
                b"changed-manifest",
                99,
                "docker",
                "full_device",
                "always",
                b"runtime-v2",
                b"launch-v2",
                b"receipt-v2",
            )
            .unwrap();
        let AdmissionResult::Replay(saved) = replay else {
            panic!("expected replay")
        };
        assert_eq!(saved.provider_id, "native");
        assert_eq!(saved.operation.local_policy_revision, 7);
        assert_eq!(saved.runtime_request, b"runtime-v1");
        assert_eq!(saved.launch_plan, b"launch-v1");
        assert_eq!(saved.admission_receipt, b"receipt-v1");
    }
    #[test]
    fn future_schema_version_is_rejected() {
        let d = tempdir().unwrap();
        let conn = Connection::open(d.path().join("node.sqlite3")).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_migrations VALUES(999, 0);",
        )
        .unwrap();
        drop(conn);
        fs::set_permissions(
            d.path().join("node.sqlite3"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            NodeStore::open(d.path()),
            Err(StoreError::Invalid(message)) if message.contains("newer than supported")
        ));
    }
}
