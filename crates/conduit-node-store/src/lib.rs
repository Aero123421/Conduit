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
const STORE_SCHEMA_VERSION: u32 = 10;

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
                    Self::Starting | Self::Cancelled | Self::RecoveryRequired | Self::Expired
                ) | (
                    Self::Starting,
                    Self::Running
                        | Self::Failed
                        | Self::Cancelled
                        | Self::TimedOut
                        | Self::Lost
                        | Self::Uncertain
                        | Self::RecoveryRequired
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
                    Self::Running
                        | Self::Cancelled
                        | Self::TimedOut
                        | Self::Lost
                        | Self::Uncertain
                        | Self::RecoveryRequired
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
pub struct AgentApprovalRecord {
    pub approval_id: String,
    pub idempotency_key: String,
    pub operation_digest: String,
    pub provider_request_id: Vec<u8>,
    pub method: String,
    pub parameters_digest: String,
    pub expires_at_unix_ms: u64,
    pub request_payload: Option<Vec<u8>>,
    pub state: String,
    pub resolution: Option<Vec<u8>>,
    pub resolution_authority: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionResult {
    Admitted(AdmissionRecord),
    Replay(AdmissionRecord),
    Uncertain(AdmissionRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEffectRecord {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub target_run_id: String,
    pub target_runtime_id: Option<String>,
    pub target_digest: String,
    pub controller_epoch: u64,
    pub expected_revision: u64,
    pub command: String,
    pub state: String,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEffectResult {
    Reserved(ControlEffectRecord),
    Replay(ControlEffectRecord),
    Uncertain(ControlEffectRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeTicketRequestRecord {
    pub request_id: String,
    pub operation_idempotency_key: String,
    pub ticket_idempotency_key: String,
    pub request_digest: String,
    pub request_payload: Vec<u8>,
    pub state: String,
    pub ticket_id: Option<String>,
    pub ticket_digest: Option<String>,
    pub signed_ticket: Option<Vec<u8>>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeTicketRequestResult {
    Reserved(PrivilegeTicketRequestRecord),
    Replay(PrivilegeTicketRequestRecord),
    Uncertain(PrivilegeTicketRequestRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedOperationBinding {
    pub idempotency_key: String,
    pub installation_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub helper_key_id: String,
    pub ticket_id: String,
    pub ticket_digest: String,
    pub signed_ticket: Vec<u8>,
    pub runtime_spec_digest: String,
    pub launch_plan_digest: String,
    pub local_plan_digest: String,
    pub local_plan: Vec<u8>,
    pub controller_epoch: u64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedReceiptRecord {
    pub receipt_digest: String,
    pub idempotency_key: String,
    pub ticket_id: String,
    pub ticket_digest: String,
    pub runtime_id: String,
    pub state_revision: u64,
    pub transition: String,
    pub previous_receipt_digest: Option<String>,
    pub signed_receipt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionRecord {
    pub idempotency_key: String,
    pub policy: String,
    pub controller_epoch: u64,
    pub revision: u64,
    pub state: String,
    pub lease_expires_at_unix_ms: Option<u64>,
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

    pub fn journal_generation(&self) -> Result<u64, StoreError> {
        self.conn()?
            .query_row(
                "SELECT value FROM metadata WHERE key='journal_generation'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sql)?
            .parse()
            .map_err(|_| StoreError::Corrupt("invalid journal generation".into()))
    }

    pub fn advance_journal_generation(&self) -> Result<u64, StoreError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(map_sql)?;
        let current = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='journal_generation'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(map_sql)?
            .parse::<u64>()
            .map_err(|_| StoreError::Corrupt("invalid journal generation".into()))?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("journal generation exhausted".into()))?;
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='journal_generation'",
            [next.to_string()],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;
        Ok(next)
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

    #[allow(clippy::too_many_arguments)]
    pub fn record_agent_approval(
        &self,
        approval_id: &str,
        idempotency_key: &str,
        operation_digest: &str,
        provider_request_id: &[u8],
        method: &str,
        parameters_digest: &str,
        expires_at_unix_ms: u64,
        request_payload: &[u8],
    ) -> Result<AgentApprovalRecord, StoreError> {
        validate_digest(operation_digest)?;
        validate_digest(parameters_digest)?;
        if provider_request_id.len() > 512
            || method.is_empty()
            || method.len() > 128
            || request_payload.len() > MAX_EVENT_BYTES
        {
            return Err(StoreError::Invalid(
                "agent approval fields exceed bounds".into(),
            ));
        }
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let existing_approval_id = tx
            .query_row(
                "SELECT approval_id FROM agent_approval_journal WHERE idempotency_key=?1 AND provider_request_id=?2 LIMIT 1",
                params![idempotency_key, provider_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sql)?;
        if existing_approval_id
            .as_deref()
            .is_some_and(|existing| existing != approval_id)
        {
            return Err(StoreError::IdempotencyConflict);
        }
        tx.execute(
            "INSERT OR IGNORE INTO agent_approval_journal(approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending')",
            params![approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload],
        ).map_err(map_sql)?;
        let record = query_agent_approval(&tx, approval_id)?.ok_or(StoreError::NotFound)?;
        if record.idempotency_key != idempotency_key
            || record.operation_digest != operation_digest
            || record.provider_request_id != provider_request_id
            || record.method != method
            || record.parameters_digest != parameters_digest
            || record.expires_at_unix_ms != expires_at_unix_ms
            || record.request_payload.as_deref() != Some(request_payload)
        {
            return Err(StoreError::IdempotencyConflict);
        }
        let state = query_operation(&tx, idempotency_key)?
            .ok_or(StoreError::NotFound)?
            .state;
        match state {
            OperationState::Running => {
                tx.execute(
                    "UPDATE operations SET state='waiting_approval',updated_at=unixepoch() WHERE idempotency_key=?1 AND state='running'",
                    [idempotency_key],
                )
                .map_err(map_sql)?;
            }
            OperationState::WaitingApproval => {}
            other => {
                return Err(StoreError::InvalidTransition {
                    from: other.as_str().into(),
                    to: OperationState::WaitingApproval.as_str().into(),
                });
            }
        }
        tx.commit().map_err(map_sql)?;
        Ok(record)
    }

    pub fn unqueued_agent_approvals(
        &self,
        idempotency_key: &str,
    ) -> Result<Vec<AgentApprovalRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare("SELECT approval_id FROM agent_approval_journal WHERE idempotency_key=?1 AND state='pending' ORDER BY created_at LIMIT 1")
            .map_err(map_sql)?;
        let ids = statement
            .query_map([idempotency_key], |row| row.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        ids.into_iter()
            .map(|id| query_agent_approval(&conn, &id)?.ok_or(StoreError::NotFound))
            .collect()
    }

    pub fn mark_agent_approval_requested(&self, approval_id: &str) -> Result<(), StoreError> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE agent_approval_journal SET state='requested',updated_at=unixepoch() WHERE approval_id=?1 AND state='pending'",
            [approval_id],
        ).map_err(map_sql)?;
        if changed != 1 {
            let current = query_agent_approval(&conn, approval_id)?.ok_or(StoreError::NotFound)?;
            if current.state != "requested" {
                return Err(StoreError::Invalid(
                    "approval request is not pending".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn agent_approval(
        &self,
        approval_id: &str,
    ) -> Result<Option<AgentApprovalRecord>, StoreError> {
        let conn = self.conn()?;
        query_agent_approval(&conn, approval_id)
    }

    pub fn agent_approval_for_provider_request(
        &self,
        idempotency_key: &str,
        provider_request_id: &[u8],
    ) -> Result<Option<AgentApprovalRecord>, StoreError> {
        let conn = self.conn()?;
        let approval_id = conn
            .query_row(
                "SELECT approval_id FROM agent_approval_journal WHERE idempotency_key=?1 AND provider_request_id=?2 ORDER BY created_at DESC LIMIT 1",
                params![idempotency_key, provider_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sql)?;
        approval_id
            .map(|id| query_agent_approval(&conn, &id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn resolved_agent_approvals(
        &self,
        idempotency_key: &str,
    ) -> Result<Vec<AgentApprovalRecord>, StoreError> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare("SELECT approval_id FROM agent_approval_journal WHERE idempotency_key=?1 AND state='resolved' ORDER BY created_at LIMIT 32")
            .map_err(map_sql)?;
        let ids = statement
            .query_map([idempotency_key], |row| row.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        ids.into_iter()
            .map(|id| query_agent_approval(&conn, &id)?.ok_or(StoreError::NotFound))
            .collect()
    }

    pub fn record_agent_approval_resolution(
        &self,
        approval_id: &str,
        resolution: &[u8],
        resolution_authority: &[u8],
    ) -> Result<(), StoreError> {
        if resolution.len() > MAX_EVENT_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_EVENT_BYTES,
            });
        }
        if resolution_authority.is_empty() || resolution_authority.len() > 256 {
            return Err(StoreError::Invalid(
                "approval resolution authority must contain 1..=256 bytes".into(),
            ));
        }
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE agent_approval_journal SET state='resolved',resolution=?1,resolution_authority=?2,updated_at=unixepoch() WHERE approval_id=?3 AND state IN ('pending','requested')",
            params![resolution, resolution_authority, approval_id],
        ).map_err(map_sql)?;
        if changed != 1 {
            let current = query_agent_approval(&conn, approval_id)?.ok_or(StoreError::NotFound)?;
            if current.state == "abandoned" {
                return Err(StoreError::Invalid(
                    "approval request was abandoned during agent finalization".into(),
                ));
            }
            if current.resolution.as_deref() != Some(resolution)
                || current.resolution_authority.as_deref() != Some(resolution_authority)
            {
                return Err(StoreError::IdempotencyConflict);
            }
        }
        Ok(())
    }

    pub fn mark_agent_approval_applied_and_resume(
        &self,
        approval_id: &str,
        idempotency_key: &str,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let approval = query_agent_approval(&tx, approval_id)?.ok_or(StoreError::NotFound)?;
        if approval.idempotency_key != idempotency_key {
            return Err(StoreError::IdempotencyConflict);
        }
        let authority = approval.resolution_authority.as_deref().ok_or_else(|| {
            StoreError::Corrupt("resolved approval lacks authority binding".into())
        })?;
        let operation = query_operation(&tx, idempotency_key)?.ok_or(StoreError::NotFound)?;
        match (approval.state.as_str(), operation.state) {
            ("resolved", OperationState::WaitingApproval) => {
                tx.execute(
                    "UPDATE agent_approval_journal SET state='applied',updated_at=unixepoch() WHERE approval_id=?1 AND state='resolved'",
                    [approval_id],
                )
                .map_err(map_sql)?;
                tx.execute(
                    "UPDATE operations SET state='running',receipt=?1,updated_at=unixepoch() WHERE idempotency_key=?2 AND state='waiting_approval'",
                    params![authority, idempotency_key],
                )
                .map_err(map_sql)?;
            }
            ("applied", OperationState::Running) => {}
            _ => {
                return Err(StoreError::Invalid(
                    "approval apply and operation resume are not jointly ready".into(),
                ));
            }
        }
        tx.commit().map_err(map_sql)
    }

    /// Atomically closes approval custody before an Agent operation is finalized.
    ///
    /// Replays while the operation is already finishing are idempotent. An
    /// abandoned approval can never be requested, resolved, or applied later.
    pub fn begin_agent_finalization(&self, idempotency_key: &str) -> Result<(), StoreError> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let operation = query_operation(&tx, idempotency_key)?.ok_or(StoreError::NotFound)?;
        if !matches!(
            operation.state,
            OperationState::Running
                | OperationState::WaitingInput
                | OperationState::WaitingApproval
                | OperationState::Finishing
        ) {
            return Err(StoreError::InvalidTransition {
                from: operation.state.as_str().into(),
                to: OperationState::Finishing.as_str().into(),
            });
        }
        tx.execute(
            "UPDATE agent_approval_journal SET state='abandoned',updated_at=unixepoch() WHERE idempotency_key=?1 AND state IN ('pending','requested','resolved')",
            [idempotency_key],
        )
        .map_err(map_sql)?;
        if operation.state != OperationState::Finishing {
            let changed = tx
                .execute(
                    "UPDATE operations SET state='finishing',updated_at=unixepoch() WHERE idempotency_key=?1 AND state IN ('running','waiting_input','waiting_approval')",
                    [idempotency_key],
                )
                .map_err(map_sql)?;
            if changed != 1 {
                return Err(StoreError::InvalidTransition {
                    from: operation.state.as_str().into(),
                    to: OperationState::Finishing.as_str().into(),
                });
            }
        }
        tx.commit().map_err(map_sql)
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

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_control_effect(
        &self,
        operation_id: &str,
        idempotency_key: &str,
        request_digest: &str,
        target_run_id: &str,
        target_runtime_id: Option<&str>,
        target_digest: &str,
        controller_epoch: u64,
        expected_revision: u64,
        command: &str,
    ) -> Result<ControlEffectResult, StoreError> {
        validate_digest(request_digest)?;
        validate_digest(target_digest)?;
        if operation_id.is_empty()
            || idempotency_key.len() < 16
            || idempotency_key.len() > 256
            || target_run_id.is_empty()
            || command.is_empty()
            || command.len() > 64
            || controller_epoch == 0
            || expected_revision == 0
        {
            return Err(StoreError::Invalid("invalid control effect fields".into()));
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(existing) = query_control_effect(&transaction, idempotency_key)? {
            if existing.operation_id != operation_id
                || existing.request_digest != request_digest
                || existing.target_run_id != target_run_id
                || existing.target_runtime_id.as_deref() != target_runtime_id
                || existing.target_digest != target_digest
                || existing.controller_epoch != controller_epoch
                || existing.expected_revision != expected_revision
                || existing.command != command
            {
                return Err(StoreError::IdempotencyConflict);
            }
            transaction.commit().map_err(map_sql)?;
            return Ok(
                if existing.state == "applied" || existing.state == "failed" {
                    ControlEffectResult::Replay(existing)
                } else {
                    ControlEffectResult::Uncertain(existing)
                },
            );
        }
        transaction.execute(
            "INSERT INTO control_effect_journal(operation_id,idempotency_key,request_digest,target_run_id,target_runtime_id,target_digest,controller_epoch,expected_revision,command,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending')",
            params![operation_id,idempotency_key,request_digest,target_run_id,target_runtime_id,target_digest,controller_epoch,expected_revision,command],
        ).map_err(map_sql)?;
        let record = query_control_effect(&transaction, idempotency_key)?
            .ok_or_else(|| StoreError::Corrupt("reserved control effect missing".into()))?;
        transaction.commit().map_err(map_sql)?;
        Ok(ControlEffectResult::Reserved(record))
    }

    pub fn complete_control_effect(
        &self,
        idempotency_key: &str,
        succeeded: bool,
        receipt: &[u8],
    ) -> Result<ControlEffectRecord, StoreError> {
        if receipt.len() > MAX_EVENT_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_EVENT_BYTES,
            });
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let existing =
            query_control_effect(&transaction, idempotency_key)?.ok_or(StoreError::NotFound)?;
        let next = if succeeded { "applied" } else { "failed" };
        match existing.state.as_str() {
            "pending" => {
                transaction.execute(
                    "UPDATE control_effect_journal SET state=?2,receipt=?3,updated_at=unixepoch() WHERE idempotency_key=?1 AND state='pending'",
                    params![idempotency_key,next,receipt],
                ).map_err(map_sql)?;
            }
            "applied" | "failed"
                if existing.state == next && existing.receipt.as_deref() == Some(receipt) => {}
            "applied" | "failed" => return Err(StoreError::IdempotencyConflict),
            _ => return Err(StoreError::Corrupt("unknown control effect state".into())),
        }
        let record =
            query_control_effect(&transaction, idempotency_key)?.ok_or(StoreError::NotFound)?;
        transaction.commit().map_err(map_sql)?;
        Ok(record)
    }

    pub fn control_effect(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<ControlEffectRecord>, StoreError> {
        let connection = self.conn()?;
        query_control_effect(&connection, idempotency_key)
    }

    pub fn reserve_privilege_ticket_request(
        &self,
        request_id: &str,
        operation_idempotency_key: &str,
        ticket_idempotency_key: &str,
        request_digest: &str,
        request_payload: &[u8],
    ) -> Result<PrivilegeTicketRequestResult, StoreError> {
        validate_digest(request_digest)?;
        if request_id.is_empty()
            || request_id.len() > 128
            || request_payload.is_empty()
            || request_payload.len() > MAX_EVENT_BYTES
            || ticket_idempotency_key.len() < 16
            || ticket_idempotency_key.len() > 256
        {
            return Err(StoreError::Invalid(
                "invalid privilege ticket request fields".into(),
            ));
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if query_operation(&transaction, operation_idempotency_key)?.is_none() {
            return Err(StoreError::NotFound);
        }
        if let Some(existing) = query_privilege_ticket_request(&transaction, request_id)? {
            if existing.operation_idempotency_key != operation_idempotency_key
                || existing.ticket_idempotency_key != ticket_idempotency_key
                || existing.request_digest != request_digest
                || existing.request_payload != request_payload
            {
                return Err(StoreError::IdempotencyConflict);
            }
            transaction.commit().map_err(map_sql)?;
            return Ok(if existing.state == "pending" {
                PrivilegeTicketRequestResult::Uncertain(existing)
            } else {
                PrivilegeTicketRequestResult::Replay(existing)
            });
        }
        let conflicting = transaction
            .query_row(
                "SELECT 1 FROM privilege_ticket_requests WHERE ticket_idempotency_key=?1 LIMIT 1",
                [ticket_idempotency_key],
                |_| Ok(()),
            )
            .optional()
            .map_err(map_sql)?
            .is_some();
        if conflicting {
            return Err(StoreError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO privilege_ticket_requests(request_id,operation_idempotency_key,ticket_idempotency_key,request_digest,request_payload,state) VALUES(?1,?2,?3,?4,?5,'pending')",
            params![request_id,operation_idempotency_key,ticket_idempotency_key,request_digest,request_payload],
        ).map_err(map_sql)?;
        let record = query_privilege_ticket_request(&transaction, request_id)?
            .ok_or_else(|| StoreError::Corrupt("privilege ticket request missing".into()))?;
        transaction.commit().map_err(map_sql)?;
        Ok(PrivilegeTicketRequestResult::Reserved(record))
    }

    pub fn complete_privilege_ticket_request(
        &self,
        request_id: &str,
        ticket: Option<(&str, &str, &[u8])>,
        error_code: Option<&str>,
    ) -> Result<PrivilegeTicketRequestRecord, StoreError> {
        if ticket.is_some() == error_code.is_some() {
            return Err(StoreError::Invalid(
                "ticket result must contain exactly one outcome".into(),
            ));
        }
        if let Some((ticket_id, ticket_digest, signed_ticket)) = ticket {
            validate_digest(ticket_digest)?;
            if ticket_id.is_empty()
                || ticket_id.len() > 128
                || signed_ticket.is_empty()
                || signed_ticket.len() > MAX_EVENT_BYTES
            {
                return Err(StoreError::Invalid("invalid signed ticket".into()));
            }
        }
        if error_code.is_some_and(|code| code.is_empty() || code.len() > 128) {
            return Err(StoreError::Invalid("invalid ticket error code".into()));
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let existing = query_privilege_ticket_request(&transaction, request_id)?
            .ok_or(StoreError::NotFound)?;
        let expected_state = if ticket.is_some() {
            "issued"
        } else {
            "rejected"
        };
        if existing.state == "pending" {
            let (ticket_id, ticket_digest, signed_ticket) = ticket
                .map(|(id, digest, signed)| (Some(id), Some(digest), Some(signed)))
                .unwrap_or((None, None, None));
            transaction.execute(
                "UPDATE privilege_ticket_requests SET state=?2,ticket_id=?3,ticket_digest=?4,signed_ticket=?5,error_code=?6,updated_at=unixepoch() WHERE request_id=?1 AND state='pending'",
                params![request_id,expected_state,ticket_id,ticket_digest,signed_ticket,error_code],
            ).map_err(map_sql)?;
        } else {
            let exact = existing.state == expected_state
                && match ticket {
                    Some((id, digest, signed)) => {
                        existing.ticket_id.as_deref() == Some(id)
                            && existing.ticket_digest.as_deref() == Some(digest)
                            && existing.signed_ticket.as_deref() == Some(signed)
                            && existing.error_code.is_none()
                    }
                    None => existing.error_code.as_deref() == error_code,
                };
            if !exact {
                return Err(StoreError::IdempotencyConflict);
            }
        }
        let record = query_privilege_ticket_request(&transaction, request_id)?
            .ok_or(StoreError::NotFound)?;
        transaction.commit().map_err(map_sql)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bind_privileged_operation(
        &self,
        idempotency_key: &str,
        installation_id: &str,
        policy_revision: u64,
        policy_digest: &str,
        helper_key_id: &str,
        ticket_id: &str,
        ticket_digest: &str,
        signed_ticket: &[u8],
        runtime_spec_digest: &str,
        launch_plan_digest: &str,
        local_plan_digest: &str,
        local_plan: &[u8],
        controller_epoch: u64,
    ) -> Result<PrivilegedOperationBinding, StoreError> {
        for digest in [
            policy_digest,
            ticket_digest,
            runtime_spec_digest,
            launch_plan_digest,
            local_plan_digest,
        ] {
            validate_digest(digest)?;
        }
        if installation_id.is_empty()
            || installation_id.len() > 128
            || helper_key_id.is_empty()
            || helper_key_id.len() > 128
            || ticket_id.is_empty()
            || ticket_id.len() > 128
            || policy_revision == 0
            || controller_epoch == 0
            || signed_ticket.is_empty()
            || signed_ticket.len() > MAX_EVENT_BYTES
            || local_plan.is_empty()
            || local_plan.len() > MAX_MANIFEST_BYTES
        {
            return Err(StoreError::Invalid(
                "invalid privileged operation binding".into(),
            ));
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if query_operation(&transaction, idempotency_key)?.is_none() {
            return Err(StoreError::NotFound);
        }
        let issued_ticket = transaction
            .query_row(
                "SELECT ticket_id,ticket_digest,signed_ticket FROM privilege_ticket_requests WHERE operation_idempotency_key=?1 AND ticket_id=?2 AND state='issued'",
                params![idempotency_key,ticket_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)),
            )
            .optional()
            .map_err(map_sql)?
            .ok_or(StoreError::NotFound)?;
        if issued_ticket.0 != ticket_id
            || issued_ticket.1 != ticket_digest
            || issued_ticket.2 != signed_ticket
        {
            return Err(StoreError::IdempotencyConflict);
        }
        if let Some(existing) = query_privileged_binding(&transaction, idempotency_key)? {
            let proposed = PrivilegedOperationBinding {
                idempotency_key: idempotency_key.into(),
                installation_id: installation_id.into(),
                policy_revision,
                policy_digest: policy_digest.into(),
                helper_key_id: helper_key_id.into(),
                ticket_id: ticket_id.into(),
                ticket_digest: ticket_digest.into(),
                signed_ticket: signed_ticket.to_vec(),
                runtime_spec_digest: runtime_spec_digest.into(),
                launch_plan_digest: launch_plan_digest.into(),
                local_plan_digest: local_plan_digest.into(),
                local_plan: local_plan.to_vec(),
                controller_epoch,
                state: existing.state.clone(),
            };
            if existing != proposed {
                return Err(StoreError::IdempotencyConflict);
            }
            transaction.commit().map_err(map_sql)?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO privileged_operation_bindings(idempotency_key,installation_id,policy_revision,policy_digest,helper_key_id,ticket_id,ticket_digest,signed_ticket,runtime_spec_digest,launch_plan_digest,local_plan_digest,local_plan,controller_epoch,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'ticketed')",
            params![idempotency_key,installation_id,policy_revision,policy_digest,helper_key_id,ticket_id,ticket_digest,signed_ticket,runtime_spec_digest,launch_plan_digest,local_plan_digest,local_plan,controller_epoch],
        ).map_err(map_sql)?;
        let record = query_privileged_binding(&transaction, idempotency_key)?
            .ok_or_else(|| StoreError::Corrupt("privileged binding missing".into()))?;
        transaction.commit().map_err(map_sql)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_privileged_receipt(
        &self,
        idempotency_key: &str,
        receipt_digest: &str,
        ticket_id: &str,
        ticket_digest: &str,
        runtime_id: &str,
        state_revision: u64,
        transition: &str,
        previous_receipt_digest: Option<&str>,
        signed_receipt: &[u8],
    ) -> Result<PrivilegedReceiptRecord, StoreError> {
        validate_digest(receipt_digest)?;
        validate_digest(ticket_digest)?;
        if let Some(digest) = previous_receipt_digest {
            validate_digest(digest)?;
        }
        if ticket_id.is_empty()
            || ticket_id.len() > 128
            || runtime_id.is_empty()
            || runtime_id.len() > 128
            || state_revision == 0
            || transition.is_empty()
            || transition.len() > 64
            || signed_receipt.is_empty()
            || signed_receipt.len() > MAX_EVENT_BYTES
        {
            return Err(StoreError::Invalid("invalid privileged receipt".into()));
        }
        let mut connection = self.conn()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let _binding =
            query_privileged_binding(&transaction, idempotency_key)?.ok_or(StoreError::NotFound)?;
        let issued_ticket = transaction
            .query_row(
                "SELECT ticket_digest FROM privilege_ticket_requests WHERE operation_idempotency_key=?1 AND ticket_id=?2 AND state='issued' LIMIT 1",
                params![idempotency_key,ticket_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sql)?
            .ok_or(StoreError::NotFound)?;
        if issued_ticket != ticket_digest {
            return Err(StoreError::IdempotencyConflict);
        }
        let last = query_last_privileged_receipt(&transaction, idempotency_key)?;
        let expected_revision = last
            .as_ref()
            .map_or(1, |receipt| receipt.state_revision + 1);
        let expected_previous = last.as_ref().map(|receipt| receipt.receipt_digest.as_str());
        if state_revision != expected_revision || previous_receipt_digest != expected_previous {
            if let Some(existing) = query_privileged_receipt(&transaction, receipt_digest)? {
                if existing.idempotency_key == idempotency_key
                    && existing.ticket_id == ticket_id
                    && existing.ticket_digest == ticket_digest
                    && existing.runtime_id == runtime_id
                    && existing.state_revision == state_revision
                    && existing.transition == transition
                    && existing.previous_receipt_digest.as_deref() == previous_receipt_digest
                    && existing.signed_receipt == signed_receipt
                {
                    transaction.commit().map_err(map_sql)?;
                    return Ok(existing);
                }
            }
            return Err(StoreError::SequenceConflict);
        }
        transaction.execute(
            "INSERT INTO privileged_receipt_chain(receipt_digest,idempotency_key,ticket_id,ticket_digest,runtime_id,state_revision,transition,previous_receipt_digest,signed_receipt) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![receipt_digest,idempotency_key,ticket_id,ticket_digest,runtime_id,state_revision,transition,previous_receipt_digest,signed_receipt],
        ).map_err(|error| match map_sql(error) {
            StoreError::Unavailable(_) => StoreError::IdempotencyConflict,
            other => other,
        })?;
        transaction.execute(
            "UPDATE privileged_operation_bindings SET state=?2,updated_at=unixepoch() WHERE idempotency_key=?1",
            params![idempotency_key,transition],
        ).map_err(map_sql)?;
        let record = query_privileged_receipt(&transaction, receipt_digest)?
            .ok_or_else(|| StoreError::Corrupt("privileged receipt missing".into()))?;
        transaction.commit().map_err(map_sql)?;
        Ok(record)
    }

    pub fn privilege_ticket_request(
        &self,
        request_id: &str,
    ) -> Result<Option<PrivilegeTicketRequestRecord>, StoreError> {
        let connection = self.conn()?;
        query_privilege_ticket_request(&connection, request_id)
    }

    pub fn privilege_ticket_for_operation(
        &self,
        operation_idempotency_key: &str,
        ticket_id: &str,
    ) -> Result<Option<PrivilegeTicketRequestRecord>, StoreError> {
        let connection = self.conn()?;
        connection
            .query_row(
                "SELECT request_id FROM privilege_ticket_requests WHERE operation_idempotency_key=?1 AND ticket_id=?2 AND state='issued' LIMIT 1",
                params![operation_idempotency_key,ticket_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sql)?
            .map(|request_id| query_privilege_ticket_request(&connection, &request_id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn privileged_binding(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<PrivilegedOperationBinding>, StoreError> {
        let connection = self.conn()?;
        query_privileged_binding(&connection, idempotency_key)
    }

    pub fn privileged_receipts(
        &self,
        idempotency_key: &str,
    ) -> Result<Vec<PrivilegedReceiptRecord>, StoreError> {
        let connection = self.conn()?;
        let mut statement = connection.prepare(
            "SELECT receipt_digest,idempotency_key,ticket_id,ticket_digest,runtime_id,state_revision,transition,previous_receipt_digest,signed_receipt FROM privileged_receipt_chain WHERE idempotency_key=?1 ORDER BY state_revision",
        ).map_err(map_sql)?;
        statement
            .query_map([idempotency_key], row_to_privileged_receipt)
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)
    }

    pub fn record_agent_session(
        &self,
        idempotency_key: &str,
        policy: &str,
        controller_epoch: u64,
        lease_expires_at_unix_ms: Option<u64>,
    ) -> Result<AgentSessionRecord, StoreError> {
        if !matches!(policy, "close_on_settle" | "persistent") || controller_epoch == 0 {
            return Err(StoreError::Invalid("invalid Agent session policy".into()));
        }
        let connection = self.conn()?;
        connection.execute(
            "INSERT OR IGNORE INTO agent_sessions(idempotency_key,policy,controller_epoch,revision,state,lease_expires_at_unix_ms) VALUES(?1,?2,?3,1,'running',?4)",
            params![idempotency_key,policy,controller_epoch,lease_expires_at_unix_ms],
        ).map_err(map_sql)?;
        let record =
            query_agent_session(&connection, idempotency_key)?.ok_or(StoreError::NotFound)?;
        if record.policy != policy || record.controller_epoch != controller_epoch {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(record)
    }

    pub fn transition_agent_session(
        &self,
        idempotency_key: &str,
        expected_state: &str,
        expected_revision: u64,
        next_state: &str,
        lease_expires_at_unix_ms: Option<u64>,
    ) -> Result<AgentSessionRecord, StoreError> {
        let allowed = matches!(
            (expected_state, next_state),
            (
                "running",
                "running" | "waiting_input" | "closed" | "cancelled"
            ) | (
                "waiting_input",
                "waiting_input" | "running" | "closed" | "cancelled" | "timed_out"
            )
        );
        if !allowed {
            return Err(StoreError::InvalidTransition {
                from: expected_state.into(),
                to: next_state.into(),
            });
        }
        let connection = self.conn()?;
        let changed = connection.execute(
            "UPDATE agent_sessions SET state=?4,revision=revision+1,lease_expires_at_unix_ms=?5,updated_at=unixepoch() WHERE idempotency_key=?1 AND state=?2 AND revision=?3",
            params![idempotency_key,expected_state,expected_revision,next_state,lease_expires_at_unix_ms],
        ).map_err(map_sql)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition {
                from: expected_state.into(),
                to: next_state.into(),
            });
        }
        query_agent_session(&connection, idempotency_key)?.ok_or(StoreError::NotFound)
    }

    pub fn agent_session(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<AgentSessionRecord>, StoreError> {
        let connection = self.conn()?;
        query_agent_session(&connection, idempotency_key)
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
        if let Some((sequence, prior_digest, frame)) = tx
            .query_row(
                "SELECT sequence,payload_digest,frame FROM transport_outbox WHERE direction=?1 AND message_id=?2 LIMIT 1",
                params![direction.as_str(), message_id],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sql)?
        {
            if prior_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            tx.commit().map_err(map_sql)?;
            return Ok((sequence, frame));
        }
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

    pub fn inbound_applied_through(&self, direction: Direction) -> Result<u64, StoreError> {
        self.conn()?
            .query_row(
                "SELECT CASE WHEN EXISTS(SELECT 1 FROM transport_inbox WHERE direction=?1 AND application_state<>'applied') THEN (SELECT MIN(sequence)-1 FROM transport_inbox WHERE direction=?1 AND application_state<>'applied') ELSE (SELECT received_through FROM transport_positions WHERE direction=?1) END",
                [direction.as_str()],
                |row| row.get(0),
            )
            .map_err(map_sql)
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

fn query_agent_approval(
    conn: &Connection,
    approval_id: &str,
) -> Result<Option<AgentApprovalRecord>, StoreError> {
    conn.query_row(
        "SELECT approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload,state,resolution,resolution_authority FROM agent_approval_journal WHERE approval_id=?1 LIMIT 1",
        [approval_id],
        |row| Ok(AgentApprovalRecord {
            approval_id: row.get(0)?,
            idempotency_key: row.get(1)?,
            operation_digest: row.get(2)?,
            provider_request_id: row.get(3)?,
            method: row.get(4)?,
            parameters_digest: row.get(5)?,
            expires_at_unix_ms: row.get(6)?,
            request_payload: row.get(7)?,
            state: row.get(8)?,
            resolution: row.get(9)?,
            resolution_authority: row.get(10)?,
        }),
    )
    .optional()
    .map_err(map_sql)
}

fn query_control_effect(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<ControlEffectRecord>, StoreError> {
    connection.query_row(
        "SELECT operation_id,idempotency_key,request_digest,target_run_id,target_runtime_id,target_digest,controller_epoch,expected_revision,command,state,receipt FROM control_effect_journal WHERE idempotency_key=?1",
        [idempotency_key],
        |row| Ok(ControlEffectRecord {
            operation_id: row.get(0)?,
            idempotency_key: row.get(1)?,
            request_digest: row.get(2)?,
            target_run_id: row.get(3)?,
            target_runtime_id: row.get(4)?,
            target_digest: row.get(5)?,
            controller_epoch: row.get(6)?,
            expected_revision: row.get(7)?,
            command: row.get(8)?,
            state: row.get(9)?,
            receipt: row.get(10)?,
        }),
    ).optional().map_err(map_sql)
}

fn query_privilege_ticket_request(
    connection: &Connection,
    request_id: &str,
) -> Result<Option<PrivilegeTicketRequestRecord>, StoreError> {
    connection
        .query_row(
            "SELECT request_id,operation_idempotency_key,ticket_idempotency_key,request_digest,request_payload,state,ticket_id,ticket_digest,signed_ticket,error_code FROM privilege_ticket_requests WHERE request_id=?1",
            [request_id],
            |row| {
                Ok(PrivilegeTicketRequestRecord {
                    request_id: row.get(0)?,
                    operation_idempotency_key: row.get(1)?,
                    ticket_idempotency_key: row.get(2)?,
                    request_digest: row.get(3)?,
                    request_payload: row.get(4)?,
                    state: row.get(5)?,
                    ticket_id: row.get(6)?,
                    ticket_digest: row.get(7)?,
                    signed_ticket: row.get(8)?,
                    error_code: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(map_sql)
}

fn query_privileged_binding(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<PrivilegedOperationBinding>, StoreError> {
    connection
        .query_row(
            "SELECT idempotency_key,installation_id,policy_revision,policy_digest,helper_key_id,ticket_id,ticket_digest,signed_ticket,runtime_spec_digest,launch_plan_digest,local_plan_digest,local_plan,controller_epoch,state FROM privileged_operation_bindings WHERE idempotency_key=?1",
            [idempotency_key],
            |row| {
                Ok(PrivilegedOperationBinding {
                    idempotency_key: row.get(0)?,
                    installation_id: row.get(1)?,
                    policy_revision: row.get(2)?,
                    policy_digest: row.get(3)?,
                    helper_key_id: row.get(4)?,
                    ticket_id: row.get(5)?,
                    ticket_digest: row.get(6)?,
                    signed_ticket: row.get(7)?,
                    runtime_spec_digest: row.get(8)?,
                    launch_plan_digest: row.get(9)?,
                    local_plan_digest: row.get(10)?,
                    local_plan: row.get(11)?,
                    controller_epoch: row.get(12)?,
                    state: row.get(13)?,
                })
            },
        )
        .optional()
        .map_err(map_sql)
}

fn row_to_privileged_receipt(row: &rusqlite::Row<'_>) -> rusqlite::Result<PrivilegedReceiptRecord> {
    Ok(PrivilegedReceiptRecord {
        receipt_digest: row.get(0)?,
        idempotency_key: row.get(1)?,
        ticket_id: row.get(2)?,
        ticket_digest: row.get(3)?,
        runtime_id: row.get(4)?,
        state_revision: row.get(5)?,
        transition: row.get(6)?,
        previous_receipt_digest: row.get(7)?,
        signed_receipt: row.get(8)?,
    })
}

fn query_privileged_receipt(
    connection: &Connection,
    receipt_digest: &str,
) -> Result<Option<PrivilegedReceiptRecord>, StoreError> {
    connection
        .query_row(
            "SELECT receipt_digest,idempotency_key,ticket_id,ticket_digest,runtime_id,state_revision,transition,previous_receipt_digest,signed_receipt FROM privileged_receipt_chain WHERE receipt_digest=?1",
            [receipt_digest],
            row_to_privileged_receipt,
        )
        .optional()
        .map_err(map_sql)
}

fn query_last_privileged_receipt(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<PrivilegedReceiptRecord>, StoreError> {
    connection
        .query_row(
            "SELECT receipt_digest,idempotency_key,ticket_id,ticket_digest,runtime_id,state_revision,transition,previous_receipt_digest,signed_receipt FROM privileged_receipt_chain WHERE idempotency_key=?1 ORDER BY state_revision DESC LIMIT 1",
            [idempotency_key],
            row_to_privileged_receipt,
        )
        .optional()
        .map_err(map_sql)
}

fn query_agent_session(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<AgentSessionRecord>, StoreError> {
    connection.query_row(
        "SELECT idempotency_key,policy,controller_epoch,revision,state,lease_expires_at_unix_ms FROM agent_sessions WHERE idempotency_key=?1",
        [idempotency_key],
        |row| Ok(AgentSessionRecord {
            idempotency_key: row.get(0)?,
            policy: row.get(1)?,
            controller_epoch: row.get(2)?,
            revision: row.get(3)?,
            state: row.get(4)?,
            lease_expires_at_unix_ms: row.get(5)?,
        }),
    ).optional().map_err(map_sql)
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
    if version == 4 {
        conn.execute_batch(
            r#"BEGIN IMMEDIATE;
ALTER TABLE agent_approval_journal RENAME TO agent_approval_journal_v4;
CREATE TABLE agent_approval_journal(
 approval_id TEXT PRIMARY KEY,
 idempotency_key TEXT NOT NULL REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 operation_digest TEXT NOT NULL,
 provider_request_id BLOB NOT NULL,
 method TEXT NOT NULL,
 parameters_digest TEXT NOT NULL,
 expires_at_unix_ms INTEGER NOT NULL,
 request_payload BLOB,
 state TEXT NOT NULL CHECK(state IN ('pending','requested','resolved','applied')),
 resolution BLOB,
 resolution_authority BLOB,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(operation_digest)=64), CHECK(length(parameters_digest)=64),
 CHECK(length(provider_request_id)<=512), CHECK(length(method)<=128),
 CHECK(request_payload IS NULL OR length(request_payload)<=60000),
 CHECK(resolution IS NULL OR length(resolution)<=60000),
 CHECK(resolution_authority IS NULL OR (length(resolution_authority)>=1 AND length(resolution_authority)<=256)));
INSERT INTO agent_approval_journal(approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,state,resolution,created_at,updated_at)
 SELECT approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,CASE WHEN state='pending' THEN 'requested' ELSE state END,resolution,created_at,updated_at FROM agent_approval_journal_v4;
DROP TABLE agent_approval_journal_v4;
COMMIT;"#,
        )
        .map_err(map_sql)?;
    }
    if version == 5 {
        conn.execute(
            "ALTER TABLE agent_approval_journal ADD COLUMN resolution_authority BLOB",
            [],
        )
        .map_err(map_sql)?;
    }
    if (4..8).contains(&version) {
        conn.execute_batch(
            r#"BEGIN IMMEDIATE;
DROP INDEX IF EXISTS agent_approval_pending_idx;
DROP INDEX IF EXISTS agent_approval_provider_request_unique_idx;
ALTER TABLE agent_approval_journal RENAME TO agent_approval_journal_v7;
CREATE TABLE agent_approval_journal(
 approval_id TEXT PRIMARY KEY,
 idempotency_key TEXT NOT NULL REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 operation_digest TEXT NOT NULL,
 provider_request_id BLOB NOT NULL,
 method TEXT NOT NULL,
 parameters_digest TEXT NOT NULL,
 expires_at_unix_ms INTEGER NOT NULL,
 request_payload BLOB,
 state TEXT NOT NULL CHECK(state IN ('pending','requested','resolved','applied','abandoned')),
 resolution BLOB,
 resolution_authority BLOB,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(operation_digest)=64), CHECK(length(parameters_digest)=64),
 CHECK(length(provider_request_id)<=512), CHECK(length(method)<=128),
 CHECK(request_payload IS NULL OR length(request_payload)<=60000),
 CHECK(resolution IS NULL OR length(resolution)<=60000),
 CHECK(resolution_authority IS NULL OR (length(resolution_authority)>=1 AND length(resolution_authority)<=256)));
INSERT INTO agent_approval_journal(approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload,state,resolution,resolution_authority,created_at,updated_at)
 SELECT approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload,state,resolution,resolution_authority,created_at,updated_at FROM agent_approval_journal_v7;
DROP TABLE agent_approval_journal_v7;
CREATE INDEX agent_approval_pending_idx ON agent_approval_journal(state,expires_at_unix_ms);
CREATE UNIQUE INDEX agent_approval_provider_request_unique_idx ON agent_approval_journal(idempotency_key,provider_request_id);
COMMIT;"#,
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
CREATE TABLE IF NOT EXISTS control_effect_journal(
 operation_id TEXT NOT NULL, idempotency_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
 target_run_id TEXT NOT NULL, target_runtime_id TEXT, target_digest TEXT NOT NULL,
 controller_epoch INTEGER NOT NULL, expected_revision INTEGER NOT NULL, command TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','applied','failed')), receipt BLOB,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(request_digest)=64), CHECK(length(target_digest)=64), CHECK(length(command) BETWEEN 1 AND 64),
 CHECK(controller_epoch>0), CHECK(expected_revision>0), CHECK(receipt IS NULL OR length(receipt)<=60000));
CREATE TABLE IF NOT EXISTS privilege_ticket_requests(
 request_id TEXT PRIMARY KEY,
 operation_idempotency_key TEXT NOT NULL REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 ticket_idempotency_key TEXT NOT NULL UNIQUE,
 request_digest TEXT NOT NULL, request_payload BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','issued','rejected')),
 ticket_id TEXT UNIQUE, ticket_digest TEXT UNIQUE, signed_ticket BLOB, error_code TEXT,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(request_id) BETWEEN 1 AND 128), CHECK(length(request_digest)=64),
 CHECK(length(ticket_idempotency_key) BETWEEN 16 AND 256),
 CHECK(length(request_payload) BETWEEN 1 AND 60000),
 CHECK(ticket_id IS NULL OR length(ticket_id) BETWEEN 1 AND 128),
 CHECK(ticket_digest IS NULL OR length(ticket_digest)=64),
 CHECK(signed_ticket IS NULL OR length(signed_ticket) BETWEEN 1 AND 60000),
 CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
 CHECK((state='pending' AND ticket_id IS NULL AND signed_ticket IS NULL AND error_code IS NULL)
    OR (state='issued' AND ticket_id IS NOT NULL AND ticket_digest IS NOT NULL AND signed_ticket IS NOT NULL AND error_code IS NULL)
    OR (state='rejected' AND ticket_id IS NULL AND ticket_digest IS NULL AND signed_ticket IS NULL AND error_code IS NOT NULL)));
CREATE INDEX IF NOT EXISTS privilege_ticket_operation_idx ON privilege_ticket_requests(operation_idempotency_key,created_at);
CREATE TABLE IF NOT EXISTS privileged_operation_bindings(
 idempotency_key TEXT PRIMARY KEY REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 installation_id TEXT NOT NULL, policy_revision INTEGER NOT NULL, policy_digest TEXT NOT NULL,
 helper_key_id TEXT NOT NULL, ticket_id TEXT NOT NULL UNIQUE, ticket_digest TEXT NOT NULL UNIQUE,
 signed_ticket BLOB NOT NULL, runtime_spec_digest TEXT NOT NULL, launch_plan_digest TEXT NOT NULL,
 local_plan_digest TEXT NOT NULL, local_plan BLOB NOT NULL, controller_epoch INTEGER NOT NULL, state TEXT NOT NULL,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(policy_revision>0), CHECK(controller_epoch>0), CHECK(length(policy_digest)=64),
 CHECK(length(ticket_digest)=64), CHECK(length(runtime_spec_digest)=64),
 CHECK(length(launch_plan_digest)=64), CHECK(length(local_plan_digest)=64),
 CHECK(length(local_plan) BETWEEN 1 AND 262144),
 CHECK(length(signed_ticket) BETWEEN 1 AND 60000));
CREATE TABLE IF NOT EXISTS privileged_receipt_chain(
 receipt_digest TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL REFERENCES privileged_operation_bindings(idempotency_key) ON DELETE RESTRICT,
 ticket_id TEXT NOT NULL, ticket_digest TEXT NOT NULL,
 runtime_id TEXT NOT NULL, state_revision INTEGER NOT NULL, transition TEXT NOT NULL,
 previous_receipt_digest TEXT, signed_receipt BLOB NOT NULL,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 UNIQUE(idempotency_key,state_revision),
 CHECK(length(receipt_digest)=64), CHECK(length(ticket_id) BETWEEN 1 AND 128),
 CHECK(length(ticket_digest)=64), CHECK(state_revision>0),
 CHECK(length(transition) BETWEEN 1 AND 64),
 CHECK(previous_receipt_digest IS NULL OR length(previous_receipt_digest)=64),
 CHECK(length(signed_receipt) BETWEEN 1 AND 60000));
CREATE TABLE IF NOT EXISTS agent_sessions(
 idempotency_key TEXT PRIMARY KEY REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 policy TEXT NOT NULL CHECK(policy IN ('close_on_settle','persistent')),
 controller_epoch INTEGER NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL,
 lease_expires_at_unix_ms INTEGER, created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT(unixepoch()), CHECK(controller_epoch>0), CHECK(revision>0),
 CHECK(state IN ('running','waiting_input','closed','cancelled','timed_out')));
CREATE TABLE IF NOT EXISTS agent_approval_journal(
 approval_id TEXT PRIMARY KEY,
 idempotency_key TEXT NOT NULL REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 operation_digest TEXT NOT NULL,
 provider_request_id BLOB NOT NULL,
 method TEXT NOT NULL,
 parameters_digest TEXT NOT NULL,
 expires_at_unix_ms INTEGER NOT NULL,
 request_payload BLOB,
 state TEXT NOT NULL CHECK(state IN ('pending','requested','resolved','applied','abandoned')),
 resolution BLOB,
 resolution_authority BLOB,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(operation_digest)=64), CHECK(length(parameters_digest)=64),
 CHECK(length(provider_request_id)<=512), CHECK(length(method)<=128),
 CHECK(request_payload IS NULL OR length(request_payload)<=60000),
 CHECK(resolution IS NULL OR length(resolution)<=60000),
 CHECK(resolution_authority IS NULL OR (length(resolution_authority)>=1 AND length(resolution_authority)<=256)));
CREATE INDEX IF NOT EXISTS agent_approval_pending_idx ON agent_approval_journal(state,expires_at_unix_ms);
CREATE UNIQUE INDEX IF NOT EXISTS agent_approval_provider_request_unique_idx ON agent_approval_journal(idempotency_key,provider_request_id);
INSERT OR IGNORE INTO schema_migrations(version) VALUES(1),(2),(3),(4),(5),(6),(7),(8),(9),(10);
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
    fn reconciliation_can_terminalize_every_pre_terminal_custody_state() {
        for state in [
            OperationState::Admitted,
            OperationState::Starting,
            OperationState::Running,
            OperationState::WaitingInput,
            OperationState::WaitingApproval,
            OperationState::Finishing,
        ] {
            assert!(state.permits(OperationState::Cancelled), "{state:?}");
            assert!(state.permits(OperationState::RecoveryRequired), "{state:?}");
        }
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
    fn control_effect_journal_replays_receipt_and_fences_ambiguous_effect() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let key = "runtime-control-idempotency-0001";
        assert!(matches!(
            store
                .reserve_control_effect(
                    "op_control_0001",
                    key,
                    &digest(1),
                    "run_control_0001",
                    Some("rt_control_0001"),
                    &digest(2),
                    7,
                    3,
                    "pause",
                )
                .unwrap(),
            ControlEffectResult::Reserved(_)
        ));
        assert!(matches!(
            store
                .reserve_control_effect(
                    "op_control_0001",
                    key,
                    &digest(1),
                    "run_control_0001",
                    Some("rt_control_0001"),
                    &digest(2),
                    7,
                    3,
                    "pause",
                )
                .unwrap(),
            ControlEffectResult::Uncertain(_)
        ));
        store
            .complete_control_effect(key, true, b"receipt-a")
            .unwrap();
        drop(store);
        let store = NodeStore::open(directory.path()).unwrap();
        let replay = store
            .reserve_control_effect(
                "op_control_0001",
                key,
                &digest(1),
                "run_control_0001",
                Some("rt_control_0001"),
                &digest(2),
                7,
                3,
                "pause",
            )
            .unwrap();
        assert!(
            matches!(replay, ControlEffectResult::Replay(record) if record.receipt.as_deref() == Some(b"receipt-a"))
        );
        assert!(matches!(
            store.reserve_control_effect(
                "op_control_0001",
                key,
                &digest(1),
                "run_control_0001",
                Some("rt_control_0001"),
                &digest(2),
                7,
                4,
                "pause",
            ),
            Err(StoreError::IdempotencyConflict)
        ));
    }

    #[test]
    fn persistent_agent_session_lease_supports_follow_up_close_cancel_and_idle_timeout() {
        for (suffix, terminal) in [
            ("follow-close", "closed"),
            ("cancel", "cancelled"),
            ("idle", "timed_out"),
        ] {
            let directory = tempdir().unwrap();
            let store = NodeStore::open(directory.path()).unwrap();
            let key = format!("agent-session-{suffix}-idempotency");
            store
                .reserve_operation(
                    &format!("op_agent_{suffix}0001"),
                    &key,
                    &digest(1),
                    b"{}",
                    1,
                )
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Reserved,
                    OperationState::Admitted,
                    None,
                    None,
                    None,
                )
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Admitted,
                    OperationState::Starting,
                    None,
                    None,
                    None,
                )
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Starting,
                    OperationState::Running,
                    None,
                    None,
                    None,
                )
                .unwrap();
            store
                .record_agent_session(&key, "persistent", 3, Some(50_000))
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Running,
                    OperationState::WaitingInput,
                    None,
                    None,
                    None,
                )
                .unwrap();
            let waiting = store
                .transition_agent_session(&key, "running", 1, "waiting_input", Some(40_000))
                .unwrap();
            assert_eq!(waiting.revision, 2);
            if suffix == "follow-close" {
                store
                    .transition_operation(
                        &key,
                        OperationState::WaitingInput,
                        OperationState::Running,
                        None,
                        None,
                        None,
                    )
                    .unwrap();
                let resumed = store
                    .transition_agent_session(&key, "waiting_input", 2, "running", Some(45_000))
                    .unwrap();
                assert_eq!(resumed.revision, 3);
                store
                    .transition_agent_session(&key, "running", 3, terminal, None)
                    .unwrap();
            } else {
                store
                    .transition_agent_session(&key, "waiting_input", 2, terminal, None)
                    .unwrap();
            }
            assert_eq!(store.agent_session(&key).unwrap().unwrap().state, terminal);
        }
    }

    #[test]
    fn agent_approval_response_is_durable_and_idempotent_before_apply() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        store
            .reserve_operation(
                "op_approval01",
                "approval-idempotency-key",
                &digest(1),
                b"{}",
                1,
            )
            .unwrap();
        store
            .transition_operation(
                "approval-idempotency-key",
                OperationState::Reserved,
                OperationState::Admitted,
                None,
                None,
                None,
            )
            .unwrap();
        store
            .transition_operation(
                "approval-idempotency-key",
                OperationState::Admitted,
                OperationState::Starting,
                None,
                None,
                None,
            )
            .unwrap();
        store
            .transition_operation(
                "approval-idempotency-key",
                OperationState::Starting,
                OperationState::Running,
                None,
                None,
                None,
            )
            .unwrap();
        let request_id = br#""provider-7""#;
        let request_payload = br#"{"approvalId":"appr_xapproval01"}"#;
        store
            .record_agent_approval(
                "appr_xapproval01",
                "approval-idempotency-key",
                &digest(2),
                request_id,
                "item/commandExecution/requestApproval",
                &digest(3),
                2_000_000_000_000,
                request_payload,
            )
            .unwrap();
        assert!(matches!(
            store.record_agent_approval(
                "appr_xapproval02",
                "approval-idempotency-key",
                &digest(4),
                request_id,
                "item/commandExecution/requestApproval",
                &digest(5),
                2_000_000_000_000,
                br#"{"approvalId":"appr_xapproval02"}"#,
            ),
            Err(StoreError::IdempotencyConflict)
        ));
        assert_eq!(
            store
                .operation("approval-idempotency-key")
                .unwrap()
                .unwrap()
                .state,
            OperationState::WaitingApproval
        );
        let unqueued = store
            .unqueued_agent_approvals("approval-idempotency-key")
            .unwrap();
        assert_eq!(unqueued.len(), 1);
        assert_eq!(
            unqueued[0].request_payload.as_deref(),
            Some(request_payload.as_slice())
        );
        store
            .mark_agent_approval_requested("appr_xapproval01")
            .unwrap();
        store
            .mark_agent_approval_requested("appr_xapproval01")
            .unwrap();
        store
            .record_agent_approval_resolution(
                "appr_xapproval01",
                b"provider-frame\n",
                b"receipt-digest-a",
            )
            .unwrap();
        store
            .record_agent_approval_resolution(
                "appr_xapproval01",
                b"provider-frame\n",
                b"receipt-digest-a",
            )
            .unwrap();
        assert!(matches!(
            store.record_agent_approval_resolution(
                "appr_xapproval01",
                b"provider-frame\n",
                b"receipt-digest-b",
            ),
            Err(StoreError::IdempotencyConflict)
        ));
        drop(store);
        let reopened = NodeStore::open(directory.path()).unwrap();
        let pending = reopened
            .resolved_agent_approvals("approval-idempotency-key")
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].provider_request_id, request_id);
        assert_eq!(
            pending[0].resolution.as_deref(),
            Some(b"provider-frame\n".as_slice())
        );
        assert_eq!(
            pending[0].resolution_authority.as_deref(),
            Some(b"receipt-digest-a".as_slice())
        );
        reopened
            .mark_agent_approval_applied_and_resume("appr_xapproval01", "approval-idempotency-key")
            .unwrap();
        reopened
            .mark_agent_approval_applied_and_resume("appr_xapproval01", "approval-idempotency-key")
            .unwrap();
        assert_eq!(
            reopened
                .operation("approval-idempotency-key")
                .unwrap()
                .unwrap()
                .state,
            OperationState::Running
        );
        assert_eq!(
            reopened
                .operation("approval-idempotency-key")
                .unwrap()
                .unwrap()
                .receipt
                .as_deref(),
            Some(b"receipt-digest-a".as_slice())
        );
        assert!(matches!(
            reopened.record_agent_approval_resolution(
                "appr_xapproval01",
                b"opposite-provider-frame\n",
                b"receipt-digest-b",
            ),
            Err(StoreError::IdempotencyConflict)
        ));
        assert_eq!(
            reopened
                .operation("approval-idempotency-key")
                .unwrap()
                .unwrap()
                .receipt
                .as_deref(),
            Some(b"receipt-digest-a".as_slice())
        );
        assert!(
            reopened
                .resolved_agent_approvals("approval-idempotency-key")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn agent_finalization_atomically_abandons_outstanding_approvals() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let key = "finalization-idempotency-key";
        store
            .reserve_operation("op_finalize01", key, &digest(1), b"{}", 1)
            .unwrap();
        for (from, to) in [
            (OperationState::Reserved, OperationState::Admitted),
            (OperationState::Admitted, OperationState::Starting),
            (OperationState::Starting, OperationState::Running),
        ] {
            store
                .transition_operation(key, from, to, None, None, None)
                .unwrap();
        }
        for suffix in ["pending", "requested", "resolved"] {
            store
                .record_agent_approval(
                    &format!("appr_x{suffix}01"),
                    key,
                    &digest(2),
                    format!("\"provider-{suffix}\"").as_bytes(),
                    "item/commandExecution/requestApproval",
                    &digest(3),
                    2_000_000_000_000,
                    format!("{{\"approvalId\":\"appr_x{suffix}01\"}}").as_bytes(),
                )
                .unwrap();
        }
        store
            .mark_agent_approval_requested("appr_xrequested01")
            .unwrap();
        store
            .record_agent_approval_resolution(
                "appr_xresolved01",
                b"provider-frame\n",
                b"receipt-digest",
            )
            .unwrap();

        store.begin_agent_finalization(key).unwrap();
        store.begin_agent_finalization(key).unwrap();

        assert_eq!(
            store.operation(key).unwrap().unwrap().state,
            OperationState::Finishing
        );
        for suffix in ["pending", "requested", "resolved"] {
            assert_eq!(
                store
                    .agent_approval(&format!("appr_x{suffix}01"))
                    .unwrap()
                    .unwrap()
                    .state,
                "abandoned"
            );
        }
        assert!(store.unqueued_agent_approvals(key).unwrap().is_empty());
        assert!(store.resolved_agent_approvals(key).unwrap().is_empty());
        assert!(matches!(
            store.mark_agent_approval_requested("appr_xpending01"),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.record_agent_approval_resolution(
                "appr_xrequested01",
                b"late-provider-frame\n",
                b"late-receipt"
            ),
            Err(StoreError::Invalid(message)) if message.contains("abandoned")
        ));
        assert!(matches!(
            store.mark_agent_approval_applied_and_resume("appr_xresolved01", key),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn version_seven_approval_journal_migrates_to_abandoned_state() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("node.sqlite3");
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT(unixepoch()));
INSERT INTO schema_migrations(version) VALUES(1),(2),(3),(4),(5),(6),(7);
CREATE TABLE operations(
 operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
 manifest BLOB NOT NULL, local_policy_revision INTEGER NOT NULL, state TEXT NOT NULL,
 runtime_id TEXT, process_identity TEXT, last_event_sequence INTEGER NOT NULL DEFAULT 0,
 receipt BLOB, updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 CHECK(length(request_digest)=64), CHECK(length(manifest)<=262144));
CREATE TABLE agent_approval_journal(
 approval_id TEXT PRIMARY KEY,
 idempotency_key TEXT NOT NULL REFERENCES operations(idempotency_key) ON DELETE RESTRICT,
 operation_digest TEXT NOT NULL, provider_request_id BLOB NOT NULL, method TEXT NOT NULL,
 parameters_digest TEXT NOT NULL, expires_at_unix_ms INTEGER NOT NULL, request_payload BLOB,
 state TEXT NOT NULL CHECK(state IN ('pending','requested','resolved','applied')),
 resolution BLOB, resolution_authority BLOB,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()));
CREATE INDEX agent_approval_pending_idx ON agent_approval_journal(state,expires_at_unix_ms);
CREATE UNIQUE INDEX agent_approval_provider_request_unique_idx ON agent_approval_journal(idempotency_key,provider_request_id);
INSERT INTO operations(operation_id,idempotency_key,request_digest,manifest,local_policy_revision,state)
 VALUES('op_migrate01','migration-idempotency-key','1111111111111111111111111111111111111111111111111111111111111111',X'7B7D',1,'waiting_approval');
INSERT INTO agent_approval_journal(approval_id,idempotency_key,operation_digest,provider_request_id,method,parameters_digest,expires_at_unix_ms,request_payload,state)
 VALUES('appr_xmigrate01','migration-idempotency-key','2222222222222222222222222222222222222222222222222222222222222222',X'2270726F76696465722D3122','approval','3333333333333333333333333333333333333333333333333333333333333333',2000000000000,X'7B7D','requested');"#,
        )
        .unwrap();
        drop(conn);
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();

        let store = NodeStore::open(directory.path()).unwrap();
        store
            .begin_agent_finalization("migration-idempotency-key")
            .unwrap();
        assert_eq!(
            store
                .agent_approval("appr_xmigrate01")
                .unwrap()
                .unwrap()
                .state,
            "abandoned"
        );
        assert_eq!(
            store
                .operation("migration-idempotency-key")
                .unwrap()
                .unwrap()
                .state,
            OperationState::Finishing
        );
        let version: u32 = store
            .conn()
            .unwrap()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, STORE_SCHEMA_VERSION);
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
            s.inbound_applied_through(Direction::ControlToNode).unwrap(),
            0
        );
        assert_eq!(
            s.receive(Direction::ControlToNode, &one).unwrap(),
            ReceiveResult::DuplicatePending
        );
        s.mark_inbound_applied(Direction::ControlToNode, 1).unwrap();
        assert_eq!(
            s.inbound_applied_through(Direction::ControlToNode).unwrap(),
            1
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
    fn privilege_ticket_and_receipt_chain_survive_restart_and_reject_conflicts() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let key = "privileged-idempotency-key-0001";
        store
            .reserve_operation("op_privileged_0001", key, &digest(1), b"{}", 7)
            .unwrap();
        assert!(matches!(
            store
                .reserve_privilege_ticket_request(
                    "ptreq_0001",
                    key,
                    "ticket-idempotency-0001",
                    &digest(2),
                    b"ticket-request",
                )
                .unwrap(),
            PrivilegeTicketRequestResult::Reserved(_)
        ));
        assert!(matches!(
            store
                .reserve_privilege_ticket_request(
                    "ptreq_0001",
                    key,
                    "ticket-idempotency-0001",
                    &digest(2),
                    b"ticket-request",
                )
                .unwrap(),
            PrivilegeTicketRequestResult::Uncertain(_)
        ));
        assert!(matches!(
            store.reserve_privilege_ticket_request(
                "ptreq_0001",
                key,
                "ticket-idempotency-0001",
                &digest(3),
                b"changed",
            ),
            Err(StoreError::IdempotencyConflict)
        ));
        store
            .complete_privilege_ticket_request(
                "ptreq_0001",
                Some(("ptkt_0001", &digest(3), b"signed-ticket")),
                None,
            )
            .unwrap();
        store
            .bind_privileged_operation(
                key,
                "install_0001",
                3,
                &digest(4),
                "receipt-key-0001",
                "ptkt_0001",
                &digest(3),
                b"signed-ticket",
                &digest(5),
                &digest(6),
                &digest(7),
                b"local-plan",
                2,
            )
            .unwrap();
        let first = store
            .append_privileged_receipt(
                key,
                &digest(8),
                "ptkt_0001",
                &digest(3),
                "runtime_0001",
                1,
                "prepared",
                None,
                b"signed-receipt-1",
            )
            .unwrap();
        assert_eq!(first.state_revision, 1);
        drop(store);

        let reopened = NodeStore::open(directory.path()).unwrap();
        reopened
            .reserve_privilege_ticket_request(
                "ptreq_0001_start",
                key,
                "ticket-idempotency-0001-start",
                &digest(11),
                b"start-ticket-request",
            )
            .unwrap();
        reopened
            .complete_privilege_ticket_request(
                "ptreq_0001_start",
                Some(("ptkt_0001_start", &digest(12), b"signed-start-ticket")),
                None,
            )
            .unwrap();
        let second = reopened
            .append_privileged_receipt(
                key,
                &digest(9),
                "ptkt_0001_start",
                &digest(12),
                "runtime_0001",
                2,
                "running",
                Some(&digest(8)),
                b"signed-receipt-2",
            )
            .unwrap();
        assert_eq!(second.previous_receipt_digest.as_deref(), Some(&*digest(8)));
        assert_eq!(reopened.privileged_receipts(key).unwrap().len(), 2);
        assert!(matches!(
            reopened.append_privileged_receipt(
                key,
                &digest(10),
                "ptkt_0001",
                &digest(3),
                "runtime_0001",
                3,
                "completed",
                Some(&digest(7)),
                b"bad-chain",
            ),
            Err(StoreError::SequenceConflict)
        ));
    }

    #[test]
    fn rejected_privilege_ticket_cannot_be_bound() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let key = "privileged-idempotency-key-0002";
        store
            .reserve_operation("op_privileged_0002", key, &digest(1), b"{}", 7)
            .unwrap();
        store
            .reserve_privilege_ticket_request(
                "ptreq_0002",
                key,
                "ticket-idempotency-0002",
                &digest(2),
                b"request",
            )
            .unwrap();
        store
            .complete_privilege_ticket_request(
                "ptreq_0002",
                None,
                Some("full_device_helper_disabled"),
            )
            .unwrap();
        assert!(matches!(
            store.bind_privileged_operation(
                key,
                "install_0001",
                1,
                &digest(3),
                "receipt-key-0001",
                "ptkt_0002",
                &digest(4),
                b"forged",
                &digest(5),
                &digest(6),
                &digest(7),
                b"local-plan",
                1,
            ),
            Err(StoreError::NotFound)
        ));
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
