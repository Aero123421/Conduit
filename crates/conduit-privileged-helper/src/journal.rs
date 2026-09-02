use crate::{HelperError, Result};
use conduit_privileged_protocol::{HelperReceipt, LocalExecutionPlan, PrivilegeTicket};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

pub const JOURNAL_SCHEMA_VERSION: u32 = 3;
const MAX_RECORD_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEffect {
    pub ticket_id: String,
    pub ticket_digest: String,
    pub request_digest: String,
    pub operation: String,
    pub runtime_id: String,
    pub state: String,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectDisposition {
    Reserved(JournalEffect),
    InProgress(JournalEffect),
    Replay(JournalEffect),
    Uncertain(JournalEffect),
}

#[derive(Debug, Clone)]
pub struct RuntimeRecord {
    pub runtime_id: String,
    pub run_id: String,
    pub operation_id: String,
    pub plan_digest: String,
    pub plan: LocalExecutionPlan,
    pub authority_ticket: PrivilegeTicket,
    pub unit_name: String,
    pub invocation_id: Option<String>,
    pub main_pid: Option<u32>,
    pub state: String,
    pub state_revision: u64,
    pub previous_receipt_digest: Option<String>,
    pub last_receipt: Option<HelperReceipt>,
    pub stdout_cursor: u64,
    pub stderr_cursor: u64,
}

#[derive(Clone)]
pub struct HelperJournal {
    connection: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl HelperJournal {
    /// Production entry point. The database and its parent must be owned by
    /// root and unavailable to group/other users.
    pub fn open_root_owned(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_owned(path, 0)
    }

    pub fn open_owned(path: impl AsRef<Path>, expected_uid: u32) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .ok_or_else(|| HelperError::Journal("journal parent missing".into()))?;
        fs::create_dir_all(parent)?;
        validate_directory(parent, expected_uid)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        if path.exists() {
            validate_regular(&path, expected_uid, 0o600)?;
        }
        let connection = Connection::open(&path).map_err(sql_error)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
            )
            .map_err(sql_error)?;
        migrate(&connection)?;
        integrity(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn integrity_check(&self) -> Result<()> {
        let connection = self.lock()?;
        integrity(&connection)
    }

    /// Returns true only when this exact signed ticket was already placed in
    /// durable custody. This permits an identical retry to replay after the
    /// ticket's wall-clock expiry without extending authority to a different
    /// request (the effect identity is checked again by `reserve_effect`).
    pub fn has_admitted_ticket(&self, ticket_id: &str, ticket_digest: &str) -> Result<bool> {
        let connection = self.lock()?;
        let existing = query_effect(&connection, ticket_id)?;
        Ok(existing
            .as_ref()
            .is_some_and(|effect| effect.ticket_digest == ticket_digest))
    }

    pub fn admit_prepare(
        &self,
        ticket: &PrivilegeTicket,
        ticket_digest: &str,
        request_digest: &str,
        plan_digest: &str,
        plan: &LocalExecutionPlan,
    ) -> Result<EffectDisposition> {
        let ticket_id = &ticket.claims.ticket_id;
        let encoded_plan = serde_jcs::to_vec(plan)?;
        if encoded_plan.len() > MAX_RECORD_BYTES {
            return Err(HelperError::Journal("execution plan exceeds bound".into()));
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(existing) = query_effect(&transaction, ticket_id)? {
            verify_effect_identity(
                &existing,
                ticket_digest,
                request_digest,
                "prepare",
                &plan.runtime_id,
            )?;
            transaction.commit().map_err(sql_error)?;
            return Ok(disposition(existing));
        }
        if let Some(existing_digest) = transaction
            .query_row(
                "SELECT plan_digest FROM runtimes WHERE runtime_id=?1",
                [&plan.runtime_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sql_error)?
        {
            if existing_digest != plan_digest {
                return Err(HelperError::Denied("privilege_ticket_conflict".into()));
            }
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO runtimes(runtime_id,run_id,operation_id,plan_digest,plan,authority_ticket,unit_name,state,state_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,'admitted',0)",
                params![plan.runtime_id, plan.run_id, plan.operation_id, plan_digest, encoded_plan, serde_jcs::to_vec(ticket)?, plan.systemd_unit],
            )
            .map_err(sql_error)?;
        insert_effect(
            &transaction,
            ticket_id,
            ticket_digest,
            request_digest,
            "prepare",
            &plan.runtime_id,
        )?;
        transaction.execute("UPDATE runtimes SET authority_ticket=?2,updated_at=unixepoch() WHERE runtime_id=?1",params![plan.runtime_id,serde_jcs::to_vec(ticket)?]).map_err(sql_error)?;
        let effect = query_effect(&transaction, ticket_id)?
            .ok_or_else(|| HelperError::Journal("durable prepare admission missing".into()))?;
        transaction.commit().map_err(sql_error)?;
        sync_parent(&self.path)?;
        Ok(EffectDisposition::Reserved(effect))
    }

    pub fn reserve_effect(
        &self,
        ticket: &PrivilegeTicket,
        ticket_digest: &str,
        request_digest: &str,
        operation: &str,
        runtime_id: &str,
    ) -> Result<EffectDisposition> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(existing) = query_effect(&transaction, &ticket.claims.ticket_id)? {
            verify_effect_identity(
                &existing,
                ticket_digest,
                request_digest,
                operation,
                runtime_id,
            )?;
            transaction.commit().map_err(sql_error)?;
            return Ok(disposition(existing));
        }
        let runtime_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runtimes WHERE runtime_id=?1)",
                [runtime_id],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if !runtime_exists {
            return Err(HelperError::Denied(
                "privileged_runtime_not_prepared".into(),
            ));
        }
        insert_effect(
            &transaction,
            &ticket.claims.ticket_id,
            ticket_digest,
            request_digest,
            operation,
            runtime_id,
        )?;
        transaction.execute("UPDATE runtimes SET authority_ticket=?2,updated_at=unixepoch() WHERE runtime_id=?1",params![runtime_id,serde_jcs::to_vec(ticket)?]).map_err(sql_error)?;
        let effect = query_effect(&transaction, &ticket.claims.ticket_id)?
            .ok_or_else(|| HelperError::Journal("durable effect admission missing".into()))?;
        transaction.commit().map_err(sql_error)?;
        sync_parent(&self.path)?;
        Ok(EffectDisposition::Reserved(effect))
    }

    pub fn complete_effect(
        &self,
        ticket_id: &str,
        receipt: &HelperReceipt,
        runtime_state: &str,
        invocation_id: Option<&str>,
        main_pid: Option<u32>,
    ) -> Result<()> {
        self.record_effect_boundary(
            ticket_id,
            receipt,
            runtime_state,
            invocation_id,
            main_pid,
            true,
        )
    }
    pub fn record_effect_boundary(
        &self,
        ticket_id: &str,
        receipt: &HelperReceipt,
        runtime_state: &str,
        invocation_id: Option<&str>,
        main_pid: Option<u32>,
        final_boundary: bool,
    ) -> Result<()> {
        let encoded = serde_jcs::to_vec(receipt)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(HelperError::Journal("receipt exceeds bound".into()));
        }
        let digest = receipt.digest()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let effect = query_effect(&transaction, ticket_id)?
            .ok_or_else(|| HelperError::Journal("effect admission missing".into()))?;
        match effect.state.as_str() {
            "reserved" => {
                let mut chain = decode_chain(effect.receipt.as_deref())?;
                if let Some(existing) = chain
                    .iter()
                    .find(|value| value.claims.state_revision == receipt.claims.state_revision)
                {
                    if existing == receipt {
                        return Ok(());
                    }
                    return Err(HelperError::Denied("receipt_boundary_conflict".into()));
                }
                chain.push(receipt.clone());
                let encoded_chain = serde_jcs::to_vec(&chain)?;
                transaction
                    .execute(
                        "UPDATE effects SET state=?3,receipt=?2,updated_at=unixepoch() WHERE ticket_id=?1 AND state='reserved'",
                        params![ticket_id, encoded_chain,if final_boundary{"complete"}else{"reserved"}],
                    )
                    .map_err(sql_error)?;
            }
            "complete" if effect.receipt.as_deref() == Some(encoded.as_slice()) => return Ok(()),
            "complete" => return Err(HelperError::Denied("privilege_ticket_conflict".into())),
            _ => {
                return Err(HelperError::RecoveryRequired(
                    "effect state is uncertain".into(),
                ));
            }
        }
        let changed = transaction
            .execute(
                "UPDATE runtimes SET state=?2,state_revision=?3,invocation_id=COALESCE(?4,invocation_id),main_pid=COALESCE(?5,main_pid),previous_receipt_digest=?6,stdout_cursor=?7,stderr_cursor=?8,last_receipt=?9,updated_at=unixepoch() WHERE runtime_id=?1 AND state_revision<?3",
                params![receipt.claims.runtime_id, runtime_state, receipt.claims.state_revision, invocation_id, main_pid, digest, receipt.claims.stdout_cursor, receipt.claims.stderr_cursor,serde_jcs::to_vec(receipt)?],
            )
            .map_err(sql_error)?;
        if changed != 1 {
            return Err(HelperError::RecoveryRequired(
                "receipt state revision did not advance".into(),
            ));
        }
        transaction.commit().map_err(sql_error)?;
        sync_parent(&self.path)
    }

    pub fn record_observation(
        &self,
        receipt: &HelperReceipt,
        runtime_state: &str,
        invocation_id: Option<&str>,
        main_pid: Option<u32>,
    ) -> Result<()> {
        let digest = receipt.digest()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let changed=transaction.execute("UPDATE runtimes SET state=?2,state_revision=?3,invocation_id=COALESCE(?4,invocation_id),main_pid=?5,previous_receipt_digest=?6,stdout_cursor=?7,stderr_cursor=?8,last_receipt=?9,updated_at=unixepoch() WHERE runtime_id=?1 AND state_revision<?3",params![receipt.claims.runtime_id,runtime_state,receipt.claims.state_revision,invocation_id,main_pid,digest,receipt.claims.stdout_cursor,receipt.claims.stderr_cursor,serde_jcs::to_vec(receipt)?]).map_err(sql_error)?;
        if changed != 1 {
            return Err(HelperError::RecoveryRequired(
                "observation state revision did not advance".into(),
            ));
        }
        transaction.commit().map_err(sql_error)?;
        sync_parent(&self.path)
    }

    pub fn mark_uncertain(&self, ticket_id: &str) -> Result<()> {
        let connection = self.lock()?;
        let changed = connection
            .execute(
                "UPDATE effects SET state='uncertain',updated_at=unixepoch() WHERE ticket_id=?1 AND state='reserved'",
                [ticket_id],
            )
            .map_err(sql_error)?;
        if changed != 1 {
            return Err(HelperError::Journal("uncertain effect missing".into()));
        }
        Ok(())
    }

    pub fn active_runtime_count(&self) -> Result<u64> {
        self.lock()?
            .query_row(
                "SELECT count(*) FROM runtimes WHERE state NOT IN ('stopped','failed','terminal','recovery_required')",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)
    }

    pub fn purge_terminal(&self) -> Result<u64> {
        let changed = self
            .lock()?
            .execute(
                "DELETE FROM runtimes WHERE state IN ('stopped','failed','terminal','recovery_required')",
                [],
            )
            .map_err(sql_error)?;
        Ok(changed as u64)
    }

    pub fn runtime(&self, runtime_id: &str) -> Result<Option<RuntimeRecord>> {
        let connection = self.lock()?;
        query_runtime(&connection, runtime_id)
    }

    pub fn nonterminal_runtimes(&self) -> Result<Vec<RuntimeRecord>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT runtime_id FROM runtimes WHERE state NOT IN ('stopped','failed','terminal','recovery_required') ORDER BY updated_at,runtime_id LIMIT 256")
            .map_err(sql_error)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        ids.into_iter()
            .map(|id| {
                query_runtime(&connection, &id)?
                    .ok_or_else(|| HelperError::Journal("nonterminal runtime disappeared".into()))
            })
            .collect()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| HelperError::Journal("journal mutex poisoned".into()))
    }
}

fn insert_effect(
    transaction: &rusqlite::Transaction<'_>,
    ticket_id: &str,
    ticket_digest: &str,
    request_digest: &str,
    operation: &str,
    runtime_id: &str,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO effects(ticket_id,ticket_digest,request_digest,operation,runtime_id,state) VALUES(?1,?2,?3,?4,?5,'reserved')",
            params![ticket_id, ticket_digest, request_digest, operation, runtime_id],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn query_effect(connection: &Connection, ticket_id: &str) -> Result<Option<JournalEffect>> {
    connection
        .query_row(
            "SELECT ticket_id,ticket_digest,request_digest,operation,runtime_id,state,receipt FROM effects WHERE ticket_id=?1",
            [ticket_id],
            |row| {
                Ok(JournalEffect {
                    ticket_id: row.get(0)?,
                    ticket_digest: row.get(1)?,
                    request_digest: row.get(2)?,
                    operation: row.get(3)?,
                    runtime_id: row.get(4)?,
                    state: row.get(5)?,
                    receipt: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(sql_error)
}

fn query_runtime(connection: &Connection, runtime_id: &str) -> Result<Option<RuntimeRecord>> {
    connection
        .query_row(
            "SELECT runtime_id,run_id,operation_id,plan_digest,plan,authority_ticket,unit_name,invocation_id,main_pid,state,state_revision,previous_receipt_digest,stdout_cursor,stderr_cursor,last_receipt FROM runtimes WHERE runtime_id=?1",
            [runtime_id],
            |row| {
                let plan: Vec<u8> = row.get(4)?;
                let plan = serde_json::from_slice(&plan).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        plan.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?;
                let authority: Option<Vec<u8>>=row.get(5)?;
                let authority_ticket=authority.ok_or_else(||rusqlite::Error::InvalidQuery).and_then(|bytes|serde_json::from_slice(&bytes).map_err(|error|rusqlite::Error::FromSqlConversionFailure(bytes.len(),rusqlite::types::Type::Blob,Box::new(error))))?;
                let last_receipt: Option<Vec<u8>> = row.get(14)?;
                let last_receipt = last_receipt
                    .map(|bytes| serde_json::from_slice(&bytes).map_err(|error| rusqlite::Error::FromSqlConversionFailure(bytes.len(), rusqlite::types::Type::Blob, Box::new(error))))
                    .transpose()?;
                Ok(RuntimeRecord {
                    runtime_id: row.get(0)?,
                    run_id: row.get(1)?,
                    operation_id: row.get(2)?,
                    plan_digest: row.get(3)?,
                    plan,
                    authority_ticket,
                    unit_name: row.get(6)?,
                    invocation_id: row.get(7)?,
                    main_pid: row.get(8)?,
                    state: row.get(9)?,
                    state_revision: row.get(10)?,
                    previous_receipt_digest: row.get(11)?,
                    stdout_cursor: row.get(12)?,
                    stderr_cursor: row.get(13)?,
                    last_receipt,
                })
            },
        )
        .optional()
        .map_err(sql_error)
}

fn verify_effect_identity(
    effect: &JournalEffect,
    ticket_digest: &str,
    request_digest: &str,
    operation: &str,
    runtime_id: &str,
) -> Result<()> {
    if effect.ticket_digest != ticket_digest
        || effect.request_digest != request_digest
        || effect.operation != operation
        || effect.runtime_id != runtime_id
    {
        return Err(HelperError::Denied("privilege_ticket_conflict".into()));
    }
    Ok(())
}

fn disposition(effect: JournalEffect) -> EffectDisposition {
    match effect.state.as_str() {
        "complete" => EffectDisposition::Replay(effect),
        "reserved" if effect.receipt.is_some() => EffectDisposition::InProgress(effect),
        _ => EffectDisposition::Uncertain(effect),
    }
}
fn decode_chain(bytes: Option<&[u8]>) -> Result<Vec<HelperReceipt>> {
    match bytes {
        None => Ok(vec![]),
        Some(value) => {
            if let Ok(chain) = serde_json::from_slice::<Vec<HelperReceipt>>(value) {
                Ok(chain)
            } else {
                Ok(vec![serde_json::from_slice::<HelperReceipt>(value)?])
            }
        }
    }
}

fn migrate(connection: &Connection) -> Result<()> {
    let existing: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql_error)?;
    if existing > JOURNAL_SCHEMA_VERSION {
        return Err(HelperError::Journal(format!(
            "journal schema {existing} is newer than supported {JOURNAL_SCHEMA_VERSION}"
        )));
    }
    if existing == 1 {
        connection
            .execute("ALTER TABLE runtimes ADD COLUMN authority_ticket BLOB", [])
            .map_err(sql_error)?;
    }
    if existing > 0 && existing < 3 {
        connection
            .execute("ALTER TABLE runtimes ADD COLUMN last_receipt BLOB", [])
            .map_err(sql_error)?;
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS effects(
               ticket_id TEXT PRIMARY KEY, ticket_digest TEXT NOT NULL,
               request_digest TEXT NOT NULL, operation TEXT NOT NULL,
               runtime_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('reserved','complete','uncertain')),
               receipt BLOB, created_at INTEGER NOT NULL DEFAULT(unixepoch()),
               updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
               CHECK(length(ticket_digest)=64), CHECK(length(request_digest)=64),
               CHECK(receipt IS NULL OR length(receipt)<=262144));
             CREATE TABLE IF NOT EXISTS runtimes(
               runtime_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, operation_id TEXT NOT NULL,
               plan_digest TEXT NOT NULL, plan BLOB NOT NULL, authority_ticket BLOB, unit_name TEXT NOT NULL UNIQUE,
               invocation_id TEXT, main_pid INTEGER, state TEXT NOT NULL,
               state_revision INTEGER NOT NULL, previous_receipt_digest TEXT,
               stdout_cursor INTEGER NOT NULL DEFAULT 0, stderr_cursor INTEGER NOT NULL DEFAULT 0,
               last_receipt BLOB,
               created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
               CHECK(length(plan_digest)=64), CHECK(length(plan)<=262144));
             PRAGMA user_version=3;
             COMMIT;",
        )
        .map_err(sql_error)
}

fn integrity(connection: &Connection) -> Result<()> {
    let value: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql_error)?;
    if value != "ok" {
        return Err(HelperError::Journal("SQLite quick_check failed".into()));
    }
    Ok(())
}

fn sql_error(error: rusqlite::Error) -> HelperError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error {
        return match code.code {
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => {
                HelperError::RecoveryRequired("helper journal corrupt".into())
            }
            ErrorCode::DiskFull | ErrorCode::ReadOnly => {
                HelperError::Journal("helper journal unavailable before effect".into())
            }
            _ => HelperError::Journal(error.to_string()),
        };
    }
    HelperError::Journal(error.to_string())
}

fn validate_directory(path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(HelperError::Journal(
            "journal directory must be owner-only and non-symlink".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_regular(path: &Path, expected_uid: u32, maximum_mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 & !maximum_mode != 0
    {
        return Err(HelperError::Policy(
            "root-owned file ownership or mode invalid".into(),
        ));
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| HelperError::Journal("journal parent missing".into()))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_privileged_protocol::{
        ApprovalEnforcement, FileIdentity, PrivilegeTicketClaims, PrivilegedOperation,
        ResourceCeilings, SignedClaims, StdioMode,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn fixtures() -> (PrivilegeTicket, LocalExecutionPlan) {
        let plan = LocalExecutionPlan {
            plan_version: 1,
            runtime_id: "rt_journal0001".into(),
            run_id: "run_journal0001".into(),
            operation_id: "op_journal0001".into(),
            executable: file("/bin/true"),
            interpreter: None,
            argv: vec!["true".into()],
            cwd: file("/tmp"),
            systemd_unit: "conduit-elevated-journal0001.service".into(),
            adapter_id: None,
            environment: BTreeMap::new(),
            environment_value_digests: BTreeMap::new(),
            workspaces: vec![],
            credentials: vec![],
            stdio: StdioMode::Pipes,
            resources: ResourceCeilings {
                cpu_quota_per_sec_usec: None,
                memory_max_bytes: None,
                tasks_max: None,
                io_weight: None,
                runtime_max_usec: None,
            },
            helper_protocol: conduit_privileged_protocol::PROTOCOL.into(),
            helper_min_version: "0.1.0".into(),
        };
        let key = SigningKey::from_bytes(&[7; 32]);
        let ticket = SignedClaims::sign(
            "pkey_test",
            PrivilegeTicketClaims {
                schema_version: 1,
                protocol: conduit_privileged_protocol::PROTOCOL.into(),
                ticket_id: "ptkt_journal0001".into(),
                issuer_kind: "control_plane".into(),
                issuer_key_id: "pkey_test".into(),
                audience: "conduit-privileged-helper".into(),
                public_origin: "https://example.test".into(),
                helper_installation_id: "phinst_journal0001".into(),
                helper_key_id: "hkey_journal0001".into(),
                helper_policy_revision: 1,
                helper_policy_digest: "11".repeat(32),
                device_id: "dev_journal0001".into(),
                device_key_id: "dkey_journal0001".into(),
                device_policy_revision: 1,
                device_revision: 1,
                expected_uid: unsafe { libc::geteuid() },
                operation_id: plan.operation_id.clone(),
                idempotency_key_digest: "22".repeat(32),
                operation_request_digest: "33".repeat(32),
                run_manifest_digest: "34".repeat(32),
                run_id: plan.run_id.clone(),
                runtime_id: plan.runtime_id.clone(),
                runtime_spec_digest: "44".repeat(32),
                launch_plan_digest: "55".repeat(32),
                local_execution_plan_digest: plan.digest().unwrap(),
                control_digest: None,
                controller_epoch: 1,
                connector_policy_id: Some("cpol_journal0001".into()),
                connector_policy_revision: 1,
                project_id: None,
                project_revision: None,
                assignment_id: None,
                project_agent_id: None,
                project_agent_revision: None,
                runtime_configuration_revision: 1,
                access_scope: "full_device".into(),
                approval_mode: "always".into(),
                approval_receipt_digest: Some("66".repeat(32)),
                approval_enforcement: ApprovalEnforcement::ExactCommand,
                required_approval_risk_classes: vec![],
                allowed_operation: PrivilegedOperation::Prepare,
                resource_ceilings: plan.resources.clone(),
                issued_at: "2026-09-03T00:00:00Z".into(),
                expires_at: "2026-09-03T00:01:00Z".into(),
                nonce: "nonce-journal".into(),
                max_use_count: 1,
            },
            &key,
        )
        .unwrap();
        (ticket, plan)
    }

    fn file(path: &str) -> FileIdentity {
        FileIdentity {
            opaque_path_id: path.into(),
            device: 1,
            inode: 1,
            mode: 0o100755,
            uid: 0,
            size: 1,
            sha256: "aa".repeat(32),
        }
    }

    #[test]
    fn admission_is_durable_and_conflict_is_rejected() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal = HelperJournal::open_owned(directory.path().join("helper.sqlite3"), unsafe {
            libc::geteuid()
        })
        .unwrap();
        let (ticket, plan) = fixtures();
        let ticket_digest = ticket.digest().unwrap();
        let request_digest = "77".repeat(32);
        assert!(matches!(
            journal
                .admit_prepare(
                    &ticket,
                    &ticket_digest,
                    &request_digest,
                    &plan.digest().unwrap(),
                    &plan
                )
                .unwrap(),
            EffectDisposition::Reserved(_)
        ));
        assert!(matches!(
            journal
                .admit_prepare(
                    &ticket,
                    &ticket_digest,
                    &request_digest,
                    &plan.digest().unwrap(),
                    &plan
                )
                .unwrap(),
            EffectDisposition::Uncertain(_)
        ));
        assert!(matches!(
            journal.admit_prepare(&ticket, &ticket_digest, &"88".repeat(32), &plan.digest().unwrap(), &plan),
            Err(HelperError::Denied(code)) if code == "privilege_ticket_conflict"
        ));
        drop(journal);
        HelperJournal::open_owned(directory.path().join("helper.sqlite3"), unsafe {
            libc::geteuid()
        })
        .unwrap()
        .integrity_check()
        .unwrap();
    }

    #[test]
    fn rejects_insecure_parent_and_corrupt_database() {
        let directory = tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(HelperJournal::open_owned(directory.path().join("helper.sqlite3"), uid).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("corrupt.sqlite3");
        fs::write(&path, b"not sqlite").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(HelperJournal::open_owned(&path, uid).is_err());
    }
}
