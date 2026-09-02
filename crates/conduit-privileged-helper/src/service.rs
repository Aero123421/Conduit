use crate::{
    EffectDisposition, HelperError, HelperJournal, PeerCredentials, Result, SystemdManager,
    UnitObservation, UnitSpec, journal::validate_regular, worker::write_execution_record,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_protocol::{
    CapabilityClaims, ChallengeClaims, ControlTarget, CredentialDescriptor, HelperReceipt,
    HelperRequest, HelperResponse, LocalExecutionPlan, PROTOCOL, PrivilegeTicket,
    PrivilegedOperation, ReceiptClaims, RootPolicy, SignedClaims,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::Mutex,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct PinnedTicketKeys(pub BTreeMap<String, [u8; 32]>);

pub struct AuthorityLock {
    file: File,
}

impl AuthorityLock {
    pub fn shared(state_dir: &Path, expected_uid: u32) -> Result<Self> {
        Self::acquire(state_dir, expected_uid, libc::LOCK_SH)
    }

    pub fn exclusive(state_dir: &Path, expected_uid: u32) -> Result<Self> {
        Self::acquire(state_dir, expected_uid, libc::LOCK_EX)
    }

    fn acquire(state_dir: &Path, expected_uid: u32, operation: libc::c_int) -> Result<Self> {
        let state_metadata = fs::symlink_metadata(state_dir)?;
        if !state_metadata.is_dir()
            || state_metadata.file_type().is_symlink()
            || state_metadata.uid() != expected_uid
            || state_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(HelperError::Policy(
                "authority lock directory ownership or mode invalid".into(),
            ));
        }
        let path = state_dir.join("authority.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(HelperError::Policy(
                "authority lock ownership or mode invalid".into(),
            ));
        }
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

impl Drop for AuthorityLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl PinnedTicketKeys {
    pub fn load_root_owned(path: &Path) -> Result<Self> {
        validate_regular(path, 0, 0o600)?;
        #[derive(Deserialize)]
        struct KeyFile {
            keys: BTreeMap<String, String>,
        }
        let file: KeyFile = serde_json::from_slice(&fs::read(path)?)?;
        let mut keys = BTreeMap::new();
        for (id, value) in file.keys {
            let raw = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| HelperError::Policy("ticket public key encoding".into()))?;
            let key: [u8; 32] = raw
                .try_into()
                .map_err(|_| HelperError::Policy("ticket public key length".into()))?;
            VerifyingKey::from_bytes(&key)
                .map_err(|_| HelperError::Policy("ticket public key invalid".into()))?;
            keys.insert(id, key);
        }
        if keys.is_empty() {
            return Err(HelperError::Policy("no ticket keys pinned".into()));
        }
        Ok(Self(keys))
    }
}

#[derive(Clone)]
pub struct HelperConfig {
    pub policy: RootPolicy,
    pub policy_digest: String,
    pub policy_path: Option<PathBuf>,
    pub policy_owner_uid: u32,
    pub receipt_key_id: String,
    pub helper_version: String,
    pub state_dir: PathBuf,
    pub worker_path: PathBuf,
    pub device_key_id: String,
    pub device_public_key: [u8; 32],
    pub policy_change: PolicyChangeEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyChangeEvidence {
    pub revision: u64,
    pub policy_digest: String,
    pub previous_policy_digest: Option<String>,
    pub change_class: String,
    pub changed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicPolicySummary {
    pub enabled: bool,
    pub ticket_key_ids: Vec<String>,
    pub allowed_operations: Vec<PrivilegedOperation>,
    pub allowed_adapters: Vec<String>,
    pub allowed_launch_profiles: Vec<String>,
    pub launch_profile_executable_digests: BTreeMap<String, String>,
    pub allowed_credential_profiles: Vec<String>,
    pub ceilings: conduit_privileged_protocol::ResourceCeilings,
    pub allow_never: bool,
    pub allow_unrestricted_launch: bool,
    pub allow_persistent_sessions: bool,
    pub allow_offline_control: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicPolicyAttestation {
    pub revision: u64,
    pub policy_digest: String,
    pub previous_policy_digest: Option<String>,
    pub public_summary: PublicPolicySummary,
    pub change_class: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationBundle {
    pub protocol: String,
    pub installation_id: String,
    pub device_id: String,
    pub device_key_id: String,
    pub uid: u32,
    pub origin: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub receipt_public_jwk: PublicJwk,
    pub signed_policy_attestation:
        conduit_privileged_protocol::SignedClaims<conduit_privileged_protocol::RootPolicy>,
    pub signed_capability: conduit_privileged_protocol::SignedCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemdCapabilityProbe {
    pub system_manager: bool,
    pub transient_units: bool,
    pub freeze: bool,
}

impl SystemdCapabilityProbe {
    pub fn measure<M: SystemdManager>(manager: &M) -> Self {
        let system_manager = manager.available().unwrap_or(false);
        Self {
            system_manager,
            transient_units: system_manager && manager.transient_units_available().unwrap_or(false),
            freeze: system_manager && manager.freeze_available().unwrap_or(false),
        }
    }
}

impl HelperConfig {
    pub fn load_policy_root_owned(
        path: &Path,
        node_key_path: &Path,
        receipt_key_id: String,
        state_dir: PathBuf,
        worker_path: PathBuf,
    ) -> Result<Self> {
        validate_regular(path, 0, 0o600)?;
        validate_regular(&worker_path, 0, 0o755)?;
        let state_metadata = fs::symlink_metadata(&state_dir)?;
        if !state_metadata.is_dir()
            || state_metadata.file_type().is_symlink()
            || state_metadata.uid() != 0
            || state_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(HelperError::Policy(
                "helper state directory ownership or mode invalid".into(),
            ));
        }
        if state_dir.join("admin-update.json").exists() {
            return Err(HelperError::RecoveryRequired(
                "root policy update did not commit atomically".into(),
            ));
        }
        let policy: RootPolicy = serde_json::from_slice(&fs::read(path)?)?;
        validate_regular(node_key_path, 0, 0o644)?;
        let node_key: [u8; 32] = fs::read(node_key_path)?
            .try_into()
            .map_err(|_| HelperError::Policy("node public key length".into()))?;
        VerifyingKey::from_bytes(&node_key)
            .map_err(|_| HelperError::Policy("node public key invalid".into()))?;
        let digest = policy.digest()?;
        let policy_change_path = state_dir.join("policy-change.json");
        validate_regular(&policy_change_path, 0, 0o600)?;
        let policy_change: PolicyChangeEvidence =
            serde_json::from_slice(&fs::read(policy_change_path)?)?;
        if policy_change.revision != policy.revision || policy_change.policy_digest != digest {
            return Err(HelperError::Policy(
                "policy change evidence does not match root policy".into(),
            ));
        }
        Ok(Self {
            policy,
            policy_digest: digest,
            policy_path: Some(path.to_path_buf()),
            policy_owner_uid: 0,
            receipt_key_id,
            helper_version: env!("CARGO_PKG_VERSION").into(),
            state_dir,
            worker_path,
            device_key_id: conduit_privileged_protocol::key_id("dkey", &node_key),
            device_public_key: node_key,
            policy_change,
        })
    }
}

pub fn load_receipt_key_root_owned(path: &Path) -> Result<SigningKey> {
    validate_regular(path, 0, 0o600)?;
    let bytes = fs::read(path)?;
    let decoded = if bytes.len() == 32 {
        bytes
    } else {
        URL_SAFE_NO_PAD
            .decode(String::from_utf8_lossy(&bytes).trim())
            .map_err(|_| HelperError::Policy("receipt key encoding".into()))?
    };
    let seed: [u8; 32] = decoded
        .try_into()
        .map_err(|_| HelperError::Policy("receipt key length".into()))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub struct HelperEngine<M: SystemdManager> {
    config: HelperConfig,
    keys: PinnedTicketKeys,
    receipt_key: SigningKey,
    journal: HelperJournal,
    systemd: M,
    challenges: Mutex<BTreeMap<(u32, u32), ChallengeClaims>>,
}

impl<M: SystemdManager> HelperEngine<M> {
    pub fn new(
        config: HelperConfig,
        keys: PinnedTicketKeys,
        receipt_key: SigningKey,
        journal: HelperJournal,
        systemd: M,
    ) -> Result<Self> {
        if config.policy.digest()? != config.policy_digest {
            return Err(HelperError::Policy("policy digest mismatch".into()));
        }
        Ok(Self {
            config,
            keys,
            receipt_key,
            journal,
            systemd,
            challenges: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn recover_nonterminal(&self) -> Result<Vec<HelperReceipt>> {
        let mut receipts = Vec::new();
        let mut after_runtime_id = None;
        loop {
            let runtimes = self
                .journal
                .nonterminal_runtimes_after(after_runtime_id.as_deref())?;
            if runtimes.is_empty() {
                break;
            }
            after_runtime_id = runtimes.last().map(|runtime| runtime.runtime_id.clone());
            let ids = runtimes
                .into_iter()
                .map(|runtime| runtime.runtime_id)
                .collect();
            match self.reconcile(ids)? {
                HelperResponse::Receipts(page) => receipts.extend(page),
                _ => unreachable!(),
            }
        }
        Ok(receipts)
    }

    /// Complete custody for an admitted/prepared Runtime which never acquired
    /// a systemd unit. This is used only by the explicit local-root
    /// stop-active recovery path; it cannot terminate or relabel a process.
    pub fn cancel_unstarted_for_admin(&self, runtime_id: &str) -> Result<HelperReceipt> {
        let runtime = self
            .journal
            .runtime(runtime_id)?
            .ok_or_else(|| HelperError::Denied("privileged_runtime_not_prepared".into()))?;
        if !matches!(runtime.state.as_str(), "admitted" | "prepared")
            || runtime.invocation_id.is_some()
            || runtime.main_pid.is_some()
        {
            return Err(HelperError::RecoveryRequired(
                "active_runtime_identity_missing".into(),
            ));
        }
        if self.systemd.inspect_optional(&runtime.unit_name)?.is_some() {
            return Err(HelperError::RecoveryRequired(
                "active_runtime_identity_mismatch".into(),
            ));
        }
        let receipt = self.receipt(
            &runtime.authority_ticket,
            "admin_stop_unstarted",
            "cancelled",
            None,
            runtime.state_revision + 1,
        )?;
        self.journal
            .record_observation(&receipt, "stopped", None, None)?;
        Ok(receipt)
    }

    /// Close a previously started custody record only after the system manager
    /// proves the exact unit no longer exists. The result is failed, not
    /// completed, because exit status and final stream positions are gone.
    pub fn fail_missing_runtime_for_admin(&self, runtime_id: &str) -> Result<HelperReceipt> {
        let runtime = self
            .journal
            .runtime(runtime_id)?
            .ok_or_else(|| HelperError::Denied("privileged_runtime_not_prepared".into()))?;
        if !matches!(
            runtime.state.as_str(),
            "starting"
                | "running"
                | "active"
                | "activating"
                | "frozen"
                | "paused"
                | "recovery_required"
        ) || runtime.invocation_id.is_none()
            || self.systemd.inspect_optional(&runtime.unit_name)?.is_some()
        {
            return Err(HelperError::RecoveryRequired(
                "active_runtime_identity_missing".into(),
            ));
        }
        let receipt = self.receipt(
            &runtime.authority_ticket,
            "admin_stop_missing_unit",
            "failed",
            None,
            runtime.state_revision + 1,
        )?;
        self.journal
            .record_observation(&receipt, "failed", None, None)?;
        Ok(receipt)
    }

    /// Reconcile durable root custody with systemd before the server exposes
    /// an admission socket. Callers must treat any error as a startup failure.
    pub fn reconcile_before_admission(&self) -> Result<Vec<HelperReceipt>> {
        let _authority =
            AuthorityLock::shared(&self.config.state_dir, self.config.policy_owner_uid)?;
        self.recover_nonterminal()
    }

    fn ensure_policy_current(&self) -> Result<()> {
        let Some(path) = &self.config.policy_path else {
            return Ok(());
        };
        if self.config.state_dir.join("admin-update.json").exists() {
            return Err(HelperError::RecoveryRequired(
                "root_policy_update_in_progress".into(),
            ));
        }
        validate_regular(path, self.config.policy_owner_uid, 0o600)?;
        let current: RootPolicy = serde_json::from_slice(&fs::read(path)?)?;
        let current_digest = current.digest()?;
        let evidence_path = self.config.state_dir.join("policy-change.json");
        validate_regular(&evidence_path, self.config.policy_owner_uid, 0o600)?;
        let evidence: PolicyChangeEvidence = serde_json::from_slice(&fs::read(evidence_path)?)?;
        if current.revision != self.config.policy.revision
            || current_digest != self.config.policy_digest
            || evidence.revision != current.revision
            || evidence.policy_digest != current_digest
        {
            return Err(HelperError::Denied(
                "privileged_helper_policy_mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn registration_bundle(&self) -> Result<RegistrationBundle> {
        build_registration_bundle(
            &self.config.policy,
            &self.config.policy_change,
            self.config.device_public_key,
            &self.receipt_key,
            SystemdCapabilityProbe::measure(&self.systemd),
            &self.config.helper_version,
            &self.config.state_dir,
        )
    }
    pub fn handle_managed(
        &self,
        authenticated: bool,
        request: crate::ManagedIoRequest,
        descriptor_count: usize,
    ) -> Result<crate::ManagedIoResponse> {
        let _authority =
            AuthorityLock::shared(&self.config.state_dir, self.config.policy_owner_uid)?;
        if !authenticated {
            return Err(HelperError::Authentication("handshake_required".into()));
        }
        if descriptor_count != 0 {
            return Err(HelperError::Authentication(
                "unexpected managed request descriptors".into(),
            ));
        }
        self.ensure_policy_current()?;
        match request {
            crate::ManagedIoRequest::ReadStream(request) => self.read_stream(&request),
            crate::ManagedIoRequest::PolicyAttest => self
                .registration_bundle()
                .map(|bundle| crate::ManagedIoResponse::RegistrationBundle(Box::new(bundle))),
        }
    }
    pub fn converge_terminal(&self) -> Result<Vec<HelperReceipt>> {
        let _authority =
            AuthorityLock::shared(&self.config.state_dir, self.config.policy_owner_uid)?;
        let mut receipts = Vec::new();
        for runtime in self.journal.nonterminal_runtimes()? {
            match self.systemd.inspect_optional(&runtime.unit_name) {
                Ok(Some(observation))
                    if matches!(
                        observation.active_state.as_str(),
                        "inactive" | "dead" | "failed"
                    ) && runtime_identity_matches(&runtime, &observation) =>
                {
                    let ticket = runtime.authority_ticket.clone();
                    let transition = receipt_transition(&observation.active_state);
                    let receipt = self.receipt(
                        &ticket,
                        "terminal_watcher",
                        transition,
                        Some(&observation),
                        runtime.state_revision + 1,
                    )?;
                    self.journal.record_observation(
                        &receipt,
                        normalize_unit_state(&observation.active_state),
                        observation.invocation_id.as_deref(),
                        observation.main_pid,
                    )?;
                    receipts.push(receipt)
                }
                Ok(Some(observation))
                    if matches!(
                        observation.active_state.as_str(),
                        "inactive" | "dead" | "failed"
                    ) =>
                {
                    let ticket = runtime.authority_ticket.clone();
                    let receipt = self.receipt(
                        &ticket,
                        "terminal_watcher_identity_mismatch",
                        "recovery_required",
                        None,
                        runtime.state_revision + 1,
                    )?;
                    self.journal
                        .record_observation(&receipt, "recovery_required", None, None)?;
                    receipts.push(receipt)
                }
                Ok(None)
                    if matches!(
                        runtime.state.as_str(),
                        "starting" | "running" | "active" | "activating" | "frozen" | "paused"
                    ) =>
                {
                    let ticket = runtime.authority_ticket.clone();
                    let receipt = self.receipt(
                        &ticket,
                        "terminal_watcher_missing",
                        "recovery_required",
                        None,
                        runtime.state_revision + 1,
                    )?;
                    self.journal
                        .record_observation(&receipt, "recovery_required", None, None)?;
                    receipts.push(receipt)
                }
                _ => {}
            }
        }
        Ok(receipts)
    }
    pub fn read_stream(
        &self,
        request: &crate::StreamReadRequest,
    ) -> Result<crate::ManagedIoResponse> {
        if request.max_bytes == 0 || request.max_bytes > 48 * 1024 {
            return Err(HelperError::Denied("stream_read_bound".into()));
        }
        let runtime = self.exact_target(&request.target)?;
        let name = match request.stream {
            crate::ManagedStream::Stdout => "stdout.spool",
            crate::ManagedStream::Stderr => "stderr.spool",
        };
        let path = self
            .config
            .state_dir
            .join("runtimes")
            .join(&runtime.runtime_id)
            .join(name);
        validate_regular(&path, 0, 0o600)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let length = file.metadata()?.len();
        if request.cursor > length {
            return Err(HelperError::Denied("stream_cursor_ahead".into()));
        }
        file.seek(SeekFrom::Start(request.cursor))?;
        let mut data = vec![0u8; request.max_bytes as usize];
        let count = file.read(&mut data)?;
        data.truncate(count);
        let next_cursor = request.cursor + count as u64;
        let observation = self.systemd.inspect(&runtime.unit_name).ok();
        let terminal = observation
            .as_ref()
            .map(|v| matches!(v.active_state.as_str(), "inactive" | "failed" | "dead"))
            .unwrap_or(true);
        Ok(crate::ManagedIoResponse::StreamChunk {
            data,
            next_cursor,
            eof: next_cursor >= length,
            terminal,
        })
    }
    pub fn handle(
        &self,
        peer: PeerCredentials,
        authenticated: bool,
        request: HelperRequest,
        descriptors: Vec<OwnedFd>,
    ) -> Result<HelperResponse> {
        let _authority =
            AuthorityLock::shared(&self.config.state_dir, self.config.policy_owner_uid)?;
        if peer.uid != self.config.policy.uid {
            return Err(HelperError::Authentication("peer uid mismatch".into()));
        }
        let expected_descriptors = match &request {
            HelperRequest::Prepare { plan, .. } => plan.credentials.len(),
            HelperRequest::Input { .. } => 1,
            _ => 0,
        };
        if descriptors.len() != expected_descriptors {
            return Err(HelperError::Denied("unexpected_fd_manifest".into()));
        }
        self.ensure_policy_current()?;
        match request {
            HelperRequest::Hello {
                protocol_versions,
                device_id,
                node_boot_id,
                nonce,
            } => self.hello(peer, protocol_versions, device_id, node_boot_id, nonce),
            HelperRequest::Prove { .. } => Err(HelperError::Authentication(
                "use prove() with pinned node key".into(),
            )),
            _ if !authenticated => Err(HelperError::Authentication("handshake_required".into())),
            HelperRequest::Probe => self.probe(),
            HelperRequest::Prepare { ticket, plan } => self.prepare(*ticket, *plan, descriptors),
            HelperRequest::Start {
                ticket,
                plan_digest,
            } => self.start(*ticket, plan_digest),
            HelperRequest::Inspect { target } => self.inspect(target),
            HelperRequest::Input {
                ticket,
                target,
                descriptor_index,
            } => self.input(*ticket, target, descriptor_index, descriptors),
            HelperRequest::ResizePty {
                ticket,
                target,
                rows,
                columns,
            } => self.resize(*ticket, target, rows, columns),
            HelperRequest::Control {
                ticket,
                target,
                operation,
            } => self.control(*ticket, target, operation),
            HelperRequest::Reconcile { runtime_ids } => self.reconcile(runtime_ids),
        }
    }
    pub fn prove(
        &self,
        peer: PeerCredentials,
        challenge: &ChallengeClaims,
        signature: &str,
        node_key: &VerifyingKey,
    ) -> Result<HelperResponse> {
        let _authority =
            AuthorityLock::shared(&self.config.state_dir, self.config.policy_owner_uid)?;
        self.ensure_policy_current()?;
        let stored = self
            .challenges
            .lock()
            .map_err(|_| HelperError::Authentication("challenge lock".into()))?
            .remove(&(peer.pid, peer.uid))
            .ok_or_else(|| HelperError::Authentication("challenge missing".into()))?;
        if &stored != challenge {
            return Err(HelperError::Authentication("challenge mismatch".into()));
        }
        let raw = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| HelperError::Authentication("proof encoding".into()))?;
        let signature = ed25519_dalek::Signature::from_slice(&raw)
            .map_err(|_| HelperError::Authentication("proof signature".into()))?;
        use ed25519_dalek::Verifier;
        node_key
            .verify(&serde_jcs::to_vec(challenge)?, &signature)
            .map_err(|_| HelperError::Authentication("proof invalid".into()))?;
        if parse_time(&challenge.expires_at)? < OffsetDateTime::now_utc() {
            return Err(HelperError::Authentication("challenge expired".into()));
        }
        Ok(HelperResponse::Accepted {
            protocol: PROTOCOL.into(),
            installation_id: self.config.policy.installation_id.clone(),
            policy_revision: self.config.policy.revision,
        })
    }
    fn hello(
        &self,
        peer: PeerCredentials,
        versions: Vec<String>,
        device_id: String,
        node_boot_id: String,
        client_nonce: String,
    ) -> Result<HelperResponse> {
        if !versions.iter().any(|v| v == PROTOCOL) || device_id != self.config.policy.device_id {
            return Err(HelperError::Authentication(
                "protocol or device mismatch".into(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        let nonce = getrandom::u64().map_err(|e| HelperError::Policy(e.to_string()))?;
        let claims = ChallengeClaims {
            protocol: PROTOCOL.into(),
            installation_id: self.config.policy.installation_id.clone(),
            device_id,
            pid: peer.pid,
            uid: peer.uid,
            pid_start: process_start(peer.pid)?,
            node_boot_id,
            client_nonce,
            helper_nonce: hex::encode(nonce.to_ne_bytes()),
            issued_at: now.format(&Rfc3339).unwrap(),
            expires_at: (now + time::Duration::seconds(30))
                .format(&Rfc3339)
                .unwrap(),
        };
        self.challenges
            .lock()
            .map_err(|_| HelperError::Authentication("challenge lock".into()))?
            .insert((peer.pid, peer.uid), claims.clone());
        Ok(HelperResponse::Challenge(claims))
    }
    fn probe(&self) -> Result<HelperResponse> {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let claims = effective_capability_claims(
            &self.config.policy,
            &self.config.policy_digest,
            &self.config.receipt_key_id,
            &self.config.helper_version,
            now,
            SystemdCapabilityProbe::measure(&self.systemd),
            &self.config.state_dir,
        );
        Ok(HelperResponse::Capability(SignedClaims::sign(
            &self.config.receipt_key_id,
            claims,
            &self.receipt_key,
        )?))
    }
    fn prepare(
        &self,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        descriptors: Vec<OwnedFd>,
    ) -> Result<HelperResponse> {
        self.validate_ticket(&ticket, PrivilegedOperation::Prepare, Some(&plan))?;
        let credential_payloads = validate_credential_descriptors(&plan, &descriptors)?;
        for workspace in &plan.workspaces {
            let identity =
                crate::capture_file_identity(Path::new(&workspace.opaque_path_id), false)?;
            if identity.sha256 != workspace.expected_identity_digest {
                return Err(HelperError::Denied("workspace_identity_changed".into()));
            }
        }
        let ticket_digest = ticket.digest()?;
        let request = request_digest(&HelperRequest::Prepare {
            ticket: Box::new(ticket.clone()),
            plan: Box::new(plan.clone()),
        })?;
        let plan_digest = plan.digest()?;
        let mut chain = match self.journal.admit_prepare(
            &ticket,
            &ticket_digest,
            &request,
            &plan_digest,
            &plan,
        )? {
            EffectDisposition::Replay(effect) => return decode_receipt(effect.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "prepare outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => vec![],
            EffectDisposition::InProgress(effect) => decode_receipt_chain(effect.receipt)?,
        };
        if chain.is_empty() {
            let admitted = self.receipt(&ticket, &request, "admitted", None, 1)?;
            self.journal.record_effect_boundary(
                &ticket.claims.ticket_id,
                &admitted,
                "admitted",
                None,
                None,
                false,
            )?;
            chain.push(admitted);
        }
        let runtime_dir = self
            .config
            .state_dir
            .join("runtimes")
            .join(&plan.runtime_id);
        fs::create_dir_all(&runtime_dir)?;
        let managed_home = runtime_dir.join("home");
        fs::create_dir_all(&managed_home)?;
        fs::set_permissions(&managed_home, fs::Permissions::from_mode(0o700))?;
        if !plan.credentials.is_empty() {
            for (credential, bytes) in &credential_payloads {
                let path = managed_home.join(&credential.target_name);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .open(path)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
        }
        for name in ["stdout.spool", "stderr.spool"] {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(runtime_dir.join(name))?;
        }
        if matches!(plan.stdio, conduit_privileged_protocol::StdioMode::Pipes) {
            let fifo = runtime_dir.join("stdin.fifo");
            if !fifo.exists() {
                let raw = std::ffi::CString::new(fifo.as_os_str().as_bytes())
                    .map_err(|_| HelperError::Denied("fifo path".into()))?;
                if unsafe { libc::mkfifo(raw.as_ptr(), 0o600) } < 0 {
                    return Err(HelperError::Io(std::io::Error::last_os_error()));
                }
            }
        }
        write_execution_record(
            &runtime_dir.join("execution-record.json"),
            &plan,
            &self.config.receipt_key_id,
            &self.receipt_key,
            unsafe { libc::geteuid() },
        )?;
        let receipt = self.receipt(&ticket, &request, "prepared", None, 2)?;
        self.journal
            .complete_effect(&ticket.claims.ticket_id, &receipt, "prepared", None, None)?;
        chain.push(receipt);
        Ok(HelperResponse::Receipts(chain))
    }
    fn start(&self, ticket: PrivilegeTicket, plan_digest: String) -> Result<HelperResponse> {
        self.validate_ticket(&ticket, PrivilegedOperation::Start, None)?;
        let runtime = self
            .journal
            .runtime(&ticket.claims.runtime_id)?
            .ok_or_else(|| HelperError::Denied("runtime_not_prepared".into()))?;
        self.validate_runtime_ticket(&ticket, &runtime)?;
        if runtime.plan_digest != plan_digest
            || ticket.claims.local_execution_plan_digest != plan_digest
        {
            return Err(HelperError::Denied("plan_digest_mismatch".into()));
        }
        let request = request_digest(&HelperRequest::Start {
            ticket: Box::new(ticket.clone()),
            plan_digest,
        })?;
        let ticket_digest = ticket.digest()?;
        let mut chain = match self.journal.reserve_effect(
            &ticket,
            &ticket_digest,
            &request,
            "start",
            &runtime.runtime_id,
        )? {
            EffectDisposition::Replay(effect) => return decode_receipt(effect.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "start outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => vec![],
            EffectDisposition::InProgress(effect) => decode_receipt_chain(effect.receipt)?,
        };
        let runtime_dir = self
            .config
            .state_dir
            .join("runtimes")
            .join(&runtime.runtime_id);
        let spec = UnitSpec {
            unit_name: runtime.unit_name.clone(),
            worker_path: self.config.worker_path.to_string_lossy().into(),
            execution_record_path: runtime_dir
                .join("execution-record.json")
                .to_string_lossy()
                .into(),
            receipt_public_key_path: self
                .config
                .state_dir
                .join("receipt.public")
                .to_string_lossy()
                .into(),
            stdout_path: runtime_dir.join("stdout.spool").to_string_lossy().into(),
            stderr_path: runtime_dir.join("stderr.spool").to_string_lossy().into(),
            resources: runtime.plan.resources.clone(),
        };
        let observation =
            if chain.last().map(|v| v.claims.transition.as_str()) == Some("unit_created") {
                self.systemd.inspect(&runtime.unit_name)?
            } else {
                match self.systemd.start_transient(&spec) {
                    Ok(v) => v,
                    Err(e) => {
                        self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
                        return Err(e);
                    }
                }
            };
        if chain.is_empty() {
            let created = self.receipt(
                &ticket,
                &request,
                "unit_created",
                Some(&observation),
                runtime.state_revision + 1,
            )?;
            self.journal.record_effect_boundary(
                &ticket.claims.ticket_id,
                &created,
                "starting",
                observation.invocation_id.as_deref(),
                observation.main_pid,
                false,
            )?;
            chain.push(created);
        }
        let running_revision = chain.last().map_or(runtime.state_revision + 1, |receipt| {
            receipt.claims.state_revision + 1
        });
        let receipt = self.receipt(
            &ticket,
            &request,
            "running",
            Some(&observation),
            running_revision,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            "running",
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        chain.push(receipt);
        Ok(HelperResponse::Receipts(chain))
    }
    fn inspect(&self, target: ControlTarget) -> Result<HelperResponse> {
        let runtime = self.exact_target(&target)?;
        let observation = self.systemd.inspect(&runtime.unit_name)?;
        let ticket = runtime.authority_ticket.clone();
        let receipt = self.receipt(
            &ticket,
            &target.runtime_handle_digest,
            receipt_transition(&observation.active_state),
            Some(&observation),
            runtime.state_revision + 1,
        )?;
        self.journal.record_observation(
            &receipt,
            normalize_unit_state(&observation.active_state),
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        Ok(HelperResponse::Receipt(Box::new(receipt)))
    }
    fn input(
        &self,
        ticket: PrivilegeTicket,
        target: ControlTarget,
        index: u16,
        mut descriptors: Vec<OwnedFd>,
    ) -> Result<HelperResponse> {
        self.validate_ticket(&ticket, PrivilegedOperation::Input, None)?;
        let runtime = self.exact_target(&target)?;
        self.validate_control_authority(&ticket, &target, &runtime)?;
        if descriptors.len() != 1 || index != 0 {
            return Err(HelperError::Denied("descriptor_mismatch".into()));
        }
        let request = request_digest(&HelperRequest::Input {
            ticket: Box::new(ticket.clone()),
            target,
            descriptor_index: index,
        })?;
        let ticket_digest = ticket.digest()?;
        match self.journal.reserve_effect(
            &ticket,
            &ticket_digest,
            &request,
            "input",
            &runtime.runtime_id,
        )? {
            EffectDisposition::Replay(v) => return decode_receipt(v.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "input outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => {}
            EffectDisposition::InProgress(_) => {
                return Err(HelperError::RecoveryRequired(
                    "input boundary incomplete".into(),
                ));
            }
        }
        let source = File::from(descriptors.remove(0));
        let mut data = Vec::new();
        source.take(1024 * 1024 + 1).read_to_end(&mut data)?;
        if data.len() > 1024 * 1024 {
            self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
            return Err(HelperError::Denied("input_bound".into()));
        }
        let directory = self
            .config
            .state_dir
            .join("runtimes")
            .join(&runtime.runtime_id);
        let effect: Result<()> = match runtime.plan.stdio {
            conduit_privileged_protocol::StdioMode::Pipes => {
                let mut sink = OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(directory.join("stdin.fifo"))?;
                sink.write_all(&data).map_err(HelperError::Io)
            }
            conduit_privileged_protocol::StdioMode::Pty => {
                let client = crate::SeqpacketClient::connect(&directory.join("control.sock"))?;
                client.send(
                    &serde_jcs::to_vec(&crate::worker::WorkerControl::Input { data })?,
                    &[],
                )
            }
        };
        if let Err(error) = effect {
            self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
            return Err(error);
        }
        let observation = self.systemd.inspect(&runtime.unit_name).ok();
        let receipt = self.receipt(
            &ticket,
            &request,
            "input_applied",
            observation.as_ref(),
            runtime.state_revision + 1,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            &runtime.state,
            observation
                .as_ref()
                .and_then(|v| v.invocation_id.as_deref()),
            observation.as_ref().and_then(|v| v.main_pid),
        )?;
        Ok(HelperResponse::Receipt(Box::new(receipt)))
    }
    fn resize(
        &self,
        ticket: PrivilegeTicket,
        target: ControlTarget,
        rows: u16,
        columns: u16,
    ) -> Result<HelperResponse> {
        self.validate_ticket(&ticket, PrivilegedOperation::ResizePty, None)?;
        let runtime = self.exact_target(&target)?;
        self.validate_control_authority(&ticket, &target, &runtime)?;
        if !matches!(
            runtime.plan.stdio,
            conduit_privileged_protocol::StdioMode::Pty
        ) || rows == 0
            || columns == 0
        {
            return Err(HelperError::Denied("pty_resize_invalid".into()));
        }
        let request = request_digest(&HelperRequest::ResizePty {
            ticket: Box::new(ticket.clone()),
            target,
            rows,
            columns,
        })?;
        let ticket_digest = ticket.digest()?;
        match self.journal.reserve_effect(
            &ticket,
            &ticket_digest,
            &request,
            "resize_pty",
            &runtime.runtime_id,
        )? {
            EffectDisposition::Replay(v) => return decode_receipt(v.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "resize outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => {}
            EffectDisposition::InProgress(_) => {
                return Err(HelperError::RecoveryRequired(
                    "resize boundary incomplete".into(),
                ));
            }
        }
        let client = crate::SeqpacketClient::connect(
            &self
                .config
                .state_dir
                .join("runtimes")
                .join(&runtime.runtime_id)
                .join("control.sock"),
        )?;
        if let Err(error) = client.send(
            &serde_jcs::to_vec(&crate::worker::WorkerControl::Resize { rows, columns })?,
            &[],
        ) {
            self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
            return Err(error);
        }
        let observation = self.systemd.inspect(&runtime.unit_name).ok();
        let receipt = self.receipt(
            &ticket,
            &request,
            "pty_resized",
            observation.as_ref(),
            runtime.state_revision + 1,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            &runtime.state,
            observation
                .as_ref()
                .and_then(|v| v.invocation_id.as_deref()),
            observation.as_ref().and_then(|v| v.main_pid),
        )?;
        Ok(HelperResponse::Receipt(Box::new(receipt)))
    }
    fn control(
        &self,
        ticket: PrivilegeTicket,
        target: ControlTarget,
        operation: PrivilegedOperation,
    ) -> Result<HelperResponse> {
        self.validate_ticket(&ticket, operation.clone(), None)?;
        let runtime = self.exact_target(&target)?;
        self.validate_control_authority(&ticket, &target, &runtime)?;
        let request = request_digest(&HelperRequest::Control {
            ticket: Box::new(ticket.clone()),
            target,
            operation: operation.clone(),
        })?;
        let ticket_digest = ticket.digest()?;
        let opname = format!("{operation:?}").to_ascii_lowercase();
        match self.journal.reserve_effect(
            &ticket,
            &ticket_digest,
            &request,
            &opname,
            &runtime.runtime_id,
        )? {
            EffectDisposition::Replay(effect) => return decode_receipt(effect.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "control outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => {}
            EffectDisposition::InProgress(_) => {
                return Err(HelperError::RecoveryRequired(
                    "control boundary incomplete".into(),
                ));
            }
        }
        let result = match operation {
            PrivilegedOperation::Pause => self.systemd.pause(&runtime.unit_name),
            PrivilegedOperation::Resume => self.systemd.resume(&runtime.unit_name),
            PrivilegedOperation::GracefulStop => self.systemd.graceful_stop(&runtime.unit_name),
            PrivilegedOperation::ForceStop => self.systemd.force_stop(&runtime.unit_name),
            _ => Err(HelperError::Denied("invalid_control_operation".into())),
        };
        if let Err(e) = result {
            self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
            return Err(e);
        }
        let stopping = matches!(
            operation,
            PrivilegedOperation::GracefulStop | PrivilegedOperation::ForceStop
        );
        let mut observation = None;
        for _ in 0..if stopping { 100 } else { 1 } {
            match self.systemd.inspect(&runtime.unit_name) {
                Ok(value) => {
                    let terminal =
                        matches!(value.active_state.as_str(), "inactive" | "dead" | "failed");
                    observation = Some(value);
                    if !stopping || terminal {
                        break;
                    }
                }
                Err(_) if stopping => {
                    // A successful exact StopUnit/KillUnit followed by the
                    // disappearance of that same transient unit is terminal
                    // evidence; systemd has released its process custody.
                    observation = Some(UnitObservation {
                        unit_name: runtime.unit_name.clone(),
                        invocation_id: runtime.invocation_id.clone(),
                        main_pid: None,
                        active_state: "inactive".into(),
                        cgroup: None,
                        effective_uid: Some(0),
                        effective_gid: Some(0),
                        process_birth: None,
                        exit_code: None,
                        signal: None,
                    });
                    break;
                }
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let observation = observation.unwrap_or(UnitObservation {
            unit_name: runtime.unit_name.clone(),
            invocation_id: runtime.invocation_id.clone(),
            main_pid: runtime.main_pid,
            active_state: "unknown".into(),
            cgroup: None,
            effective_uid: None,
            effective_gid: None,
            process_birth: None,
            exit_code: None,
            signal: None,
        });
        let transition = match operation {
            PrivilegedOperation::Pause => "paused",
            PrivilegedOperation::Resume => "resumed",
            PrivilegedOperation::GracefulStop | PrivilegedOperation::ForceStop => "cancelled",
            _ => "failed",
        };
        let receipt = self.receipt(
            &ticket,
            &request,
            transition,
            Some(&observation),
            runtime.state_revision + 1,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            normalize_unit_state(&observation.active_state),
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        Ok(HelperResponse::Receipt(Box::new(receipt)))
    }
    fn reconcile(&self, ids: Vec<String>) -> Result<HelperResponse> {
        if ids.len() > 256 {
            return Err(HelperError::Denied("reconcile_bound".into()));
        }
        let mut receipts = Vec::new();
        for id in ids {
            if let Some(runtime) = self.journal.runtime(&id)? {
                if let Some(receipt) = runtime.last_receipt.clone() {
                    receipts.push(receipt);
                }
                if matches!(runtime.state.as_str(), "stopped" | "failed" | "terminal") {
                    continue;
                }
                let observation = self.systemd.inspect(&runtime.unit_name).ok();
                let exact_observation = observation
                    .as_ref()
                    .filter(|value| runtime_identity_matches(&runtime, value));
                if runtime.state == "recovery_required"
                    && !exact_observation.is_some_and(|value| {
                        matches!(value.active_state.as_str(), "inactive" | "dead" | "failed")
                    })
                {
                    continue;
                }
                let ticket = runtime.authority_ticket.clone();
                // A structured Agent process may still be alive after the
                // unprivileged Node restarts, but the adapter's pending
                // request correlation is process-local.  Never claim that
                // such a session was resumed merely because systemd still
                // owns the process.  Preserve process custody and return a
                // helper-signed recovery decision instead.  Exact command
                // Runtimes have no adapter correlation and can be attached
                // to the same invocation.
                let adapter_state_lost = runtime.plan.adapter_id.is_some()
                    && exact_observation.is_some_and(|value| {
                        matches!(
                            value.active_state.as_str(),
                            "active" | "activating" | "running" | "frozen" | "paused"
                        )
                    });
                let transition = if adapter_state_lost {
                    "recovery_required"
                } else if let Some(observation) = exact_observation {
                    receipt_transition(observation.active_state.as_str())
                } else {
                    "recovery_required"
                };
                let state = if adapter_state_lost {
                    "recovery_required"
                } else {
                    exact_observation
                        .map(|v| normalize_unit_state(&v.active_state))
                        .unwrap_or("recovery_required")
                };
                let receipt = self.receipt(
                    &ticket,
                    "reconcile",
                    transition,
                    exact_observation,
                    runtime.state_revision + 1,
                )?;
                self.journal.record_observation(
                    &receipt,
                    state,
                    exact_observation.and_then(|v| v.invocation_id.as_deref()),
                    exact_observation.and_then(|v| v.main_pid),
                )?;
                receipts.push(receipt);
            }
        }
        Ok(HelperResponse::Receipts(receipts))
    }
    fn exact_target(&self, target: &ControlTarget) -> Result<crate::RuntimeRecord> {
        let runtime = self
            .journal
            .runtime(&target.runtime_id)?
            .ok_or_else(|| HelperError::Denied("runtime_not_found".into()))?;
        if runtime.unit_name != target.unit_name
            || runtime.invocation_id.as_deref() != Some(&target.invocation_id)
            || target.controller_epoch == 0
            || runtime.state_revision != target.expected_state_revision
            || target.runtime_handle_digest != control_target_digest(target)?
        {
            return Err(HelperError::Denied("exact_target_mismatch".into()));
        }
        Ok(runtime)
    }
    fn validate_runtime_ticket(
        &self,
        ticket: &PrivilegeTicket,
        runtime: &crate::RuntimeRecord,
    ) -> Result<()> {
        self.validate_runtime_commitments(ticket, runtime)?;
        let current = &ticket.claims;
        let admitted = &runtime.authority_ticket.claims;
        if current.operation_id != runtime.operation_id
            || current.operation_request_digest != admitted.operation_request_digest
        {
            return Err(HelperError::Denied("ticket_runtime_mismatch".into()));
        }
        Ok(())
    }

    fn validate_runtime_commitments(
        &self,
        ticket: &PrivilegeTicket,
        runtime: &crate::RuntimeRecord,
    ) -> Result<()> {
        let current = &ticket.claims;
        let admitted = &runtime.authority_ticket.claims;
        if current.runtime_id != runtime.runtime_id
            || current.run_id != runtime.run_id
            || current.local_execution_plan_digest != runtime.plan_digest
            || current.run_manifest_digest != admitted.run_manifest_digest
            || current.runtime_spec_digest != admitted.runtime_spec_digest
            || current.launch_plan_digest != admitted.launch_plan_digest
            || current.device_policy_revision != admitted.device_policy_revision
            || current.device_revision != admitted.device_revision
            || current.connector_policy_id != admitted.connector_policy_id
            || current.connector_policy_revision != admitted.connector_policy_revision
            || current.project_id != admitted.project_id
            || current.project_revision != admitted.project_revision
            || current.assignment_id != admitted.assignment_id
            || current.project_agent_id != admitted.project_agent_id
            || current.project_agent_revision != admitted.project_agent_revision
            || current.runtime_configuration_revision != admitted.runtime_configuration_revision
        {
            return Err(HelperError::Denied("ticket_runtime_mismatch".into()));
        }
        Ok(())
    }
    fn validate_control_authority(
        &self,
        ticket: &PrivilegeTicket,
        target: &ControlTarget,
        runtime: &crate::RuntimeRecord,
    ) -> Result<()> {
        self.validate_runtime_commitments(ticket, runtime)?;
        let mediated_agent_internal_control = ticket.claims.operation_id == runtime.operation_id
            && runtime.plan.adapter_id.is_some()
            && ticket.claims.approval_enforcement
                == conduit_privileged_protocol::ApprovalEnforcement::AdapterMediated;
        if (ticket.claims.operation_id == runtime.operation_id && !mediated_agent_internal_control)
            || ticket.claims.control_digest.is_none()
        {
            return Err(HelperError::Denied("control_operation_mismatch".into()));
        }
        if ticket.claims.controller_epoch != target.controller_epoch {
            return Err(HelperError::Denied("controller_epoch_mismatch".into()));
        }
        Ok(())
    }
    fn validate_ticket(
        &self,
        ticket: &PrivilegeTicket,
        operation: PrivilegedOperation,
        plan: Option<&LocalExecutionPlan>,
    ) -> Result<()> {
        let key = self
            .keys
            .0
            .get(&ticket.key_id)
            .ok_or_else(|| HelperError::Denied("ticket_key_unpinned".into()))?;
        ticket.verify(key)?;
        let c = &ticket.claims;
        c.validate(&ticket.key_id)?;
        let ticket_digest = ticket.digest()?;
        let already_admitted = self
            .journal
            .has_admitted_ticket(&c.ticket_id, &ticket_digest)?;
        let now = OffsetDateTime::now_utc();
        let not_before = parse_time(&c.issued_at)?;
        let expires_at = parse_time(&c.expires_at)?;
        let control_digest_required = matches!(
            operation,
            PrivilegedOperation::Input
                | PrivilegedOperation::ResizePty
                | PrivilegedOperation::Pause
                | PrivilegedOperation::Resume
                | PrivilegedOperation::GracefulStop
                | PrivilegedOperation::ForceStop
        );
        if !self.config.policy.enabled {
            return Err(HelperError::Denied("privileged_helper_disabled".into()));
        }
        if c.approval_mode == "never" && !self.config.policy.allow_never {
            return Err(HelperError::Denied(
                "full_device_never_local_opt_in_required".into(),
            ));
        }
        if c.protocol != PROTOCOL
            || c.audience != "conduit-privileged-helper"
            || c.helper_installation_id != self.config.policy.installation_id
            || c.device_id != self.config.policy.device_id
            || c.device_key_id != self.config.device_key_id
            || c.expected_uid != self.config.policy.uid
            || c.public_origin != self.config.policy.origin
            || c.helper_policy_revision != self.config.policy.revision
            || c.helper_policy_digest != self.config.policy_digest
            || c.helper_key_id != self.config.receipt_key_id
            || !self.config.policy.ticket_key_ids.contains(&ticket.key_id)
            || c.allowed_operation != operation
            || !self.config.policy.allowed_operations.contains(&operation)
            || ((now < not_before || now > expires_at) && !already_admitted)
            || expires_at - not_before > time::Duration::minutes(10)
            || c.access_scope != "full_device"
            || (matches!(
                c.approval_enforcement,
                conduit_privileged_protocol::ApprovalEnforcement::ExactCommand
            ) && c.approval_mode != "never"
                && c.approval_receipt_digest.is_none())
            || (c.approval_mode == "never"
                && (!c.required_approval_risk_classes.is_empty()
                    || c.approval_receipt_digest.is_some()))
            || !within_ceilings(&c.resource_ceilings, &self.config.policy.ceilings)
            || (control_digest_required && !c.control_digest.as_deref().is_some_and(valid_sha256))
            || (!control_digest_required && c.control_digest.is_some())
        {
            return Err(HelperError::Denied("privilege_ticket_invalid".into()));
        }
        if let Some(plan) = plan {
            if c.runtime_id != plan.runtime_id
                || c.run_id != plan.run_id
                || c.operation_id != plan.operation_id
                || c.local_execution_plan_digest != plan.digest()?
                || c.resource_ceilings != plan.resources
            {
                return Err(HelperError::Denied("ticket_plan_mismatch".into()));
            }
            if (plan.adapter_id.is_some()
                && c.approval_enforcement
                    != conduit_privileged_protocol::ApprovalEnforcement::AdapterMediated)
                || (plan.adapter_id.is_none()
                    && c.approval_enforcement
                        != conduit_privileged_protocol::ApprovalEnforcement::ExactCommand)
            {
                return Err(HelperError::Denied("approval_enforcement_mismatch".into()));
            }
            if let Some(adapter) = &plan.adapter_id {
                if !self.config.policy.allow_unrestricted_launch
                    || !self.config.policy.allowed_adapters.contains(adapter)
                {
                    return Err(HelperError::Denied("adapter_not_allowed".into()));
                }
            } else if let Some(profile) = &plan.launch_profile_id {
                let registered = self
                    .config
                    .policy
                    .launch_profile_executable_digests
                    .get(profile)
                    .is_some_and(|digest| digest == &plan.executable.sha256);
                let unrestricted_named = self.config.policy.allow_unrestricted_launch
                    && self.config.policy.allowed_launch_profiles.contains(profile);
                if !registered && !unrestricted_named {
                    return Err(HelperError::Denied("launch_profile_not_allowed".into()));
                }
            } else {
                return Err(HelperError::Denied("launch_authority_missing".into()));
            }
            if (!plan.credentials.is_empty() && plan.adapter_id.is_none())
                || plan.credentials.iter().any(|credential| {
                    !self
                        .config
                        .policy
                        .allowed_credential_profiles
                        .contains(&credential.projection_id)
                })
            {
                return Err(HelperError::Denied(
                    "credential_projection_not_allowed".into(),
                ));
            }
            if plan.resources.runtime_max_usec.is_none()
                && !self.config.policy.allow_persistent_sessions
            {
                return Err(HelperError::Denied("persistent_session_not_allowed".into()));
            }
        }
        Ok(())
    }
    fn receipt(
        &self,
        ticket: &PrivilegeTicket,
        _request: &str,
        transition: &str,
        observation: Option<&UnitObservation>,
        revision: u64,
    ) -> Result<HelperReceipt> {
        let c = &ticket.claims;
        let runtime = self.journal.runtime(&c.runtime_id)?;
        let previous = runtime
            .as_ref()
            .and_then(|v| v.previous_receipt_digest.clone());
        let observed_at = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let receipt_id = format!(
            "hrcp_{}",
            &hex::encode(Sha256::digest(
                format!("{}:{revision}:{transition}", c.ticket_id).as_bytes()
            ))[..24]
        );
        let claims = ReceiptClaims {
            protocol: PROTOCOL.into(),
            receipt_id,
            installation_id: self.config.policy.installation_id.clone(),
            receipt_key_id: self.config.receipt_key_id.clone(),
            helper_version: self.config.helper_version.clone(),
            policy_revision: self.config.policy.revision,
            policy_digest: self.config.policy_digest.clone(),
            ticket_id: c.ticket_id.clone(),
            ticket_digest: ticket.digest()?,
            operation_id: c.operation_id.clone(),
            request_digest: c.operation_request_digest.clone(),
            run_id: c.run_id.clone(),
            runtime_id: c.runtime_id.clone(),
            runtime_spec_digest: c.runtime_spec_digest.clone(),
            launch_plan_digest: c.launch_plan_digest.clone(),
            local_execution_plan_digest: c.local_execution_plan_digest.clone(),
            control_request_digest: c.control_digest.clone(),
            controller_epoch: c.controller_epoch,
            state_revision: revision,
            transition: transition.into(),
            unit_name: runtime
                .as_ref()
                .map(|v| v.unit_name.clone())
                .unwrap_or_default(),
            invocation_id: observation.and_then(|v| v.invocation_id.clone()),
            cgroup: observation.and_then(|v| v.cgroup.clone()),
            main_pid: observation.and_then(|v| v.main_pid),
            process_birth: observation.and_then(|v| v.process_birth.clone()),
            effective_uid: observation.and_then(|v| v.effective_uid),
            effective_gid: observation.and_then(|v| v.effective_gid),
            stdout_cursor: runtime.as_ref().map_or(0, |v| v.stdout_cursor),
            stderr_cursor: runtime.as_ref().map_or(0, |v| v.stderr_cursor),
            exit_code: observation.and_then(|v| v.exit_code),
            signal: observation.and_then(|v| v.signal),
            observed_at,
            previous_receipt_digest: previous,
        };
        Ok(SignedClaims::sign(
            &self.config.receipt_key_id,
            claims,
            &self.receipt_key,
        )?)
    }
}

pub fn build_registration_bundle(
    policy: &RootPolicy,
    policy_change: &PolicyChangeEvidence,
    device_public_key: [u8; 32],
    receipt_key: &SigningKey,
    systemd: SystemdCapabilityProbe,
    helper_version: &str,
    state_dir: &Path,
) -> Result<RegistrationBundle> {
    let policy_digest = policy.digest()?;
    if policy_change.revision != policy.revision || policy_change.policy_digest != policy_digest {
        return Err(HelperError::Policy(
            "policy change evidence does not match root policy".into(),
        ));
    }
    let receipt_key_id =
        conduit_privileged_protocol::key_id("hkey", receipt_key.verifying_key().as_bytes());
    let capability = effective_capability_claims(
        policy,
        &policy_digest,
        &receipt_key_id,
        helper_version,
        policy_change.changed_at.clone(),
        systemd,
        state_dir,
    );
    Ok(RegistrationBundle {
        protocol: PROTOCOL.into(),
        installation_id: policy.installation_id.clone(),
        device_id: policy.device_id.clone(),
        device_key_id: conduit_privileged_protocol::key_id("dkey", &device_public_key),
        uid: policy.uid,
        origin: policy.origin.clone(),
        policy_revision: policy.revision,
        policy_digest: policy_digest.clone(),
        receipt_public_jwk: PublicJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(receipt_key.verifying_key().as_bytes()),
            kid: receipt_key_id.clone(),
        },
        signed_policy_attestation: SignedClaims::sign(
            &receipt_key_id,
            policy.clone(),
            receipt_key,
        )?,
        signed_capability: SignedClaims::sign(&receipt_key_id, capability, receipt_key)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostCapabilityProbe {
    socket_peer_credentials: bool,
    cgroup_v2: bool,
    freeze: bool,
    pidfd: bool,
    openat2: bool,
    execveat: bool,
    pty: bool,
    stream_replay: bool,
}

fn effective_capability_claims(
    policy: &RootPolicy,
    policy_digest: &str,
    receipt_key_id: &str,
    helper_version: &str,
    observed_at: String,
    systemd: SystemdCapabilityProbe,
    state_dir: &Path,
) -> CapabilityClaims {
    let host = probe_host_capabilities(state_dir);
    let mut claims = CapabilityClaims {
        protocol: PROTOCOL.into(),
        helper_version: helper_version.into(),
        installation_id: policy.installation_id.clone(),
        receipt_key_id: receipt_key_id.into(),
        policy_revision: policy.revision,
        policy_digest: policy_digest.into(),
        enabled: policy.enabled,
        observed_at,
        systemd_system_manager: systemd.system_manager,
        socket_peer_credentials: host.socket_peer_credentials,
        transient_units: systemd.system_manager && systemd.transient_units,
        cgroup_v2: host.cgroup_v2,
        freeze: systemd.system_manager && systemd.freeze && host.freeze,
        pidfd: host.pidfd,
        openat2: host.openat2,
        execveat: host.execveat,
        pty: host.pty,
        stream_replay: host.stream_replay,
        never_opt_in: policy.allow_never,
        unrestricted_launch_opt_in: policy.allow_unrestricted_launch,
        unavailable_reason: None,
    };
    claims.unavailable_reason = claims.full_device_unavailable_reason().map(str::to_owned);
    claims
}

fn probe_host_capabilities(state_dir: &Path) -> HostCapabilityProbe {
    let cgroup_v2 = probe_cgroup_v2();
    HostCapabilityProbe {
        socket_peer_credentials: probe_socket_peer_credentials(),
        cgroup_v2,
        freeze: cgroup_v2 && probe_cgroup_freeze(),
        pidfd: probe_pidfd(),
        openat2: probe_openat2(),
        execveat: probe_execveat(),
        pty: probe_pty(),
        stream_replay: probe_stream_replay(state_dir),
    }
}

fn probe_socket_peer_credentials() -> bool {
    let mut descriptors = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    } != 0
    {
        return false;
    }
    let left = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let _right = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            left.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        ) == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.pid == libc::getpid()
            && credentials.uid == libc::geteuid()
            && credentials.gid == libc::getegid()
    }
}

fn probe_cgroup_v2() -> bool {
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    let path = CString::new("/sys/fs/cgroup").expect("static path");
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    stat.f_type as libc::c_long == CGROUP2_SUPER_MAGIC
        && File::open("/sys/fs/cgroup/cgroup.controllers").is_ok()
}

fn probe_cgroup_freeze() -> bool {
    fn readable_freezer(directory: &Path, remaining_depth: usize) -> bool {
        if File::open(directory.join("cgroup.freeze")).is_ok() {
            return true;
        }
        if remaining_depth == 0 {
            return false;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            return false;
        };
        entries.filter_map(std::result::Result::ok).any(|entry| {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
                && readable_freezer(&entry.path(), remaining_depth - 1)
        })
    }
    readable_freezer(Path::new("/sys/fs/cgroup"), 2)
}

fn probe_pidfd() -> bool {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if descriptor < 0 {
        return false;
    }
    drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    true
}

#[repr(C)]
struct ProbeOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn probe_openat2() -> bool {
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    let path = CString::new(".").expect("static path");
    let how = ProbeOpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<ProbeOpenHow>(),
        )
    } as i32;
    if descriptor < 0 {
        return false;
    }
    drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    true
}

fn probe_execveat() -> bool {
    let empty = CString::new("").expect("static string");
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            -1,
            empty.as_ptr(),
            std::ptr::null::<*const libc::c_char>(),
            std::ptr::null::<*const libc::c_char>(),
            libc::AT_EMPTY_PATH,
        )
    };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
}

fn probe_pty() -> bool {
    let mut master = -1;
    let mut slave = -1;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return false;
    }
    drop(unsafe { OwnedFd::from_raw_fd(master) });
    drop(unsafe { OwnedFd::from_raw_fd(slave) });
    true
}

fn probe_stream_replay(state_dir: &Path) -> bool {
    let nonce = match getrandom::u64() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let path = state_dir.join(format!(
        ".capability-stream-probe-{}-{nonce:016x}",
        std::process::id()
    ));
    let result = (|| -> std::io::Result<bool> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let marker = b"conduit-stream-replay-probe";
        file.write_all(marker)?;
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;
        let mut observed = Vec::with_capacity(marker.len());
        file.take(marker.len() as u64).read_to_end(&mut observed)?;
        Ok(observed == marker)
    })();
    let removed = fs::remove_file(&path).is_ok();
    result.unwrap_or(false) && removed
}

fn parse_time(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| HelperError::Denied("invalid_ticket_time".into()))
}
fn within_ceilings(
    requested: &conduit_privileged_protocol::ResourceCeilings,
    policy: &conduit_privileged_protocol::ResourceCeilings,
) -> bool {
    fn le<T: Ord>(requested: Option<T>, policy: Option<T>) -> bool {
        match (requested, policy) {
            (Some(a), Some(b)) => a <= b,
            (Some(_), None) | (None, None) => true,
            (None, Some(_)) => false,
        }
    }
    le(
        requested.cpu_quota_per_sec_usec,
        policy.cpu_quota_per_sec_usec,
    ) && le(requested.memory_max_bytes, policy.memory_max_bytes)
        && le(requested.tasks_max, policy.tasks_max)
        && le(requested.io_weight, policy.io_weight)
        && le(requested.runtime_max_usec, policy.runtime_max_usec)
}

fn validate_credential_descriptors(
    plan: &LocalExecutionPlan,
    descriptors: &[OwnedFd],
) -> Result<Vec<(CredentialDescriptor, Zeroizing<Vec<u8>>)>> {
    if descriptors.len() != plan.credentials.len() {
        return Err(HelperError::Denied("credential_descriptor_count".into()));
    }
    let mut indices = BTreeSet::new();
    let mut target_names = BTreeSet::new();
    let mut payloads = Vec::with_capacity(plan.credentials.len());
    for credential in &plan.credentials {
        let index = credential.descriptor_index as usize;
        if index >= descriptors.len()
            || !indices.insert(index)
            || !target_names.insert(credential.target_name.clone())
            || !credential.read_only
            || credential.revision == 0
            || credential.size > 1024 * 1024
            || !valid_sha256(&credential.sha256)
            || !safe_credential_target(&credential.target_name)
        {
            return Err(HelperError::Denied("credential_descriptor_invalid".into()));
        }
        let raw = descriptors[index].as_raw_fd();
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(raw, status.as_mut_ptr()) } != 0 {
            return Err(HelperError::Io(std::io::Error::last_os_error()));
        }
        let status = unsafe { status.assume_init() };
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_size < 0
            || status.st_size as u64 != credential.size
            || unsafe { libc::fcntl(raw, libc::F_GETFD) } & libc::FD_CLOEXEC == 0
            || unsafe { libc::lseek(raw, 0, libc::SEEK_CUR) } != 0
        {
            return Err(HelperError::Denied("credential_descriptor_invalid".into()));
        }
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        let required_seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if seals < 0 || seals & required_seals != required_seals {
            return Err(HelperError::Denied("credential_descriptor_unsealed".into()));
        }
        let duplicate = descriptors[index].try_clone()?;
        let mut source = File::from(duplicate);
        source.seek(SeekFrom::Start(0))?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(credential.size as usize));
        source
            .take(credential.size + 1)
            .read_to_end(bytes.as_mut())?;
        if bytes.len() as u64 != credential.size
            || hex::encode(Sha256::digest(bytes.as_slice())) != credential.sha256
        {
            return Err(HelperError::Denied("credential_projection_mismatch".into()));
        }
        payloads.push((credential.clone(), bytes));
    }
    Ok(payloads)
}

fn safe_credential_target(value: &str) -> bool {
    use std::path::Component;
    if value.is_empty() || value.len() > 128 || value.starts_with('/') {
        return false;
    }
    let mut count = 0usize;
    for component in Path::new(value).components() {
        let Component::Normal(name) = component else {
            return false;
        };
        let bytes = name.as_encoded_bytes();
        if bytes.is_empty()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || name == "."
            || name == ".."
        {
            return false;
        }
        count += 1;
    }
    count > 0 && count <= 8
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub fn runtime_identity_matches(
    runtime: &crate::RuntimeRecord,
    observed: &UnitObservation,
) -> bool {
    let expected_invocation = runtime.invocation_id.as_deref().or_else(|| {
        runtime
            .last_receipt
            .as_ref()?
            .claims
            .invocation_id
            .as_deref()
    });
    if expected_invocation != observed.invocation_id.as_deref() {
        return false;
    }
    let terminal = matches!(
        observed.active_state.as_str(),
        "inactive" | "dead" | "failed"
    );
    if terminal {
        return true;
    }
    let expected_pid = runtime.main_pid.or_else(|| {
        runtime
            .last_receipt
            .as_ref()
            .and_then(|receipt| receipt.claims.main_pid)
    });
    let expected_cgroup = runtime
        .last_receipt
        .as_ref()
        .and_then(|receipt| receipt.claims.cgroup.as_deref());
    let expected_process_birth = runtime
        .last_receipt
        .as_ref()
        .and_then(|receipt| receipt.claims.process_birth.as_deref());
    expected_pid.is_some_and(|value| observed.main_pid == Some(value))
        && expected_cgroup.is_some_and(|value| observed.cgroup.as_deref() == Some(value))
        && expected_process_birth
            .is_some_and(|value| observed.process_birth.as_deref() == Some(value))
}
fn normalize_unit_state(value: &str) -> &str {
    match value {
        "inactive" | "dead" => "stopped",
        "failed" => "failed",
        other => other,
    }
}
fn receipt_transition(value: &str) -> &'static str {
    match value {
        "active" | "activating" | "running" => "running",
        "frozen" | "paused" => "paused",
        "prepared" => "prepared",
        "inactive" | "dead" | "stopped" => "completed",
        "failed" => "failed",
        "missing" => "recovery_required",
        _ => "recovery_required",
    }
}
fn request_digest(request: &HelperRequest) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(request)?)))
}
pub fn control_target_digest(target: &ControlTarget) -> Result<String> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Binding<'a> {
        runtime_id: &'a str,
        unit_name: &'a str,
        invocation_id: &'a str,
        controller_epoch: u64,
        expected_state_revision: u64,
    }
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(&Binding {
        runtime_id: &target.runtime_id,
        unit_name: &target.unit_name,
        invocation_id: &target.invocation_id,
        controller_epoch: target.controller_epoch,
        expected_state_revision: target.expected_state_revision,
    })?)))
}
fn decode_receipt(value: Option<Vec<u8>>) -> Result<HelperResponse> {
    let value = value.ok_or_else(|| HelperError::RecoveryRequired("receipt missing".into()))?;
    if let Ok(chain) = serde_json::from_slice::<Vec<HelperReceipt>>(&value) {
        Ok(HelperResponse::Receipts(chain))
    } else {
        Ok(HelperResponse::Receipt(Box::new(serde_json::from_slice(
            &value,
        )?)))
    }
}
fn decode_receipt_chain(value: Option<Vec<u8>>) -> Result<Vec<HelperReceipt>> {
    let value =
        value.ok_or_else(|| HelperError::RecoveryRequired("receipt chain missing".into()))?;
    if let Ok(chain) = serde_json::from_slice::<Vec<HelperReceipt>>(&value) {
        Ok(chain)
    } else {
        Ok(vec![serde_json::from_slice(&value)?])
    }
}
fn process_start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| HelperError::Authentication("proc stat".into()))?;
    Ok(stat[end + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| HelperError::Authentication("proc start".into()))?
        .into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeSystemd, capture_file_identity};
    use conduit_privileged_protocol::{
        ApprovalEnforcement, PrivilegeTicketClaims, ResourceCeilings, StdioMode,
    };
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
    use tempfile::tempdir;
    fn resources() -> ResourceCeilings {
        ResourceCeilings {
            cpu_quota_per_sec_usec: None,
            memory_max_bytes: None,
            tasks_max: None,
            io_weight: None,
            runtime_max_usec: None,
        }
    }
    fn setup() -> (
        HelperEngine<FakeSystemd>,
        FakeSystemd,
        LocalExecutionPlan,
        SigningKey,
        VerifyingKey,
    ) {
        let directory = tempdir().unwrap().keep();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let issuer = SigningKey::from_bytes(&[31; 32]);
        let receipt = SigningKey::from_bytes(&[32; 32]);
        let issuer_id =
            conduit_privileged_protocol::key_id("pkey", issuer.verifying_key().as_bytes());
        let receipt_id =
            conduit_privileged_protocol::key_id("hkey", receipt.verifying_key().as_bytes());
        let policy = RootPolicy {
            policy_version: 1,
            installation_id: "phinst_service0001".into(),
            device_id: "dev_service0001".into(),
            uid,
            revision: 7,
            enabled: true,
            origin: "https://example.test".into(),
            ticket_key_ids: vec![issuer_id.clone()],
            allowed_operations: vec![
                PrivilegedOperation::Prepare,
                PrivilegedOperation::Start,
                PrivilegedOperation::Input,
                PrivilegedOperation::ResizePty,
                PrivilegedOperation::Pause,
                PrivilegedOperation::Resume,
                PrivilegedOperation::GracefulStop,
                PrivilegedOperation::ForceStop,
            ],
            allowed_adapters: vec!["codex".into()],
            allowed_launch_profiles: vec!["service-test".into()],
            launch_profile_executable_digests: BTreeMap::from([(
                "service-test".into(),
                capture_file_identity(Path::new("/bin/true"), true)
                    .unwrap()
                    .sha256,
            )]),
            allowed_credential_profiles: vec!["cred_test".into()],
            ceilings: resources(),
            allow_never: false,
            allow_unrestricted_launch: true,
            allow_persistent_sessions: true,
            allow_offline_control: false,
            receipt_retention_seconds: 3600,
        };
        let policy_digest = policy.digest().unwrap();
        let device_public_key = [44; 32];
        let config = HelperConfig {
            policy_digest: policy_digest.clone(),
            policy,
            policy_path: None,
            policy_owner_uid: uid,
            receipt_key_id: receipt_id,
            helper_version: "test".into(),
            state_dir: directory.clone(),
            worker_path: "/usr/lib/conduit/conduit-privileged-helper".into(),
            device_key_id: conduit_privileged_protocol::key_id("dkey", &device_public_key),
            device_public_key,
            policy_change: PolicyChangeEvidence {
                revision: 7,
                policy_digest,
                previous_policy_digest: None,
                change_class: "installation".into(),
                changed_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let plan = LocalExecutionPlan {
            plan_version: 1,
            runtime_id: "rt_service0001".into(),
            run_id: "run_service0001".into(),
            operation_id: "op_service0001".into(),
            executable: capture_file_identity(Path::new("/bin/true"), true).unwrap(),
            interpreter: None,
            argv: vec!["true".into()],
            cwd: capture_file_identity(Path::new("/tmp"), false).unwrap(),
            systemd_unit: "conduit-elevated-rt_service0001.service".into(),
            adapter_id: None,
            launch_profile_id: Some("service-test".into()),
            environment: BTreeMap::new(),
            environment_value_digests: BTreeMap::new(),
            workspaces: vec![],
            credentials: vec![],
            stdio: StdioMode::Pipes,
            resources: resources(),
            helper_protocol: PROTOCOL.into(),
            helper_min_version: "0.1.0".into(),
        };
        let backend = FakeSystemd::default();
        let engine = HelperEngine::new(
            config,
            PinnedTicketKeys(BTreeMap::from([(
                issuer_id,
                *issuer.verifying_key().as_bytes(),
            )])),
            receipt.clone(),
            HelperJournal::open_owned(directory.join("helper.sqlite3"), uid).unwrap(),
            backend.clone(),
        )
        .unwrap();
        (engine, backend, plan, issuer, receipt.verifying_key())
    }
    fn ticket<M: SystemdManager>(
        engine: &HelperEngine<M>,
        issuer: &SigningKey,
        plan: &LocalExecutionPlan,
        operation: PrivilegedOperation,
        id: &str,
    ) -> PrivilegeTicket {
        let now = OffsetDateTime::now_utc();
        SignedClaims::sign(
            engine.config.policy.ticket_key_ids[0].clone(),
            PrivilegeTicketClaims {
                schema_version: 1,
                protocol: PROTOCOL.into(),
                ticket_id: id.into(),
                issuer_kind: "control_plane".into(),
                issuer_key_id: engine.config.policy.ticket_key_ids[0].clone(),
                audience: "conduit-privileged-helper".into(),
                public_origin: engine.config.policy.origin.clone(),
                helper_installation_id: engine.config.policy.installation_id.clone(),
                helper_key_id: engine.config.receipt_key_id.clone(),
                helper_policy_revision: engine.config.policy.revision,
                helper_policy_digest: engine.config.policy_digest.clone(),
                device_id: engine.config.policy.device_id.clone(),
                device_key_id: engine.config.device_key_id.clone(),
                device_policy_revision: 1,
                device_revision: 1,
                expected_uid: engine.config.policy.uid,
                operation_id: plan.operation_id.clone(),
                idempotency_key_digest: "11".repeat(32),
                operation_request_digest: "22".repeat(32),
                run_manifest_digest: "23".repeat(32),
                run_id: plan.run_id.clone(),
                runtime_id: plan.runtime_id.clone(),
                runtime_spec_digest: "33".repeat(32),
                launch_plan_digest: "44".repeat(32),
                control_digest: None,
                local_execution_plan_digest: plan.digest().unwrap(),
                controller_epoch: 1,
                connector_policy_id: Some("cpol_test".into()),
                connector_policy_revision: 1,
                project_id: None,
                project_revision: None,
                assignment_id: None,
                project_agent_id: None,
                project_agent_revision: None,
                runtime_configuration_revision: 1,
                access_scope: "full_device".into(),
                approval_mode: "always".into(),
                approval_receipt_digest: Some("55".repeat(32)),
                approval_enforcement: if plan.adapter_id.is_some() {
                    ApprovalEnforcement::AdapterMediated
                } else {
                    ApprovalEnforcement::ExactCommand
                },
                required_approval_risk_classes: vec![],
                allowed_operation: operation,
                resource_ceilings: resources(),
                issued_at: (now - time::Duration::seconds(5)).format(&Rfc3339).unwrap(),
                expires_at: (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
                nonce: "nonce".into(),
                max_use_count: 1,
            },
            issuer,
        )
        .unwrap()
    }
    #[test]
    fn prepare_start_receipts_are_signed_and_start_replays() {
        let (engine, _backend, plan, issuer, receipt_key) = setup();
        let prepared = engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_prepare0001",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        let HelperResponse::Receipts(prepared) = prepared else {
            panic!()
        };
        assert_eq!(
            prepared
                .iter()
                .map(|v| v.claims.transition.as_str())
                .collect::<Vec<_>>(),
            vec!["admitted", "prepared"]
        );
        for receipt in &prepared {
            receipt.verify(receipt_key.as_bytes()).unwrap()
        }
        let start = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Start,
            "ptkt_start0001",
        );
        let response = engine.start(start.clone(), plan.digest().unwrap()).unwrap();
        let HelperResponse::Receipts(started) = response else {
            panic!()
        };
        assert_eq!(
            started
                .iter()
                .map(|v| v.claims.transition.as_str())
                .collect::<Vec<_>>(),
            vec!["unit_created", "running"]
        );
        for receipt in &started {
            receipt.verify(receipt_key.as_bytes()).unwrap()
        }
        let replay = engine.start(start, plan.digest().unwrap()).unwrap();
        assert_eq!(replay, HelperResponse::Receipts(started));
    }

    #[test]
    fn running_agent_reconcile_is_helper_signed_recovery_required_without_respawn() {
        let (engine, backend, mut plan, issuer, receipt_key) = setup();
        plan.adapter_id = Some("codex".into());
        plan.launch_profile_id = None;
        let prepared = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_agent_prepare01",
        );
        engine.prepare(prepared, plan.clone(), vec![]).unwrap();
        let started = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Start,
            "ptkt_agent_start001",
        );
        engine.start(started, plan.digest().unwrap()).unwrap();
        let starts_before = backend
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("start:"))
            .count();

        let HelperResponse::Receipts(receipts) =
            engine.reconcile(vec![plan.runtime_id.clone()]).unwrap()
        else {
            panic!("agent reconcile receipts")
        };
        let final_receipt = receipts.last().unwrap();
        final_receipt.verify(receipt_key.as_bytes()).unwrap();
        assert_eq!(final_receipt.claims.transition, "recovery_required");
        assert_eq!(
            final_receipt.claims.invocation_id.as_deref(),
            Some(format!("inv-{}", plan.systemd_unit).as_str())
        );
        assert_eq!(
            backend
                .calls()
                .into_iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            starts_before
        );
        assert_eq!(
            engine
                .journal
                .runtime(&plan.runtime_id)
                .unwrap()
                .unwrap()
                .state,
            "recovery_required"
        );
    }

    #[test]
    fn registered_launch_profile_does_not_require_unrestricted_root_opt_in() {
        let (mut engine, _backend, plan, issuer, _) = setup();
        engine.config.policy.allow_unrestricted_launch = false;
        engine.config.policy_digest = engine.config.policy.digest().unwrap();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_profileok01",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();

        let mut changed = plan;
        changed.runtime_id = "rt_profilebad0001".into();
        changed.systemd_unit = "conduit-elevated-rt_profilebad0001.service".into();
        changed.executable.sha256 = "fe".repeat(32);
        assert!(matches!(
            engine.prepare(
                ticket(
                    &engine,
                    &issuer,
                    &changed,
                    PrivilegedOperation::Prepare,
                    "ptkt_profilebad01",
                ),
                changed,
                vec![]
            ),
            Err(HelperError::Denied(reason)) if reason == "launch_profile_not_allowed"
        ));
    }

    #[test]
    fn never_requires_the_separate_root_owned_opt_in() {
        let (engine, _backend, plan, issuer, _) = setup();
        let mut claims = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_neverdeny01",
        )
        .claims;
        claims.approval_mode = "never".into();
        claims.approval_receipt_digest = None;
        let denied = SignedClaims::sign(
            engine.config.policy.ticket_key_ids[0].clone(),
            claims,
            &issuer,
        )
        .unwrap();
        assert!(matches!(
            engine.prepare(denied, plan, vec![]),
            Err(HelperError::Denied(reason))
                if reason == "full_device_never_local_opt_in_required"
        ));
    }

    #[test]
    fn expired_ticket_replays_only_after_exact_durable_admission() {
        let (engine, _backend, plan, issuer, _receipt_key) = setup();
        let base = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_expired_replay",
        );
        let now = OffsetDateTime::now_utc();
        let mut claims = base.claims;
        claims.issued_at = (now - time::Duration::minutes(2)).format(&Rfc3339).unwrap();
        claims.expires_at = (now - time::Duration::minutes(1)).format(&Rfc3339).unwrap();
        let expired = SignedClaims::sign(base.key_id, claims, &issuer).unwrap();
        assert!(matches!(
            engine.prepare(expired.clone(), plan.clone(), vec![]),
            Err(HelperError::Denied(reason)) if reason == "privilege_ticket_invalid"
        ));

        let request = request_digest(&HelperRequest::Prepare {
            ticket: Box::new(expired.clone()),
            plan: Box::new(plan.clone()),
        })
        .unwrap();
        engine
            .journal
            .admit_prepare(
                &expired,
                &expired.digest().unwrap(),
                &request,
                &plan.digest().unwrap(),
                &plan,
            )
            .unwrap();
        let admitted = engine
            .receipt(&expired, &request, "admitted", None, 1)
            .unwrap();
        engine
            .journal
            .record_effect_boundary(
                &expired.claims.ticket_id,
                &admitted,
                "admitted",
                None,
                None,
                false,
            )
            .unwrap();
        let replay = engine.prepare(expired, plan, vec![]).unwrap();
        assert!(matches!(replay, HelperResponse::Receipts(ref values) if values.len() == 2));
    }

    #[test]
    fn credential_projection_requires_exact_sealed_memfd() {
        use std::os::fd::FromRawFd;

        let (engine, _backend, mut plan, issuer, _receipt_key) = setup();
        let secret = b"bounded-test-secret";
        let name = std::ffi::CString::new("conduit-credential-test").unwrap();
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(raw >= 0);
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(secret).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        plan.credentials = vec![CredentialDescriptor {
            projection_id: "cred_test".into(),
            revision: 1,
            target_name: ".codex/auth.json".into(),
            descriptor_index: 0,
            size: secret.len() as u64,
            sha256: hex::encode(Sha256::digest(secret)),
            read_only: true,
        }];
        assert!(matches!(
            validate_credential_descriptors(&plan, &[file.try_clone().unwrap().into()]),
            Err(HelperError::Denied(reason)) if reason == "credential_descriptor_unsealed"
        ));
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) },
            0
        );
        let payloads =
            validate_credential_descriptors(&plan, &[file.try_clone().unwrap().into()]).unwrap();
        assert_eq!(payloads[0].1.as_slice(), secret);

        plan.adapter_id = Some("codex".into());
        plan.launch_profile_id = None;
        file.seek(SeekFrom::Start(0)).unwrap();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_credential01",
                ),
                plan.clone(),
                vec![file.try_clone().unwrap().into()],
            )
            .unwrap();
        let projected = engine
            .config
            .state_dir
            .join("runtimes")
            .join(&plan.runtime_id)
            .join("home/.codex/auth.json");
        assert_eq!(fs::read(projected).unwrap(), secret);

        file.seek(SeekFrom::End(0)).unwrap();
        assert!(matches!(
            validate_credential_descriptors(&plan, &[file.into()]),
            Err(HelperError::Denied(reason)) if reason == "credential_descriptor_invalid"
        ));
    }
    #[test]
    fn systemd_failure_becomes_uncertain_and_is_not_repeated() {
        let (engine, backend, plan, issuer, _) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_prepare0002",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        backend.fail_next("crash window");
        let start = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Start,
            "ptkt_start0002",
        );
        assert!(matches!(
            engine.start(start.clone(), plan.digest().unwrap()),
            Err(HelperError::Systemd(_))
        ));
        assert!(matches!(
            engine.start(start, plan.digest().unwrap()),
            Err(HelperError::RecoveryRequired(_))
        ));
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|v| v.starts_with("start:"))
                .count(),
            1
        );
    }

    #[test]
    fn control_ticket_requires_signed_control_digest_and_receipt_uses_it() {
        let (engine, _backend, plan, issuer, _) = setup();
        let generated = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Input,
            "ptkt_input_missing_digest",
        );
        let mut missing_claims = generated.claims;
        missing_claims.control_digest = None;
        let missing = SignedClaims::sign(
            engine.config.policy.ticket_key_ids[0].clone(),
            missing_claims,
            &issuer,
        )
        .unwrap();
        assert!(matches!(
            engine.validate_ticket(&missing, PrivilegedOperation::Input, None),
            Err(HelperError::Denied(_))
        ));

        let mut claims = missing.claims;
        claims.ticket_id = "ptkt_input_bound_digest".into();
        claims.control_digest = Some("ab".repeat(32));
        let bound = SignedClaims::sign(
            engine.config.policy.ticket_key_ids[0].clone(),
            claims,
            &issuer,
        )
        .unwrap();
        engine
            .validate_ticket(&bound, PrivilegedOperation::Input, None)
            .unwrap();
        let receipt = engine
            .receipt(&bound, "local-request-digest", "input_applied", None, 1)
            .unwrap();
        assert_eq!(receipt.claims.control_request_digest, Some("ab".repeat(32)));
        assert_ne!(
            receipt.claims.control_request_digest.as_deref(),
            Some("local-request-digest")
        );

        let mut prepare_claims = bound.claims;
        prepare_claims.allowed_operation = PrivilegedOperation::Prepare;
        let prepare_with_control = SignedClaims::sign(
            engine.config.policy.ticket_key_ids[0].clone(),
            prepare_claims,
            &issuer,
        )
        .unwrap();
        assert!(matches!(
            engine.validate_ticket(
                &prepare_with_control,
                PrivilegedOperation::Prepare,
                Some(&plan)
            ),
            Err(HelperError::Denied(_))
        ));
    }

    #[test]
    fn ticket_binding_matrix_fails_closed() {
        let (engine, _backend, plan, issuer, _) = setup();
        let valid = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_binding0001",
        );
        engine
            .validate_ticket(&valid, PrivilegedOperation::Prepare, Some(&plan))
            .unwrap();

        let resign = |claims: PrivilegeTicketClaims| {
            SignedClaims::sign(
                engine.config.policy.ticket_key_ids[0].clone(),
                claims,
                &issuer,
            )
            .unwrap()
        };
        let rejected = |candidate: PrivilegeTicket| {
            assert!(matches!(
                engine.validate_ticket(&candidate, PrivilegedOperation::Prepare, Some(&plan)),
                Err(HelperError::Denied(_)) | Err(HelperError::Protocol(_))
            ));
        };

        let mut claims = valid.claims.clone();
        claims.audience = "another-helper".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.public_origin = "https://wrong.example.test".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.helper_installation_id = "phinst_wrong0001".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.helper_key_id = "hkey_wrong000001".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.expected_uid = engine.config.policy.uid.saturating_add(1);
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.device_id = "dev_wrong000001".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.device_key_id = "dkey_wrong00001".into();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.allowed_operation = PrivilegedOperation::Start;
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.local_execution_plan_digest = "ab".repeat(32);
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.schema_version = 2;
        rejected(resign(claims));

        let now = OffsetDateTime::now_utc();
        let mut claims = valid.claims.clone();
        claims.issued_at = (now - time::Duration::minutes(2)).format(&Rfc3339).unwrap();
        claims.expires_at = (now - time::Duration::minutes(1)).format(&Rfc3339).unwrap();
        rejected(resign(claims));
        let mut claims = valid.claims.clone();
        claims.issued_at = (now + time::Duration::minutes(1)).format(&Rfc3339).unwrap();
        claims.expires_at = (now + time::Duration::minutes(2)).format(&Rfc3339).unwrap();
        rejected(resign(claims));

        let mut wrong_key = valid.clone();
        wrong_key.key_id = "pkey_unpinned0001".into();
        rejected(wrong_key);
        let mut bad_signature = valid;
        bad_signature.claims.operation_request_digest = "cd".repeat(32);
        assert!(matches!(
            engine.validate_ticket(&bad_signature, PrivilegedOperation::Prepare, Some(&plan)),
            Err(HelperError::Protocol(_))
        ));
    }

    #[test]
    fn control_ticket_is_bound_to_controller_epoch() {
        let (engine, _backend, plan, issuer, _) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_epochprep01",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        let runtime = engine.journal.runtime(&plan.runtime_id).unwrap().unwrap();
        let control = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Pause,
            "ptkt_epochctrl01",
        );
        let mut control_claims = control.claims;
        control_claims.operation_id = "op_epochcontrol0001".into();
        control_claims.control_digest = Some("66".repeat(32));
        control_claims.operation_request_digest = "66".repeat(32);
        let control = SignedClaims::sign(control.key_id, control_claims, &issuer).unwrap();
        let target = ControlTarget {
            runtime_id: runtime.runtime_id.clone(),
            unit_name: runtime.unit_name.clone(),
            invocation_id: "0".repeat(32),
            controller_epoch: control.claims.controller_epoch + 1,
            expected_state_revision: runtime.state_revision,
            runtime_handle_digest: "00".repeat(32),
        };
        assert!(matches!(
            engine.validate_control_authority(&control, &target, &runtime),
            Err(HelperError::Denied(reason)) if reason == "controller_epoch_mismatch"
        ));
    }

    #[test]
    fn request_fd_manifest_is_exact() {
        let (engine, _backend, _plan, _issuer, _) = setup();
        let peer = PeerCredentials {
            pid: std::process::id(),
            uid: engine.config.policy.uid,
            gid: unsafe { libc::getegid() },
        };
        let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
        assert!(matches!(
            engine.handle(peer, true, HelperRequest::Probe, vec![descriptor]),
            Err(HelperError::Denied(reason)) if reason == "unexpected_fd_manifest"
        ));
    }

    #[test]
    fn restarted_disabled_policy_returns_specific_denial() {
        let (mut engine, _backend, plan, issuer, _) = setup();
        let prepare = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_disabled_policy",
        );
        engine.config.policy.enabled = false;
        assert!(matches!(
            engine.validate_ticket(&prepare, PrivilegedOperation::Prepare, Some(&plan)),
            Err(HelperError::Denied(reason)) if reason == "privileged_helper_disabled"
        ));
    }

    #[test]
    fn live_root_policy_change_fences_old_engine_before_more_work() {
        let (mut engine, _backend, _plan, issuer, _) = setup();
        let policy_path = engine.config.state_dir.join("root-policy.json");
        fs::write(
            &policy_path,
            serde_jcs::to_vec(&engine.config.policy).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            engine.config.state_dir.join("policy-change.json"),
            serde_jcs::to_vec(&engine.config.policy_change).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            engine.config.state_dir.join("policy-change.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        engine.config.policy_path = Some(policy_path.clone());
        engine.config.policy_owner_uid = unsafe { libc::geteuid() };
        let peer = PeerCredentials {
            pid: std::process::id(),
            uid: engine.config.policy.uid,
            gid: unsafe { libc::getegid() },
        };
        assert!(matches!(
            engine.handle(peer, true, HelperRequest::Probe, vec![]),
            Ok(HelperResponse::Capability(_))
        ));
        let HelperResponse::Challenge(challenge) = engine
            .handle(
                peer,
                false,
                HelperRequest::Hello {
                    protocol_versions: vec![PROTOCOL.into()],
                    device_id: engine.config.policy.device_id.clone(),
                    node_boot_id: "boot-policy-fence".into(),
                    nonce: "nonce-policy-fence".into(),
                },
                vec![],
            )
            .unwrap()
        else {
            panic!("challenge")
        };

        let mut narrowed = engine.config.policy.clone();
        narrowed.enabled = false;
        narrowed.revision += 1;
        let narrowed_digest = narrowed.digest().unwrap();
        fs::write(&policy_path, serde_jcs::to_vec(&narrowed).unwrap()).unwrap();
        let narrowed_evidence = PolicyChangeEvidence {
            revision: narrowed.revision,
            policy_digest: narrowed_digest,
            previous_policy_digest: Some(engine.config.policy_digest.clone()),
            change_class: "disable".into(),
            changed_at: "2026-01-02T00:00:00Z".into(),
        };
        fs::write(
            engine.config.state_dir.join("policy-change.json"),
            serde_jcs::to_vec(&narrowed_evidence).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            engine.handle(peer, true, HelperRequest::Probe, vec![]),
            Err(HelperError::Denied(reason))
                if reason == "privileged_helper_policy_mismatch"
        ));
        assert!(matches!(
            engine.prove(peer, &challenge, "invalid", &issuer.verifying_key()),
            Err(HelperError::Denied(reason))
                if reason == "privileged_helper_policy_mismatch"
        ));
    }

    #[test]
    fn authority_mutation_lock_excludes_request_admission() {
        let directory = tempdir().unwrap().keep();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let exclusive = AuthorityLock::exclusive(&directory, uid).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let child_directory = directory.clone();
        let thread = std::thread::spawn(move || {
            let _shared = AuthorityLock::shared(&child_directory, uid).unwrap();
            sender.send(()).unwrap();
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(exclusive);
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn host_probe_measures_stream_custody_and_leaves_no_probe_file() {
        let directory = tempdir().unwrap();
        let before = fs::read_dir(directory.path()).unwrap().count();
        let observed = probe_host_capabilities(directory.path());
        assert!(observed.stream_replay);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), before);

        let missing = directory.path().join("missing-state-directory");
        let unavailable = probe_host_capabilities(&missing);
        assert!(!unavailable.stream_replay);
    }

    #[test]
    fn startup_reconcile_observes_root_custody_before_admission() {
        let (engine, backend, plan, issuer, _) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_startup_reconcile_prepare",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        engine
            .start(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Start,
                    "ptkt_startup_reconcile_start",
                ),
                plan.digest().unwrap(),
            )
            .unwrap();
        let inspections_before = backend.inspection_count();
        let receipts = engine.reconcile_before_admission().unwrap();
        assert!(backend.inspection_count() > inspections_before);
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            1
        );
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 1);
        assert_eq!(receipts.last().unwrap().claims.transition, "running");
    }

    #[test]
    fn startup_reconcile_rejects_reused_unit_identity_without_restart() {
        let (engine, backend, plan, issuer, _) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_startup_identity_prepare",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        engine
            .start(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Start,
                    "ptkt_startup_identity_start",
                ),
                plan.digest().unwrap(),
            )
            .unwrap();
        backend.replace_unit_identity(&plan.systemd_unit);
        let receipts = engine.reconcile_before_admission().unwrap();
        assert_eq!(
            receipts.last().unwrap().claims.transition,
            "recovery_required"
        );
        assert_eq!(
            engine
                .journal
                .runtime(&plan.runtime_id)
                .unwrap()
                .unwrap()
                .state,
            "recovery_required"
        );
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            1
        );
    }

    #[test]
    fn startup_reconcile_pages_through_all_unresolved_custody() {
        let (engine, backend, plan, issuer, _) = setup();
        for index in 0..257 {
            let mut candidate = plan.clone();
            candidate.runtime_id = format!("rt_page{index:04}x");
            candidate.run_id = format!("run_page{index:04}x");
            candidate.operation_id = format!("op_page{index:04}x");
            candidate.systemd_unit = format!("conduit-elevated-{}.service", candidate.runtime_id);
            engine
                .prepare(
                    ticket(
                        &engine,
                        &issuer,
                        &candidate,
                        PrivilegedOperation::Prepare,
                        &format!("ptkt_page{index:04}x"),
                    ),
                    candidate,
                    vec![],
                )
                .unwrap();
        }
        let receipts = engine.reconcile_before_admission().unwrap();
        assert_eq!(backend.inspection_count(), 257);
        assert_eq!(receipts.len(), 514);
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 257);
        assert_eq!(
            engine
                .journal
                .runtime("rt_page0256x")
                .unwrap()
                .unwrap()
                .state,
            "recovery_required"
        );
    }

    #[test]
    fn local_root_stop_can_close_prepared_custody_without_a_unit() {
        let (engine, backend, plan, issuer, receipt_key) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_admin_cancel_prepared",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 1);
        assert!(
            backend
                .inspect_optional(&plan.systemd_unit)
                .unwrap()
                .is_none()
        );
        let receipt = engine.cancel_unstarted_for_admin(&plan.runtime_id).unwrap();
        assert_eq!(receipt.claims.transition, "cancelled");
        receipt.verify(receipt_key.as_bytes()).unwrap();
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 0);
    }

    #[test]
    fn local_root_stop_fails_closed_when_started_unit_was_collected() {
        let (engine, backend, plan, issuer, receipt_key) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_admin_missing_prepare",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        engine
            .start(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Start,
                    "ptkt_admin_missing_start",
                ),
                plan.digest().unwrap(),
            )
            .unwrap();
        backend.forget_unit(&plan.systemd_unit);
        let recovery = engine.reconcile_before_admission().unwrap();
        assert_eq!(
            recovery.last().unwrap().claims.transition,
            "recovery_required"
        );
        let receipt = engine
            .fail_missing_runtime_for_admin(&plan.runtime_id)
            .unwrap();
        assert_eq!(receipt.claims.transition, "failed");
        assert_eq!(receipt.claims.exit_code, None);
        receipt.verify(receipt_key.as_bytes()).unwrap();
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 0);
    }

    #[test]
    fn terminal_watcher_converges_missing_running_unit_once() {
        let (engine, backend, plan, issuer, receipt_key) = setup();
        engine
            .prepare(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Prepare,
                    "ptkt_prepare_missing_unit",
                ),
                plan.clone(),
                vec![],
            )
            .unwrap();
        engine
            .start(
                ticket(
                    &engine,
                    &issuer,
                    &plan,
                    PrivilegedOperation::Start,
                    "ptkt_start_missing_unit",
                ),
                plan.digest().unwrap(),
            )
            .unwrap();
        backend.forget_unit(&plan.systemd_unit);
        let receipts = engine.converge_terminal().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].claims.transition, "recovery_required");
        assert_eq!(receipts[0].claims.state_revision, 5);
        receipts[0].verify(receipt_key.as_bytes()).unwrap();
        assert!(engine.converge_terminal().unwrap().is_empty());
        assert_eq!(engine.journal.active_runtime_count().unwrap(), 1);
        assert_eq!(engine.journal.purge_terminal().unwrap(), 0);
        let HelperResponse::Receipts(replayed) =
            engine.reconcile(vec![plan.runtime_id.clone()]).unwrap()
        else {
            panic!("terminal reconcile receipts")
        };
        assert_eq!(replayed, receipts);
    }

    #[test]
    fn authenticated_registration_bundle_is_public_exact_and_replay_stable() {
        let (engine, _backend, _plan, _issuer, receipt_key) = setup();
        assert!(matches!(
            engine.handle_managed(false, crate::ManagedIoRequest::PolicyAttest, 0),
            Err(HelperError::Authentication(_))
        ));
        let crate::ManagedIoResponse::RegistrationBundle(first) = engine
            .handle_managed(true, crate::ManagedIoRequest::PolicyAttest, 0)
            .unwrap()
        else {
            panic!("registration bundle response")
        };
        let crate::ManagedIoResponse::RegistrationBundle(replay) = engine
            .handle_managed(true, crate::ManagedIoRequest::PolicyAttest, 0)
            .unwrap()
        else {
            panic!("registration bundle replay")
        };
        assert_eq!(first, replay);
        assert_eq!(first.receipt_public_jwk.kid, first.signed_capability.key_id);
        assert_eq!(first.device_key_id, engine.config.device_key_id);
        assert_eq!(first.policy_revision, engine.config.policy.revision);
        assert_eq!(first.policy_digest, engine.config.policy_digest);
        first
            .signed_capability
            .verify(receipt_key.as_bytes())
            .unwrap();
        first
            .signed_policy_attestation
            .verify(receipt_key.as_bytes())
            .unwrap();
        let value = serde_json::to_value(&first).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "deviceId",
                "deviceKeyId",
                "installationId",
                "origin",
                "policyDigest",
                "policyRevision",
                "protocol",
                "receiptPublicJwk",
                "signedCapability",
                "signedPolicyAttestation",
                "uid",
            ]
        );
        let jwk = value["receiptPublicJwk"].as_object().unwrap();
        assert_eq!(jwk.len(), 4);
        assert!(
            jwk.contains_key("kty")
                && jwk.contains_key("crv")
                && jwk.contains_key("x")
                && jwk.contains_key("kid")
        );
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("receipt.key"));
        assert!(!serialized.contains("/var/") && !serialized.contains("/etc/"));
    }

    #[test]
    fn crash_after_each_durable_boundary_replays_without_duplicate_effect() {
        let (engine, backend, plan, issuer, _) = setup();
        let prepare_ticket = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Prepare,
            "ptkt_prepare_boundary_crash",
        );
        let prepare_request = request_digest(&HelperRequest::Prepare {
            ticket: Box::new(prepare_ticket.clone()),
            plan: Box::new(plan.clone()),
        })
        .unwrap();
        let prepare_ticket_digest = prepare_ticket.digest().unwrap();
        let plan_digest = plan.digest().unwrap();
        assert!(matches!(
            engine
                .journal
                .admit_prepare(
                    &prepare_ticket,
                    &prepare_ticket_digest,
                    &prepare_request,
                    &plan_digest,
                    &plan,
                )
                .unwrap(),
            EffectDisposition::Reserved(_)
        ));
        let admitted = engine
            .receipt(&prepare_ticket, &prepare_request, "admitted", None, 1)
            .unwrap();
        engine
            .journal
            .record_effect_boundary(
                &prepare_ticket.claims.ticket_id,
                &admitted,
                "admitted",
                None,
                None,
                false,
            )
            .unwrap();
        let HelperResponse::Receipts(prepared) = engine
            .prepare(prepare_ticket.clone(), plan.clone(), vec![])
            .unwrap()
        else {
            panic!("prepare chain")
        };
        assert_eq!(prepared[0], admitted);
        assert_eq!(prepared[1].claims.transition, "prepared");

        let start_ticket = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Start,
            "ptkt_start_boundary_crash",
        );
        let start_request = request_digest(&HelperRequest::Start {
            ticket: Box::new(start_ticket.clone()),
            plan_digest: plan_digest.clone(),
        })
        .unwrap();
        assert!(matches!(
            engine
                .journal
                .reserve_effect(
                    &start_ticket,
                    &start_ticket.digest().unwrap(),
                    &start_request,
                    "start",
                    &plan.runtime_id,
                )
                .unwrap(),
            EffectDisposition::Reserved(_)
        ));
        let runtime_dir = engine
            .config
            .state_dir
            .join("runtimes")
            .join(&plan.runtime_id);
        let observation = backend
            .start_transient(&UnitSpec {
                unit_name: plan.systemd_unit.clone(),
                worker_path: engine.config.worker_path.to_string_lossy().into(),
                execution_record_path: runtime_dir
                    .join("execution-record.json")
                    .to_string_lossy()
                    .into(),
                receipt_public_key_path: engine
                    .config
                    .state_dir
                    .join("receipt.public")
                    .to_string_lossy()
                    .into(),
                stdout_path: runtime_dir.join("stdout.spool").to_string_lossy().into(),
                stderr_path: runtime_dir.join("stderr.spool").to_string_lossy().into(),
                resources: plan.resources.clone(),
            })
            .unwrap();
        let unit_created = engine
            .receipt(
                &start_ticket,
                &start_request,
                "unit_created",
                Some(&observation),
                3,
            )
            .unwrap();
        engine
            .journal
            .record_effect_boundary(
                &start_ticket.claims.ticket_id,
                &unit_created,
                "starting",
                observation.invocation_id.as_deref(),
                observation.main_pid,
                false,
            )
            .unwrap();
        let HelperResponse::Receipts(started) = engine
            .start(start_ticket.clone(), plan_digest.clone())
            .unwrap()
        else {
            panic!("start chain")
        };
        assert_eq!(started[0], unit_created);
        assert_eq!(started[1].claims.transition, "running");
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            1
        );
        assert_eq!(
            engine.start(start_ticket, plan_digest).unwrap(),
            HelperResponse::Receipts(started)
        );
    }
}
