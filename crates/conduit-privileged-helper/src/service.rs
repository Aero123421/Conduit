use crate::{
    EffectDisposition, HelperError, HelperJournal, PeerCredentials, Result, SystemdManager,
    UnitObservation, UnitSpec, journal::validate_regular, worker::write_execution_record,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_protocol::{
    CapabilityClaims, ChallengeClaims, ControlTarget, HelperReceipt, HelperRequest, HelperResponse,
    LocalExecutionPlan, PROTOCOL, PrivilegeTicket, PrivilegedOperation, ReceiptClaims, RootPolicy,
    SignedClaims,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::OwnedFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::Mutex,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
pub struct PinnedTicketKeys(pub BTreeMap<String, [u8; 32]>);

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
    pub receipt_key_id: String,
    pub helper_version: String,
    pub state_dir: PathBuf,
    pub worker_path: PathBuf,
}

impl HelperConfig {
    pub fn load_policy_root_owned(
        path: &Path,
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
        let policy: RootPolicy = serde_json::from_slice(&fs::read(path)?)?;
        let digest = policy.digest()?;
        Ok(Self {
            policy,
            policy_digest: digest,
            receipt_key_id,
            helper_version: env!("CARGO_PKG_VERSION").into(),
            state_dir,
            worker_path,
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
        let ids = self
            .journal
            .nonterminal_runtimes()?
            .into_iter()
            .map(|v| v.runtime_id)
            .collect();
        match self.reconcile(ids)? {
            HelperResponse::Receipts(receipts) => Ok(receipts),
            _ => unreachable!(),
        }
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
        let ticket = runtime.authority_ticket.clone();
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(request)?));
        let receipt = self.receipt(
            &ticket,
            &digest,
            receipt_transition(
                observation
                    .as_ref()
                    .map(|v| v.active_state.as_str())
                    .unwrap_or("missing"),
            ),
            observation.as_ref(),
            runtime.state_revision,
            None,
        )?;
        Ok(crate::ManagedIoResponse::StreamChunk {
            data,
            next_cursor,
            eof: next_cursor >= length,
            terminal,
            receipt,
        })
    }
    pub fn handle(
        &self,
        peer: PeerCredentials,
        authenticated: bool,
        request: HelperRequest,
        descriptors: Vec<OwnedFd>,
    ) -> Result<HelperResponse> {
        if peer.uid != self.config.policy.uid {
            return Err(HelperError::Authentication("peer uid mismatch".into()));
        }
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
            HelperRequest::Prepare { ticket, plan } => self.prepare(ticket, plan, descriptors),
            HelperRequest::Start {
                ticket,
                plan_digest,
            } => self.start(ticket, plan_digest),
            HelperRequest::Inspect { target } => self.inspect(target),
            HelperRequest::Input {
                ticket,
                target,
                descriptor_index,
            } => self.input(ticket, target, descriptor_index, descriptors),
            HelperRequest::ResizePty {
                ticket,
                target,
                rows,
                columns,
            } => self.resize(ticket, target, rows, columns),
            HelperRequest::Control {
                ticket,
                target,
                operation,
            } => self.control(ticket, target, operation),
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
        let systemd = self.systemd.available().unwrap_or(false);
        let claims = CapabilityClaims {
            protocol: PROTOCOL.into(),
            helper_version: self.config.helper_version.clone(),
            installation_id: self.config.policy.installation_id.clone(),
            receipt_key_id: self.config.receipt_key_id.clone(),
            policy_revision: self.config.policy.revision,
            policy_digest: self.config.policy_digest.clone(),
            enabled: self.config.policy.enabled,
            observed_at: now,
            systemd_system_manager: systemd,
            socket_peer_credentials: true,
            transient_units: systemd,
            cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            freeze: systemd,
            pidfd: true,
            openat2: true,
            execveat: true,
            pty: true,
            stream_replay: true,
            never_opt_in: self.config.policy.allow_never,
            unrestricted_launch_opt_in: self.config.policy.allow_unrestricted_launch,
            unavailable_reason: if self.config.policy.enabled && systemd {
                None
            } else {
                Some("root_policy_or_systemd_unavailable".into())
            },
        };
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
        if descriptors.len() != plan.credentials.len() {
            return Err(HelperError::Denied("credential_descriptor_count".into()));
        }
        let ticket_digest = ticket.digest()?;
        let request = request_digest(&HelperRequest::Prepare {
            ticket: ticket.clone(),
            plan: plan.clone(),
        })?;
        let plan_digest = plan.digest()?;
        match self
            .journal
            .admit_prepare(&ticket, &ticket_digest, &request, &plan_digest, &plan)?
        {
            EffectDisposition::Replay(effect) => return decode_receipt(effect.receipt),
            EffectDisposition::Uncertain(_) => {
                return Err(HelperError::RecoveryRequired(
                    "prepare outcome uncertain".into(),
                ));
            }
            EffectDisposition::Reserved(_) => {}
        }
        let runtime_dir = self
            .config
            .state_dir
            .join("runtimes")
            .join(&plan.runtime_id);
        fs::create_dir_all(&runtime_dir)?;
        for workspace in &plan.workspaces {
            let identity =
                crate::capture_file_identity(Path::new(&workspace.opaque_path_id), false)?;
            if identity.sha256 != workspace.expected_identity_digest {
                return Err(HelperError::Denied("workspace_identity_changed".into()));
            }
        }
        if !plan.credentials.is_empty() {
            let credential_dir = runtime_dir.join("credentials");
            fs::create_dir_all(&credential_dir)?;
            fs::set_permissions(&credential_dir, fs::Permissions::from_mode(0o700))?;
            for credential in &plan.credentials {
                let index = credential.descriptor_index as usize;
                if index >= descriptors.len()
                    || credential.size > 1024 * 1024
                    || credential.target_name.is_empty()
                    || credential.target_name.len() > 128
                    || !credential
                        .target_name
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-' | b'.'))
                {
                    return Err(HelperError::Denied("credential_descriptor_invalid".into()));
                }
                let duplicate = descriptors[index].try_clone()?;
                let source = File::from(duplicate);
                let mut bytes = Vec::new();
                source.take(credential.size + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 != credential.size
                    || hex::encode(Sha256::digest(&bytes)) != credential.sha256
                {
                    return Err(HelperError::Denied("credential_projection_mismatch".into()));
                }
                let path = credential_dir.join(&credential.target_name);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .open(path)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                bytes.fill(0)
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
        let receipt = self.receipt(&ticket, &request, "prepared", None, 1, None)?;
        self.journal
            .complete_effect(&ticket.claims.ticket_id, &receipt, "prepared", None, None)?;
        Ok(HelperResponse::Receipt(receipt))
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
            ticket: ticket.clone(),
            plan_digest,
        })?;
        let ticket_digest = ticket.digest()?;
        match self.journal.reserve_effect(
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
            EffectDisposition::Reserved(_) => {}
        }
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
            stdout_path: runtime_dir.join("stdout.spool").to_string_lossy().into(),
            stderr_path: runtime_dir.join("stderr.spool").to_string_lossy().into(),
            resources: runtime.plan.resources.clone(),
        };
        let observation = match self.systemd.start_transient(&spec) {
            Ok(v) => v,
            Err(e) => {
                self.journal.mark_uncertain(&ticket.claims.ticket_id)?;
                return Err(e);
            }
        };
        let receipt = self.receipt(
            &ticket,
            &request,
            "started",
            Some(&observation),
            runtime.state_revision + 1,
            None,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            "running",
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        Ok(HelperResponse::Receipt(receipt))
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
            None,
        )?;
        self.journal.record_observation(
            &receipt,
            normalize_unit_state(&observation.active_state),
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        Ok(HelperResponse::Receipt(receipt))
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
            ticket: ticket.clone(),
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
            Some(request.clone()),
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
        Ok(HelperResponse::Receipt(receipt))
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
            ticket: ticket.clone(),
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
            Some(request.clone()),
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
        Ok(HelperResponse::Receipt(receipt))
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
            ticket: ticket.clone(),
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
        let observation = self
            .systemd
            .inspect(&runtime.unit_name)
            .unwrap_or(UnitObservation {
                unit_name: runtime.unit_name.clone(),
                invocation_id: runtime.invocation_id.clone(),
                main_pid: runtime.main_pid,
                active_state: "unknown".into(),
                cgroup: None,
            });
        let transition = match operation {
            PrivilegedOperation::Pause => "paused",
            PrivilegedOperation::Resume => "resumed",
            PrivilegedOperation::GracefulStop | PrivilegedOperation::ForceStop => "stopped",
            _ => "failed",
        };
        let receipt = self.receipt(
            &ticket,
            &request,
            transition,
            Some(&observation),
            runtime.state_revision + 1,
            None,
        )?;
        self.journal.complete_effect(
            &ticket.claims.ticket_id,
            &receipt,
            normalize_unit_state(&observation.active_state),
            observation.invocation_id.as_deref(),
            observation.main_pid,
        )?;
        Ok(HelperResponse::Receipt(receipt))
    }
    fn reconcile(&self, ids: Vec<String>) -> Result<HelperResponse> {
        if ids.len() > 256 {
            return Err(HelperError::Denied("reconcile_bound".into()));
        }
        let mut receipts = Vec::new();
        for id in ids {
            if let Some(runtime) = self.journal.runtime(&id)? {
                let observation = self.systemd.inspect(&runtime.unit_name).ok();
                let ticket = runtime.authority_ticket.clone();
                let transition = if observation.is_some() {
                    receipt_transition(observation.as_ref().unwrap().active_state.as_str())
                } else {
                    "recovery_required"
                };
                let state = observation
                    .as_ref()
                    .map(|v| normalize_unit_state(&v.active_state))
                    .unwrap_or("recovery_required");
                let receipt = self.receipt(
                    &ticket,
                    "reconcile",
                    transition,
                    observation.as_ref(),
                    runtime.state_revision + 1,
                    None,
                )?;
                self.journal.record_observation(
                    &receipt,
                    state,
                    observation
                        .as_ref()
                        .and_then(|v| v.invocation_id.as_deref()),
                    observation.as_ref().and_then(|v| v.main_pid),
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
            || target.runtime_handle_digest.len() != 64
            || !target
                .runtime_handle_digest
                .bytes()
                .all(|v| v.is_ascii_hexdigit())
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
        if ticket.claims.runtime_id != runtime.runtime_id
            || ticket.claims.run_id != runtime.run_id
            || ticket.claims.local_execution_plan_digest != runtime.plan_digest
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
        self.validate_runtime_ticket(ticket, runtime)?;
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
        let now = OffsetDateTime::now_utc();
        let not_before = parse_time(&c.not_before)?;
        let expires_at = parse_time(&c.expires_at)?;
        if c.protocol != PROTOCOL
            || c.audience != "conduit-privileged-helper"
            || c.installation_id != self.config.policy.installation_id
            || c.device_id != self.config.policy.device_id
            || c.uid != self.config.policy.uid
            || c.origin != self.config.policy.origin
            || c.helper_policy_revision != self.config.policy.revision
            || c.helper_policy_digest != self.config.policy_digest
            || c.helper_key_id != self.config.receipt_key_id
            || !self.config.policy.ticket_key_ids.contains(&ticket.key_id)
            || c.allowed_operation != operation
            || !self.config.policy.enabled
            || !self.config.policy.allowed_operations.contains(&operation)
            || now < not_before
            || now > expires_at
            || expires_at - not_before > time::Duration::minutes(10)
            || c.access_scope != "full_device"
            || (c.approval_mode == "never" && !self.config.policy.allow_never)
            || (matches!(
                c.approval_enforcement,
                conduit_privileged_protocol::ApprovalEnforcement::ExactCommand
            ) && c.approval_receipt_digest.is_none())
            || !within_ceilings(&c.resource_ceilings, &self.config.policy.ceilings)
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
            if let Some(adapter) = &plan.adapter_id {
                if !self.config.policy.allowed_adapters.contains(adapter) {
                    return Err(HelperError::Denied("adapter_not_allowed".into()));
                }
            } else if !self.config.policy.allow_unrestricted_launch {
                return Err(HelperError::Denied(
                    "unrestricted_launch_not_allowed".into(),
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
        control: Option<String>,
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
            request_digest: c.request_digest.clone(),
            run_id: c.run_id.clone(),
            runtime_id: c.runtime_id.clone(),
            runtime_spec_digest: c.runtime_spec_digest.clone(),
            launch_plan_digest: c.launch_plan_digest.clone(),
            local_execution_plan_digest: c.local_execution_plan_digest.clone(),
            control_request_digest: control,
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
            process_birth: None,
            effective_uid: Some(0),
            effective_gid: Some(0),
            stdout_cursor: runtime.as_ref().map_or(0, |v| v.stdout_cursor),
            stderr_cursor: runtime.as_ref().map_or(0, |v| v.stderr_cursor),
            exit_code: None,
            signal: None,
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
            (Some(_), None) | (None, _) => true,
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
        "inactive" | "dead" | "stopped" => "stopped",
        "failed" => "failed",
        "missing" => "missing",
        _ => "recovery_required",
    }
}
fn request_digest(request: &HelperRequest) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(request)?)))
}
fn decode_receipt(value: Option<Vec<u8>>) -> Result<HelperResponse> {
    let value = value.ok_or_else(|| HelperError::RecoveryRequired("receipt missing".into()))?;
    Ok(HelperResponse::Receipt(serde_json::from_slice(&value)?))
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
            allowed_operations: vec![PrivilegedOperation::Prepare, PrivilegedOperation::Start],
            allowed_adapters: vec![],
            allowed_launch_profiles: vec![],
            ceilings: resources(),
            allow_never: false,
            allow_unrestricted_launch: true,
            allow_persistent_sessions: true,
            allow_offline_control: false,
            receipt_retention_seconds: 3600,
        };
        let config = HelperConfig {
            policy_digest: policy.digest().unwrap(),
            policy,
            receipt_key_id: receipt_id,
            helper_version: "test".into(),
            state_dir: directory.clone(),
            worker_path: "/usr/lib/conduit/conduit-privileged-helper".into(),
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
            systemd_unit: "conduit-elevated-service0001.service".into(),
            adapter_id: None,
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
                protocol: PROTOCOL.into(),
                ticket_id: id.into(),
                issuer: "test".into(),
                audience: "conduit-privileged-helper".into(),
                origin: engine.config.policy.origin.clone(),
                installation_id: engine.config.policy.installation_id.clone(),
                helper_key_id: engine.config.receipt_key_id.clone(),
                helper_policy_revision: engine.config.policy.revision,
                helper_policy_digest: engine.config.policy_digest.clone(),
                device_id: engine.config.policy.device_id.clone(),
                device_key_id: "dkey_test".into(),
                device_policy_revision: 1,
                uid: engine.config.policy.uid,
                operation_id: plan.operation_id.clone(),
                idempotency_key_digest: "11".repeat(32),
                request_digest: "22".repeat(32),
                run_id: plan.run_id.clone(),
                runtime_id: plan.runtime_id.clone(),
                runtime_spec_digest: "33".repeat(32),
                launch_plan_digest: "44".repeat(32),
                local_execution_plan_digest: plan.digest().unwrap(),
                controller_epoch: 1,
                connector_policy_id: "cpol_test".into(),
                connector_policy_revision: 1,
                project_id: None,
                assignment_id: None,
                access_scope: "full_device".into(),
                approval_mode: "always".into(),
                approval_receipt_digest: Some("55".repeat(32)),
                approval_enforcement: ApprovalEnforcement::ExactCommand,
                required_risk_classes: vec![],
                allowed_operation: operation,
                resource_ceilings: resources(),
                not_before: (now - time::Duration::seconds(5)).format(&Rfc3339).unwrap(),
                expires_at: (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
                nonce: "nonce".into(),
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
        let HelperResponse::Receipt(prepared) = prepared else {
            panic!()
        };
        prepared.verify(receipt_key.as_bytes()).unwrap();
        let start = ticket(
            &engine,
            &issuer,
            &plan,
            PrivilegedOperation::Start,
            "ptkt_start0001",
        );
        let response = engine.start(start.clone(), plan.digest().unwrap()).unwrap();
        let HelperResponse::Receipt(started) = response else {
            panic!()
        };
        started.verify(receipt_key.as_bytes()).unwrap();
        let replay = engine.start(start, plan.digest().unwrap()).unwrap();
        assert_eq!(replay, HelperResponse::Receipt(started));
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
}
