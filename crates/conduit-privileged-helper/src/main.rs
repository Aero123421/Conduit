use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_helper::{
    AuthorityLock, HelperConfig, HelperEngine, HelperJournal, JOURNAL_SCHEMA_VERSION,
    PinnedTicketKeys, PolicyChangeEvidence, SeqpacketServer, SystemdBackend,
    SystemdCapabilityProbe, SystemdManager, build_registration_bundle, load_receipt_key_root_owned,
    run_exec_worker, runtime_identity_matches,
};
use conduit_privileged_protocol::{
    HelperRequest, HelperResponse, PrivilegedOperation, ResourceCeilings, RootPolicy, key_id,
};
use ed25519_dalek::VerifyingKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptKeyHistory {
    schema_version: u32,
    installation_id: String,
    current_key_id: String,
    keys: Vec<ReceiptKeyHistoryEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptKeyHistoryEntry {
    key_id: String,
    public_key: String,
    fingerprint: String,
    activated_policy_revision: u64,
    retired_policy_revision: Option<u64>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("conduit-privileged-helper: {error}");
        std::process::exit(1)
    }
}
fn run() -> conduit_privileged_helper::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--version"] {
        println!("conduit-privileged-helper {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("exec-worker") => exec_worker(&args[1..]),
        Some("admin") => admin(&args[1..]),
        _ => Err(conduit_privileged_helper::HelperError::Policy(
            "expected serve, exec-worker, or admin".into(),
        )),
    }
}
fn serve(args: &[String]) -> conduit_privileged_helper::Result<()> {
    let expected_uid: u32 = value_arg(args, "--expected-uid")
        .ok_or_else(|| {
            conduit_privileged_helper::HelperError::Policy("--expected-uid required".into())
        })?
        .parse()
        .map_err(|_| {
            conduit_privileged_helper::HelperError::Policy("invalid expected uid".into())
        })?;
    let config_base = PathBuf::from("/etc/conduit/privileged-helper.d");
    let state_default =
        PathBuf::from("/var/lib/conduit/privileged-helper").join(expected_uid.to_string());
    let policy = value_arg(args, "--policy")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_base.join(format!("{expected_uid}.json")));
    let keys = value_arg(args, "--ticket-keys")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_base.join(format!("{expected_uid}.ticket-keys.json")));
    let node_key = value_arg(args, "--node-public-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_base.join(format!("{expected_uid}.node-public.key")));
    let state = value_arg(args, "--state-dir")
        .map(PathBuf::from)
        .unwrap_or(state_default);
    let receipt = value_arg(args, "--receipt-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join("receipt.key"));
    let journal_path = value_arg(args, "--journal")
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join("helper.sqlite3"));
    let socket = path_arg(args, "--socket", "/run/conduit/privileged-helper.sock");
    let worker = path_arg(
        args,
        "--exec-worker",
        "/usr/libexec/conduit/conduit-privileged-exec",
    );
    let signing = load_receipt_key_root_owned(&receipt)?;
    let config = HelperConfig::load_policy_root_owned(
        &policy,
        &node_key,
        key_id("hkey", signing.verifying_key().as_bytes()),
        state,
        worker,
    )?;
    if config.policy.uid != expected_uid {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "systemd instance uid differs from root policy".into(),
        ));
    }
    let pinned = PinnedTicketKeys::load_root_owned(&keys)?;
    let journal = HelperJournal::open_root_owned(&journal_path)?;
    let node = load_public(&node_key)?;
    let engine = Arc::new(HelperEngine::new(
        config,
        pinned,
        signing,
        journal,
        SystemdBackend::connect_system()?,
    )?);
    // Reconcile root journal custody against systemd before accepting any new
    // authority. Receipts remain in the journal for the authenticated Node to
    // fetch; a missing/ambiguous unit is never replaced automatically.
    engine.reconcile_before_admission()?;
    let watcher = engine.clone();
    std::thread::spawn(move || {
        loop {
            let _ = watcher.converge_terminal();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
    let activated = env::var("LISTEN_PID").ok().as_deref() == Some(&std::process::id().to_string())
        && env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    let server = if activated {
        unsafe { SeqpacketServer::from_fd(3)? }
    } else {
        SeqpacketServer::bind(&socket, 0o660)?
    };
    let active_connections = Arc::new(AtomicUsize::new(0));
    loop {
        let connection = server.accept()?;
        if active_connections.fetch_add(1, Ordering::AcqRel) >= 32 {
            active_connections.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        connection.set_read_timeout(std::time::Duration::from_secs(5))?;
        let engine = engine.clone();
        let active_connections = active_connections.clone();
        std::thread::spawn(move || {
            let _ = serve_connection(connection, engine, node);
            active_connections.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn serve_connection(
    connection: conduit_privileged_helper::SeqpacketConnection,
    engine: Arc<HelperEngine<SystemdBackend>>,
    node: VerifyingKey,
) -> conduit_privileged_helper::Result<()> {
    let mut authenticated = false;
    loop {
        let packet = match connection.receive() {
            Ok(value) => value,
            Err(_) => break,
        };
        let request =
            match conduit_privileged_protocol::decode_packet::<HelperRequest>(&packet.bytes) {
                Ok(v) => v,
                Err(protocol_error) => {
                    match conduit_privileged_protocol::decode_packet::<
                        conduit_privileged_helper::ManagedIoRequest,
                    >(&packet.bytes)
                    {
                        Ok(request) => {
                            let response = engine
                                .handle_managed(authenticated, request, packet.descriptors.len())
                                .unwrap_or_else(|error| {
                                    conduit_privileged_helper::ManagedIoResponse::Error {
                                        code: error.to_string(),
                                        retryable: false,
                                    }
                                });
                            connection.send(&serde_jcs::to_vec(&response)?, &[])?;
                            continue;
                        }
                        _ => {
                            send_response(
                                &connection,
                                &HelperResponse::Error {
                                    code: protocol_error.to_string(),
                                    retryable: false,
                                },
                            )?;
                            continue;
                        }
                    }
                }
            };
        let response = match &request {
            HelperRequest::Prove {
                challenge,
                signature,
            } => engine
                .prove(connection.peer_credentials(), challenge, signature, &node)
                .inspect(|_| {
                    authenticated = true;
                }),
            _ => engine.handle(
                connection.peer_credentials(),
                authenticated,
                request,
                packet.descriptors,
            ),
        };
        match response {
            Ok(v) => send_response(&connection, &v)?,
            Err(e) => send_response(
                &connection,
                &HelperResponse::Error {
                    code: e.to_string(),
                    retryable: false,
                },
            )?,
        }
    }
    Ok(())
}
fn exec_worker(args: &[String]) -> conduit_privileged_helper::Result<()> {
    let record = required_path(args, "--record")?;
    let key = path_arg(
        args,
        "--receipt-public-key",
        "/var/lib/conduit/privileged/receipt.public",
    );
    run_exec_worker(&record, &load_public(&key)?)
}

fn admin(args: &[String]) -> conduit_privileged_helper::Result<()> {
    let command = args.first().ok_or_else(|| {
        conduit_privileged_helper::HelperError::Policy("admin command missing".into())
    })?;
    let uid_hint = value_arg(args, "--uid");
    let state = value_arg(args, "--installed-state")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            uid_hint
                .as_ref()
                .map(|uid| PathBuf::from("/var/lib/conduit/privileged-helper").join(uid))
                .unwrap_or_else(|| PathBuf::from("/var/lib/conduit/privileged-helper"))
        });
    let config_base = path_arg(args, "--config-dir", "/etc/conduit/privileged-helper.d");
    let suffix = uid_hint.clone().unwrap_or_else(|| "unknown".into());
    let policy_path = config_base.join(format!("{suffix}.json"));
    let keys_path = config_base.join(format!("{suffix}.ticket-keys.json"));
    let node_path = config_base.join(format!("{suffix}.node-public.key"));
    let journal = state.join("helper.sqlite3");
    match command.as_str() {
        "prepare" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let origin = value_arg(args, "--public-origin").ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("--public-origin required".into())
            })?;
            let device_id = value_arg(args, "--device-id").ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("--device-id required".into())
            })?;
            if !device_id.starts_with("dev_") || device_id.len() > 128 {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "invalid device id".into(),
                ));
            }
            let node_source = required_path(args, "--node-public-key-file")?;
            let node_metadata = fs::symlink_metadata(&node_source)?;
            if !node_metadata.is_file()
                || node_metadata.file_type().is_symlink()
                || node_metadata.uid() != uid
                || node_metadata.permissions().mode() & 0o022 != 0
            {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "node public key ownership or mode invalid".into(),
                ));
            }
            let node_public = fs::read(&node_source)?;
            let node_raw: [u8; 32] = node_public.try_into().map_err(|_| {
                conduit_privileged_helper::HelperError::Policy("node public key length".into())
            })?;
            VerifyingKey::from_bytes(&node_raw).map_err(|_| {
                conduit_privileged_helper::HelperError::Policy("node public key invalid".into())
            })?;
            fs::create_dir_all(&state)?;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            fs::create_dir_all(&config_base)?;
            fs::set_permissions(&config_base, fs::Permissions::from_mode(0o700))?;
            let installation_id = load_or_create_installation(&state)?;
            begin_admin_update(&state, "prepare")?;
            atomic(&node_path, &node_raw, 0o644)?;
            let secret = state.join("receipt.key");
            if !secret.exists() {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed)
                    .map_err(|e| conduit_privileged_helper::HelperError::Policy(e.to_string()))?;
                atomic(&secret, &seed, 0o600)?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                atomic(
                    &state.join("receipt.public"),
                    signing.verifying_key().as_bytes(),
                    0o644,
                )?;
            }
            let policy = RootPolicy {
                policy_version: 1,
                installation_id: installation_id.clone(),
                device_id,
                uid,
                revision: 1,
                enabled: false,
                origin,
                ticket_key_ids: vec![],
                allowed_operations: all_operations(),
                allowed_adapters: vec![],
                allowed_launch_profiles: vec![],
                launch_profile_executable_digests: BTreeMap::new(),
                allowed_credential_profiles: vec![],
                ceilings: ResourceCeilings {
                    cpu_quota_per_sec_usec: None,
                    memory_max_bytes: None,
                    tasks_max: None,
                    io_weight: None,
                    runtime_max_usec: None,
                },
                allow_never: false,
                allow_unrestricted_launch: false,
                allow_persistent_sessions: false,
                allow_offline_control: false,
                receipt_retention_seconds: 604800,
            };
            let policy_bytes = serde_jcs::to_vec(&policy)?;
            atomic(&policy_path, &policy_bytes, 0o600)?;
            record_policy_change(&state, &policy, None, "installation")?;
            ensure_receipt_key_history(&state, &policy)?;
            finish_admin_update(&state)?;
            let registration = registration_bundle(&state, &policy_path, &node_path)?;
            let bundle_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&registration)?));
            output(
                json!({"prepared":true,"enabled":false,"installationId":installation_id,"bundleDigest":bundle_digest,"deviceKeyId":key_id("dkey",&node_raw),"registrationBundle":registration}),
            );
            Ok(())
        }
        "pin-ticket-key" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let source = required_path(args, "--issuer-key-file")?;
            let expected = value_arg(args, "--expected-fingerprint")
                .ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy(
                        "--expected-fingerprint required".into(),
                    )
                })?
                .to_ascii_lowercase();
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != uid
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "issuer key ownership or mode invalid".into(),
                ));
            }
            let public = fs::read(&source)?;
            let decoded = decode_public_key(&public)?;
            let raw = decoded.raw;
            VerifyingKey::from_bytes(&raw).map_err(|_| {
                conduit_privileged_helper::HelperError::Policy("issuer public key invalid".into())
            })?;
            let fingerprint = hex::encode(Sha256::digest(raw));
            if fingerprint != expected {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "issuer_key_fingerprint_mismatch".into(),
                ));
            }
            let id = key_id("pkey", &raw);
            if decoded.key_id.as_deref().is_some_and(|value| value != id)
                || decoded.revision.is_some_and(|value| value == 0)
            {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "issuer_key_metadata_mismatch".into(),
                ));
            }
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&policy_path)?)?;
            if policy.uid != uid || policy.enabled {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "policy uid mismatch or already enabled".into(),
                ));
            }
            let previous_policy_digest = policy.digest()?;
            let changed = if !policy.ticket_key_ids.contains(&id) {
                policy.ticket_key_ids.push(id.clone());
                policy.ticket_key_ids.sort();
                policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy("revision overflow".into())
                })?;
                true
            } else {
                false
            };
            let mut keys = BTreeMap::new();
            if keys_path.exists() {
                #[derive(serde::Deserialize)]
                struct Existing {
                    keys: BTreeMap<String, String>,
                }
                keys = serde_json::from_slice::<Existing>(&fs::read(&keys_path)?)?.keys;
            }
            let encoded = URL_SAFE_NO_PAD.encode(raw);
            if let Some(previous) = keys.insert(id.clone(), encoded.clone())
                && previous != encoded
            {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "issuer_key_id_conflict".into(),
                ));
            }
            if changed {
                begin_admin_update(&state, "ticket_key_pin")?;
                atomic(
                    &keys_path,
                    &serde_jcs::to_vec(&json!({"keys":keys}))?,
                    0o600,
                )?;
                atomic(&policy_path, &serde_jcs::to_vec(&policy)?, 0o600)?;
                record_policy_change(
                    &state,
                    &policy,
                    Some(previous_policy_digest),
                    "ticket_key_pin",
                )?;
                finish_admin_update(&state)?;
            }
            output(
                json!({"pinned":true,"keyId":id,"fingerprint":fingerprint,"policyRevision":policy.revision,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "rotate-device-key" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let expected_current =
                value_arg(args, "--expected-current-key-id").ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy(
                        "--expected-current-key-id required".into(),
                    )
                })?;
            validate_root_file(&node_path, 0o644)?;
            let current: [u8; 32] = fs::read(&node_path)?.try_into().map_err(|_| {
                conduit_privileged_helper::HelperError::Policy(
                    "current node public key length".into(),
                )
            })?;
            if key_id("dkey", &current) != expected_current {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "device_key_rotation_stale".into(),
                ));
            }
            let source = required_path(args, "--node-public-key-file")?;
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != uid
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "node public key ownership or mode invalid".into(),
                ));
            }
            let replacement: [u8; 32] = fs::read(source)?.try_into().map_err(|_| {
                conduit_privileged_helper::HelperError::Policy(
                    "replacement node public key length".into(),
                )
            })?;
            VerifyingKey::from_bytes(&replacement).map_err(|_| {
                conduit_privileged_helper::HelperError::Policy(
                    "replacement node public key invalid".into(),
                )
            })?;
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&policy_path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from prepared policy".into(),
                ));
            }
            if replacement != current {
                let previous_policy_digest = policy.digest()?;
                policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy("revision overflow".into())
                })?;
                begin_admin_update(&state, "device_key_rotation")?;
                atomic(&node_path, &replacement, 0o644)?;
                atomic(&policy_path, &serde_jcs::to_vec(&policy)?, 0o600)?;
                record_policy_change(
                    &state,
                    &policy,
                    Some(previous_policy_digest),
                    "device_key_rotation",
                )?;
                finish_admin_update(&state)?;
            }
            output(json!({
                "rotated": replacement != current,
                "deviceKeyId": key_id("dkey", &replacement),
                "policyRevision": policy.revision,
                "policyDigest": policy.digest()?,
                "registrationBundle": registration_bundle(&state, &policy_path, &node_path)?,
            }));
            Ok(())
        }
        "enable" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let path = policy_path.clone();
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from prepared policy".into(),
                ));
            }
            if policy.ticket_key_ids.is_empty() {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "no ticket key pinned".into(),
                ));
            }
            let previous_policy_digest = policy.digest()?;
            policy.enabled = true;
            policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("revision overflow".into())
            })?;
            begin_admin_update(&state, "enable")?;
            atomic(&path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            record_policy_change(&state, &policy, Some(previous_policy_digest), "enable")?;
            finish_admin_update(&state)?;
            output(
                json!({"enabled":true,"policyRevision":policy.revision,"policyDigest":policy.digest()?,"installationId":policy.installation_id,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "disable" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&policy_path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from prepared policy".into(),
                ));
            }
            let stop_requested = args.iter().any(|value| value == "--stop-active");
            let active_before = active_runtime_count(&journal)?;
            let previous_policy_digest = policy.digest()?;
            let changed = disable_root_policy(&mut policy)?;
            if changed {
                begin_admin_update(&state, "disable")?;
                atomic(&policy_path, &serde_jcs::to_vec(&policy)?, 0o600)?;
                record_policy_change(&state, &policy, Some(previous_policy_digest), "disable")?;
                finish_admin_update(&state)?;
            }
            let (stop_attempted, receipt_count, active_after) = if stop_requested {
                stop_active_runtimes(&state, &policy_path, &keys_path, &node_path, &journal)?
            } else {
                (0, 0, active_before)
            };
            output(json!({
                "disabled": true,
                "changed": changed,
                "policyRevision": policy.revision,
                "policyDigest": policy.digest()?,
                "helperRestartRequired": changed,
                "activeRuntimeCountBefore": active_before,
                "activeRuntimeCountAfter": active_after,
                "continuingUnderPriorAdmission": !stop_requested && active_after != 0,
                "activeRuntimeDisposition": if stop_requested {
                    "stop_requested"
                } else if active_after != 0 {
                    "preserved_under_prior_admission"
                } else {
                    "none"
                },
                "stopEvidence": {
                    "requested": stop_requested,
                    "attempted": stop_attempted,
                    "signedReceiptCount": receipt_count,
                    "terminalCustodyProven": active_after == 0
                },
                "registrationBundle": registration_bundle(&state, &policy_path, &node_path)?,
            }));
            Ok(())
        }
        "rotate-receipt-key" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let expected_current =
                value_arg(args, "--expected-current-key-id").ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy(
                        "--expected-current-key-id required".into(),
                    )
                })?;
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&policy_path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from prepared policy".into(),
                ));
            }
            let secret_path = state.join("receipt.key");
            let public_path = state.join("receipt.public");
            let current_signing = load_receipt_key_root_owned(&secret_path)?;
            validate_root_file(&public_path, 0o644)?;
            let current_public: [u8; 32] = fs::read(&public_path)?.try_into().map_err(|_| {
                conduit_privileged_helper::HelperError::Policy("receipt public key length".into())
            })?;
            if current_signing.verifying_key().as_bytes() != &current_public {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "receipt key pair mismatch".into(),
                ));
            }
            let current_key_id = key_id("hkey", &current_public);
            if current_key_id != expected_current {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "receipt_key_rotation_stale".into(),
                ));
            }
            require_receipt_key_rotation_idle(|| active_runtime_count(&journal))?;
            let history = load_receipt_key_history(&state, &policy, current_public)?;
            let previous_policy_digest = policy.digest()?;
            policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("revision overflow".into())
            })?;
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|error| {
                conduit_privileged_helper::HelperError::Policy(error.to_string())
            })?;
            let replacement = ed25519_dalek::SigningKey::from_bytes(&seed);
            let replacement_public = *replacement.verifying_key().as_bytes();
            let replacement_key_id = key_id("hkey", &replacement_public);
            let history = rotated_receipt_key_history(
                history,
                &current_key_id,
                replacement_public,
                policy.revision,
            )?;
            validate_receipt_key_history(&history, &policy, replacement_public)?;
            begin_admin_update(&state, "receipt_key_rotation")?;
            atomic(&secret_path, seed.as_ref(), 0o600)?;
            atomic(&public_path, &replacement_public, 0o644)?;
            atomic(
                &state.join("receipt-key-history.json"),
                &serde_jcs::to_vec(&history)?,
                0o600,
            )?;
            atomic(&policy_path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            record_policy_change(
                &state,
                &policy,
                Some(previous_policy_digest),
                "receipt_key_rotation",
            )?;
            finish_admin_update(&state)?;
            output(json!({
                "rotated": true,
                "previousReceiptKeyId": current_key_id,
                "previousReceiptPublicKeyFingerprint": hex::encode(Sha256::digest(current_public)),
                "receiptKeyId": replacement_key_id,
                "receiptPublicKeyFingerprint": hex::encode(Sha256::digest(replacement_public)),
                "policyRevision": policy.revision,
                "policyDigest": policy.digest()?,
                "keyHistoryEntries": history.keys.len(),
                "helperRestartRequired": true,
                "registrationBundle": registration_bundle(&state, &policy_path, &node_path)?,
            }));
            Ok(())
        }
        "policy" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let path = policy_path.clone();
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from policy".into(),
                ));
            }
            let previous_policy_digest = policy.digest()?;
            let previous_policy = policy.clone();
            if let Some(value) = value_arg(args, "--allow-never") {
                policy.allow_never = parse_bool(&value)?;
            }
            if let Some(value) = value_arg(args, "--allow-unrestricted-launch") {
                policy.allow_unrestricted_launch = parse_bool(&value)?;
            }
            if let Some(value) = value_arg(args, "--allow-persistent-sessions") {
                policy.allow_persistent_sessions = parse_bool(&value)?;
            }
            if let Some(value) = value_arg(args, "--allow-offline-control") {
                policy.allow_offline_control = parse_bool(&value)?;
            }
            if let Some(value) = value_arg(args, "--allowed-adapters") {
                policy.allowed_adapters = parse_csv(&value)?;
            }
            if let Some(value) = value_arg(args, "--allowed-launch-profiles") {
                policy.allowed_launch_profiles = parse_csv(&value)?;
            }
            if let Some(value) = value_arg(args, "--launch-profile-executable-digests") {
                policy.launch_profile_executable_digests = parse_digest_map(&value)?;
            }
            if let Some(value) = value_arg(args, "--allowed-credential-profiles") {
                policy.allowed_credential_profiles = parse_csv(&value)?;
            }
            policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("revision overflow".into())
            })?;
            let digest = policy.digest()?;
            let change = classify_policy_change(&previous_policy, &policy);
            begin_admin_update(&state, "local_policy_update")?;
            atomic(&path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            record_policy_change(
                &state,
                &policy,
                Some(previous_policy_digest),
                "local_policy_update",
            )?;
            finish_admin_update(&state)?;
            output(
                json!({"updated":true,"policyRevision":policy.revision,"policyDigest":digest,"changeDirection":change,"helperRestartRequired":true,"allowNever":policy.allow_never,"allowUnrestrictedLaunch":policy.allow_unrestricted_launch,"allowedAdapters":policy.allowed_adapters,"allowedLaunchProfiles":policy.allowed_launch_profiles,"launchProfileExecutableDigests":policy.launch_profile_executable_digests,"allowedCredentialProfiles":policy.allowed_credential_profiles,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "registration-bundle" => {
            require_root()?;
            let _authority = AuthorityLock::shared(&state, 0)?;
            output(registration_bundle(&state, &policy_path, &node_path)?);
            Ok(())
        }
        "status" => {
            require_root()?;
            let _authority = state
                .is_dir()
                .then(|| AuthorityLock::shared(&state, 0))
                .transpose()?;
            output(admin_status(
                &state,
                &policy_path,
                &keys_path,
                &node_path,
                &journal,
                false,
            )?);
            Ok(())
        }
        "doctor" => {
            require_root()?;
            let _authority = state
                .is_dir()
                .then(|| AuthorityLock::shared(&state, 0))
                .transpose()?;
            output(admin_status(
                &state,
                &policy_path,
                &keys_path,
                &node_path,
                &journal,
                true,
            )?);
            Ok(())
        }
        "package-status" => {
            require_root()?;
            let installation_id = fs::read_to_string(state.join("installation-id"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let count = if journal.exists() {
                HelperJournal::open_owned(&journal, unsafe { libc::geteuid() })?
                    .active_runtime_count()?
            } else {
                0
            };
            output(
                json!({"activeRuntimeCount":count,"protocolVersion":conduit_privileged_protocol::PROTOCOL,"journalSchemaVersion":JOURNAL_SCHEMA_VERSION,"installationId":installation_id}),
            );
            Ok(())
        }
        "package-check" => {
            require_root()?;
            let executable = required_path(args, "--exec")?;
            let metadata = fs::metadata(&executable);
            let valid = executable.is_absolute()
                && state.is_absolute()
                && metadata
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0 && m.uid() == 0)
                    .unwrap_or(false);
            output(json!({"ok":valid,"installedState":state,"executable":executable}));
            if valid {
                Ok(())
            } else {
                Err(conduit_privileged_helper::HelperError::Policy(
                    "package check failed".into(),
                ))
            }
        }
        "stop-active" => {
            require_root()?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let active_before = active_runtime_count(&journal)?;
            let (stopped, receipts, active_after) =
                stop_active_runtimes(&state, &policy_path, &keys_path, &node_path, &journal)?;
            output(json!({
                "stopped": stopped,
                "receipts": receipts,
                "activeRuntimeCountBefore": active_before,
                "activeRuntimeCountAfter": active_after,
                "terminalCustodyProven": active_after == 0
            }));
            Ok(())
        }
        "purge" => {
            require_root()?;
            let _authority = AuthorityLock::exclusive(&state, 0)?;
            let helper = HelperJournal::open_root_owned(&journal)?;
            if helper.active_runtime_count()? != 0 {
                return Err(conduit_privileged_helper::HelperError::Denied(
                    "active_runtimes_present".into(),
                ));
            }
            let purged = helper.purge_terminal()?;
            drop(helper);
            validate_managed_state(&state)?;
            fs::remove_dir_all(&state)?;
            for path in [&policy_path, &keys_path, &node_path] {
                if path.exists() {
                    fs::remove_file(path)?
                }
            }
            fs::File::open(&config_base)?.sync_all()?;
            output(json!({"purged":purged,"stateRemoved":true}));
            Ok(())
        }
        _ => Err(conduit_privileged_helper::HelperError::Policy(
            "unknown admin command".into(),
        )),
    }
}

fn admin_status(
    state: &Path,
    policy_path: &Path,
    keys_path: &Path,
    node_path: &Path,
    journal_path: &Path,
    doctor: bool,
) -> conduit_privileged_helper::Result<serde_json::Value> {
    let executable = env::current_exe()?;
    let executable_custody = root_owned_regular(&executable, 0o022);
    let policy_custody = root_owned_regular(policy_path, 0o077);
    let key_custody = root_owned_regular(keys_path, 0o077);
    let node_key_custody = root_owned_regular(node_path, 0o022);
    let state_custody = root_owned_directory(state, 0o077);
    let prepared = policy_custody
        && node_key_custody
        && state.join("installation-id").is_file()
        && state.join("receipt.public").is_file();
    if !prepared {
        return Ok(json!({
            "schemaVersion": 1,
            "installed": executable_custody,
            "prepared": false,
            "enabled": false,
            "effective": false,
            "reasonCode": "privileged_helper_registration_missing",
            "remediationCode": "run_privileged_prepare_as_root",
            "custody": {
                "helperBinary": executable_custody,
                "stateDirectory": state_custody,
                "rootPolicy": policy_custody,
                "ticketKeys": key_custody,
                "nodePublicKey": node_key_custody
            },
            "diagnosticLevel": if doctor { "doctor" } else { "status" }
        }));
    }

    let policy: RootPolicy = serde_json::from_slice(&fs::read(policy_path)?)?;
    let policy_digest = policy.digest()?;
    let receipt_public = fs::read(state.join("receipt.public"))?;
    let receipt_public: [u8; 32] = receipt_public.try_into().map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("receipt public key length".into())
    })?;
    VerifyingKey::from_bytes(&receipt_public).map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("receipt public key invalid".into())
    })?;
    let receipt_key_id = key_id("hkey", &receipt_public);
    let receipt_fingerprint = hex::encode(Sha256::digest(receipt_public));
    let receipt_key_history = load_receipt_key_history(state, &policy, receipt_public)?;
    let active_runtime_count = if journal_path.exists() {
        HelperJournal::open_root_owned(journal_path)?.active_runtime_count()?
    } else {
        0
    };
    let systemd_reachable = SystemdBackend::connect_system()
        .and_then(|backend| backend.available())
        .unwrap_or(false);
    let capability = registration_bundle(state, policy_path, node_path)?
        .pointer("/signedCapability/claims")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let effective = policy.enabled
        && policy_custody
        && key_custody
        && node_key_custody
        && state_custody
        && executable_custody
        && systemd_reachable;
    let reason_code = if !policy.enabled {
        "privileged_helper_disabled"
    } else if !key_custody || policy.ticket_key_ids.is_empty() {
        "privileged_helper_registration_missing"
    } else if !systemd_reachable {
        "privileged_helper_unavailable"
    } else if !effective {
        "privileged_helper_policy_mismatch"
    } else {
        "ready"
    };
    let remediation_code = match reason_code {
        "privileged_helper_disabled" => "pin_ticket_key_then_enable_locally",
        "privileged_helper_registration_missing" => {
            "complete_owner_registration_and_pin_ticket_key"
        }
        "privileged_helper_unavailable" => "repair_systemd_system_manager",
        "privileged_helper_policy_mismatch" => "repair_root_owned_helper_custody",
        _ => "none",
    };
    Ok(json!({
        "schemaVersion": 1,
        "installed": executable_custody,
        "prepared": true,
        "enabled": policy.enabled,
        "effective": effective,
        "reasonCode": reason_code,
        "remediationCode": remediation_code,
        "protocolVersion": conduit_privileged_protocol::PROTOCOL,
        "helperVersion": env!("CARGO_PKG_VERSION"),
        "installationId": policy.installation_id,
        "deviceId": policy.device_id,
        "uid": policy.uid,
        "publicOrigin": policy.origin,
        "policyRevision": policy.revision,
        "policyDigest": policy_digest,
        "receiptKeyId": receipt_key_id,
        "receiptPublicKeyFingerprint": receipt_fingerprint,
        "receiptKeyHistoryEntries": receipt_key_history.keys.len(),
        "activeRuntimeCount": active_runtime_count,
        "recoveryState": if active_runtime_count == 0 { "clean" } else { "active_custody_present" },
        "controlPlaneRegistrationState": "not_observed_by_local_helper",
        "capabilities": capability,
        "custody": {
            "helperBinary": executable_custody,
            "stateDirectory": state_custody,
            "rootPolicy": policy_custody,
            "ticketKeys": key_custody,
            "nodePublicKey": node_key_custody,
            "journal": !journal_path.exists() || root_owned_regular(journal_path, 0o077)
        },
        "systemd": {
            "systemManagerReachable": systemd_reachable,
            "socketUnit": "/usr/lib/systemd/system/conduit-privileged-helper@.socket",
            "serviceUnit": "/usr/lib/systemd/system/conduit-privileged-helper@.service"
        },
        "policy": {
            "allowNever": policy.allow_never,
            "allowUnrestrictedLaunch": policy.allow_unrestricted_launch,
            "allowPersistentSessions": policy.allow_persistent_sessions,
            "allowOfflineControl": policy.allow_offline_control,
            "ticketKeyCount": policy.ticket_key_ids.len()
        },
        "diagnosticLevel": if doctor { "doctor" } else { "status" }
    }))
}

fn root_owned_regular(path: &Path, forbidden_mode: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.permissions().mode() & forbidden_mode == 0
    })
}

fn root_owned_directory(path: &Path, forbidden_mode: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.permissions().mode() & forbidden_mode == 0
    })
}

fn send_response(
    connection: &conduit_privileged_helper::SeqpacketConnection,
    response: &HelperResponse,
) -> conduit_privileged_helper::Result<()> {
    connection.send(&serde_jcs::to_vec(response)?, &[])
}
fn load_public(path: &Path) -> conduit_privileged_helper::Result<VerifyingKey> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "public key ownership or mode invalid".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| conduit_privileged_helper::HelperError::Policy("public key length".into()))?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| conduit_privileged_helper::HelperError::Policy("public key invalid".into()))
}
fn path_arg(args: &[String], name: &str, default: &str) -> PathBuf {
    value_arg(args, name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}
fn required_path(args: &[String], name: &str) -> conduit_privileged_helper::Result<PathBuf> {
    value_arg(args, name)
        .map(PathBuf::from)
        .ok_or_else(|| conduit_privileged_helper::HelperError::Policy(format!("{name} required")))
}
fn value_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|v| v[0] == name).map(|v| v[1].clone())
}
fn parse_uid(args: &[String]) -> conduit_privileged_helper::Result<u32> {
    value_arg(args, "--uid")
        .ok_or_else(|| conduit_privileged_helper::HelperError::Policy("--uid required".into()))?
        .parse()
        .map_err(|_| conduit_privileged_helper::HelperError::Policy("invalid uid".into()))
}
fn parse_bool(value: &str) -> conduit_privileged_helper::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(conduit_privileged_helper::HelperError::Policy(
            "boolean must be true or false".into(),
        )),
    }
}
fn parse_csv(value: &str) -> conduit_privileged_helper::Result<Vec<String>> {
    let mut values = value
        .split(',')
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.len() > 128
        || values.iter().any(|v| {
            v.len() > 128
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "invalid policy list".into(),
        ));
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn parse_digest_map(value: &str) -> conduit_privileged_helper::Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    if value.is_empty() {
        return Ok(result);
    }
    for item in value.split(',') {
        let (profile, digest) = item.split_once('=').ok_or_else(|| {
            conduit_privileged_helper::HelperError::Policy(
                "launch profile digest must use profile=sha256".into(),
            )
        })?;
        if profile.is_empty()
            || profile.len() > 128
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || result
                .insert(profile.to_owned(), digest.to_ascii_lowercase())
                .is_some()
        {
            return Err(conduit_privileged_helper::HelperError::Policy(
                "invalid or duplicate launch profile executable digest".into(),
            ));
        }
    }
    Ok(result)
}
struct DecodedPublicKey {
    raw: [u8; 32],
    key_id: Option<String>,
    revision: Option<u64>,
}
fn decode_public_key(bytes: &[u8]) -> conduit_privileged_helper::Result<DecodedPublicKey> {
    if bytes.len() == 32 {
        return Ok(DecodedPublicKey {
            raw: bytes.try_into().unwrap(),
            key_id: None,
            revision: None,
        });
    }
    #[derive(serde::Deserialize)]
    struct Jwk {
        kty: String,
        crv: String,
        x: String,
        kid: String,
        revision: u64,
    }
    let jwk: Jwk = serde_json::from_slice(bytes)?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "issuer JWK type".into(),
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(jwk.x)
        .map_err(|_| conduit_privileged_helper::HelperError::Policy("issuer JWK x".into()))?
        .try_into()
        .map_err(|_| {
            conduit_privileged_helper::HelperError::Policy("issuer public key length".into())
        })?;
    Ok(DecodedPublicKey {
        raw,
        key_id: Some(jwk.kid),
        revision: Some(jwk.revision),
    })
}
fn registration_bundle(
    state: &Path,
    policy_path: &Path,
    node_path: &Path,
) -> conduit_privileged_helper::Result<serde_json::Value> {
    let policy: RootPolicy = serde_json::from_slice(&fs::read(policy_path)?)?;
    let signing = load_receipt_key_root_owned(&state.join("receipt.key"))?;
    let change_path = state.join("policy-change.json");
    validate_root_file(&change_path, 0o600)?;
    let policy_change: PolicyChangeEvidence = serde_json::from_slice(&fs::read(change_path)?)?;
    let systemd = match SystemdBackend::connect_system() {
        Ok(backend) => SystemdCapabilityProbe::measure(&backend),
        Err(_) => SystemdCapabilityProbe {
            system_manager: false,
            transient_units: false,
            freeze: false,
        },
    };
    let node = fs::read(node_path)?;
    let node: [u8; 32] = node.try_into().map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("node public key length".into())
    })?;
    Ok(serde_json::to_value(build_registration_bundle(
        &policy,
        &policy_change,
        node,
        &signing,
        systemd,
        env!("CARGO_PKG_VERSION"),
        state,
    )?)?)
}
fn record_policy_change(
    state: &Path,
    policy: &RootPolicy,
    previous_policy_digest: Option<String>,
    change_class: &str,
) -> conduit_privileged_helper::Result<()> {
    let evidence = PolicyChangeEvidence {
        revision: policy.revision,
        policy_digest: policy.digest()?,
        previous_policy_digest,
        change_class: change_class.into(),
        changed_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| conduit_privileged_helper::HelperError::Policy(error.to_string()))?,
    };
    atomic(
        &state.join("policy-change.json"),
        &serde_jcs::to_vec(&evidence)?,
        0o600,
    )
}

fn active_runtime_count(journal_path: &Path) -> conduit_privileged_helper::Result<u64> {
    if journal_path.exists() {
        HelperJournal::open_root_owned(journal_path)?.active_runtime_count()
    } else {
        Ok(0)
    }
}

fn disable_root_policy(policy: &mut RootPolicy) -> conduit_privileged_helper::Result<bool> {
    if !policy.enabled {
        return Ok(false);
    }
    policy.enabled = false;
    policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
        conduit_privileged_helper::HelperError::Policy("revision overflow".into())
    })?;
    Ok(true)
}

fn require_receipt_key_rotation_idle(
    active_count: impl FnOnce() -> conduit_privileged_helper::Result<u64>,
) -> conduit_privileged_helper::Result<()> {
    if active_count()? != 0 {
        return Err(conduit_privileged_helper::HelperError::Denied(
            "active_runtimes_present".into(),
        ));
    }
    Ok(())
}

fn stop_active_runtimes(
    state: &Path,
    policy_path: &Path,
    keys_path: &Path,
    node_path: &Path,
    journal_path: &Path,
) -> conduit_privileged_helper::Result<(u64, usize, u64)> {
    let helper = HelperJournal::open_root_owned(journal_path)?;
    let backend = SystemdBackend::connect_system()?;
    let mut runtimes = Vec::new();
    let mut after_runtime_id = None;
    loop {
        let page = helper.nonterminal_runtimes_after(after_runtime_id.as_deref())?;
        if page.is_empty() {
            break;
        }
        after_runtime_id = page.last().map(|runtime| runtime.runtime_id.clone());
        runtimes.extend(page);
    }
    let expected_terminal_revisions = runtimes
        .iter()
        .map(|runtime| (runtime.runtime_id.clone(), runtime.state_revision + 1))
        .collect::<BTreeMap<_, _>>();
    let mut units_to_stop = Vec::new();
    for runtime in &runtimes {
        let observation = backend.inspect(&runtime.unit_name).map_err(|_| {
            conduit_privileged_helper::HelperError::RecoveryRequired(
                "active_runtime_identity_missing".into(),
            )
        })?;
        if !runtime_identity_matches(runtime, &observation) {
            return Err(conduit_privileged_helper::HelperError::RecoveryRequired(
                "active_runtime_identity_mismatch".into(),
            ));
        }
        if !matches!(
            observation.active_state.as_str(),
            "inactive" | "failed" | "dead"
        ) {
            units_to_stop.push(runtime.unit_name.clone());
        }
    }
    for unit in &units_to_stop {
        backend.graceful_stop(unit)?;
    }
    for unit in &units_to_stop {
        for _ in 0..100 {
            match backend.inspect(unit) {
                Ok(observation)
                    if matches!(
                        observation.active_state.as_str(),
                        "inactive" | "failed" | "dead"
                    ) =>
                {
                    break;
                }
                Err(_) => break,
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }
    let signing = load_receipt_key_root_owned(&state.join("receipt.key"))?;
    let config = HelperConfig::load_policy_root_owned(
        policy_path,
        node_path,
        key_id("hkey", signing.verifying_key().as_bytes()),
        state.to_path_buf(),
        env::current_exe()?,
    )?;
    let engine = HelperEngine::new(
        config,
        PinnedTicketKeys::load_root_owned(keys_path)?,
        signing,
        helper,
        SystemdBackend::connect_system()?,
    )?;
    let receipts = engine.recover_nonterminal()?;
    let terminal_receipts = receipts
        .iter()
        .filter(|receipt| {
            expected_terminal_revisions.get(&receipt.claims.runtime_id)
                == Some(&receipt.claims.state_revision)
                && matches!(receipt.claims.transition.as_str(), "cancelled" | "failed")
        })
        .count();
    let active_after = active_runtime_count(journal_path)?;
    if active_after != 0 {
        return Err(conduit_privileged_helper::HelperError::RecoveryRequired(
            "active_runtime_stop_not_terminal".into(),
        ));
    }
    Ok((units_to_stop.len() as u64, terminal_receipts, active_after))
}

fn receipt_key_entry(public: [u8; 32], activated_policy_revision: u64) -> ReceiptKeyHistoryEntry {
    ReceiptKeyHistoryEntry {
        key_id: key_id("hkey", &public),
        public_key: URL_SAFE_NO_PAD.encode(public),
        fingerprint: hex::encode(Sha256::digest(public)),
        activated_policy_revision,
        retired_policy_revision: None,
    }
}

fn load_receipt_key_history(
    state: &Path,
    policy: &RootPolicy,
    current_public: [u8; 32],
) -> conduit_privileged_helper::Result<ReceiptKeyHistory> {
    let path = state.join("receipt-key-history.json");
    let history = if path.exists() {
        validate_root_file(&path, 0o600)?;
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        ReceiptKeyHistory {
            schema_version: 1,
            installation_id: policy.installation_id.clone(),
            current_key_id: key_id("hkey", &current_public),
            keys: vec![receipt_key_entry(current_public, policy.revision)],
        }
    };
    validate_receipt_key_history(&history, policy, current_public)?;
    Ok(history)
}

fn ensure_receipt_key_history(
    state: &Path,
    policy: &RootPolicy,
) -> conduit_privileged_helper::Result<()> {
    let public: [u8; 32] = fs::read(state.join("receipt.public"))?
        .try_into()
        .map_err(|_| {
            conduit_privileged_helper::HelperError::Policy("receipt public key length".into())
        })?;
    let history = load_receipt_key_history(state, policy, public)?;
    atomic(
        &state.join("receipt-key-history.json"),
        &serde_jcs::to_vec(&history)?,
        0o600,
    )
}

fn validate_receipt_key_history(
    history: &ReceiptKeyHistory,
    policy: &RootPolicy,
    current_public: [u8; 32],
) -> conduit_privileged_helper::Result<()> {
    let current_key_id = key_id("hkey", &current_public);
    if history.schema_version != 1
        || history.installation_id != policy.installation_id
        || history.current_key_id != current_key_id
        || history.keys.is_empty()
        || history.keys.len() > 32
        || history
            .keys
            .iter()
            .filter(|entry| entry.retired_policy_revision.is_none())
            .count()
            != 1
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "receipt key history mismatch".into(),
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for entry in &history.keys {
        let public: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&entry.public_key)
            .map_err(|_| {
                conduit_privileged_helper::HelperError::Policy(
                    "receipt key history public key encoding".into(),
                )
            })?
            .try_into()
            .map_err(|_| {
                conduit_privileged_helper::HelperError::Policy(
                    "receipt key history public key length".into(),
                )
            })?;
        if !ids.insert(entry.key_id.clone())
            || entry.key_id != key_id("hkey", &public)
            || entry.fingerprint != hex::encode(Sha256::digest(public))
            || entry.activated_policy_revision == 0
            || entry.activated_policy_revision > policy.revision
            || entry.retired_policy_revision.is_some_and(|revision| {
                revision < entry.activated_policy_revision || revision > policy.revision
            })
        {
            return Err(conduit_privileged_helper::HelperError::Policy(
                "receipt key history entry invalid".into(),
            ));
        }
    }
    let current = history
        .keys
        .iter()
        .find(|entry| entry.key_id == current_key_id)
        .ok_or_else(|| {
            conduit_privileged_helper::HelperError::Policy(
                "receipt key history missing current key".into(),
            )
        })?;
    if current.public_key != URL_SAFE_NO_PAD.encode(current_public)
        || current.fingerprint != hex::encode(Sha256::digest(current_public))
        || current.retired_policy_revision.is_some()
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "receipt key history current key mismatch".into(),
        ));
    }
    Ok(())
}

fn rotated_receipt_key_history(
    mut history: ReceiptKeyHistory,
    expected_current_key_id: &str,
    replacement_public: [u8; 32],
    policy_revision: u64,
) -> conduit_privileged_helper::Result<ReceiptKeyHistory> {
    if history.current_key_id != expected_current_key_id {
        return Err(conduit_privileged_helper::HelperError::Denied(
            "receipt_key_rotation_stale".into(),
        ));
    }
    if history.keys.len() >= 32 {
        return Err(conduit_privileged_helper::HelperError::Denied(
            "receipt_key_history_full".into(),
        ));
    }
    let current = history
        .keys
        .iter_mut()
        .find(|entry| entry.key_id == expected_current_key_id)
        .ok_or_else(|| {
            conduit_privileged_helper::HelperError::Policy(
                "receipt key history missing current key".into(),
            )
        })?;
    if current.retired_policy_revision.is_some() {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "receipt key history current key already retired".into(),
        ));
    }
    current.retired_policy_revision = Some(policy_revision);
    let replacement = receipt_key_entry(replacement_public, policy_revision);
    if history
        .keys
        .iter()
        .any(|entry| entry.key_id == replacement.key_id)
    {
        return Err(conduit_privileged_helper::HelperError::Denied(
            "receipt_key_rotation_conflict".into(),
        ));
    }
    history.current_key_id = replacement.key_id.clone();
    history.keys.push(replacement);
    Ok(history)
}

fn classify_policy_change(previous: &RootPolicy, next: &RootPolicy) -> &'static str {
    let mut narrowing = previous.enabled && !next.enabled;
    let mut broadening = !previous.enabled && next.enabled;
    for (before, after) in [
        (previous.allow_never, next.allow_never),
        (
            previous.allow_unrestricted_launch,
            next.allow_unrestricted_launch,
        ),
        (
            previous.allow_persistent_sessions,
            next.allow_persistent_sessions,
        ),
        (previous.allow_offline_control, next.allow_offline_control),
    ] {
        narrowing |= before && !after;
        broadening |= !before && after;
    }
    for (before, after) in [
        (&previous.allowed_adapters, &next.allowed_adapters),
        (
            &previous.allowed_launch_profiles,
            &next.allowed_launch_profiles,
        ),
        (
            &previous.allowed_credential_profiles,
            &next.allowed_credential_profiles,
        ),
    ] {
        narrowing |= before.iter().any(|value| !after.contains(value));
        broadening |= after.iter().any(|value| !before.contains(value));
    }
    for (profile, digest) in &previous.launch_profile_executable_digests {
        narrowing |= next.launch_profile_executable_digests.get(profile) != Some(digest);
    }
    for (profile, digest) in &next.launch_profile_executable_digests {
        broadening |= previous.launch_profile_executable_digests.get(profile) != Some(digest);
    }
    match (narrowing, broadening) {
        (true, true) => "mixed",
        (true, false) => "narrowing",
        (false, true) => "broadening",
        (false, false) => "no_change",
    }
}

fn begin_admin_update(state: &Path, change_class: &str) -> conduit_privileged_helper::Result<()> {
    let path = state.join("admin-update.json");
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(conduit_privileged_helper::HelperError::RecoveryRequired(
                "admin_update_recovery_required".into(),
            ));
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(&serde_jcs::to_vec(&json!({"changeClass":change_class}))?)?;
    file.sync_all()?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}
fn finish_admin_update(state: &Path) -> conduit_privileged_helper::Result<()> {
    fs::remove_file(state.join("admin-update.json"))?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}
fn validate_root_file(path: &Path, mode: u32) -> conduit_privileged_helper::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "root-owned helper file ownership or mode invalid".into(),
        ));
    }
    Ok(())
}
fn validate_managed_state(state: &Path) -> conduit_privileged_helper::Result<()> {
    if !state.is_absolute() || state == Path::new("/") || state.components().count() < 3 {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "unsafe managed state path".into(),
        ));
    }
    let metadata = fs::symlink_metadata(state)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "managed state ownership or mode invalid".into(),
        ));
    }
    let allowed = [
        "installation-id",
        "receipt.key",
        "receipt.public",
        "receipt-key-history.json",
        "authority.lock",
        "policy-change.json",
        "admin-update.json",
        "privileged-policy.json",
        "ticket-keys.json",
        "node-public.key",
        "helper.sqlite3",
        "helper.sqlite3-wal",
        "helper.sqlite3-shm",
        "runtimes",
    ];
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name();
        if !allowed.iter().any(|allowed| name == *allowed) {
            return Err(conduit_privileged_helper::HelperError::Policy(format!(
                "unmanaged state entry: {}",
                name.to_string_lossy()
            )));
        }
    }
    Ok(())
}
fn load_or_create_installation(state: &Path) -> conduit_privileged_helper::Result<String> {
    let path = state.join("installation-id");
    if path.exists() {
        Ok(fs::read_to_string(path)?.trim().into())
    } else {
        let nonce = getrandom::u64()
            .map_err(|e| conduit_privileged_helper::HelperError::Policy(e.to_string()))?;
        let value = format!("phinst_{}", hex::encode(nonce.to_ne_bytes()));
        atomic(&path, value.as_bytes(), 0o600)?;
        Ok(value)
    }
}
fn output(value: serde_json::Value) {
    println!("{}", serde_json::to_string(&value).unwrap())
}
fn require_root() -> conduit_privileged_helper::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        Err(conduit_privileged_helper::HelperError::Policy(
            "admin mutation requires root".into(),
        ))
    } else {
        Ok(())
    }
}
fn atomic(path: &Path, bytes: &[u8], mode: u32) -> conduit_privileged_helper::Result<()> {
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".tmp-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_file(&temporary)?
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn all_operations() -> Vec<PrivilegedOperation> {
    vec![
        PrivilegedOperation::Prepare,
        PrivilegedOperation::Start,
        PrivilegedOperation::Inspect,
        PrivilegedOperation::Input,
        PrivilegedOperation::ResizePty,
        PrivilegedOperation::Pause,
        PrivilegedOperation::Resume,
        PrivilegedOperation::GracefulStop,
        PrivilegedOperation::ForceStop,
        PrivilegedOperation::Reconcile,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn policy() -> RootPolicy {
        RootPolicy {
            policy_version: 1,
            installation_id: "phinst_admin0001".into(),
            device_id: "dev_admin0001".into(),
            uid: unsafe { libc::geteuid() },
            revision: 7,
            enabled: true,
            origin: "https://example.test".into(),
            ticket_key_ids: vec!["pkey_admin0001".into()],
            allowed_operations: all_operations(),
            allowed_adapters: vec!["codex".into(), "pi".into()],
            allowed_launch_profiles: vec!["profile".into()],
            launch_profile_executable_digests: BTreeMap::from([(
                "profile".into(),
                "ab".repeat(32),
            )]),
            allowed_credential_profiles: vec!["credential".into()],
            ceilings: ResourceCeilings {
                cpu_quota_per_sec_usec: None,
                memory_max_bytes: None,
                tasks_max: None,
                io_weight: None,
                runtime_max_usec: None,
            },
            allow_never: true,
            allow_unrestricted_launch: true,
            allow_persistent_sessions: true,
            allow_offline_control: true,
            receipt_retention_seconds: 3600,
        }
    }

    #[test]
    fn disable_is_explicit_and_idempotent() {
        let mut policy = policy();
        assert!(disable_root_policy(&mut policy).unwrap());
        assert!(!policy.enabled);
        assert_eq!(policy.revision, 8);
        assert!(!disable_root_policy(&mut policy).unwrap());
        assert_eq!(policy.revision, 8);
    }

    #[test]
    fn policy_change_classifies_narrowing_and_mixed_changes() {
        let previous = policy();
        let mut narrowed = previous.clone();
        narrowed.allow_never = false;
        narrowed.allowed_adapters = vec!["codex".into()];
        assert_eq!(classify_policy_change(&previous, &narrowed), "narrowing");
        narrowed.allowed_launch_profiles.push("broader".into());
        assert_eq!(classify_policy_change(&previous, &narrowed), "mixed");
    }

    #[test]
    fn active_custody_aborts_receipt_rotation_without_mutating_keys() {
        let directory = tempdir().unwrap();
        let secret_path = directory.path().join("receipt.key");
        let public_path = directory.path().join("receipt.public");
        fs::write(&secret_path, [3; 32]).unwrap();
        fs::write(&public_path, [4; 32]).unwrap();
        let before_secret = fs::read(&secret_path).unwrap();
        let before_public = fs::read(&public_path).unwrap();
        assert!(matches!(
            require_receipt_key_rotation_idle(|| Ok(1)),
            Err(conduit_privileged_helper::HelperError::Denied(reason))
                if reason == "active_runtimes_present"
        ));
        assert_eq!(fs::read(secret_path).unwrap(), before_secret);
        assert_eq!(fs::read(public_path).unwrap(), before_public);
        assert!(!directory.path().join("admin-update.json").exists());
    }

    #[test]
    fn existing_admin_update_marker_cannot_be_overwritten_or_cleared() {
        let directory = tempdir().unwrap();
        begin_admin_update(directory.path(), "receipt_key_rotation").unwrap();
        let marker = directory.path().join("admin-update.json");
        let before = fs::read(&marker).unwrap();
        assert!(matches!(
            begin_admin_update(directory.path(), "enable"),
            Err(conduit_privileged_helper::HelperError::RecoveryRequired(reason))
                if reason == "admin_update_recovery_required"
        ));
        assert_eq!(fs::read(&marker).unwrap(), before);
        assert!(marker.exists());
    }

    #[test]
    fn receipt_rotation_keeps_bounded_public_key_history() {
        let policy = policy();
        let current_public = [9; 32];
        let current = receipt_key_entry(current_public, policy.revision);
        let current_key_id = current.key_id.clone();
        let history = ReceiptKeyHistory {
            schema_version: 1,
            installation_id: policy.installation_id.clone(),
            current_key_id: current_key_id.clone(),
            keys: vec![current],
        };
        let replacement_public = [10; 32];
        let rotated = rotated_receipt_key_history(
            history,
            &current_key_id,
            replacement_public,
            policy.revision + 1,
        )
        .unwrap();
        assert_eq!(rotated.installation_id, policy.installation_id);
        assert_eq!(rotated.keys.len(), 2);
        assert_eq!(
            rotated.keys[0].retired_policy_revision,
            Some(policy.revision + 1)
        );
        assert_eq!(rotated.current_key_id, key_id("hkey", &replacement_public));
        assert!(rotated.keys[1].retired_policy_revision.is_none());
        assert_eq!(
            rotated.keys[1].public_key,
            URL_SAFE_NO_PAD.encode(replacement_public)
        );
    }
}
