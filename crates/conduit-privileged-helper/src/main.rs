use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_helper::{
    HelperConfig, HelperEngine, HelperJournal, JOURNAL_SCHEMA_VERSION, PinnedTicketKeys,
    PolicyChangeEvidence, SeqpacketServer, SystemdBackend, SystemdManager,
    build_registration_bundle, load_receipt_key_root_owned, run_exec_worker,
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
    engine.recover_nonterminal()?;
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
        let node = node.clone();
        let policy = policy.clone();
        let active_connections = active_connections.clone();
        std::thread::spawn(move || {
            let _ = serve_connection(connection, engine, node, &policy);
            active_connections.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn serve_connection(
    connection: conduit_privileged_helper::SeqpacketConnection,
    engine: Arc<HelperEngine<SystemdBackend>>,
    node: VerifyingKey,
    policy: &Path,
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
                                .verify_current_policy(&policy)
                                .and_then(|()| {
                                    engine.handle_managed(
                                        authenticated,
                                        request,
                                        packet.descriptors.len(),
                                    )
                                })
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
                .map(|v| {
                    authenticated = true;
                    v
                }),
            _ => engine.verify_current_policy(&policy).and_then(|()| {
                engine.handle(
                    connection.peer_credentials(),
                    authenticated,
                    request,
                    packet.descriptors,
                )
            }),
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
            fs::create_dir_all(&config_base)?;
            fs::set_permissions(&config_base, fs::Permissions::from_mode(0o700))?;
            let installation_id = load_or_create_installation(&state)?;
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
            if let Some(previous) = keys.insert(id.clone(), URL_SAFE_NO_PAD.encode(raw)) {
                if previous != URL_SAFE_NO_PAD.encode(raw) {
                    return Err(conduit_privileged_helper::HelperError::Denied(
                        "issuer_key_id_conflict".into(),
                    ));
                }
            }
            atomic(
                &keys_path,
                &serde_jcs::to_vec(&json!({"keys":keys}))?,
                0o600,
            )?;
            atomic(&policy_path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            if changed {
                record_policy_change(
                    &state,
                    &policy,
                    Some(previous_policy_digest),
                    "ticket_key_pin",
                )?;
            }
            output(
                json!({"pinned":true,"keyId":id,"fingerprint":fingerprint,"policyRevision":policy.revision,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "rotate-device-key" => {
            require_root()?;
            let uid = parse_uid(args)?;
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
            atomic(&path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            record_policy_change(&state, &policy, Some(previous_policy_digest), "enable")?;
            output(
                json!({"enabled":true,"policyRevision":policy.revision,"policyDigest":policy.digest()?,"installationId":policy.installation_id,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "policy" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let path = policy_path.clone();
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from policy".into(),
                ));
            }
            let previous_policy_digest = policy.digest()?;
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
            policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("revision overflow".into())
            })?;
            let digest = policy.digest()?;
            atomic(&path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            record_policy_change(
                &state,
                &policy,
                Some(previous_policy_digest),
                "local_policy_update",
            )?;
            output(
                json!({"updated":true,"policyRevision":policy.revision,"policyDigest":digest,"allowNever":policy.allow_never,"allowUnrestrictedLaunch":policy.allow_unrestricted_launch,"allowedAdapters":policy.allowed_adapters,"allowedLaunchProfiles":policy.allowed_launch_profiles,"registrationBundle":registration_bundle(&state,&policy_path,&node_path)?}),
            );
            Ok(())
        }
        "registration-bundle" => {
            require_root()?;
            output(registration_bundle(&state, &policy_path, &node_path)?);
            Ok(())
        }
        "status" => {
            require_root()?;
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
            let helper = HelperJournal::open_root_owned(&journal)?;
            let backend = SystemdBackend::connect_system()?;
            let mut stopped = 0;
            let mut units = Vec::new();
            for runtime in helper.nonterminal_runtimes()? {
                backend.graceful_stop(&runtime.unit_name)?;
                units.push(runtime.unit_name);
                stopped += 1;
            }
            for unit in units {
                for _ in 0..100 {
                    match backend.inspect(&unit) {
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
                &policy_path,
                &node_path,
                key_id("hkey", signing.verifying_key().as_bytes()),
                state.clone(),
                env::current_exe()?,
            )?;
            let engine = HelperEngine::new(
                config,
                PinnedTicketKeys::load_root_owned(&keys_path)?,
                signing,
                helper,
                SystemdBackend::connect_system()?,
            )?;
            let receipts = engine.recover_nonterminal()?;
            output(json!({"stopped":stopped,"receipts":receipts.len()}));
            Ok(())
        }
        "purge" => {
            require_root()?;
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
    let systemd = SystemdBackend::connect_system()
        .and_then(|v| v.available())
        .unwrap_or(false);
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
fn begin_admin_update(state: &Path, change_class: &str) -> conduit_privileged_helper::Result<()> {
    atomic(
        &state.join("admin-update.json"),
        &serde_jcs::to_vec(&json!({"changeClass":change_class}))?,
        0o600,
    )
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
