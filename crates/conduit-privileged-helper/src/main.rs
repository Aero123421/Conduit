use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_privileged_helper::{
    HelperConfig, HelperEngine, HelperJournal, JOURNAL_SCHEMA_VERSION, PinnedTicketKeys,
    SeqpacketServer, SystemdBackend, SystemdManager, load_receipt_key_root_owned, run_exec_worker,
};
use conduit_privileged_protocol::{
    CapabilityClaims, HelperRequest, HelperResponse, PrivilegedOperation, ResourceCeilings,
    RootPolicy, SignedClaims, key_id,
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
};

fn main() {
    if let Err(error) = run() {
        eprintln!("conduit-privileged-helper: {error}");
        std::process::exit(1)
    }
}
fn run() -> conduit_privileged_helper::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
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
    let policy = path_arg(args, "--policy", "/etc/conduit/privileged-policy.json");
    let keys = path_arg(args, "--ticket-keys", "/etc/conduit/ticket-keys.json");
    let receipt = path_arg(
        args,
        "--receipt-key",
        "/var/lib/conduit/privileged/receipt.key",
    );
    let node_key = path_arg(args, "--node-public-key", "/etc/conduit/node-public.key");
    let journal_path = path_arg(
        args,
        "--journal",
        "/var/lib/conduit/privileged/helper.sqlite3",
    );
    let state = path_arg(args, "--state-dir", "/var/lib/conduit/privileged");
    let socket = path_arg(args, "--socket", "/run/conduit/privileged-helper.sock");
    let worker = env::current_exe()?;
    let signing = load_receipt_key_root_owned(&receipt)?;
    let config = HelperConfig::load_policy_root_owned(
        &policy,
        key_id("hkey", signing.verifying_key().as_bytes()),
        state,
        worker,
    )?;
    let pinned = PinnedTicketKeys::load_root_owned(&keys)?;
    let journal = HelperJournal::open_root_owned(&journal_path)?;
    let node = load_public(&node_key)?;
    let engine = HelperEngine::new(
        config,
        pinned,
        signing,
        journal,
        SystemdBackend::connect_system()?,
    )?;
    let _startup_reconciliation = engine.recover_nonterminal()?;
    let activated = env::var("LISTEN_PID").ok().as_deref() == Some(&std::process::id().to_string())
        && env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    let server = if activated {
        unsafe { SeqpacketServer::from_fd(3)? }
    } else {
        SeqpacketServer::bind(&socket, 0o660)?
    };
    loop {
        let connection = server.accept()?;
        let mut authenticated = false;
        loop {
            let packet = match connection.receive() {
                Ok(v) => v,
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
                            Ok(conduit_privileged_helper::ManagedIoRequest::ReadStream(
                                request,
                            )) if authenticated && packet.descriptors.is_empty() => {
                                let response =
                                    engine.read_stream(&request).unwrap_or_else(|error| {
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
    }
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
    let state = path_arg(args, "--installed-state", "/var/lib/conduit/privileged");
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
            let installation_id = load_or_create_installation(&state)?;
            atomic(&state.join("node-public.key"), &node_raw, 0o644)?;
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
            atomic(&state.join("privileged-policy.json"), &policy_bytes, 0o600)?;
            let registration = registration_bundle(&state)?;
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
            let raw = decode_public_key(&public)?;
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
            let policy_path = state.join("privileged-policy.json");
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&policy_path)?)?;
            if policy.uid != uid || policy.enabled {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "policy uid mismatch or already enabled".into(),
                ));
            }
            if !policy.ticket_key_ids.contains(&id) {
                policy.ticket_key_ids.push(id.clone());
                policy.ticket_key_ids.sort();
                policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                    conduit_privileged_helper::HelperError::Policy("revision overflow".into())
                })?;
            }
            let mut keys = BTreeMap::new();
            let keys_path = state.join("ticket-keys.json");
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
            output(
                json!({"pinned":true,"keyId":id,"fingerprint":fingerprint,"policyRevision":policy.revision}),
            );
            Ok(())
        }
        "enable" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let path = state.join("privileged-policy.json");
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
            policy.enabled = true;
            policy.revision = policy.revision.checked_add(1).ok_or_else(|| {
                conduit_privileged_helper::HelperError::Policy("revision overflow".into())
            })?;
            atomic(&path, &serde_jcs::to_vec(&policy)?, 0o600)?;
            output(
                json!({"enabled":true,"policyRevision":policy.revision,"policyDigest":policy.digest()?,"installationId":policy.installation_id,"registrationBundle":registration_bundle(&state)?}),
            );
            Ok(())
        }
        "policy" => {
            require_root()?;
            let uid = parse_uid(args)?;
            let path = state.join("privileged-policy.json");
            let mut policy: RootPolicy = serde_json::from_slice(&fs::read(&path)?)?;
            if policy.uid != uid {
                return Err(conduit_privileged_helper::HelperError::Policy(
                    "uid differs from policy".into(),
                ));
            }
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
            output(
                json!({"updated":true,"policyRevision":policy.revision,"policyDigest":digest,"allowNever":policy.allow_never,"allowUnrestrictedLaunch":policy.allow_unrestricted_launch,"allowedAdapters":policy.allowed_adapters,"allowedLaunchProfiles":policy.allowed_launch_profiles,"registrationBundle":registration_bundle(&state)?}),
            );
            Ok(())
        }
        "registration-bundle" => {
            require_root()?;
            output(registration_bundle(&state)?);
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
                &state.join("privileged-policy.json"),
                key_id("hkey", signing.verifying_key().as_bytes()),
                state.clone(),
                env::current_exe()?,
            )?;
            let engine = HelperEngine::new(
                config,
                PinnedTicketKeys::load_root_owned(&state.join("ticket-keys.json"))?,
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
            output(json!({"purged":purged,"stateRemoved":true}));
            Ok(())
        }
        _ => Err(conduit_privileged_helper::HelperError::Policy(
            "unknown admin command".into(),
        )),
    }
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
fn decode_public_key(bytes: &[u8]) -> conduit_privileged_helper::Result<[u8; 32]> {
    if bytes.len() == 32 {
        return Ok(bytes.try_into().unwrap());
    }
    #[derive(serde::Deserialize)]
    struct Jwk {
        kty: String,
        crv: String,
        x: String,
    }
    let jwk: Jwk = serde_json::from_slice(bytes)?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(conduit_privileged_helper::HelperError::Policy(
            "issuer JWK type".into(),
        ));
    }
    URL_SAFE_NO_PAD
        .decode(jwk.x)
        .map_err(|_| conduit_privileged_helper::HelperError::Policy("issuer JWK x".into()))?
        .try_into()
        .map_err(|_| {
            conduit_privileged_helper::HelperError::Policy("issuer public key length".into())
        })
}
fn registration_bundle(state: &Path) -> conduit_privileged_helper::Result<serde_json::Value> {
    let policy: RootPolicy =
        serde_json::from_slice(&fs::read(state.join("privileged-policy.json"))?)?;
    let signing = load_receipt_key_root_owned(&state.join("receipt.key"))?;
    let receipt_id = key_id("hkey", signing.verifying_key().as_bytes());
    let policy_digest = policy.digest()?;
    let observed = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| conduit_privileged_helper::HelperError::Policy(e.to_string()))?;
    let systemd = SystemdBackend::connect_system()
        .and_then(|v| v.available())
        .unwrap_or(false);
    let capability = CapabilityClaims {
        protocol: conduit_privileged_protocol::PROTOCOL.into(),
        helper_version: env!("CARGO_PKG_VERSION").into(),
        installation_id: policy.installation_id.clone(),
        receipt_key_id: receipt_id.clone(),
        policy_revision: policy.revision,
        policy_digest: policy_digest.clone(),
        enabled: policy.enabled,
        observed_at: observed,
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
        never_opt_in: policy.allow_never,
        unrestricted_launch_opt_in: policy.allow_unrestricted_launch,
        unavailable_reason: if policy.enabled && systemd {
            None
        } else {
            Some("policy_or_systemd_unavailable".into())
        },
    };
    let node = fs::read(state.join("node-public.key"))?;
    let node: [u8; 32] = node.try_into().map_err(|_| {
        conduit_privileged_helper::HelperError::Policy("node public key length".into())
    })?;
    Ok(
        json!({"protocol":conduit_privileged_protocol::PROTOCOL,"installationId":policy.installation_id,"deviceId":policy.device_id,"deviceKeyId":key_id("dkey",&node),"uid":policy.uid,"origin":policy.origin,"policyRevision":policy.revision,"policyDigest":policy_digest,"receiptPublicJwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),"kid":receipt_id},"signedPolicyAttestation":SignedClaims::sign(&receipt_id,policy,&signing)?,"signedCapability":SignedClaims::sign(&receipt_id,capability,&signing)?}),
    )
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
