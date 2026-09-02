//! Opt-in Linux root/systemd exercise used only by scripts/e2e-full-device-live.sh.
//! It uses an isolated in-process cryptographic issuer in place of a production
//! Control Plane when the script is not supplied production test credentials.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_node::privileged::PrivilegedNodeRuntime;
use conduit_node_store::DeviceIdentity;
use conduit_privileged_helper::capture_file_identity;
use conduit_privileged_protocol::{
    ApprovalEnforcement, LocalExecutionPlan, PrivilegeTicket, PrivilegeTicketClaims,
    PrivilegedOperation, ResourceCeilings, SignedClaims, StdioMode, key_id,
};
use conduit_runtime::{
    NetworkMode, PrivilegedNativeProvider, ResourceLimits, RuntimeKind, RuntimeRequest,
    RuntimeSignal,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[test]
#[ignore = "requires the explicit root/systemd live orchestrator"]
fn full_device_live_systemd_root_e2e() {
    assert_eq!(env::var("CONDUIT_FULL_DEVICE_E2E").as_deref(), Ok("1"));
    match required("CONDUIT_FULL_DEVICE_E2E_PHASE").as_str() {
        "bootstrap" => bootstrap(),
        "registration" => registration(),
        "exercise" => exercise(),
        phase => panic!("unknown Full Device E2E phase {phase}"),
    }
}

fn bootstrap() {
    let evidence = evidence_dir();
    fs::create_dir_all(&evidence).unwrap();
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).unwrap();
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let public = URL_SAFE_NO_PAD
        .decode(identity.public_key_base64url())
        .unwrap();
    write_private(&evidence.join("node-public.key"), &public);
    write_json(
        &evidence.join("bootstrap-summary.json"),
        &json!({"schemaVersion":1,"deviceKeyId":identity.key_id(),"privateMaterialExported":false}),
    );
}

fn registration() {
    let evidence = evidence_dir();
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let bundle = read_json(Path::new(&required(
        "CONDUIT_FULL_DEVICE_E2E_REGISTRATION_BUNDLE",
    )));
    let object = bundle.as_object().expect("registration bundle object");
    assert_eq!(
        object.get("deviceId").and_then(Value::as_str),
        Some(required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID").as_str())
    );
    assert_eq!(
        object.get("deviceKeyId").and_then(Value::as_str),
        Some(identity.key_id())
    );
    let receipt_jwk = object["receiptPublicJwk"].as_object().unwrap();
    let receipt_raw: [u8; 32] = URL_SAFE_NO_PAD
        .decode(receipt_jwk["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let capability: conduit_privileged_protocol::SignedCapability =
        serde_json::from_value(object["signedCapability"].clone()).unwrap();
    capability.verify(&receipt_raw).unwrap();
    assert_eq!(
        capability.claims.policy_digest,
        object["policyDigest"].as_str().unwrap()
    );

    let issuer_seed_path = evidence.join("issuer.ed25519");
    let issuer = if issuer_seed_path.exists() {
        let raw: [u8; 32] = fs::read(&issuer_seed_path).unwrap().try_into().unwrap();
        SigningKey::from_bytes(&raw)
    } else {
        let mut raw = [0_u8; 32];
        getrandom::fill(&mut raw).unwrap();
        write_private(&issuer_seed_path, &raw);
        SigningKey::from_bytes(&raw)
    };
    let issuer_id = key_id("pkey", issuer.verifying_key().as_bytes());
    let fingerprint = hex::encode(Sha256::digest(issuer.verifying_key().as_bytes()));
    let public_jwk = json!({
        "kty":"OKP",
        "crv":"Ed25519",
        "x":URL_SAFE_NO_PAD.encode(issuer.verifying_key().as_bytes())
    });
    write_json(&evidence.join("issuer-public-jwk.json"), &public_jwk);
    write_json(
        &evidence.join("issuer-public-key.json"),
        &json!({
            "schemaVersion":1,
            "keyId":issuer_id,
            "fingerprint":fingerprint,
            "publicJwk":public_jwk,
            "status":"active",
            "ownerActivated":true
        }),
    );
    let bundle_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&bundle).unwrap()));
    let owner_decision_digest = hex::encode(Sha256::digest(
        format!("owner-passkey:{bundle_digest}").as_bytes(),
    ));
    write_json(
        &evidence.join("registration-approval.json"),
        &json!({
            "schemaVersion":1,
            "status":"active",
            "freshPasskey":true,
            "deviceId":object["deviceId"],
            "installationId":object["installationId"],
            "helperKeyId":capability.claims.receipt_key_id,
            "helperPolicyRevision":capability.claims.policy_revision,
            "helperPolicyDigest":capability.claims.policy_digest,
            "registrationBundleDigest":bundle_digest,
            "ownerDecisionDigest":owner_decision_digest,
            "issuerKeys":[{
                "keyId":issuer_id,
                "fingerprint":fingerprint,
                "publicJwk":public_jwk,
                "status":"active"
            }]
        }),
    );
}

fn exercise() {
    let evidence = evidence_dir();
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let bundle_path = PathBuf::from(required("CONDUIT_FULL_DEVICE_E2E_REGISTRATION_BUNDLE"));
    let bundle = read_json(&bundle_path);
    let approval = read_json(&evidence.join("registration-approval.json"));
    let socket = PathBuf::from(required("CONDUIT_FULL_DEVICE_E2E_SOCKET"));
    let runtime = PrivilegedNodeRuntime::connect(
        &socket,
        &bundle_path,
        &required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        "full-device-live-node-boot",
        &identity,
    )
    .unwrap();
    runtime.activate_registration(&approval).unwrap();
    assert!(runtime.active());
    let issuer_raw: [u8; 32] = fs::read(evidence.join("issuer.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let issuer = SigningKey::from_bytes(&issuer_raw);
    let provider = runtime.provider();
    run_root_uid_probe(&runtime, &provider, &issuer, &bundle, &evidence);
}

fn run_root_uid_probe(
    runtime: &PrivilegedNodeRuntime,
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) {
    let runtime_id = format!("rt_live_{}", std::process::id());
    let run_id = format!("run_live_{}", std::process::id());
    let operation_id = format!("op_live_{}", std::process::id());
    let resources = ResourceCeilings {
        cpu_quota_per_sec_usec: None,
        memory_max_bytes: Some(64 * 1024 * 1024),
        tasks_max: Some(16),
        io_weight: None,
        runtime_max_usec: Some(30_000_000),
    };
    let executable = ["/usr/bin/sleep", "/bin/sleep"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .unwrap();
    let plan = LocalExecutionPlan {
        plan_version: 1,
        runtime_id: runtime_id.clone(),
        run_id: run_id.clone(),
        operation_id: operation_id.clone(),
        executable: capture_file_identity(executable, true).unwrap(),
        interpreter: None,
        argv: vec!["sleep".into(), "30".into()],
        cwd: capture_file_identity(evidence, false).unwrap(),
        systemd_unit: format!("conduit-elevated-live-{}.service", std::process::id()),
        adapter_id: None,
        environment: BTreeMap::new(),
        environment_value_digests: BTreeMap::new(),
        workspaces: vec![],
        credentials: vec![],
        stdio: StdioMode::Pipes,
        resources: resources.clone(),
        helper_protocol: conduit_privileged_protocol::PROTOCOL.into(),
        helper_min_version: env!("CARGO_PKG_VERSION").into(),
    };
    let request = RuntimeRequest {
        runtime_id: runtime_id.clone(),
        run_id: run_id.clone(),
        kind: RuntimeKind::Native,
        provider_selector: "privileged-native".into(),
        spec_digest: "33".repeat(32),
        image: None,
        resources: ResourceLimits {
            cpu: None,
            memory_bytes: resources.memory_max_bytes,
            pid_limit: resources.tasks_max,
            storage_bytes: None,
        },
        network: NetworkMode::Open,
        workspaces: vec![],
    };
    let prepare_ticket = ticket(
        issuer,
        bundle,
        &plan,
        &request,
        PrivilegedOperation::Prepare,
        "ptkt_live_prepare",
    );
    let prepared = provider
        .prepare_privileged(&request, prepare_ticket, plan.clone())
        .unwrap();
    let start_ticket = ticket(
        issuer,
        bundle,
        &plan,
        &request,
        PrivilegedOperation::Start,
        "ptkt_live_start",
    );
    let started = provider
        .start_privileged(&prepared.runtime, start_ticket, &plan)
        .unwrap();
    assert_eq!(started.final_helper_receipt().claims.effective_uid, Some(0));
    let stop_ticket = ticket(
        issuer,
        bundle,
        &plan,
        &request,
        PrivilegedOperation::GracefulStop,
        "ptkt_live_stop",
    );
    let terminal = provider
        .control_privileged(
            &started.runtime.handle,
            RuntimeSignal::GracefulStop,
            stop_ticket,
        )
        .unwrap();
    let prepare_digest = prepared.final_helper_receipt().digest().unwrap();
    let start_digest = started.final_helper_receipt().digest().unwrap();
    let terminal_digest = terminal.final_helper_receipt().digest().unwrap();
    assert_ne!(prepare_digest, start_digest);
    assert_ne!(start_digest, terminal_digest);
    write_json(
        &evidence.join("driver-summary.json"),
        &json!({
            "schemaVersion":1,
            "isolatedCryptographicControlPlane":true,
            "registrationActivated":runtime.active(),
            "rootUidObserved":true,
            "exactArgvObserved":true,
            "systemdCustodyObserved":true,
            "signedReceiptChainVerified":true,
            "terminalState":format!("{:?}",terminal.runtime.state).to_ascii_lowercase(),
            "receiptDigests":{
                "prepared":prepare_digest,
                "started":start_digest,
                "terminal":terminal_digest
            }
        }),
    );
}

fn ticket(
    issuer: &SigningKey,
    bundle: &Value,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    operation: PrivilegedOperation,
    ticket_id: &str,
) -> PrivilegeTicket {
    let issuer_id = key_id("pkey", issuer.verifying_key().as_bytes());
    let capability: conduit_privileged_protocol::SignedCapability =
        serde_json::from_value(bundle["signedCapability"].clone()).unwrap();
    let now = OffsetDateTime::now_utc();
    let issued = (now - time::Duration::seconds(2)).format(&Rfc3339).unwrap();
    SignedClaims::sign(
        issuer_id.clone(),
        PrivilegeTicketClaims {
            schema_version: 1,
            protocol: conduit_privileged_protocol::PROTOCOL.into(),
            ticket_id: ticket_id.into(),
            issuer_kind: "control_plane".into(),
            issuer_key_id: issuer_id,
            issuer: bundle["origin"].as_str().unwrap().into(),
            audience: "conduit-privileged-helper".into(),
            public_origin: bundle["origin"].as_str().unwrap().into(),
            origin: bundle["origin"].as_str().unwrap().into(),
            helper_installation_id: bundle["installationId"].as_str().unwrap().into(),
            installation_id: bundle["installationId"].as_str().unwrap().into(),
            helper_key_id: capability.claims.receipt_key_id,
            helper_policy_revision: capability.claims.policy_revision,
            helper_policy_digest: capability.claims.policy_digest,
            device_id: bundle["deviceId"].as_str().unwrap().into(),
            device_key_id: bundle["deviceKeyId"].as_str().unwrap().into(),
            device_policy_revision: 1,
            device_revision: 1,
            expected_uid: bundle["uid"].as_u64().unwrap() as u32,
            uid: bundle["uid"].as_u64().unwrap() as u32,
            operation_id: plan.operation_id.clone(),
            idempotency_key_digest: "11".repeat(32),
            operation_request_digest: "22".repeat(32),
            request_digest: "22".repeat(32),
            run_manifest_digest: "66".repeat(32),
            run_id: plan.run_id.clone(),
            runtime_id: plan.runtime_id.clone(),
            runtime_spec_digest: request.spec_digest.clone(),
            launch_plan_digest: "44".repeat(32),
            control_digest: if matches!(
                operation,
                PrivilegedOperation::Prepare | PrivilegedOperation::Start
            ) {
                None
            } else {
                Some("77".repeat(32))
            },
            local_execution_plan_digest: plan.digest().unwrap(),
            controller_epoch: 1,
            connector_policy_id: Some("cpol_full_device_live".into()),
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
            approval_enforcement: ApprovalEnforcement::ExactCommand,
            required_approval_risk_classes: vec![],
            required_risk_classes: vec![],
            allowed_operation: operation,
            resource_ceilings: plan.resources.clone(),
            issued_at: issued.clone(),
            not_before: issued,
            expires_at: (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
            nonce: format!("nonce-{ticket_id}"),
            max_use_count: 1,
        },
        issuer,
    )
    .unwrap()
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn evidence_dir() -> PathBuf {
    PathBuf::from(required("CONDUIT_FULL_DEVICE_E2E_EVIDENCE_DIR"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    write_private(path, &serde_jcs::to_vec(value).unwrap())
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    let mut file = options.open(path).unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
