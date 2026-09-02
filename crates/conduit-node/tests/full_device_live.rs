//! Opt-in root/systemd test used only by scripts/e2e-full-device-live.sh.
//! Public evidence contains bounded booleans and digests, never host paths.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_adapters::{
    AdapterEventKind, AdapterKind, AdapterState, ApprovalBridgeOwnership, ApprovalContext,
    ApprovalRiskClassSet, EffectiveAccessScope, EffectiveApprovalPolicy, EffectiveSandboxPolicy,
    LaunchRequest, ProtocolDriver,
};
use conduit_node::privileged::PrivilegedNodeRuntime;
use conduit_node_store::{
    CredentialMetadata, CredentialStore, DeviceIdentity, NodeStore, ProjectionKind,
};
use conduit_privileged_helper::capture_file_identity;
use conduit_privileged_helper::{SeqpacketClient, SystemdBackend, SystemdManager};
use conduit_privileged_protocol::{
    ApprovalEnforcement, CredentialDescriptor, HelperRequest, HelperResponse, LocalExecutionPlan,
    PrivilegeTicket, PrivilegeTicketClaims, PrivilegedOperation, ResourceCeilings, SignedClaims,
    StdioMode, key_id,
};
use conduit_runtime::{
    IoMode, LaunchPlan, NativeProvider, NetworkMode, PrivilegedNativeProvider, ProcessSupervisor,
    ResourceLimits, RuntimeKind, RuntimeProvider, RuntimeRequest, RuntimeSignal, RuntimeState,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write as _,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[test]
#[ignore = "requires the explicit root/systemd live orchestrator"]
fn full_device_live_systemd_root_e2e() {
    assert_eq!(env::var("CONDUIT_FULL_DEVICE_E2E").as_deref(), Ok("1"));
    match required("CONDUIT_FULL_DEVICE_E2E_PHASE").as_str() {
        "bootstrap" => bootstrap(),
        "registration" => registration(),
        "full_user" => full_user(),
        "never_denied" => never_denied(),
        "never_allowed" => never_allowed(),
        "lost_start_issue" => lost_start_issue(),
        "lost_start_recover" => lost_start_recover(),
        "node_prepare" => node_prepare(),
        "node_registered" => node_registered(),
        "node_running" => node_running(false),
        "node_recovered" => node_running(true),
        "node_stop" => node_stop(),
        "exercise" => exercise(),
        "recover" => recover(),
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

    let public_jwk = json!({"kty":"OKP","crv":"Ed25519","x":identity.public_key_base64url()});
    let bootstrap = worker_post(
        "/__full-device-live/bootstrap",
        &json!({
            "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
            "deviceKeyId":identity.key_id(),"expectedUid":unsafe { libc::geteuid() },
            "publicJwk":public_jwk
        }),
    );
    assert_eq!(bootstrap["status"], "ready");
    let never_enabled = capability.claims.never_opt_in;
    let policy_revision = if never_enabled { 2 } else { 1 };
    let previous_policy_digest = if never_enabled {
        Some(
            fs::read_to_string(evidence.join("initial-device-policy-digest"))
                .expect("initial Device policy digest")
                .trim()
                .to_owned(),
        )
    } else {
        None
    };
    let policy_summary = json!({
        "revision":policy_revision,"capabilities":["command.start"],"providers":["privileged-native"],
        "accessScopes":["full_device"],"approvalModes":if never_enabled { json!(["never"]) } else { json!([]) },
        "requiredApprovalRiskClasses":[],"launchProfiles":["full-device-live"],
        "credentialProfiles":["cred_full_device_live"],"maxCpu":null,
        "maxMemoryBytes":null,"maxStorageBytes":null,"allowFullAccessWithoutApproval":never_enabled
    });
    let request_id = format!(
        "phreq_live_policy_{:08}_{policy_revision}",
        capability.claims.policy_revision
    );
    let registration_payload = signed_registration_payload(
        &bundle,
        &identity,
        &request_id,
        policy_summary.clone(),
        policy_revision,
        previous_policy_digest.as_deref(),
    );
    let projection = worker_post(
        "/__full-device-live/frame",
        &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"frame":signed_frame("privilege.installation_attestation", &request_id, registration_payload, &identity)}),
    );
    assert!(matches!(
        projection.pointer("/result/state").and_then(Value::as_str),
        Some("pending_owner" | "active")
    ));
    let policy_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&policy_summary).unwrap()));
    if !never_enabled {
        write_private(
            &evidence.join("initial-device-policy-digest"),
            policy_digest.as_bytes(),
        );
    }
    let mut approval = worker_post(
        "/__full-device-live/approve",
        &json!({"installationId":object["installationId"]}),
    );
    assert_eq!(approval["status"], "active");
    assert_eq!(approval["isolatedCryptographicTestDeployment"], true);
    assert_eq!(approval["freshPasskey"], false);
    approval["schemaVersion"] = json!(1);
    approval["deviceId"] = object["deviceId"].clone();
    approval["registrationBundleDigest"] = Value::String(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&bundle).unwrap(),
    )));
    write_json(&evidence.join("registration-approval.json"), &approval);
    let issuer = approval["issuerKeys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["status"] == "active"))
        .expect("active isolated issuer");
    let issuer_id = issuer["keyId"].as_str().unwrap();
    let fingerprint = issuer["fingerprint"].as_str().unwrap();
    let issuer_jwk = issuer["publicJwk"].clone();
    let public_jwk = json!({
        "kty":"OKP","crv":"Ed25519","x":issuer_jwk["x"],
        "kid":issuer_id,"revision":issuer["revision"]
    });
    write_json(&evidence.join("issuer-public-jwk.json"), &public_jwk);
    write_json(
        &evidence.join("issuer-public-key.json"),
        &json!({
            "schemaVersion":1,"keyId":issuer_id,"fingerprint":fingerprint,
            "publicJwk":public_jwk,"status":"active","ownerActivated":true,
            "isolatedCryptographicTestDeployment":true,"freshPasskey":false
        }),
    );
    // Other live cases remain deterministic local protocol coverage. They use
    // the fixture's published test key, while control_plane_root_exact below
    // obtains its own tickets from D1 and never reads this seed.
    let deterministic_seed = URL_SAFE_NO_PAD
        .decode("nrtJu6YH_rZfrr6JSuItGhCt3C4zFkXIxHOQgsLD6Os")
        .unwrap();
    write_private(&evidence.join("issuer.ed25519"), &deterministic_seed);
}

/// Runs while the system helper socket is still disabled. This makes helper
/// non-contact an externally enforced precondition rather than an assertion.
fn full_user() {
    let evidence = evidence_dir();
    let supervisor_root = evidence.join("full-user-supervisor");
    let provider = NativeProvider::new(ProcessSupervisor::open(&supervisor_root).unwrap());
    let runtime_id = "rt_live_full_user_0001";
    let request = RuntimeRequest {
        runtime_id: runtime_id.into(),
        run_id: "run_live_full_user_0001".into(),
        kind: RuntimeKind::Native,
        provider_selector: "native".into(),
        spec_digest: "10".repeat(32),
        image: None,
        resources: limits(),
        network: NetworkMode::Open,
        workspaces: vec![],
    };
    let prepared = provider.prepare(&request).unwrap();
    let started = provider
        .start(
            &prepared,
            &LaunchPlan {
                executable: existing(&["/usr/bin/id", "/bin/id"]),
                argv: vec!["-u".into()],
                cwd: evidence.clone(),
                environment: BTreeMap::new(),
                io_mode: IoMode::Pipes,
                timeout_ms: Some(5_000),
            },
        )
        .unwrap();
    for _ in 0..100 {
        if provider.inspect(&started.handle).unwrap().state == RuntimeState::Stopped {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = fs::read_to_string(supervisor_root.join(format!("{runtime_id}.stream"))).unwrap();
    assert_eq!(output.trim(), unsafe { libc::geteuid() }.to_string());
    write_json(
        &evidence.join("full-user-summary.json"),
        &json!({
            "schemaVersion":1,"ordinaryProvider":"native","deviceUidObserved":true,
            "helperSocketUnavailableDuringRun":true,"helperContacted":false
        }),
    );
}

fn never_denied() {
    let evidence = evidence_dir();
    let (runtime, bundle, issuer) = connect("full-device-live-node-never-denied");
    let provider = runtime.provider();
    let (plan, request) = case_plan(
        "never_denied",
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "30".into()],
        StdioMode::Pipes,
        30_000_000,
        &evidence,
    );
    let operation_digest = hex::encode(Sha256::digest(b"never-denied-control-operation"));
    let manifest_digest = hex::encode(Sha256::digest(b"never-denied-control-manifest"));
    register_manual_intent(&plan, &operation_digest, &manifest_digest);
    let (server_result, denied_request_id) = control_plane_ticket_result(
        &bundle,
        &DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap(),
        &plan,
        &request,
        &manifest_digest,
        &operation_digest,
        PrivilegedOperation::Prepare,
        false,
    );
    assert_eq!(server_result["status"], "denied");
    let server_denial = worker_post(
        "/__full-device-live/assert-never-denied",
        &json!({
            "installationId":bundle["installationId"],
            "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
            "deniedRequestId":denied_request_id,
            "initialDevicePolicyRevision":1,
            "result":server_result,
        }),
    );
    let error = provider
        .prepare_privileged(
            &request,
            ticket_with_approval(
                &issuer,
                &bundle,
                &plan,
                &request,
                PrivilegedOperation::Prepare,
                "ptkt_live_never_denied_prepare",
                "never",
            ),
            plan,
        )
        .expect_err("Never must fail before the separate root-owned opt-in");
    assert!(
        error
            .to_string()
            .contains("full_device_never_local_opt_in_required")
    );
    write_json(
        &evidence.join("never-local-denial.json"),
        &json!({"schemaVersion":1,"rootOptIn":false,"deniedBeforeRootEffect":true,"reason":"full_device_never_local_opt_in_required","server":server_denial}),
    );
}

fn never_allowed() {
    let evidence = evidence_dir();
    let (runtime, bundle, _issuer) = connect("full-device-live-node-never-allowed");
    let provider = runtime.provider();
    let (plan, request) = case_plan(
        "never_allowed",
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "30".into()],
        StdioMode::Pipes,
        30_000_000,
        &evidence,
    );
    let operation_digest = hex::encode(Sha256::digest(b"never-allowed-control-operation"));
    let manifest_digest = hex::encode(Sha256::digest(b"never-allowed-control-manifest"));
    register_manual_intent(&plan, &operation_digest, &manifest_digest);
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let (issued_result, issued_request_id) = control_plane_ticket_result(
        &bundle,
        &identity,
        &plan,
        &request,
        &manifest_digest,
        &operation_digest,
        PrivilegedOperation::Prepare,
        true,
    );
    let server_enabled = worker_post(
        "/__full-device-live/assert-never-enabled",
        &json!({
            "installationId":bundle["installationId"],
            "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
            "deniedRequestId":read_json(&evidence.join("never-local-denial.json"))["server"]["deniedRequestId"],
            "issuedRequestId":issued_request_id,
            "initialDevicePolicyRevision":1,
            "enabledDevicePolicyRevision":2,
        }),
    );
    let prepare_ticket: PrivilegeTicket =
        serde_json::from_value(issued_result["ticket"].clone()).unwrap();
    let prepared = provider
        .prepare_privileged(&request, prepare_ticket, plan.clone())
        .unwrap();
    assert_eq!(prepared.runtime.state, RuntimeState::Prepared);
    let local_denial = read_json(&evidence.join("never-local-denial.json"));
    write_json(
        &evidence.join("never-summary.json"),
        &json!({"schemaVersion":1,"rootDisabled":local_denial,"server":server_enabled,"rootOptIn":true,"approvalReceiptPresent":false,"rootPrepareAccepted":true,"rootStartDeferredToNodeServiceE2E":true}),
    );
}

const NODE_LIVE_OPERATION_ID: &str = "op_live_node_service_0001";
const NODE_LIVE_RUN_ID: &str = "run_live_node_service_0001";

fn node_prepare() {
    let evidence = evidence_dir();
    let data = evidence.join("node-service-data");
    let identity_dir = data.join("identity");
    fs::create_dir_all(&identity_dir).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&identity_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let private = fs::read(evidence.join("device.ed25519")).unwrap();
    write_private(&identity_dir.join("device.ed25519"), &private);

    let executable = existing(&["/usr/bin/sleep", "/bin/sleep"]);
    write_json(
        &evidence.join("node-launch-profiles.json"),
        &json!({
            "localPolicy":{
                "revision":2,"capabilities":["command.start"],
                "providers":["privileged-native"],"accessScopes":["full_device"],
                "approvalModes":["never"],"requiredApprovalRiskClasses":[],
                "launchProfiles":["full-device-live"],"credentialProfiles":["cred_full_device_live"],
                "maxCpu":null,"maxMemoryBytes":null,"maxStorageBytes":null,
                "allowFullAccessWithoutApproval":true
            },
            "profiles":{
                "full-device-live":{
                    "providerId":"privileged-native","executable":executable,
                    "argv":["sleep","300"],"cwd":evidence,
                    "environment":{},"ioMode":"pipes","timeoutMs":300000
                }
            }
        }),
    );
    let manifest_digest = hex::encode(Sha256::digest(b"node-service-live-manifest-v1"));
    let now = OffsetDateTime::now_utc();
    let mut operation = json!({
        "schemaVersion":1,"operationId":NODE_LIVE_OPERATION_ID,
        "idempotencyKey":"node-service-live-operation-v1",
        "actorPrincipalId":"prin_full_device_live","clientId":"conduit.cli",
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"runId":NODE_LIVE_RUN_ID,
        "connectorPolicyId":"cpol_owner_first_party_v1","connectorPolicyRevision":1,
        "capability":"command.start","accessScope":"full_device","approvalMode":"never",
        "requiredApprovalRiskClasses":[],
        "runtime":{"kind":"native","providerId":"privileged-native","configurationRevision":1},
        "sourceRevisions":[],"arguments":{"launchProfileId":"full-device-live"},
        "issuedAt":now.format(&Rfc3339).unwrap(),
        "expiresAt":(now+time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
        "validForMs":300000
    });
    let operation_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&operation).unwrap()));
    operation["payloadDigest"] = Value::String(operation_digest);
    write_json(
        &evidence.join("node-operation-intent.json"),
        &json!({"operation":operation,"runManifestDigest":manifest_digest,"dispatch":true}),
    );
}

fn node_registered() {
    let evidence = evidence_dir();
    let policy = read_json(&evidence.join("node-launch-profiles.json"))["localPolicy"].clone();
    let expected_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&policy).unwrap()));
    let mut observed = None;
    let mut remote = Value::Null;
    for _ in 0..300 {
        observed = NodeStore::open_read_only(evidence.join("node-service-data"))
            .ok()
            .and_then(|store| store.privilege_registration_state().ok().flatten());
        remote = worker_post(
            "/__full-device-live/inspect",
            &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID")}),
        );
        if observed.as_ref().is_some_and(|state| {
            state.device_policy_revision == 2 && state.device_policy_digest == expected_digest
        }) && remote
            .pointer("/deviceRoom/activeSocketCount")
            .and_then(Value::as_u64)
            == Some(1)
        {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let observed = observed.expect("production Node did not persist accepted Device policy");
    assert_eq!(observed.device_policy_revision, 2);
    assert_eq!(observed.device_policy_digest, expected_digest);
    assert_eq!(
        remote
            .pointer("/deviceRoom/activeSocketCount")
            .and_then(Value::as_u64),
        Some(1)
    );
    write_json(
        &evidence.join("node-registration-summary.json"),
        &json!({
            "schemaVersion":1,"actualNodeService":true,"actualWssClient":true,
            "actualWorkerRoute":true,"actualDeviceRoomWebSocket":true,
            "devicePolicyRevision":observed.device_policy_revision,
            "devicePolicyDigest":observed.device_policy_digest,
            "acceptedStatePersisted":true
        }),
    );
}

fn node_running(recovered: bool) {
    let evidence = evidence_dir();
    let mut latest = Value::Null;
    for _ in 0..300 {
        latest = worker_post(
            "/__full-device-live/inspect",
            &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"operationId":NODE_LIVE_OPERATION_ID}),
        );
        if latest.pointer("/runtime/state") == Some(&Value::String("running".into()))
            && latest.pointer("/operation/state") == Some(&Value::String("claimed".into()))
            && latest
                .pointer("/deviceRoom/activeSocketCount")
                .and_then(Value::as_u64)
                == Some(1)
        {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        latest.pointer("/runtime/state").and_then(Value::as_str),
        Some("running")
    );
    assert_eq!(
        latest.pointer("/operation/state").and_then(Value::as_str),
        Some("claimed")
    );
    assert_eq!(
        latest
            .pointer("/deviceRoom/activeSocketCount")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(latest["operationTicketCount"], 2);
    let runtime_id = latest
        .pointer("/runtime/runtime_id")
        .and_then(Value::as_str)
        .unwrap();
    let invocation_id = latest
        .pointer("/runtime/invocation_id")
        .and_then(Value::as_str)
        .unwrap();
    let current = json!({
        "schemaVersion":1,"actualNodeService":true,"actualWssClient":true,
        "actualWorkerRoute":true,"actualDeviceRoomWebSocket":true,
        "durableOperationOutbox":true,"operationId":NODE_LIVE_OPERATION_ID,
        "runtimeId":runtime_id,"invocationId":invocation_id,
        "operationTicketCount":latest["operationTicketCount"],
        "connectionEpoch":latest.pointer("/deviceRoom/connection/epoch"),
        "running":true
    });
    if recovered {
        let before = read_json(&evidence.join("node-service-running.json"));
        assert_eq!(current["runtimeId"], before["runtimeId"]);
        assert_eq!(current["invocationId"], before["invocationId"]);
        assert_eq!(
            current["operationTicketCount"],
            before["operationTicketCount"]
        );
        let mut summary = current;
        summary["nodeProcessRestarted"] = json!(true);
        summary["sameDurableNodeStore"] = json!(true);
        summary["duplicateStartTicketIssued"] = json!(false);
        write_json(&evidence.join("node-service-recovered.json"), &summary);
    } else {
        write_json(&evidence.join("node-service-running.json"), &current);
    }
}

fn node_stop() {
    let evidence = evidence_dir();
    let current = worker_post(
        "/__full-device-live/inspect",
        &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"operationId":NODE_LIVE_OPERATION_ID}),
    );
    let control = worker_post(
        "/__full-device-live/control",
        &json!({
            "runtimeId":current["runtime"]["runtime_id"],
            "expectedState":"running","expectedRevision":current["runtime"]["revision"]
        }),
    );
    let mut latest = Value::Null;
    for _ in 0..300 {
        latest = worker_post(
            "/__full-device-live/inspect",
            &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"operationId":NODE_LIVE_OPERATION_ID}),
        );
        if latest.pointer("/runtime/state") == Some(&Value::String("stopped".into())) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        latest.pointer("/runtime/state").and_then(Value::as_str),
        Some("stopped")
    );
    let recovered = read_json(&evidence.join("node-service-recovered.json"));
    write_json(
        &evidence.join("node-service-summary.json"),
        &json!({
            "schemaVersion":1,"running":recovered,"exactRuntimeControl":true,
            "controlOperationId":control["operationId"],"terminalState":"stopped",
            "helperReceiptProjected":true,"rootRuntimeCustodyReleased":true
        }),
    );
}

fn exercise() {
    let evidence = evidence_dir();
    let (runtime, bundle, issuer) = connect("full-device-live-node-boot-1");
    let provider = runtime.provider();
    let mut cases = serde_json::Map::new();
    cases.insert(
        "neverDualOptIn".into(),
        read_json(&evidence.join("never-summary.json")),
    );
    cases.insert(
        "controlPlaneRootExact".into(),
        control_plane_root_exact(&runtime, &provider, &bundle, &evidence),
    );
    cases.insert(
        "rootExactArgv".into(),
        root_exact_and_replay(&runtime, &provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "lostStartResponse".into(),
        read_json(&evidence.join("lost-start-summary.json")),
    );
    cases.insert(
        "actualNodeServiceRestart".into(),
        read_json(&evidence.join("node-service-summary.json")),
    );
    cases.insert(
        "ptyInputResize".into(),
        pty_input_resize(&provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "pauseResume".into(),
        pause_resume(&provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "forceStop".into(),
        force_stop(&provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "deadline".into(),
        deadline(&runtime, &provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "invalidTicket".into(),
        invalid_ticket(&provider, &bundle, &evidence),
    );
    cases.insert(
        "rootMarker".into(),
        root_marker(&provider, &issuer, &bundle, &evidence),
    );
    cases.insert(
        "structuredCodexAgent".into(),
        structured_codex_agent(&runtime, &provider, &issuer, &bundle, &evidence),
    );
    let (plan, request, started) = leave_active(&provider, &issuer, &bundle, &evidence);
    write_json(
        &evidence.join("active-runtime.json"),
        &json!({
            "plan":plan,"request":request,"handle":started.runtime.handle,
            "invocationId":started.final_helper_receipt().claims.invocation_id,
            "startReceiptDigest":started.final_helper_receipt().digest().unwrap()
        }),
    );
    write_json(&evidence.join("live-cases.json"), &Value::Object(cases));
}

/// Runs as a new live-driver process after update and helper restart.
/// Reconciliation must attach the same invocation; no start ticket is issued
/// on this path. This does not claim to exercise the `NodeService` event loop.
fn recover() {
    let evidence = evidence_dir();
    let active = read_json(&evidence.join("active-runtime.json"));
    let plan: LocalExecutionPlan = serde_json::from_value(active["plan"].clone()).unwrap();
    let request: RuntimeRequest = serde_json::from_value(active["request"].clone()).unwrap();
    let expected_invocation = active["invocationId"].as_str().unwrap();
    let (runtime, bundle, issuer) = connect("full-device-live-node-boot-2");
    let capability: conduit_privileged_protocol::SignedCapability =
        serde_json::from_value(bundle["signedCapability"].clone()).unwrap();
    capability.verify(runtime.receipt_key()).unwrap();
    assert!(capability.claims.supports_full_device());
    let capability_digest = capability.digest().unwrap();
    let provider = runtime.provider();
    let attached = provider
        .attach_reconciled_privileged(plan.clone(), request.spec_digest.clone())
        .unwrap();
    assert_eq!(attached.runtime.state, RuntimeState::Running);
    assert_eq!(
        attached
            .final_helper_receipt()
            .claims
            .invocation_id
            .as_deref(),
        Some(expected_invocation)
    );
    let stopped = stop(
        &provider,
        &issuer,
        &bundle,
        &plan,
        &request,
        &attached.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_recovered_stop",
    );
    let full_user = read_json(&evidence.join("full-user-summary.json"));
    let cases = read_json(&evidence.join("live-cases.json"));
    let packaging = read_json(&evidence.join("packaging-live-summary.json"));
    write_json(
        &evidence.join("driver-summary.json"),
        &json!({
            "schemaVersion":3,"isolatedWorkerD1DeviceRoomControlPlane":true,
            "controlPlaneTransport":"guarded_device_room_rpc","deviceRoomWebSocketTransport":false,
            "registrationActivated":runtime.active(),"ordinaryFullUser":full_user,"cases":cases,
            "packageLifecycle":packaging,
            "hostCapability":{"signedProbeVerified":true,"signedProbeDigest":capability_digest,
                "systemdSystemManager":capability.claims.systemd_system_manager,
                "socketPeerCredentials":capability.claims.socket_peer_credentials,
                "transientUnits":capability.claims.transient_units,
                "cgroupV2":capability.claims.cgroup_v2,"freeze":capability.claims.freeze,
                "pidfd":capability.claims.pidfd,"openat2":capability.claims.openat2,
                "execveat":capability.claims.execveat,"pty":capability.claims.pty,
                "streamReplay":capability.claims.stream_replay,
                "unavailableReason":capability.claims.unavailable_reason},
        "driverProcessRestart":{"newHelperClientEpoch":true,"durableAttach":true,"duplicateStart":false,"invocationPreserved":true},
            "helperRestart":{"durableAttach":true,"processCustodyPreserved":true,"invocationPreserved":true},
            "terminalState":"stopped","recoveredTerminalReceiptDigest":stopped.final_helper_receipt().digest().unwrap()
        }),
    );
}

/// Sends an authenticated Start request and closes the seqpacket connection
/// without reading its response. The helper necessarily attempts that response
/// only after `StartTransientUnit` and both receipt boundaries have completed.
/// A typed systemd observation proves that the effect became visible while the
/// caller had no response bytes in its custody.
fn lost_start_issue() {
    let evidence = evidence_dir();
    let (runtime, bundle, issuer) = connect("full-device-live-lost-start-issue");
    let provider = runtime.provider();
    let (plan, request) = case_plan(
        "lost_start",
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "120".into()],
        StdioMode::Pipes,
        120_000_000,
        &evidence,
    );
    let prepare_ticket = ticket(
        &issuer,
        &bundle,
        &plan,
        &request,
        PrivilegedOperation::Prepare,
        "ptkt_live_lost_start_prepare",
    );
    provider
        .prepare_privileged(&request, prepare_ticket.clone(), plan.clone())
        .unwrap();
    let start_ticket = ticket(
        &issuer,
        &bundle,
        &plan,
        &request,
        PrivilegedOperation::Start,
        "ptkt_live_lost_start_start",
    );
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    send_start_without_receiving(
        Path::new(&required("CONDUIT_FULL_DEVICE_E2E_SOCKET")),
        &required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        "full-device-live-lost-start-fault",
        &identity,
        start_ticket.clone(),
        plan.digest().unwrap(),
    );

    let systemd = SystemdBackend::connect_system().unwrap();
    let observation = (0..200)
        .find_map(|_| match systemd.inspect(&plan.systemd_unit) {
            Ok(value) if value.active_state == "active" && value.invocation_id.is_some() => {
                Some(value)
            }
            _ => {
                thread::sleep(Duration::from_millis(20));
                None
            }
        })
        .expect("systemd did not expose the started invocation after the response was dropped");
    write_json(
        &evidence.join("lost-start-runtime.json"),
        &json!({
            "plan": plan,
            "request": request,
            "prepareTicket": prepare_ticket,
            "startTicket": start_ticket,
            "invocationId": observation.invocation_id,
            "responseReceiveAttempted": false
        }),
    );
}

/// Runs in a fresh live-driver process. Replaying Prepare reconstructs only
/// Node-side provider state; replaying the identical Start ticket must return
/// the helper's durable signed receipt chain without replacing the systemd
/// invocation. A second exact replay proves stable receipt bytes as well.
fn lost_start_recover() {
    let evidence = evidence_dir();
    let state = read_json(&evidence.join("lost-start-runtime.json"));
    let plan: LocalExecutionPlan = serde_json::from_value(state["plan"].clone()).unwrap();
    let request: RuntimeRequest = serde_json::from_value(state["request"].clone()).unwrap();
    let prepare_ticket: PrivilegeTicket =
        serde_json::from_value(state["prepareTicket"].clone()).unwrap();
    let start_ticket: PrivilegeTicket =
        serde_json::from_value(state["startTicket"].clone()).unwrap();
    let expected_invocation = state["invocationId"].as_str().unwrap();
    assert_eq!(state["responseReceiveAttempted"], false);

    let (runtime, bundle, issuer) = connect("full-device-live-lost-start-recover");
    let provider = runtime.provider();
    let prepared = provider
        .prepare_privileged(&request, prepare_ticket, plan.clone())
        .unwrap();
    let systemd = SystemdBackend::connect_system().unwrap();
    let before = systemd.inspect(&plan.systemd_unit).unwrap();
    assert_eq!(before.invocation_id.as_deref(), Some(expected_invocation));

    let replay = (0..200)
        .find_map(|_| {
            match provider.start_privileged(&prepared.runtime, start_ticket.clone(), &plan) {
                Ok(value) => Some(value),
                Err(error) if error.to_string().contains("start outcome uncertain") => {
                    thread::sleep(Duration::from_millis(20));
                    None
                }
                Err(error) => panic!("lost Start response replay failed: {error}"),
            }
        })
        .expect("helper did not complete the original Start receipt boundary");
    let transitions = replay
        .helper_receipts
        .iter()
        .map(|receipt| receipt.claims.transition.as_str())
        .collect::<Vec<_>>();
    assert_eq!(transitions, ["unit_created", "running"]);
    for receipt in &replay.helper_receipts {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    assert_eq!(
        replay
            .final_helper_receipt()
            .claims
            .invocation_id
            .as_deref(),
        Some(expected_invocation)
    );
    let exact_replay = provider
        .start_privileged(&prepared.runtime, start_ticket, &plan)
        .unwrap();
    assert_eq!(exact_replay.helper_receipts, replay.helper_receipts);
    let after = systemd.inspect(&plan.systemd_unit).unwrap();
    assert_eq!(after.invocation_id, before.invocation_id);

    let stopped = stop(
        &provider,
        &issuer,
        &bundle,
        &plan,
        &request,
        &replay.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_lost_start_stop",
    );
    write_json(
        &evidence.join("lost-start-summary.json"),
        &json!({
            "passed": true,
            "requestSentWithoutReceive": true,
            "newLiveDriverProcess": true,
            "signedReceiptReplay": true,
            "exactReceiptBytesStable": true,
            "duplicateStart": false,
            "invocationPreserved": true,
            "transitions": transitions,
            "terminalState": state_name(stopped.runtime.state)
        }),
    );
}

fn send_start_without_receiving(
    socket: &Path,
    device_id: &str,
    node_boot_id: &str,
    identity: &DeviceIdentity,
    ticket: PrivilegeTicket,
    plan_digest: String,
) {
    let client = SeqpacketClient::connect(socket).unwrap();
    let nonce = getrandom::u64().unwrap();
    let hello = HelperRequest::Hello {
        protocol_versions: vec![conduit_privileged_protocol::PROTOCOL.into()],
        device_id: device_id.into(),
        node_boot_id: node_boot_id.into(),
        nonce: hex::encode(nonce.to_ne_bytes()),
    };
    let challenge = match raw_response(client.call(&hello, &[]).unwrap()) {
        HelperResponse::Challenge(value) => value,
        value => panic!("unexpected helper challenge response: {value:?}"),
    };
    let signature =
        URL_SAFE_NO_PAD.encode(identity.sign_bytes(&serde_jcs::to_vec(&challenge).unwrap()));
    match raw_response(
        client
            .call(
                &HelperRequest::Prove {
                    challenge,
                    signature,
                },
                &[],
            )
            .unwrap(),
    ) {
        HelperResponse::Accepted { protocol, .. }
            if protocol == conduit_privileged_protocol::PROTOCOL => {}
        value => panic!("unexpected helper authentication response: {value:?}"),
    }
    client
        .send(
            &serde_jcs::to_vec(&HelperRequest::Start {
                ticket: Box::new(ticket),
                plan_digest,
            })
            .unwrap(),
            &[],
        )
        .unwrap();
    drop(client);
}

fn raw_response(packet: conduit_privileged_helper::Packet) -> HelperResponse {
    assert!(packet.descriptors.is_empty());
    conduit_privileged_protocol::decode_packet(&packet.bytes).unwrap()
}

fn connect(boot: &str) -> (std::sync::Arc<PrivilegedNodeRuntime>, Value, SigningKey) {
    let evidence = evidence_dir();
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let bundle_path = PathBuf::from(required("CONDUIT_FULL_DEVICE_E2E_REGISTRATION_BUNDLE"));
    let bundle = read_json(&bundle_path);
    let runtime = PrivilegedNodeRuntime::connect(
        Path::new(&required("CONDUIT_FULL_DEVICE_E2E_SOCKET")),
        &bundle_path,
        &required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        boot,
        &identity,
    )
    .unwrap();
    runtime
        .activate_registration(&read_json(&evidence.join("registration-approval.json")))
        .unwrap();
    assert!(runtime.active());
    let issuer_raw: [u8; 32] = fs::read(evidence.join("issuer.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    (runtime, bundle, SigningKey::from_bytes(&issuer_raw))
}

fn root_exact_and_replay(
    runtime: &PrivilegedNodeRuntime,
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let python = existing(&[
        "/usr/bin/python3.12",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
    ]);
    let expected_arguments = vec![
        "space value".to_owned(),
        "ユニコード".to_owned(),
        String::new(),
        "--leading-dash".to_owned(),
    ];
    let recorder = r#"import json,sys,time
print(json.dumps(sys.argv[1:],ensure_ascii=False),flush=True)
time.sleep(120)
"#;
    let mut argv = vec!["python3".into(), "-u".into(), "-c".into(), recorder.into()];
    argv.extend(expected_arguments.clone());
    let (plan, request) = case_plan(
        "exact",
        python,
        argv,
        StdioMode::Pipes,
        120_000_000,
        evidence,
    );
    let prepare_ticket = ticket(
        issuer,
        bundle,
        &plan,
        &request,
        PrivilegedOperation::Prepare,
        "ptkt_live_exact_prepare",
    );
    let prepared = provider
        .prepare_privileged(&request, prepare_ticket.clone(), plan.clone())
        .unwrap();
    let prepare_replay = provider
        .prepare_privileged(&request, prepare_ticket, plan.clone())
        .unwrap();
    assert_eq!(
        prepared.final_helper_receipt().digest().unwrap(),
        prepare_replay.final_helper_receipt().digest().unwrap()
    );
    let start_ticket = ticket(
        issuer,
        bundle,
        &plan,
        &request,
        PrivilegedOperation::Start,
        "ptkt_live_exact_start",
    );
    let mut started = provider
        .start_managed_privileged(&prepared.runtime, start_ticket.clone(), &plan)
        .unwrap();
    assert_eq!(
        started.receipt.final_helper_receipt().claims.effective_uid,
        Some(0)
    );
    let replay = provider
        .start_privileged(&prepared.runtime, start_ticket, &plan)
        .unwrap();
    for receipt in &replay.helper_receipts {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    let replay_final = replay.final_helper_receipt();
    assert_eq!(
        replay_final.digest().unwrap(),
        started.receipt.final_helper_receipt().digest().unwrap()
    );
    assert_eq!(
        replay_final.claims.invocation_id,
        started.receipt.final_helper_receipt().claims.invocation_id
    );
    let mut output = Vec::new();
    let mut cursor = 0;
    for _ in 0..100 {
        let page = started.io.read_stdout(cursor, 16 * 1024).unwrap();
        cursor = page.next_cursor;
        output.extend(page.bytes);
        if output.contains(&b'\n') {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let record = output.split(|byte| *byte == b'\n').next().unwrap();
    let observed_arguments: Vec<String> = serde_json::from_slice(record).unwrap();
    assert_eq!(observed_arguments, expected_arguments);
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &started.receipt.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_exact_stop",
    );
    json!({"passed":true,"effectiveUid":0,"exactArgv":true,
        "spaceArgumentPreserved":true,"unicodeArgumentPreserved":true,
        "emptyArgumentPreserved":true,"leadingDashArgumentPreserved":true,
        "shellReconstruction":false,"prepareReplaySameReceipt":true,
        "exactStartReplaySameReceipt":true,"duplicateStart":false,"invocationPreserved":true,
        "terminalState":state_name(stopped.runtime.state)})
}

fn control_plane_root_exact(
    runtime: &PrivilegedNodeRuntime,
    provider: &PrivilegedNativeProvider,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let identity = DeviceIdentity::load_or_create(evidence.join("device.ed25519")).unwrap();
    let python = existing(&[
        "/usr/bin/python3.12",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
    ]);
    let program = "import os,time;print(os.geteuid(),flush=True);time.sleep(1)";
    let (plan, request) = case_plan(
        "control_plane",
        python,
        vec!["python3".into(), "-u".into(), "-c".into(), program.into()],
        StdioMode::Pipes,
        10_000_000,
        evidence,
    );
    let now = OffsetDateTime::now_utc();
    let issued_at = now.format(&Rfc3339).unwrap();
    let expires_at = (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap();
    let operation_digest = hex::encode(Sha256::digest(
        format!("control-plane-operation:{}", plan.operation_id).as_bytes(),
    ));
    let manifest_digest = hex::encode(Sha256::digest(
        format!("control-plane-manifest:{}", plan.run_id).as_bytes(),
    ));
    let operation = json!({
        "schemaVersion":1,"operationId":plan.operation_id,
        "idempotencyKey":format!("control-plane-operation-{}", std::process::id()),
        "actorPrincipalId":"prin_full_device_live","clientId":"conduit.cli",
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"runId":plan.run_id,
        "connectorPolicyId":"cpol_owner_first_party_v1","connectorPolicyRevision":1,
        "capability":"command.start","accessScope":"full_device","approvalMode":"never",
        "requiredApprovalRiskClasses":[],
        "runtime":{"kind":"native","providerId":"privileged-native","configurationRevision":1},
        "sourceRevisions":[],"arguments":{"launchProfileId":"full-device-live"},
        "issuedAt":issued_at,"expiresAt":expires_at,"validForMs":300000,
        "payloadDigest":operation_digest
    });
    let intent = worker_post(
        "/__full-device-live/intent",
        &json!({"operation":operation,"runManifestDigest":manifest_digest}),
    );
    assert_eq!(intent["status"], "custodied");

    let prepare_ticket = control_plane_ticket(
        bundle,
        &identity,
        &plan,
        &request,
        &manifest_digest,
        &operation_digest,
        PrivilegedOperation::Prepare,
    );
    let prepared = provider
        .prepare_privileged(&request, prepare_ticket, plan.clone())
        .unwrap();
    project_receipts(&identity, &prepared.helper_receipts);

    let start_ticket = control_plane_ticket(
        bundle,
        &identity,
        &plan,
        &request,
        &manifest_digest,
        &operation_digest,
        PrivilegedOperation::Start,
    );
    let mut managed = provider
        .start_managed_privileged(&prepared.runtime, start_ticket, &plan)
        .unwrap();
    project_receipts(&identity, &managed.receipt.helper_receipts);
    assert_eq!(
        managed.receipt.final_helper_receipt().claims.effective_uid,
        Some(0)
    );
    let mut output = Vec::new();
    let mut cursor = 0;
    for _ in 0..100 {
        let page = managed.io.read_stdout(cursor, 4096).unwrap();
        cursor = page.next_cursor;
        output.extend(page.bytes);
        if output.contains(&b'\n') {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(String::from_utf8(output).unwrap().trim(), "0");
    let terminal = loop {
        let receipt = provider
            .inspect_privileged(&managed.receipt.runtime.handle)
            .unwrap();
        if receipt.runtime.state == RuntimeState::Stopped {
            break receipt;
        }
        thread::sleep(Duration::from_millis(25));
    };
    project_receipts(&identity, &terminal.helper_receipts);
    for receipt in prepared
        .helper_receipts
        .iter()
        .chain(managed.receipt.helper_receipts.iter())
        .chain(terminal.helper_receipts.iter())
    {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    let inspection = worker_post(
        "/__full-device-live/inspect",
        &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID")}),
    );
    let remote_denials = worker_post("/__full-device-live/assert-remote-denials", &json!({}));
    assert_eq!(remote_denials["privilegedAuthorityUnchanged"], true);
    assert_eq!(inspection["worker"], true);
    assert!(
        inspection
            .pointer("/d1/tickets")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );
    assert!(
        inspection
            .pointer("/d1/receipts")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 5
    );
    assert!(
        inspection
            .pointer("/deviceRoom/projected")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    json!({
        "passed":true,"workerIsolate":true,"d1Custody":true,"deviceRoomDurableCourier":true,
        "deviceRoomWebSocketTransport":false,"controlPlaneIssuedPrepareAndStartTickets":true,
        "helperReceiptsProjected":true,"effectiveUid":0,"stdoutUidZero":true,
        "terminalState":state_name(terminal.runtime.state),
        "ticketCount":inspection.pointer("/d1/tickets"),
        "receiptCount":inspection.pointer("/d1/receipts"),
        "deviceRoomInboundCount":inspection.pointer("/deviceRoom/inbound"),
        "remoteRootAdministration":remote_denials
    })
}

fn control_plane_ticket(
    bundle: &Value,
    identity: &DeviceIdentity,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    manifest_digest: &str,
    operation_digest: &str,
    operation: PrivilegedOperation,
) -> PrivilegeTicket {
    let (projection, _) = control_plane_ticket_result(
        bundle,
        identity,
        plan,
        request,
        manifest_digest,
        operation_digest,
        operation,
        true,
    );
    serde_json::from_value(projection["ticket"].clone()).unwrap()
}

fn control_plane_ticket_result(
    bundle: &Value,
    identity: &DeviceIdentity,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    manifest_digest: &str,
    operation_digest: &str,
    operation: PrivilegedOperation,
    expect_issued: bool,
) -> (Value, String) {
    let capability: conduit_privileged_protocol::SignedCapability =
        serde_json::from_value(bundle["signedCapability"].clone()).unwrap();
    let action = serde_json::to_value(&operation)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert!(matches!(action.as_str(), "prepare" | "start"));
    let request_id = format!("ptreq_livecp_{}_{}", action, std::process::id());
    let now = OffsetDateTime::now_utc();
    let unsigned = json!({
        "requestId":request_id,
        "idempotencyKey":format!("full-device-live-control-plane-{action}-{}", std::process::id()),
        "installationId":bundle["installationId"],"deviceKeyId":identity.key_id(),
        "operationId":plan.operation_id,"runId":plan.run_id,"runtimeId":plan.runtime_id,
        "runtimeSpecDigest":request.spec_digest,"launchPlanDigest":"44".repeat(32),
        "localExecutionPlanDigest":plan.digest().unwrap(),"controlRequestDigest":Value::Null,
        "controlAuthority":Value::Null,"runManifestDigest":manifest_digest,
        "helperPolicyRevision":capability.claims.policy_revision,
        "helperPolicyDigest":capability.claims.policy_digest,
        "devicePolicyRevision":if capability.claims.never_opt_in { 2 } else { 1 },
        "approvalReceiptDigest":Value::Null,"approvalEnforcement":"exact_command",
        "allowedOperation":action,"resourceCeilings":plan.resources,
        "redactedSummary":{"operation":action,"runtimeKind":"native","reasonCodes":[],"resourceProfile":"root-policy-bounded","credentialProfiles":[]},
        "requestedAt":(now-time::Duration::seconds(1)).format(&Rfc3339).unwrap(),
        "expiresAt":(now+time::Duration::minutes(2)).format(&Rfc3339).unwrap()
    });
    let mut payload = unsigned.clone();
    payload["deviceSignature"] = Value::String(sign_device_payload(
        "privilege.ticket_request",
        &unsigned,
        identity,
    ));
    let projection = worker_post(
        "/__full-device-live/frame",
        &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"frame":signed_frame("privilege.ticket_request", &request_id, payload, identity)}),
    );
    let result = projection.pointer("/result").unwrap().clone();
    if expect_issued {
        assert_eq!(result["status"], "issued");
        let ticket: PrivilegeTicket = serde_json::from_value(result["ticket"].clone()).unwrap();
        assert_eq!(ticket.claims.operation_request_digest, operation_digest);
    } else {
        assert_eq!(result["status"], "denied");
    }
    (result, request_id)
}

fn register_manual_intent(
    plan: &LocalExecutionPlan,
    operation_digest: &str,
    manifest_digest: &str,
) {
    let now = OffsetDateTime::now_utc();
    let operation = json!({
        "schemaVersion":1,"operationId":plan.operation_id,
        "idempotencyKey":format!("manual-intent-{}", plan.operation_id),
        "actorPrincipalId":"prin_full_device_live","clientId":"conduit.cli",
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"runId":plan.run_id,
        "connectorPolicyId":"cpol_owner_first_party_v1","connectorPolicyRevision":1,
        "capability":"command.start","accessScope":"full_device","approvalMode":"never",
        "requiredApprovalRiskClasses":[],
        "runtime":{"kind":"native","providerId":"privileged-native","configurationRevision":1},
        "sourceRevisions":[],"arguments":{"launchProfileId":"full-device-live"},
        "issuedAt":now.format(&Rfc3339).unwrap(),
        "expiresAt":(now+time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
        "validForMs":300000,"payloadDigest":operation_digest
    });
    let result = worker_post(
        "/__full-device-live/intent",
        &json!({"operation":operation,"runManifestDigest":manifest_digest,"dispatch":false}),
    );
    assert_eq!(result["status"], "custodied");
}

fn project_receipts(
    identity: &DeviceIdentity,
    receipts: &[conduit_privileged_protocol::HelperReceipt],
) {
    for receipt in receipts {
        let unsigned = json!({"receipt":receipt,"deviceKeyId":identity.key_id()});
        let mut payload = unsigned.clone();
        payload["deviceSignature"] = Value::String(sign_device_payload(
            "privilege.receipt",
            &unsigned,
            identity,
        ));
        let result = worker_post(
            "/__full-device-live/frame",
            &json!({"deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),"frame":signed_frame("privilege.receipt", &receipt.claims.operation_id, payload, identity)}),
        );
        assert_eq!(
            result.pointer("/result/status"),
            Some(&Value::String("verified".into()))
        );
    }
}

fn pty_input_resize(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let (plan, request) = case_plan(
        "pty",
        existing(&["/usr/bin/cat", "/bin/cat"]),
        vec!["cat".into()],
        StdioMode::Pty,
        30_000_000,
        evidence,
    );
    let prepared = provider
        .prepare_privileged(
            &request,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Prepare,
                "ptkt_live_pty_prepare",
            ),
            plan.clone(),
        )
        .unwrap();
    let mut managed = provider
        .start_managed_privileged(
            &prepared.runtime,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Start,
                "ptkt_live_pty_start",
            ),
            &plan,
        )
        .unwrap();
    let input = provider
        .input_authorized(
            &managed.receipt.runtime.handle,
            b"conduit-pty-live-marker\n",
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Input,
                "ptkt_live_pty_input",
            ),
        )
        .unwrap();
    let resized = provider
        .resize_authorized(
            &input.runtime.handle,
            40,
            100,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::ResizePty,
                "ptkt_live_pty_resize",
            ),
        )
        .unwrap();
    let mut observed = false;
    for _ in 0..100 {
        let page = managed.io.read_stdout(0, 16 * 1024).unwrap();
        if String::from_utf8_lossy(&page.bytes).contains("conduit-pty-live-marker") {
            observed = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(observed);
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &resized.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_pty_stop",
    );
    json!({"passed":true,"stdin":true,"stdout":true,"pty":true,"resize":{"rows":40,"columns":100},"terminalState":state_name(stopped.runtime.state)})
}

fn pause_resume(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let (plan, request, started) =
        start_sleep("pause", provider, issuer, bundle, evidence, 30_000_000);
    let paused = provider
        .control_privileged(
            &started.runtime.handle,
            RuntimeSignal::Pause,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Pause,
                "ptkt_live_pause",
            ),
        )
        .unwrap();
    assert_eq!(paused.runtime.state, RuntimeState::Paused);
    let resumed = provider
        .control_privileged(
            &paused.runtime.handle,
            RuntimeSignal::Resume,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Resume,
                "ptkt_live_resume",
            ),
        )
        .unwrap();
    assert_eq!(resumed.runtime.state, RuntimeState::Running);
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &resumed.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_pause_stop",
    );
    json!({"passed":true,"paused":true,"resumed":true,"terminalState":state_name(stopped.runtime.state)})
}

fn force_stop(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let (plan, request, started) =
        start_sleep("force", provider, issuer, bundle, evidence, 30_000_000);
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &started.runtime.handle,
        RuntimeSignal::ForceStop,
        "ptkt_live_force_stop",
    );
    json!({"passed":true,"forceStop":true,"terminalState":state_name(stopped.runtime.state)})
}

fn deadline(
    runtime: &PrivilegedNodeRuntime,
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let (plan, request, started) =
        start_sleep("deadline", provider, issuer, bundle, evidence, 500_000);
    thread::sleep(Duration::from_millis(1_200));
    let reconciled = provider
        .attach_reconciled_privileged(plan, request.spec_digest)
        .unwrap();
    assert!(matches!(
        reconciled.runtime.state,
        RuntimeState::Stopped | RuntimeState::Failed | RuntimeState::RecoveryRequired
    ));
    for receipt in &reconciled.helper_receipts {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    json!({"passed":true,"runtimeMaxUsec":500000,
        "startedInvocationObserved":started.final_helper_receipt().claims.invocation_id.is_some(),
        "convergedState":state_name(reconciled.runtime.state),"duplicateStart":false})
}

fn invalid_ticket(provider: &PrivilegedNativeProvider, bundle: &Value, evidence: &Path) -> Value {
    let (plan, request) = case_plan(
        "invalid",
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "30".into()],
        StdioMode::Pipes,
        30_000_000,
        evidence,
    );
    let rogue = SigningKey::from_bytes(&[0x93; 32]);
    let denied = provider
        .prepare_privileged(
            &request,
            ticket(
                &rogue,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Prepare,
                "ptkt_live_invalid_prepare",
            ),
            plan,
        )
        .unwrap_err();
    assert!(denied.to_string().contains("ticket_key_unpinned"));
    json!({"passed":true,"untrustedIssuerDenied":true,"runtimeStarted":false})
}

fn root_marker(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let marker = evidence.join("root-marker");
    let python = existing(&[
        "/usr/bin/python3.12",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
    ]);
    let (create_plan, create_request) = case_plan(
        "marker_create",
        python.clone(),
        vec![
            "python3".into(),
            "-u".into(),
            "-c".into(),
            "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(exist_ok=False); time.sleep(120)".into(),
            marker.to_string_lossy().into(),
        ],
        StdioMode::Pipes,
        10_000_000,
        evidence,
    );
    let prepared = provider
        .prepare_privileged(
            &create_request,
            ticket(
                issuer,
                bundle,
                &create_plan,
                &create_request,
                PrivilegedOperation::Prepare,
                "ptkt_live_marker_create_prepare",
            ),
            create_plan.clone(),
        )
        .unwrap();
    let created = provider
        .start_privileged(
            &prepared.runtime,
            ticket(
                issuer,
                bundle,
                &create_plan,
                &create_request,
                PrivilegedOperation::Start,
                "ptkt_live_marker_create_start",
            ),
            &create_plan,
        )
        .unwrap();
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let marker_owner = fs::metadata(&marker).unwrap().uid();
    assert_eq!(marker_owner, 0);
    let created_stopped = stop(
        provider,
        issuer,
        bundle,
        &create_plan,
        &create_request,
        &created.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_marker_create_stop",
    );
    let (remove_plan, remove_request) = case_plan(
        "marker_remove",
        python,
        vec![
            "python3".into(),
            "-u".into(),
            "-c".into(),
            "import pathlib,sys,time; pathlib.Path(sys.argv[1]).unlink(); time.sleep(120)".into(),
            marker.to_string_lossy().into(),
        ],
        StdioMode::Pipes,
        10_000_000,
        evidence,
    );
    let prepared = provider
        .prepare_privileged(
            &remove_request,
            ticket(
                issuer,
                bundle,
                &remove_plan,
                &remove_request,
                PrivilegedOperation::Prepare,
                "ptkt_live_marker_remove_prepare",
            ),
            remove_plan.clone(),
        )
        .unwrap();
    let removed = provider
        .start_privileged(
            &prepared.runtime,
            ticket(
                issuer,
                bundle,
                &remove_plan,
                &remove_request,
                PrivilegedOperation::Start,
                "ptkt_live_marker_remove_start",
            ),
            &remove_plan,
        )
        .unwrap();
    for _ in 0..100 {
        if !marker.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!marker.exists());
    let removed_stopped = stop(
        provider,
        issuer,
        bundle,
        &remove_plan,
        &remove_request,
        &removed.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_marker_remove_stop",
    );
    json!({"passed":true,"createdByUid":marker_owner,
        "startReceiptVerified":created.final_helper_receipt().claims.effective_uid == Some(0),
        "createTerminalReceiptVerified":created_stopped.runtime.state == RuntimeState::Stopped,
        "independentSignedCleanup":true,
        "cleanupLaunchUid":removed.final_helper_receipt().claims.effective_uid,
        "cleanupTerminalReceiptVerified":removed_stopped.runtime.state == RuntimeState::Stopped})
}

fn structured_codex_agent(
    runtime: &PrivilegedNodeRuntime,
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> Value {
    let credential_store = CredentialStore::open(
        NodeStore::open(evidence.join("live-credential-store")).unwrap(),
        evidence.join("live-credential.dek"),
        evidence.join("live-credential-projections"),
    )
    .unwrap();
    let credential_metadata = CredentialMetadata {
        profile_id: "cred_full_device_live".into(),
        revision: 1,
        adapter_id: "codex".into(),
        kind: ProjectionKind::ReadOnlyFile,
        label: "synthetic-live-fixture".into(),
    };
    credential_store
        .put(&credential_metadata, b"synthetic-live-credential")
        .unwrap();
    let sealed = credential_store
        .sealed_read_only("cred_full_device_live", "codex", 1)
        .unwrap();
    let expected_credential_digest = sealed.sha256.clone();
    let python = existing(&[
        "/usr/bin/python3.12",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
    ]);
    let fixture = r#"import hashlib,json,os,pathlib,sys
credential=pathlib.Path(os.environ["HOME"])/".codex"/"auth.json"
credential_digest=hashlib.sha256(credential.read_bytes()).hexdigest()
for line in sys.stdin:
    message=json.loads(line)
    method=message.get("method")
    request_id=message.get("id")
    if method == "initialize":
        print(json.dumps({"id":request_id,"result":{"serverInfo":{"name":"conduit-live-fixture","version":"1","credentialDigest":credential_digest}}}),flush=True)
    elif method == "thread/start":
        print(json.dumps({"id":request_id,"result":{"thread":{"id":"codex-thread-live"}}}),flush=True)
    elif method == "turn/start":
        print(json.dumps({"id":request_id,"result":{"turn":{"id":"codex-turn-live"}}}),flush=True)
        print(json.dumps({"method":"item/completed","params":{"item":{"id":"codex-item-live","type":"agentMessage","text":"bounded live fixture response"}}}),flush=True)
        print(json.dumps({"method":"turn/completed","params":{"turn":{"id":"codex-turn-live","status":{"type":"completed"}}}}),flush=True)
        print("bounded-live-stderr",file=sys.stderr,flush=True)
"#;
    let (mut plan, request) = case_plan(
        "codex_agent",
        python,
        vec!["python3".into(), "-u".into(), "-c".into(), fixture.into()],
        StdioMode::Pipes,
        30_000_000,
        evidence,
    );
    plan.adapter_id = Some("codex".into());
    plan.launch_profile_id = None;
    plan.credentials = vec![CredentialDescriptor {
        projection_id: "cred_full_device_live".into(),
        revision: 1,
        target_name: ".codex/auth.json".into(),
        descriptor_index: 0,
        size: sealed.size,
        sha256: sealed.sha256.clone(),
        read_only: true,
    }];
    let prepared = provider
        .prepare_privileged_with_descriptors(
            &request,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Prepare,
                "ptkt_live_codex_prepare",
            ),
            plan.clone(),
            &[sealed.file.as_raw_fd()],
        )
        .unwrap();
    let mut managed = provider
        .start_managed_privileged(
            &prepared.runtime,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Start,
                "ptkt_live_codex_start",
            ),
            &plan,
        )
        .unwrap();
    assert_eq!(
        managed.receipt.final_helper_receipt().claims.effective_uid,
        Some(0)
    );

    let launch = LaunchRequest {
        cwd: evidence.into(),
        prompt: Some("run the bounded live fixture".into()),
        native_session_id: None,
        model: None,
        effort: None,
        session_data_dir: None,
    };
    let mut driver = ProtocolDriver::new_with_authority_context(
        AdapterKind::Codex,
        &launch,
        EffectiveAccessScope::FullDevice,
        EffectiveSandboxPolicy::External,
        ApprovalContext {
            effective_policy: EffectiveApprovalPolicy::Always,
            bridge: ApprovalBridgeOwnership::Typed,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        },
    )
    .unwrap();
    assert_eq!(driver.state(), AdapterState::Starting);
    let mut frames = driver.start().unwrap();
    let mut stdout_cursor = 0;
    let mut stderr_cursor = 0;
    let mut pending = Vec::new();
    let mut prompt_accepted = false;
    let mut completed = false;
    let mut assistant_observed = false;
    let mut credential_observed = false;
    let mut input_index = 0_u32;
    let root_liveness_before_prompt = managed.receipt.runtime.state == RuntimeState::Running;
    assert!(root_liveness_before_prompt && !prompt_accepted);

    for _ in 0..24_u32 {
        for frame in frames.drain(..) {
            queue_adapter_input(runtime, issuer, bundle, &plan, &request, input_index);
            managed.io.write_input(&frame.0).unwrap();
            input_index += 1;
        }
        let page = managed.io.read_stdout(stdout_cursor, 32 * 1024).unwrap();
        stdout_cursor = page.next_cursor;
        pending.extend(page.bytes);
        let mut next = Vec::new();
        while let Some(offset) = pending.iter().position(|byte| *byte == b'\n') {
            let record: Vec<u8> = pending.drain(..=offset).collect();
            let value: Value = serde_json::from_slice(&record).unwrap();
            if value.get("id") == Some(&json!(1)) {
                credential_observed = value.pointer("/result/serverInfo/credentialDigest")
                    == Some(&Value::String(expected_credential_digest.clone()));
            }
            let (outbound, events) = driver.on_record(&record).unwrap();
            next.extend(outbound);
            for event in events {
                prompt_accepted |= event.kind == AdapterEventKind::PromptAccepted;
                assistant_observed |= matches!(
                    event.kind,
                    AdapterEventKind::AssistantMessage | AdapterEventKind::AssistantMessageDelta
                );
                completed |= event.kind == AdapterEventKind::Completed;
            }
        }
        frames = next;
        if completed && frames.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(prompt_accepted);
    assert!(assistant_observed);
    assert!(completed);
    assert!(credential_observed);
    assert_eq!(driver.state(), AdapterState::Completed);

    let mut stderr = Vec::new();
    for _ in 0..100 {
        let page = managed.io.read_stderr(stderr_cursor, 16 * 1024).unwrap();
        stderr_cursor = page.next_cursor;
        stderr.extend(page.bytes);
        if String::from_utf8_lossy(&stderr).contains("bounded-live-stderr") {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(String::from_utf8_lossy(&stderr).contains("bounded-live-stderr"));
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &managed.receipt.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_codex_stop",
    );
    for receipt in &stopped.helper_receipts {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    json!({
        "passed":true,"adapter":"codex","effectiveUid":0,
        "rootLivenessBeforePromptAcceptance":root_liveness_before_prompt,
        "promptAccepted":prompt_accepted,"assistantOutput":assistant_observed,
        "agentSettled":completed,"explicitSessionClose":true,"stderr":true,
        "sealedCredentialProjection":credential_observed,"credentialPlaintextInEvidence":false,
        "terminalReceiptVerified":true
    })
}

fn queue_adapter_input(
    runtime: &PrivilegedNodeRuntime,
    issuer: &SigningKey,
    bundle: &Value,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    index: u32,
) {
    runtime
        .queue_ticket(ticket(
            issuer,
            bundle,
            plan,
            request,
            PrivilegedOperation::Input,
            &format!("ptkt_live_codex_input_{index}"),
        ))
        .unwrap();
}

fn leave_active(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
) -> (
    LocalExecutionPlan,
    RuntimeRequest,
    conduit_runtime::PrivilegedRuntimeReceipt,
) {
    start_sleep("custody", provider, issuer, bundle, evidence, 120_000_000)
}

fn start_sleep(
    label: &str,
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    evidence: &Path,
    max_usec: u64,
) -> (
    LocalExecutionPlan,
    RuntimeRequest,
    conduit_runtime::PrivilegedRuntimeReceipt,
) {
    let (plan, request) = case_plan(
        label,
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "120".into()],
        StdioMode::Pipes,
        max_usec,
        evidence,
    );
    let prepared = provider
        .prepare_privileged(
            &request,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Prepare,
                &format!("ptkt_live_{label}_prepare"),
            ),
            plan.clone(),
        )
        .unwrap();
    let started = provider
        .start_privileged(
            &prepared.runtime,
            ticket(
                issuer,
                bundle,
                &plan,
                &request,
                PrivilegedOperation::Start,
                &format!("ptkt_live_{label}_start"),
            ),
            &plan,
        )
        .unwrap();
    assert_eq!(started.runtime.state, RuntimeState::Running);
    (plan, request, started)
}

// Keep each authority input explicit in the live root harness so a test cannot
// accidentally reuse an ambient ticket or target while shortening the call.
#[allow(clippy::too_many_arguments)]
fn stop(
    provider: &PrivilegedNativeProvider,
    issuer: &SigningKey,
    bundle: &Value,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    handle: &conduit_runtime::RuntimeHandle,
    signal: RuntimeSignal,
    ticket_id: &str,
) -> conduit_runtime::PrivilegedRuntimeReceipt {
    let operation = match signal {
        RuntimeSignal::GracefulStop => PrivilegedOperation::GracefulStop,
        RuntimeSignal::ForceStop => PrivilegedOperation::ForceStop,
        _ => unreachable!(),
    };
    let stopped = provider
        .control_privileged(
            handle,
            signal,
            ticket(issuer, bundle, plan, request, operation, ticket_id),
        )
        .unwrap();
    assert_eq!(stopped.runtime.state, RuntimeState::Stopped);
    stopped
}

fn case_plan(
    label: &str,
    executable: PathBuf,
    argv: Vec<String>,
    stdio: StdioMode,
    runtime_max_usec: u64,
    evidence: &Path,
) -> (LocalExecutionPlan, RuntimeRequest) {
    let runtime_id = format!("rt_live_{label}_{}", std::process::id());
    let run_id = format!("run_live_{label}_{}", std::process::id());
    let resources = ResourceCeilings {
        cpu_quota_per_sec_usec: None,
        memory_max_bytes: Some(64 * 1024 * 1024),
        tasks_max: Some(16),
        io_weight: None,
        runtime_max_usec: Some(runtime_max_usec),
    };
    let plan = LocalExecutionPlan {
        plan_version: 1,
        runtime_id: runtime_id.clone(),
        run_id: run_id.clone(),
        operation_id: format!("op_live_{label}_{}", std::process::id()),
        executable: capture_file_identity(&executable, true).unwrap(),
        interpreter: None,
        argv,
        cwd: capture_file_identity(evidence, false).unwrap(),
        systemd_unit: format!(
            "conduit-elevated-live-{label}-{}.service",
            std::process::id()
        ),
        adapter_id: None,
        launch_profile_id: Some("full-device-live".into()),
        environment: BTreeMap::new(),
        environment_value_digests: BTreeMap::new(),
        workspaces: vec![],
        credentials: vec![],
        stdio,
        resources: resources.clone(),
        helper_protocol: conduit_privileged_protocol::PROTOCOL.into(),
        helper_min_version: env!("CARGO_PKG_VERSION").into(),
    };
    let request = RuntimeRequest {
        runtime_id,
        run_id,
        kind: RuntimeKind::Native,
        provider_selector: "privileged-native".into(),
        spec_digest: hex::encode(Sha256::digest(format!("live-spec:{label}").as_bytes())),
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
    (plan, request)
}

fn ticket(
    issuer: &SigningKey,
    bundle: &Value,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    operation: PrivilegedOperation,
    ticket_id: &str,
) -> PrivilegeTicket {
    ticket_with_approval(
        issuer, bundle, plan, request, operation, ticket_id, "always",
    )
}

fn ticket_with_approval(
    issuer: &SigningKey,
    bundle: &Value,
    plan: &LocalExecutionPlan,
    request: &RuntimeRequest,
    operation: PrivilegedOperation,
    ticket_id: &str,
    approval_mode: &str,
) -> PrivilegeTicket {
    let issuer_id = key_id("pkey", issuer.verifying_key().as_bytes());
    let capability: conduit_privileged_protocol::SignedCapability =
        serde_json::from_value(bundle["signedCapability"].clone()).unwrap();
    let now = OffsetDateTime::now_utc();
    let issued = (now - time::Duration::seconds(2)).format(&Rfc3339).unwrap();
    let idempotency_digest = hex::encode(Sha256::digest(ticket_id.as_bytes()));
    let operation_digest = hex::encode(Sha256::digest(
        format!("live-operation:{}", plan.operation_id).as_bytes(),
    ));
    let is_control = !matches!(
        &operation,
        PrivilegedOperation::Prepare | PrivilegedOperation::Start
    );
    let control_digest = is_control.then(|| "77".repeat(32));
    let ticket_operation_id = if is_control {
        format!(
            "op_{}",
            &hex::encode(Sha256::digest(ticket_id.as_bytes()))[..24]
        )
    } else {
        plan.operation_id.clone()
    };
    SignedClaims::sign(
        issuer_id.clone(),
        PrivilegeTicketClaims {
            schema_version: 1,
            protocol: conduit_privileged_protocol::PROTOCOL.into(),
            ticket_id: ticket_id.into(),
            issuer_kind: "control_plane".into(),
            issuer_key_id: issuer_id,
            audience: "conduit-privileged-helper".into(),
            public_origin: bundle["origin"].as_str().unwrap().into(),
            helper_installation_id: bundle["installationId"].as_str().unwrap().into(),
            helper_key_id: capability.claims.receipt_key_id,
            helper_policy_revision: capability.claims.policy_revision,
            helper_policy_digest: capability.claims.policy_digest,
            device_id: bundle["deviceId"].as_str().unwrap().into(),
            device_key_id: bundle["deviceKeyId"].as_str().unwrap().into(),
            device_policy_revision: 1,
            device_revision: 1,
            expected_uid: bundle["uid"].as_u64().unwrap() as u32,
            operation_id: ticket_operation_id,
            idempotency_key_digest: idempotency_digest,
            operation_request_digest: control_digest.clone().unwrap_or(operation_digest),
            run_manifest_digest: "66".repeat(32),
            run_id: plan.run_id.clone(),
            runtime_id: plan.runtime_id.clone(),
            runtime_spec_digest: request.spec_digest.clone(),
            launch_plan_digest: "44".repeat(32),
            control_digest,
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
            approval_mode: approval_mode.into(),
            approval_receipt_digest: (approval_mode != "never").then(|| "55".repeat(32)),
            approval_enforcement: if plan.adapter_id.is_some() {
                ApprovalEnforcement::AdapterMediated
            } else {
                ApprovalEnforcement::ExactCommand
            },
            required_approval_risk_classes: vec![],
            allowed_operation: operation,
            resource_ceilings: plan.resources.clone(),
            issued_at: issued,
            expires_at: (now + time::Duration::minutes(5)).format(&Rfc3339).unwrap(),
            nonce: format!("nonce-{ticket_id}"),
            max_use_count: 1,
        },
        issuer,
    )
    .unwrap()
}

fn limits() -> ResourceLimits {
    ResourceLimits {
        cpu: None,
        memory_bytes: Some(64 * 1024 * 1024),
        pid_limit: Some(16),
        storage_bytes: None,
    }
}
fn existing(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .unwrap()
}
fn state_name(state: RuntimeState) -> String {
    serde_json::to_value(state)
        .unwrap()
        .as_str()
        .unwrap()
        .into()
}
fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}
fn evidence_dir() -> PathBuf {
    PathBuf::from(required("CONDUIT_FULL_DEVICE_E2E_EVIDENCE_DIR"))
}

fn worker_post(path: &str, value: &Value) -> Value {
    let mut child = Command::new("curl")
        .args([
            "--insecure",
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            "15",
            "--request",
            "POST",
            "--header",
            &format!(
                "Authorization: Bearer {}",
                required("CONDUIT_FULL_DEVICE_E2E_WORKER_TOKEN")
            ),
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            &format!("{}{}", required("CONDUIT_FULL_DEVICE_E2E_WORKER_URL"), path),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_jcs::to_vec(value).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "isolated Control Plane request failed: {}; response: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn next_worker_sequence() -> u64 {
    let path = evidence_dir().join("control-plane-sequence");
    let prior = if path.exists() {
        fs::read_to_string(&path).unwrap().parse::<u64>().unwrap()
    } else {
        0
    };
    let next = prior.checked_add(1).unwrap();
    write_private(&path, next.to_string().as_bytes());
    next
}

fn signed_frame(
    frame_type: &str,
    correlation_id: &str,
    payload: Value,
    _identity: &DeviceIdentity,
) -> Value {
    let sequence = next_worker_sequence();
    let message_digest = hex::encode(Sha256::digest(
        format!("{frame_type}:{correlation_id}:{sequence}").as_bytes(),
    ));
    json!({
        "protocol":"conduit.node/1",
        "messageId":format!("nmsg_{}", &message_digest[..24]),
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        "connectionEpoch":"1","direction":"node_to_control",
        "sequence":sequence.to_string(),"type":frame_type,
        "correlationId":correlation_id,
        "payloadDigest":hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap())),
        "payload":payload,
    })
}

fn sign_device_payload(frame_type: &str, payload: &Value, identity: &DeviceIdentity) -> String {
    let transcript = json!({
        "domain":format!("conduit.{frame_type}.v1"),
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        "connectionEpoch":"1","payload":payload,
    });
    identity.sign(&serde_jcs::to_vec(&transcript).unwrap())
}

fn signed_registration_payload(
    bundle: &Value,
    identity: &DeviceIdentity,
    request_id: &str,
    policy_summary: Value,
    policy_revision: u64,
    previous_policy_digest: Option<&str>,
) -> Value {
    let policy_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&policy_summary).unwrap()));
    let policy_unsigned = json!({
        "deviceId":required("CONDUIT_FULL_DEVICE_E2E_DEVICE_ID"),
        "revision":policy_revision,"policyDigest":policy_digest,
        "previousPolicyDigest":previous_policy_digest,"publicSummary":policy_summary,
    });
    let device_policy = json!({
        "revision":policy_revision,"policyDigest":policy_digest,
        "previousPolicyDigest":previous_policy_digest,"publicSummary":policy_unsigned["publicSummary"],
        "signature":identity.sign(&serde_jcs::to_vec(&policy_unsigned).unwrap())
    });
    let unsigned = json!({
        "requestId":request_id,"registrationBundle":bundle,
        "devicePolicy":device_policy,"deviceKeyId":identity.key_id()
    });
    let mut payload = unsigned.clone();
    payload["deviceSignature"] = Value::String(sign_device_payload(
        "privilege.installation_attestation",
        &unsigned,
        identity,
    ));
    payload
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
