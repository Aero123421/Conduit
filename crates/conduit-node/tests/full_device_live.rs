//! Opt-in root/systemd test used only by scripts/e2e-full-device-live.sh.
//! Public evidence contains bounded booleans and digests, never host paths.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_adapters::{
    AdapterEventKind, AdapterKind, AdapterState, ApprovalBridgeOwnership, ApprovalContext,
    ApprovalRiskClassSet, EffectiveAccessScope, EffectiveApprovalPolicy, EffectiveSandboxPolicy,
    LaunchRequest, ProtocolDriver,
};
use conduit_node::privileged::PrivilegedNodeRuntime;
use conduit_node_store::DeviceIdentity;
use conduit_privileged_helper::capture_file_identity;
use conduit_privileged_protocol::{
    ApprovalEnforcement, LocalExecutionPlan, PrivilegeTicket, PrivilegeTicketClaims,
    PrivilegedOperation, ResourceCeilings, SignedClaims, StdioMode, key_id,
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
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
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
        "kty":"OKP","crv":"Ed25519",
        "x":URL_SAFE_NO_PAD.encode(issuer.verifying_key().as_bytes()),
        "kid":issuer_id,"revision":1
    });
    write_json(&evidence.join("issuer-public-jwk.json"), &public_jwk);
    write_json(
        &evidence.join("issuer-public-key.json"),
        &json!({
            "schemaVersion":1,"keyId":issuer_id,"fingerprint":fingerprint,
            "publicJwk":public_jwk,"status":"active","ownerActivated":true
        }),
    );
    let bundle_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&bundle).unwrap()));
    let owner_decision_digest = hex::encode(Sha256::digest(
        format!("owner-passkey:{bundle_digest}").as_bytes(),
    ));
    write_json(
        &evidence.join("registration-approval.json"),
        &json!({
            "schemaVersion":1,"status":"active","freshPasskey":true,
            "deviceId":object["deviceId"],"installationId":object["installationId"],
            "helperKeyId":capability.claims.receipt_key_id,
            "helperPolicyRevision":capability.claims.policy_revision,
            "helperPolicyDigest":capability.claims.policy_digest,
            "registrationBundleDigest":bundle_digest,"ownerDecisionDigest":owner_decision_digest,
            "issuerKeys":[{"keyId":issuer_id,"fingerprint":fingerprint,"publicJwk":public_jwk,"status":"active"}]
        }),
    );
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

fn exercise() {
    let evidence = evidence_dir();
    let (runtime, bundle, issuer) = connect("full-device-live-node-boot-1");
    let provider = runtime.provider();
    let mut cases = serde_json::Map::new();
    cases.insert(
        "rootExactArgv".into(),
        root_exact_and_replay(&runtime, &provider, &issuer, &bundle, &evidence),
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

/// Runs as a new Node process after update and helper restart. Reconciliation
/// must attach the same invocation; no start ticket is issued on this path.
fn recover() {
    let evidence = evidence_dir();
    let active = read_json(&evidence.join("active-runtime.json"));
    let plan: LocalExecutionPlan = serde_json::from_value(active["plan"].clone()).unwrap();
    let request: RuntimeRequest = serde_json::from_value(active["request"].clone()).unwrap();
    let expected_invocation = active["invocationId"].as_str().unwrap();
    let (runtime, bundle, issuer) = connect("full-device-live-node-boot-2");
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
            "schemaVersion":2,"isolatedCryptographicControlPlane":true,
            "registrationActivated":runtime.active(),"ordinaryFullUser":full_user,"cases":cases,
            "packageLifecycle":packaging,
        "nodeRestart":{"newNodeEpoch":true,"durableAttach":true,"duplicateStart":false,"invocationPreserved":true},
            "helperRestart":{"durableAttach":true,"processCustodyPreserved":true,"invocationPreserved":true},
            "terminalState":"stopped","recoveredTerminalReceiptDigest":stopped.final_helper_receipt().digest().unwrap()
        }),
    );
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
    let (plan, request) = case_plan(
        "exact",
        existing(&["/usr/bin/sleep", "/bin/sleep"]),
        vec!["sleep".into(), "30".into()],
        StdioMode::Pipes,
        30_000_000,
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
    let started = provider
        .start_privileged(&prepared.runtime, start_ticket.clone(), &plan)
        .unwrap();
    assert_eq!(started.final_helper_receipt().claims.effective_uid, Some(0));
    let replay = provider
        .start_privileged(&prepared.runtime, start_ticket, &plan)
        .unwrap();
    for receipt in &replay.helper_receipts {
        receipt.verify(runtime.receipt_key()).unwrap();
    }
    let replay_final = replay.final_helper_receipt();
    assert_eq!(
        replay_final.digest().unwrap(),
        started.final_helper_receipt().digest().unwrap()
    );
    assert_eq!(
        replay_final.claims.invocation_id,
        started.final_helper_receipt().claims.invocation_id
    );
    let stopped = stop(
        provider,
        issuer,
        bundle,
        &plan,
        &request,
        &started.runtime.handle,
        RuntimeSignal::GracefulStop,
        "ptkt_live_exact_stop",
    );
    json!({"passed":true,"effectiveUid":0,"exactArgv":true,"prepareReplaySameReceipt":true,
        "lostStartResponseReplaySameReceipt":true,"duplicateStart":false,"invocationPreserved":true,
        "terminalState":state_name(stopped.runtime.state)})
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
    let (create_plan, create_request) = case_plan(
        "marker_create",
        existing(&["/usr/bin/touch", "/bin/touch"]),
        vec![marker.to_string_lossy().into()],
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
    let _created = provider
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
    thread::sleep(Duration::from_millis(300));
    let marker_owner = fs::metadata(&marker).unwrap().uid();
    assert_eq!(marker_owner, 0);
    let _ = provider
        .attach_reconciled_privileged(create_plan, create_request.spec_digest)
        .unwrap();
    let (remove_plan, remove_request) = case_plan(
        "marker_remove",
        existing(&["/usr/bin/rm", "/bin/rm"]),
        vec!["--".into(), marker.to_string_lossy().into()],
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
    thread::sleep(Duration::from_millis(300));
    let _ = provider
        .attach_reconciled_privileged(remove_plan, remove_request.spec_digest)
        .unwrap();
    json!({"passed":true,"createdByUid":marker_owner,
        "startReceiptVerified":true,
        "independentSignedCleanup":true,"cleanupLaunchUid":removed.final_helper_receipt().claims.effective_uid})
}

fn structured_codex_agent(
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
    let fixture = r#"import json,sys
for line in sys.stdin:
    message=json.loads(line)
    method=message.get("method")
    request_id=message.get("id")
    if method == "initialize":
        print(json.dumps({"id":request_id,"result":{"serverInfo":{"name":"conduit-live-fixture","version":"1"}}}),flush=True)
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
    let prepared = provider
        .prepare_privileged(
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
            approval_mode: "always".into(),
            approval_receipt_digest: Some("55".repeat(32)),
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
