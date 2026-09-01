use conduit_node::ipc::{IpcRequest, IpcResponse, read_frame, write_frame};
use conduit_node::{Node, OperationOffer};
use conduit_node_store::NodeStore;
use conduit_runtime::{
    IoMode, LaunchPlan, NativeProvider, NetworkMode, ProcessSupervisor, ResourceLimits,
    RuntimeKind, RuntimeProvider, RuntimeRequest, RuntimeState,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tempfile::tempdir;

fn start(binary: &str, data: &Path, socket: &Path) -> Child {
    Command::new(binary)
        .args(["serve", "--data-dir"])
        .arg(data)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "node exited before binding IPC"
        );
        if socket.exists() && UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("node did not bind IPC within deadline")
}

fn health(socket: &Path, request_id: &str) -> IpcResponse {
    let mut stream = UnixStream::connect(socket).unwrap();
    write_frame(
        &mut stream,
        &IpcRequest {
            request_id: request_id.into(),
            method: "health".into(),
            version: Some(1),
            revision: None,
            idempotency_key: None,
            params: serde_json::json!({}),
        },
    )
    .unwrap();
    read_frame(&mut stream).unwrap()
}

#[test]
fn service_ipc_restart_and_journal_are_live() {
    let root = tempdir().unwrap();
    let data = root.path().join("data");
    let runtime = root.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = runtime.join("node.sock");
    let binary = env!("CARGO_BIN_EXE_conduit-node");

    let mut first = start(binary, &data, &socket);
    wait_for_socket(&mut first, &socket);
    let response = health(&socket, "req-health-0001");
    assert!(response.ok);
    assert_eq!(response.request_id, "req-health-0001");
    assert_eq!(response.result.unwrap()["status"], "ready");
    first.kill().unwrap();
    first.wait().unwrap();

    NodeStore::open(&data).unwrap().integrity_check().unwrap();
    let mut second = start(binary, &data, &socket);
    wait_for_socket(&mut second, &socket);
    let response = health(&socket, "req-health-0002");
    assert!(response.ok);
    assert_eq!(response.result.unwrap()["connectionEpoch"], "0");
    second.kill().unwrap();
    second.wait().unwrap();
}

#[test]
fn native_quick_operation_is_exact_once_and_durable() {
    let root = tempdir().unwrap();
    let store = NodeStore::open(root.path().join("store")).unwrap();
    let provider: std::sync::Arc<dyn RuntimeProvider> = std::sync::Arc::new(NativeProvider::new(
        ProcessSupervisor::open(root.path().join("supervisor")).unwrap(),
    ));
    let mut operation = serde_json::json!({"operationId":"op_e2e_native_01"});
    let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&operation).unwrap()));
    operation["payloadDigest"] = serde_json::Value::String(digest.clone());
    let request = OperationOffer {
        operation_id: "op_e2e_native_01".into(),
        idempotency_key: "e2e-native-idempotency-key".into(),
        request_digest: digest,
        manifest: serde_jcs::to_vec(&operation).unwrap(),
        local_policy_revision: 1,
        runtime: RuntimeRequest {
            runtime_id: "rt_e2e_native_01".into(),
            run_id: "run_e2e_native_01".into(),
            kind: RuntimeKind::Native,
            provider_selector: "native".into(),
            spec_digest: "33".repeat(32),
            image: None,
            resources: ResourceLimits {
                cpu: None,
                memory_bytes: None,
                pid_limit: None,
                storage_bytes: None,
            },
            network: NetworkMode::Open,
            workspaces: vec![],
        },
        launch: LaunchPlan {
            executable: "/bin/sh".into(),
            argv: vec!["-c".into(), "printf e2e-native".into()],
            cwd: root.path().into(),
            environment: Default::default(),
            io_mode: IoMode::Pipes,
            timeout_ms: Some(5_000),
        },
    };
    let mut node = Node::new(store.clone());
    node.register_provider(provider);
    assert_eq!(
        node.admit(&request, "native", "project_full", "never")
            .unwrap()
            .disposition,
        "admitted"
    );
    assert!(matches!(
        node.admit(&request, "native", "full_device", "always"),
        Err(conduit_node::NodeError::Rejected(reason))
            if reason == "full_device_capability_unavailable"
    ));
    let started = node.start(&request.idempotency_key).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observed = node.inspect_runtime("native", &started.handle).unwrap();
        if observed.state == RuntimeState::Stopped {
            assert_eq!(observed.exit_code, Some(0));
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(node);
    let reopened = NodeStore::open(root.path().join("store")).unwrap();
    let admission = reopened
        .admission(&request.idempotency_key)
        .unwrap()
        .unwrap();
    assert_eq!(admission.provider_id, "native");
    assert_eq!(admission.access_scope, "project_full");
    assert_eq!(admission.approval_policy, "never");
}
