use conduit_adapters::{
    AdapterCatalog, AdapterChild, AdapterEventKind, AdapterKind, LaunchRequest,
};
use conduit_domain::{DeviceId, LocationId, Sha256Digest, SourceId};
use conduit_node::{
    Node, OperationOffer,
    ipc::{IpcHandler, IpcRequest},
    local::{LocalServices, LocalSourceConfig, SourceRevision, WorkspaceMode},
    local_ipc::LocalIpcService,
};
use conduit_node_store::{DeviceIdentity, NodeStore};
use conduit_runtime::{
    IoMode, LaunchPlan, NativeProvider, NetworkMode, ProcessSupervisor, ResourceLimits,
    RuntimeKind, RuntimeProvider, RuntimeRequest,
};
use conduit_workspace::{GitRepository, LocationRecord, SourceKind, SourceRecord};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use tempfile::tempdir;

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repository(path: &Path) -> (String, Sha256Digest) {
    fs::create_dir_all(path).unwrap();
    run(Command::new("git").arg("init").arg(path));
    run(Command::new("git").args(["-C"]).arg(path).args([
        "config",
        "user.email",
        "fixture@example.invalid",
    ]));
    run(Command::new("git")
        .args(["-C"])
        .arg(path)
        .args(["config", "user.name", "Fixture"]));
    fs::write(path.join("README.md"), "fixture\n").unwrap();
    run(Command::new("git")
        .args(["-C"])
        .arg(path)
        .args(["add", "README.md"]));
    run(Command::new("git")
        .args(["-C"])
        .arg(path)
        .args(["commit", "-m", "fixture"]));
    let observed = GitRepository::open(path).unwrap().observe().unwrap();
    (observed.diagnostics.head.unwrap(), observed.identity.digest)
}

fn source_entry(path: &Path, digest: Sha256Digest) -> LocalSourceConfig {
    LocalSourceConfig {
        source: SourceRecord {
            source_id: SourceId::parse("src_fixture01").unwrap(),
            kind: SourceKind::GitRepository,
            display_name: "fixture".into(),
            repository_identity_digest: Some(digest),
        },
        location: LocationRecord {
            location_id: LocationId::parse("loc_fixture01").unwrap(),
            source_id: SourceId::parse("src_fixture01").unwrap(),
            device_id: DeviceId::parse("dev_fixture01").unwrap(),
            revision: 3,
            display_path: "~/fixture".into(),
        },
        canonical_path: path.into(),
    }
}

#[test]
fn source_revision_failures_and_worktree_restart_are_durable() {
    let directory = tempdir().unwrap();
    let repo = directory.path().join("repo");
    let (head, identity) = repository(&repo);
    let root = directory.path().join("local");
    let local = LocalServices::open(&root, [7; 32]).unwrap();
    local
        .register_location(source_entry(&repo, identity))
        .unwrap();

    let missing = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_missing01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::ReadOnly,
        base_commit: Some(head.clone()),
        dirty_digest: None,
    };
    assert!(local.prepare_sources("run_fixture01", &[missing]).is_err());

    let stale = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 2,
        mode: WorkspaceMode::ReadOnly,
        base_commit: Some(head.clone()),
        dirty_digest: None,
    };
    assert!(
        local
            .prepare_sources("run_fixture01", &[stale])
            .unwrap_err()
            .to_string()
            .contains("stale")
    );

    let missing_revision = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::ReadOnly,
        base_commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
        dirty_digest: None,
    };
    assert!(
        local
            .prepare_sources("run_missing01", &[missing_revision])
            .unwrap_err()
            .to_string()
            .contains("missing")
    );

    let read_only = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::ReadOnly,
        base_commit: Some(head.clone()),
        dirty_digest: None,
    };
    let read_only_prepared = local
        .prepare_sources("run_readonly01", &[read_only])
        .unwrap();
    assert_eq!(
        read_only_prepared[0].host_path,
        fs::canonicalize(&repo).unwrap()
    );
    assert!(read_only_prepared[0].attachment(repo.clone()).read_only);

    let direct = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::Direct,
        base_commit: Some(head.clone()),
        dirty_digest: None,
    };
    assert_eq!(
        local.prepare_sources("run_direct001", &[direct]).unwrap()[0].host_path,
        fs::canonicalize(&repo).unwrap()
    );

    let managed = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::ManagedCopy,
        base_commit: None,
        dirty_digest: None,
    };
    let managed_prepared = local.prepare_sources("run_managed01", &[managed]).unwrap();
    assert_ne!(
        managed_prepared[0].host_path,
        fs::canonicalize(&repo).unwrap()
    );
    assert!(managed_prepared[0].host_path.join("README.md").exists());

    let revision = SourceRevision {
        source_id: SourceId::parse("src_fixture01").unwrap(),
        location_id: LocationId::parse("loc_fixture01").unwrap(),
        location_revision: 3,
        mode: WorkspaceMode::Worktree,
        base_commit: Some(head),
        dirty_digest: None,
    };
    let first = local
        .prepare_sources("run_fixture01", std::slice::from_ref(&revision))
        .unwrap();
    assert!(first[0].host_path.exists());
    drop(local);

    let reopened = LocalServices::open(&root, [7; 32]).unwrap();
    let second = reopened
        .prepare_sources("run_fixture01", std::slice::from_ref(&revision))
        .unwrap();
    assert_eq!(first[0].host_path, second[0].host_path);
    reopened
        .reconcile_worktrees("run_fixture01", &[revision])
        .unwrap();
}

#[test]
fn structured_agent_fixture_completes_without_inference_and_crash_is_visible() {
    let directory = tempdir().unwrap();
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let pi = bin.join("pi");
    fs::write(
        &pi,
        "#!/bin/sh\nIFS= read -r ignored\nprintf '%s\\n' '{\"id\":\"conduit-1\",\"type\":\"response\",\"command\":\"prompt\",\"success\":true}' '{\"type\":\"agent_start\"}' '{\"type\":\"message_update\",\"assistantMessageEvent\":{\"type\":\"text_delta\",\"contentIndex\":0,\"delta\":\"visible fixture response\"}}' '{\"type\":\"agent_end\"}'\n",
    )
    .unwrap();
    fs::set_permissions(&pi, fs::Permissions::from_mode(0o700)).unwrap();
    let prior = std::env::var_os("PATH");
    unsafe { std::env::set_var("PATH", &bin) };
    let request = LaunchRequest {
        cwd: directory.path().into(),
        prompt: Some("fixture prompt".into()),
        native_session_id: None,
        model: None,
        effort: None,
        session_data_dir: Some(directory.path().join("sessions")),
    };
    let (spec, mut driver) = AdapterCatalog::launch(AdapterKind::Pi, &request).unwrap();
    let mut child = AdapterChild::spawn(&spec).unwrap();
    let mut kinds = Vec::new();
    while let Some(record) = child.read_record().unwrap() {
        let (_, events) = driver.on_record(&record).unwrap();
        kinds.extend(events.into_iter().map(|event| event.kind));
    }
    let status = child.try_wait().unwrap().unwrap();
    assert!(status.success());
    assert!(kinds.contains(&AdapterEventKind::AssistantMessageDelta));
    assert!(kinds.contains(&AdapterEventKind::Completed));

    fs::write(&pi, "#!/bin/sh\nIFS= read -r ignored\nexit 17\n").unwrap();
    let (spec, _) = AdapterCatalog::launch(AdapterKind::Pi, &request).unwrap();
    let mut crashed = AdapterChild::spawn(&spec).unwrap();
    assert!(crashed.read_record().unwrap().is_none());
    assert_eq!(crashed.try_wait().unwrap().unwrap().code(), Some(17));
    match prior {
        Some(path) => unsafe { std::env::set_var("PATH", path) },
        None => unsafe { std::env::remove_var("PATH") },
    }
}

fn offer(cwd: &Path) -> OperationOffer {
    let mut manifest = json!({"operationId":"op_fixture01","payloadDigest":""});
    let mut committed = manifest.clone();
    committed.as_object_mut().unwrap().remove("payloadDigest");
    let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&committed).unwrap()));
    manifest["payloadDigest"] = Value::String(digest.clone());
    let runtime = RuntimeRequest {
        runtime_id: "rt_fixture01".into(),
        run_id: "run_fixture01".into(),
        kind: RuntimeKind::Native,
        provider_selector: "native".into(),
        spec_digest: "22".repeat(32),
        image: None,
        resources: ResourceLimits {
            cpu: None,
            memory_bytes: None,
            pid_limit: None,
            storage_bytes: None,
        },
        network: NetworkMode::Open,
        workspaces: vec![],
    };
    OperationOffer {
        operation_id: "op_fixture01".into(),
        idempotency_key: "fixture-idempotency-key".into(),
        request_digest: digest,
        manifest: serde_jcs::to_vec(&manifest).unwrap(),
        local_policy_revision: 1,
        runtime,
        launch: LaunchPlan {
            executable: "/bin/sh".into(),
            argv: vec!["-c".into(), "sleep 30".into()],
            cwd: cwd.into(),
            environment: BTreeMap::new(),
            io_mode: IoMode::Pipes,
            timeout_ms: Some(60_000),
        },
    }
}

fn request(method: &str, params: Value) -> IpcRequest {
    IpcRequest {
        request_id: "req_fixture01".into(),
        method: method.into(),
        version: Some(1),
        revision: None,
        idempotency_key: Some("ipc-fixture-idempotency".into()),
        params,
    }
}

#[test]
fn ipc_runtime_backup_storage_and_enrollment_services_are_real() {
    let directory = tempdir().unwrap();
    let store = NodeStore::open(directory.path().join("data")).unwrap();
    let identity = Arc::new(
        DeviceIdentity::load_or_create(directory.path().join("data/identity/device.ed25519"))
            .unwrap(),
    );
    let supervisor = ProcessSupervisor::open(directory.path().join("data/supervisor")).unwrap();
    let provider: Arc<dyn RuntimeProvider> = Arc::new(NativeProvider::new(supervisor));
    let mut node = Node::new(store.clone());
    node.register_provider(provider.clone());
    let operation = offer(directory.path());
    node.admit(&operation, "native", "project_full", "never")
        .unwrap();
    let node = Arc::new(node);
    let local = Arc::new(
        LocalServices::open(directory.path().join("data/local-services"), [3; 32]).unwrap(),
    );
    let ipc = LocalIpcService::new(
        vec![provider],
        store,
        identity,
        node,
        local,
        directory.path().join("data"),
    )
    .unwrap();

    let started = ipc
        .handle(&request(
            "runtime.start",
            json!({"targetId":"fixture-idempotency-key"}),
        ))
        .unwrap();
    assert_eq!(started["state"], "running");
    assert_eq!(
        ipc.handle(&request("runtime.list", json!({})))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    ipc.handle(&request("runtime.stop", json!({"targetId":"rt_fixture01"})))
        .unwrap();

    let backup = ipc.handle(&request("backup.create", json!({}))).unwrap();
    assert!(backup["backupId"].as_str().unwrap().starts_with("backup_"));
    assert!(PathBuf::from(backup["manifestPath"].as_str().unwrap()).exists());
    let verified = ipc
        .handle(&request(
            "backup.verify",
            json!({"backupId":backup["backupId"]}),
        ))
        .unwrap();
    assert_eq!(verified["verified"], true);
    assert!(
        !ipc.handle(&request("storage.list", json!({})))
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ipc.handle(&request("device.enroll", json!({"nonce":"fixture"})))
            .unwrap()["state"],
        "request_ready"
    );
}
