use crate::{
    Node,
    ipc::{IpcHandler, IpcRequest},
    local::{LocalServices, LocalSourceConfig},
    startup::{
        BACKUP_DATABASE_FILE, BackupManifest, VerifiedBackup, activate_storage_configuration,
        file_digest, stage_database_restore, stage_storage_configuration, valid_backup_id,
        verify_backup,
    },
};
use conduit_adapters::{AdapterCatalog, AdapterKind};
use conduit_domain::{DeviceId, LocationId, Sha256Digest, SourceId};
use conduit_node_store::{
    AdmissionRecord, DeviceIdentity, NodeStore, StorageClass, StorageManager, StorageObject,
};
use conduit_runtime::{DestroyRequest, RuntimeProvider, RuntimeRequest, RuntimeSignal};
use conduit_workspace::{LocationRecord, SourceKind, SourceRecord};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct LocalIpcService {
    providers: Vec<Arc<dyn RuntimeProvider>>,
    store: NodeStore,
    identity: Arc<DeviceIdentity>,
    node: Arc<Node>,
    local: Arc<LocalServices>,
    storage: StorageManager,
    data_root: PathBuf,
}

impl LocalIpcService {
    pub fn new(
        providers: Vec<Arc<dyn RuntimeProvider>>,
        store: NodeStore,
        identity: Arc<DeviceIdentity>,
        node: Arc<Node>,
        local: Arc<LocalServices>,
        data_root: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let data_root = fs::canonicalize(data_root).map_err(|error| error.to_string())?;
        let storage_configuration =
            activate_storage_configuration(&data_root).map_err(|error| error.to_string())?;
        let roots = storage_configuration.root_array();
        let storage = StorageManager::new(
            store.clone(),
            roots[0].clone(),
            roots[1].clone(),
            roots[2].clone(),
            roots[3].clone(),
            storage_configuration.quota_array(),
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            providers,
            store,
            identity,
            node,
            local,
            storage,
            data_root,
        })
    }

    fn runtime_admission(&self, target: &str) -> Result<AdmissionRecord, String> {
        if target.starts_with("rt_") {
            self.store
                .admission_by_runtime_id(target)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "runtime_not_found".into())
        } else {
            self.store
                .admission(target)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "runtime_not_found".into())
        }
    }

    fn runtime_target(&self, request: &IpcRequest) -> Result<AdmissionRecord, String> {
        let target = request
            .params
            .get("targetId")
            .and_then(Value::as_str)
            .or_else(|| request.method.split_once('/').map(|(_, id)| id))
            .ok_or_else(|| "runtime_target_required".to_owned())?;
        self.runtime_admission(target)
    }

    fn runtime_list(&self) -> Result<Value, String> {
        let values = self
            .store
            .admissions()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|admission| {
                let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
                    .map_err(|_| "durable_runtime_request_corrupt".to_owned())?;
                Ok(json!({
                    "runtimeId": runtime.runtime_id,
                    "runId": runtime.run_id,
                    "providerId": admission.provider_id,
                    "kind": runtime.kind,
                    "state": admission.operation.state,
                    "processIdentity": admission.operation.process_identity,
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Value::Array(values))
    }

    fn logs_search(&self, request: &IpcRequest) -> Result<Value, String> {
        let selected_run = request.params.get("runId").and_then(Value::as_str);
        let query = request
            .params
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if query.len() > 1024 {
            return Err("log_query_too_large".into());
        }
        let mut results = Vec::new();
        for admission in self.store.admissions().map_err(|error| error.to_string())? {
            let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
                .map_err(|_| "durable_runtime_request_corrupt".to_owned())?;
            if selected_run.is_some_and(|run_id| run_id != runtime.run_id) {
                continue;
            }
            if admission.operation.last_event_sequence == 0 {
                continue;
            }
            for frame in self
                .store
                .event_range(&runtime.run_id, 1, admission.operation.last_event_sequence)
                .map_err(|error| error.to_string())?
            {
                let value: Value = serde_json::from_slice(&frame.frame)
                    .map_err(|_| "durable_event_corrupt".to_owned())?;
                if query.is_empty() || value.to_string().contains(query) {
                    results.push(value);
                    if results.len() == 128 {
                        return Ok(Value::Array(results));
                    }
                }
            }
        }
        Ok(Value::Array(results))
    }

    fn runtime_show(&self, request: &IpcRequest) -> Result<Value, String> {
        let admission = self.runtime_target(request)?;
        let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
            .map_err(|_| "durable_runtime_request_corrupt".to_owned())?;
        let handle = self
            .node
            .runtime_handle(&admission)
            .map_err(|error| error.to_string())?;
        let observed = self.node.inspect_runtime(&admission.provider_id, &handle);
        Ok(json!({
            "request": runtime,
            "operation": {
                "operationId": admission.operation.operation_id,
                "state": admission.operation.state,
                "requestDigest": admission.operation.request_digest,
            },
            "observed": observed.ok(),
        }))
    }

    fn runtime_signal(&self, request: &IpcRequest, signal: RuntimeSignal) -> Result<Value, String> {
        let admission = self.runtime_target(request)?;
        let handle = self
            .node
            .runtime_handle(&admission)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(
            self.node
                .signal_runtime(&admission.provider_id, &handle, signal)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    fn runtime_snapshot(&self, request: &IpcRequest) -> Result<Value, String> {
        let admission = self.runtime_target(request)?;
        let name = request
            .params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("manual");
        if name.is_empty() || name.len() > 128 {
            return Err("snapshot_name_invalid".into());
        }
        let handle = self
            .node
            .runtime_handle(&admission)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(
            self.node
                .snapshot_runtime(&admission.provider_id, &handle, name)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    fn runtime_archive(&self, request: &IpcRequest) -> Result<Value, String> {
        let admission = self.runtime_target(request)?;
        let handle = self
            .node
            .runtime_handle(&admission)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(
            self.node
                .collect_runtime(&admission.provider_id, &handle)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    fn runtime_destroy(&self, request: &IpcRequest) -> Result<Value, String> {
        let admission = self.runtime_target(request)?;
        let handle = self
            .node
            .runtime_handle(&admission)
            .map_err(|error| error.to_string())?;
        let destroy = DestroyRequest {
            discard_authorized: request
                .params
                .get("discardAuthorized")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            custody_complete: request
                .params
                .get("custodyComplete")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        serde_json::to_value(
            self.node
                .destroy_runtime(&admission.provider_id, &handle, &destroy)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    fn add_location(&self, request: &IpcRequest) -> Result<Value, String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Input {
            source_id: String,
            #[serde(default = "git_kind")]
            source_kind: String,
            display_name: String,
            location_id: String,
            device_id: String,
            revision: u64,
            display_path: String,
            path: PathBuf,
            repository_identity_digest: Option<String>,
        }
        fn git_kind() -> String {
            "git_repository".into()
        }
        let input: Input = serde_json::from_value(request.params.clone())
            .map_err(|error| format!("location_request_invalid:{error}"))?;
        let kind = match input.source_kind.as_str() {
            "git_repository" => SourceKind::GitRepository,
            "managed_folder" => SourceKind::ManagedFolder,
            _ => return Err("source_kind_invalid".into()),
        };
        let entry = LocalSourceConfig {
            source: SourceRecord {
                source_id: SourceId::parse(input.source_id).map_err(|error| error.to_string())?,
                kind,
                display_name: input.display_name,
                repository_identity_digest: input
                    .repository_identity_digest
                    .as_deref()
                    .map(Sha256Digest::parse)
                    .transpose()
                    .map_err(|error| error.to_string())?,
            },
            location: LocationRecord {
                location_id: LocationId::parse(input.location_id)
                    .map_err(|error| error.to_string())?,
                source_id: SourceId::parse(
                    request.params["sourceId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
                .map_err(|error| error.to_string())?,
                device_id: DeviceId::parse(input.device_id).map_err(|error| error.to_string())?,
                revision: input.revision,
                display_path: input.display_path,
            },
            canonical_path: input.path,
            filesystem_identity: None,
        };
        let result = serde_json::to_value(&entry.location).map_err(|error| error.to_string())?;
        self.local
            .register_location(entry)
            .map_err(|error| error.to_string())?;
        Ok(result)
    }

    fn storage_list(&self) -> Result<Value, String> {
        serde_json::to_value(self.storage.list().map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn storage_target(&self, request: &IpcRequest) -> Result<String, String> {
        request
            .params
            .get("targetId")
            .and_then(Value::as_str)
            .or_else(|| request.method.split_once('/').map(|(_, id)| id))
            .map(str::to_owned)
            .ok_or_else(|| "storage_target_required".into())
    }

    fn storage_class(request: &IpcRequest) -> Result<StorageClass, String> {
        match request.params.get("class").and_then(Value::as_str) {
            Some("hot") => Ok(StorageClass::Hot),
            Some("archive") => Ok(StorageClass::Archive),
            Some("backup") => Ok(StorageClass::Backup),
            Some("cache") => Ok(StorageClass::Cache),
            _ => Err("storage_class_invalid".into()),
        }
    }

    fn configure_storage(&self, request: &IpcRequest) -> Result<Value, String> {
        let (path, configuration) =
            stage_storage_configuration(&self.data_root, request.params.clone())
                .map_err(|error| error.to_string())?;
        Ok(json!({
            "configurationPath": path,
            "configuration": configuration,
            "state": "pending_restart",
            "applied": false,
            "restartRequired": true,
        }))
    }

    fn backup_create(&self) -> Result<Value, String> {
        let seed = format!(
            "{}:{}",
            now(),
            self.store
                .connection_epoch()
                .map_err(|error| error.to_string())?
        );
        let digest = hex::encode(Sha256::digest(seed));
        let backup_id = format!("backup_{}", &digest[..24]);
        let directory = self.storage.root(StorageClass::Backup).join(&backup_id);
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let database = directory.join(BACKUP_DATABASE_FILE);
        self.store
            .backup_database(&database)
            .map_err(|error| error.to_string())?;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let database_digest = file_digest(&database).map_err(|error| error.to_string())?;
        let manifest_path = directory.join("manifest.json");
        let database_size = fs::metadata(&database)
            .map_err(|error| error.to_string())?
            .len();
        let manifest = BackupManifest::signed(
            &self.identity,
            backup_id.clone(),
            now(),
            database_digest.clone(),
            database_size,
            self.store
                .journal_generation()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let manifest_bytes = manifest
            .canonical_bytes()
            .map_err(|error| error.to_string())?;
        write_owner_only(&manifest_path, &manifest_bytes)?;
        let size = database_size + manifest_bytes.len() as u64;
        self.storage
            .reserve(&StorageObject {
                object_id: format!("obj_{}", &digest[..24]),
                class: StorageClass::Backup,
                path: directory,
                size_bytes: size,
                pinned: true,
                custody_count: 1,
                contains_credentials: false,
                collected: true,
            })
            .map_err(|error| error.to_string())?;
        Ok(
            json!({"backupId":backup_id,"manifestPath":manifest_path,"databaseDigest":database_digest,"custodyComplete":true}),
        )
    }

    fn backup_manifest(&self, request: &IpcRequest) -> Result<VerifiedBackup, String> {
        let backup_root = fs::canonicalize(self.storage.root(StorageClass::Backup))
            .map_err(|error| error.to_string())?;
        let backup_id = request.params.get("backupId").and_then(Value::as_str);
        let target_id = request.params.get("targetId").and_then(Value::as_str);
        if backup_id
            .zip(target_id)
            .is_some_and(|(left, right)| left != right)
        {
            return Err("backup_id_conflict".into());
        }
        let expected_id = backup_id.or(target_id);
        if expected_id.is_some_and(|id| !valid_backup_id(id)) {
            return Err("backup_id_invalid".into());
        }
        let requested =
            if let Some(path) = request.params.get("manifestPath").and_then(Value::as_str) {
                PathBuf::from(path)
            } else if let Some(id) = expected_id {
                backup_root.join(id).join("manifest.json")
            } else {
                return Err("backup_id_or_manifest_path_required".into());
            };
        verify_backup(&self.identity, &backup_root, &requested, expected_id)
            .map_err(|error| error.to_string())
    }

    fn backup_verify(&self, request: &IpcRequest) -> Result<Value, String> {
        let backup = self.backup_manifest(request)?;
        Ok(
            json!({"backupId":backup.manifest.backup_id,"manifestPath":backup.manifest_path,"verified":true,"databaseDigest":backup.manifest.database_digest,"databaseSize":backup.manifest.database_size,"journalGeneration":backup.manifest.journal_generation}),
        )
    }

    fn backup_restore(&self, request: &IpcRequest) -> Result<Value, String> {
        let backup = self.backup_manifest(request)?;
        stage_database_restore(&self.data_root, &backup).map_err(|error| error.to_string())?;
        let pending = self.data_root.join("restore-pending.sqlite3");
        Ok(
            json!({"backupId":backup.manifest.backup_id,"stagedPath":pending,"state":"pending_restart","applied":false,"restartRequired":true,"custodyVerified":true}),
        )
    }

    fn enrollment_request(&self, request: &IpcRequest) -> Result<Value, String> {
        let nonce = request
            .params
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or("local-enrollment-request");
        if nonce.len() > 512 || nonce.chars().any(char::is_control) {
            return Err("enrollment_nonce_invalid".into());
        }
        let transcript = serde_jcs::to_vec(&json!({
            "keyId":self.identity.key_id(),
            "publicKey":self.identity.public_key_base64url(),
            "nonce":nonce,
        }))
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "keyId":self.identity.key_id(),
            "publicKey":self.identity.public_key_base64url(),
            "nonce":nonce,
            "proof":self.identity.sign(&transcript),
            "state":"request_ready",
            "externalEnrollmentRequired":true,
        }))
    }

    fn rotate_key(&self) -> Result<Value, String> {
        let pending = self.data_root.join("identity/pending-device.ed25519");
        if pending.exists() {
            return Err("key_rotation_already_pending".into());
        }
        let candidate =
            DeviceIdentity::load_or_create(&pending).map_err(|error| error.to_string())?;
        let transcript = serde_jcs::to_vec(&json!({
            "oldKeyId":self.identity.key_id(),
            "newKeyId":candidate.key_id(),
            "newPublicKey":candidate.public_key_base64url(),
        }))
        .map_err(|error| error.to_string())?;
        Ok(json!({
            "oldKeyId":self.identity.key_id(),
            "newKeyId":candidate.key_id(),
            "newPublicKey":candidate.public_key_base64url(),
            "continuityProof":self.identity.sign(&transcript),
            "state":"pending_external_confirmation",
        }))
    }
}

impl IpcHandler for LocalIpcService {
    fn handle(&self, request: &IpcRequest) -> Result<Value, String> {
        match request.method.as_str() {
            "health" => {
                self.store.integrity_check().map_err(|error| error.to_string())?;
                Ok(json!({"status":"ready","keyId":self.identity.key_id(),"connectionEpoch":self.store.connection_epoch().map_err(|error|error.to_string())?.to_string()}))
            }
            "doctor" | "device.doctor" => Ok(Value::Array(
                self.providers
                    .iter()
                    .map(|provider| provider.probe().map(|value| serde_json::to_value(value).unwrap_or_else(|_| json!({"providerId":provider.provider_id(),"error":"receipt_encoding_failed"}))).unwrap_or_else(|error|json!({"providerId":provider.provider_id(),"capabilities":[],"error":error.to_string()})))
                    .collect(),
            )),
            "device.enroll" => self.enrollment_request(request),
            "device.rotate_key" => self.rotate_key(),
            "project.add_location" => self.add_location(request),
            "agent.probe" => {
                let selected = request.params.get("adapterId").and_then(Value::as_str);
                let probes = AdapterKind::ALL.into_iter().filter(|kind| selected.is_none_or(|value| value == kind.as_str())).map(AdapterCatalog::discover).collect::<Vec<_>>();
                serde_json::to_value(probes).map_err(|error| error.to_string())
            }
            "runtime.list" => self.runtime_list(),
            method if method.starts_with("runtime.show/") => self.runtime_show(request),
            "runtime.start" => {
                let admission = self.runtime_target(request)?;
                serde_json::to_value(self.node.start(&admission.operation.idempotency_key).map_err(|error|error.to_string())?).map_err(|error|error.to_string())
            }
            "runtime.stop" => self.runtime_signal(request, RuntimeSignal::GracefulStop),
            "runtime.pause" => self.runtime_signal(request, RuntimeSignal::Pause),
            "runtime.resume" => self.runtime_signal(request, RuntimeSignal::Resume),
            "runtime.snapshot" => self.runtime_snapshot(request),
            "runtime.archive" => self.runtime_archive(request),
            "runtime.restore" => Err("runtime_restore_requires_provider_snapshot_import".into()),
            "runtime.destroy" => self.runtime_destroy(request),
            "logs.search" => self.logs_search(request),
            method if method.starts_with("logs.show/") => {
                let run_id = method.split_once('/').unwrap().1;
                let admission = self.store.admissions().map_err(|error|error.to_string())?.into_iter().find(|admission| serde_json::from_slice::<RuntimeRequest>(&admission.runtime_request).is_ok_and(|runtime| runtime.run_id == run_id)).ok_or_else(||"run_not_found".to_owned())?;
                let through = admission.operation.last_event_sequence.max(1);
                let frames = self.store.event_range(run_id, 1, through).unwrap_or_default();
                Ok(Value::Array(frames.into_iter().filter_map(|frame|serde_json::from_slice(&frame.frame).ok()).collect()))
            }
            "logs.export" => {
                let run_id = request.params.get("runId").and_then(Value::as_str).ok_or_else(||"run_id_required".to_owned())?;
                let path = self.data_root.join("exports").join(format!("{run_id}.json"));
                let values = self.store.event_range(run_id,1,u64::MAX).unwrap_or_default().into_iter().filter_map(|frame|serde_json::from_slice::<Value>(&frame.frame).ok()).collect::<Vec<_>>();
                write_owner_only(&path,&serde_jcs::to_vec(&values).map_err(|error|error.to_string())?)?;
                Ok(json!({"runId":run_id,"path":path,"eventCount":values.len()}))
            }
            "storage.list" => self.storage_list(),
            method if method.starts_with("storage.show/") => serde_json::to_value(self.storage.get(method.split_once('/').unwrap().1).map_err(|error|error.to_string())?).map_err(|error|error.to_string()),
            "storage.configure" => self.configure_storage(request),
            "storage.pin" => { let id=self.storage_target(request)?; self.storage.pin(&id,true).map_err(|error|error.to_string())?; Ok(json!({"objectId":id,"pinned":true})) },
            "storage.unpin" => { let id=self.storage_target(request)?; self.storage.pin(&id,false).map_err(|error|error.to_string())?; Ok(json!({"objectId":id,"pinned":false})) },
            "storage.move" => { let id=self.storage_target(request)?; let path=self.storage.move_class(&id,Self::storage_class(request)?).map_err(|error|error.to_string())?; Ok(json!({"objectId":id,"path":path})) },
            "storage.restore" => { let id=self.storage_target(request)?; let path=self.storage.move_class(&id,StorageClass::Hot).map_err(|error|error.to_string())?; Ok(json!({"objectId":id,"path":path,"class":"hot"})) },
            "backup.create" => self.backup_create(),
            "backup.verify" => self.backup_verify(request),
            "backup.restore" => self.backup_restore(request),
            _ => Err("method_unknown".into()),
        }
    }
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "path_parent_missing".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(temporary, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
