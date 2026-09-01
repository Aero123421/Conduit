use conduit_domain::{AnyRunId, DeviceId, LocationId, RunId, Sha256Digest, SourceId};
use conduit_observability::{
    EventDraft, EvidenceLevel, RedactionPolicy, RetentionClass, RunManifest, RunManifestInput,
    Sensitivity, TraceStore,
};
use conduit_runtime::WorkspaceAttachment;
use conduit_workspace::{
    DeviceLocationRegistry, FilesystemIdentity, GitRepository, LocationRecord, RegistryError,
    SnapshotPolicy, SourceKind, SourceRecord, WorktreeManager, create_managed_copy,
    snapshot_folder,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Debug, thiserror::Error)]
pub enum LocalServiceError {
    #[error("source registry failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("workspace preparation failed: {0}")]
    Workspace(String),
    #[error("trace storage failed: {0}")]
    Trace(String),
    #[error("local service I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("local service record is invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalSourceConfig {
    pub source: SourceRecord,
    pub location: LocationRecord,
    pub canonical_path: PathBuf,
    #[serde(default)]
    pub filesystem_identity: Option<FilesystemIdentity>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRevision {
    pub source_id: SourceId,
    pub location_id: LocationId,
    pub location_revision: u64,
    pub mode: WorkspaceMode,
    pub base_commit: Option<String>,
    pub dirty_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    ReadOnly,
    Direct,
    Worktree,
    ManagedCopy,
}

impl WorkspaceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Direct => "direct",
            Self::Worktree => "worktree",
            Self::ManagedCopy => "managed_copy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSource {
    pub source_id: SourceId,
    pub location_id: LocationId,
    pub location_revision: u64,
    pub mode: WorkspaceMode,
    pub host_path: PathBuf,
    pub base_revision: String,
    pub initial_state_digest: Sha256Digest,
    pub repository_identity_digest: Option<Sha256Digest>,
    pub display_path: String,
}

impl PreparedSource {
    pub fn attachment(&self, guest_path: PathBuf) -> WorkspaceAttachment {
        WorkspaceAttachment {
            host_path: self.host_path.clone(),
            guest_path,
            read_only: matches!(self.mode, WorkspaceMode::ReadOnly),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFile {
    #[serde(default)]
    entries: Vec<LocalSourceConfig>,
}

struct SourceState {
    registry: DeviceLocationRegistry,
    entries: Vec<LocalSourceConfig>,
    worktrees: WorktreeManager,
    device_id: Option<DeviceId>,
}

pub struct LocalServices {
    root: PathBuf,
    registry_path: PathBuf,
    sources: Mutex<SourceState>,
    trace: TraceStore,
}

impl LocalServices {
    pub fn open(root: impl AsRef<Path>, cursor_key: [u8; 32]) -> Result<Self, LocalServiceError> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let root = fs::canonicalize(root)?;
        let registry_path = root.join("sources.json");
        let entries = load_registry(&registry_path)?;
        let (registry, device_id) = build_registry(&entries)?;
        let worktrees = WorktreeManager::new(root.join("worktrees"))
            .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
        let trace = TraceStore::open(root.join("traces"), cursor_key)
            .map_err(|error| LocalServiceError::Trace(error.to_string()))?;
        Ok(Self {
            root,
            registry_path,
            sources: Mutex::new(SourceState {
                registry,
                entries,
                worktrees,
                device_id,
            }),
            trace,
        })
    }

    pub fn register_location(&self, entry: LocalSourceConfig) -> Result<(), LocalServiceError> {
        let canonical = fs::canonicalize(&entry.canonical_path)?;
        let metadata = fs::symlink_metadata(&canonical)?;
        if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(LocalServiceError::Invalid(
                "Source path must be an owner-controlled directory".into(),
            ));
        }
        let mut state = self
            .sources
            .lock()
            .map_err(|_| LocalServiceError::Invalid("source registry lock poisoned".into()))?;
        if state
            .device_id
            .as_ref()
            .is_some_and(|device_id| device_id != &entry.location.device_id)
        {
            return Err(LocalServiceError::Invalid(
                "Location belongs to a different Device".into(),
            ));
        }
        if state
            .entries
            .iter()
            .any(|value| value.location.location_id == entry.location.location_id)
        {
            return Err(LocalServiceError::Invalid("location already exists".into()));
        }
        if let Some(existing) = state
            .entries
            .iter()
            .find(|value| value.source.source_id == entry.source.source_id)
        {
            if existing.source != entry.source {
                return Err(LocalServiceError::Invalid(
                    "Source identity conflicts with existing custody".into(),
                ));
            }
        } else {
            state.registry.register_source(entry.source.clone())?;
        }
        state
            .registry
            .register_location(entry.location.clone(), &canonical)?;
        let mut entry = entry;
        entry.canonical_path = canonical;
        entry.filesystem_identity = Some(filesystem_identity(&entry.canonical_path)?);
        state
            .device_id
            .get_or_insert(entry.location.device_id.clone());
        state.entries.push(entry);
        persist_registry(&self.registry_path, &state.entries)
    }

    pub fn bind_device(&self, device_id: DeviceId) -> Result<(), LocalServiceError> {
        let mut state = self
            .sources
            .lock()
            .map_err(|_| LocalServiceError::Invalid("source registry lock poisoned".into()))?;
        if state
            .device_id
            .as_ref()
            .is_some_and(|existing| existing != &device_id)
        {
            return Err(LocalServiceError::Invalid(
                "Source registry belongs to a different Device".into(),
            ));
        }
        state.device_id = Some(device_id);
        Ok(())
    }

    pub fn locations(&self) -> Result<Vec<LocationRecord>, LocalServiceError> {
        let state = self
            .sources
            .lock()
            .map_err(|_| LocalServiceError::Invalid("source registry lock poisoned".into()))?;
        Ok(state.registry.shareable_locations())
    }

    pub fn agent_scratch(&self, run_id: &str) -> PathBuf {
        let path = self.root.join("runs").join(run_id).join("scratch");
        let _ = fs::create_dir_all(&path);
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
        path
    }

    pub fn agent_session_dir(&self, run_id: &str) -> PathBuf {
        let path = self.root.join("runs").join(run_id).join("adapter-session");
        let _ = fs::create_dir_all(&path);
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
        path
    }

    pub fn prepare_sources(
        &self,
        run_id: &str,
        revisions: &[SourceRevision],
    ) -> Result<Vec<PreparedSource>, LocalServiceError> {
        if revisions.len() > 128 {
            return Err(LocalServiceError::Invalid(
                "too many Source revisions".into(),
            ));
        }
        let typed_run = revisions
            .iter()
            .any(|revision| matches!(revision.mode, WorkspaceMode::Worktree))
            .then(|| RunId::parse(run_id.to_owned()))
            .transpose()
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
        let mut state = self
            .sources
            .lock()
            .map_err(|_| LocalServiceError::Invalid("source registry lock poisoned".into()))?;
        let mut prepared = Vec::with_capacity(revisions.len());
        for revision in revisions {
            let resolved = state
                .registry
                .resolve(&revision.location_id, revision.location_revision)?;
            if state
                .device_id
                .as_ref()
                .is_some_and(|device_id| device_id != &resolved.record.device_id)
            {
                return Err(LocalServiceError::Invalid(
                    "Location belongs to a different Device".into(),
                ));
            }
            if resolved.record.source_id != revision.source_id {
                return Err(LocalServiceError::Invalid(
                    "Location does not belong to the requested Source".into(),
                ));
            }
            let configured = state
                .entries
                .iter()
                .find(|entry| entry.location.location_id == revision.location_id)
                .ok_or_else(|| LocalServiceError::Invalid("Location custody is missing".into()))?
                .clone();
            let item = match configured.source.kind {
                SourceKind::GitRepository => prepare_git(
                    &self.root,
                    &mut state.worktrees,
                    typed_run.as_ref(),
                    run_id,
                    revision,
                    &configured,
                    &resolved.canonical_path,
                )?,
                SourceKind::ManagedFolder => prepare_managed(
                    &self.root,
                    run_id,
                    revision,
                    &configured,
                    &resolved.canonical_path,
                )?,
            };
            prepared.push(item);
        }
        persist_preparation(&self.root, run_id, &prepared)?;
        Ok(prepared)
    }

    pub fn reconcile_worktrees(
        &self,
        run_id: &str,
        revisions: &[SourceRevision],
    ) -> Result<(), LocalServiceError> {
        let run_id = RunId::parse(run_id.to_owned())
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
        let state = self
            .sources
            .lock()
            .map_err(|_| LocalServiceError::Invalid("source registry lock poisoned".into()))?;
        for revision in revisions
            .iter()
            .filter(|revision| matches!(revision.mode, WorkspaceMode::Worktree))
        {
            state
                .worktrees
                .reconcile(&run_id, &revision.source_id)
                .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
        }
        Ok(())
    }

    pub fn commit_manifest(&self, manifest: &RunManifest) -> Result<(), LocalServiceError> {
        match self.trace.commit_manifest(manifest) {
            Ok(()) => Ok(()),
            Err(conduit_observability::TraceError::ManifestImmutable) => {
                let existing = self
                    .trace
                    .manifest(&manifest.input.run_id)
                    .map_err(|error| LocalServiceError::Trace(error.to_string()))?;
                if existing.manifest_digest == manifest.manifest_digest {
                    Ok(())
                } else {
                    Err(LocalServiceError::Trace(
                        "immutable Run Manifest conflicts with replay".into(),
                    ))
                }
            }
            Err(error) => Err(LocalServiceError::Trace(error.to_string())),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_visible_event(
        &self,
        run_id: &str,
        device_id: &str,
        sequence: u64,
        boot_id: &str,
        correlation_id: &str,
        event_type: &str,
        payload: Value,
    ) -> Result<Value, LocalServiceError> {
        let run = AnyRunId::parse(run_id.to_owned())
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
        let device = DeviceId::parse(device_id.to_owned())
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
        let event_hash = hex::encode(Sha256::digest(format!(
            "{run_id}:{sequence}:{event_type}:{correlation_id}"
        )));
        let event = self
            .trace
            .append_event(
                &run,
                device,
                sequence,
                EventDraft {
                    event_id: conduit_domain::EventId::parse(format!("evt_{}", &event_hash[..24]))
                        .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
                    event_type: event_type.to_owned(),
                    source_component: "conduit_adapter".into(),
                    observed_at: conduit_domain::UtcTimestamp::parse(super::service::now())
                        .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
                    monotonic_ns: None,
                    boot_id: boot_id.to_owned(),
                    correlation_id: correlation_id.to_owned(),
                    parent_event_id: None,
                    trace_id: None,
                    span_id: None,
                    parent_span_id: None,
                    evidence_level: EvidenceLevel::Observed,
                    sensitivity: Sensitivity::ProjectContent,
                    retention: RetentionClass::R1,
                    payload,
                },
                &RedactionPolicy::default(),
            )
            .map_err(|error| LocalServiceError::Trace(error.to_string()))?;
        serde_json::to_value(event).map_err(|error| LocalServiceError::Invalid(error.to_string()))
    }
}

fn prepare_git(
    root: &Path,
    worktrees: &mut WorktreeManager,
    typed_run_id: Option<&RunId>,
    run_id: &str,
    revision: &SourceRevision,
    configured: &LocalSourceConfig,
    path: &Path,
) -> Result<PreparedSource, LocalServiceError> {
    if matches!(revision.mode, WorkspaceMode::ManagedCopy) {
        return prepare_managed(root, run_id, revision, configured, path);
    }
    let repository = GitRepository::open(path)
        .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
    let observed = repository
        .observe()
        .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
    if configured
        .source
        .repository_identity_digest
        .is_some_and(|digest| digest != observed.identity.digest)
    {
        return Err(LocalServiceError::Workspace(
            "repository identity changed".into(),
        ));
    }
    if revision
        .dirty_digest
        .is_some_and(|digest| digest != observed.diagnostics.status_digest)
    {
        return Err(LocalServiceError::Workspace(
            "Source dirty revision is stale".into(),
        ));
    }
    let base = revision
        .base_commit
        .as_deref()
        .or(observed.diagnostics.head.as_deref())
        .ok_or_else(|| LocalServiceError::Invalid("Git Source has no base commit".into()))?;
    repository
        .verify_object(&format!("{base}^{{commit}}"))
        .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
    if matches!(
        revision.mode,
        WorkspaceMode::ReadOnly | WorkspaceMode::Direct
    ) && observed.diagnostics.head.as_deref() != Some(base)
    {
        return Err(LocalServiceError::Workspace(
            "Source base revision is stale".into(),
        ));
    }
    if matches!(revision.mode, WorkspaceMode::Direct) {
        repository
            .direct_preflight()
            .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
    }
    let host_path = if matches!(revision.mode, WorkspaceMode::Worktree) {
        let run_id = typed_run_id.ok_or_else(|| {
            LocalServiceError::Invalid("worktree Source requires a shared Run ID".into())
        })?;
        match worktrees.lease(run_id, &revision.source_id) {
            Some(lease) => {
                worktrees
                    .reconcile(run_id, &revision.source_id)
                    .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
                lease.path
            }
            None => {
                worktrees
                    .create(
                        &repository,
                        run_id.clone(),
                        revision.source_id.clone(),
                        &configured.source.display_name,
                        base,
                    )
                    .map_err(|error| LocalServiceError::Workspace(error.to_string()))?
                    .path
            }
        }
    } else {
        path.to_path_buf()
    };
    Ok(PreparedSource {
        source_id: revision.source_id.clone(),
        location_id: revision.location_id.clone(),
        location_revision: revision.location_revision,
        mode: revision.mode,
        host_path,
        base_revision: base.to_owned(),
        initial_state_digest: observed.diagnostics.status_digest,
        repository_identity_digest: Some(observed.identity.digest),
        display_path: configured.location.display_path.clone(),
    })
}

fn prepare_managed(
    root: &Path,
    run_id: &str,
    revision: &SourceRevision,
    configured: &LocalSourceConfig,
    path: &Path,
) -> Result<PreparedSource, LocalServiceError> {
    if matches!(revision.mode, WorkspaceMode::Worktree) {
        return Err(LocalServiceError::Workspace(
            "managed folder cannot use Git worktree mode".into(),
        ));
    }
    let policy = SnapshotPolicy::default();
    let snapshot = snapshot_folder(revision.source_id.clone(), path, &policy)
        .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
    let expected_base = revision.base_commit.as_deref();
    if expected_base.is_some_and(|base| base != snapshot.snapshot_id) {
        return Err(LocalServiceError::Workspace(
            "managed Source snapshot revision is stale".into(),
        ));
    }
    let host_path = if matches!(revision.mode, WorkspaceMode::ManagedCopy) {
        let destination = root
            .join("managed-copies")
            .join(run_id)
            .join(revision.source_id.as_str());
        if destination.exists() {
            let existing = snapshot_folder(revision.source_id.clone(), &destination, &policy)
                .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
            if existing.manifest_digest != snapshot.manifest_digest {
                return Err(LocalServiceError::Workspace(
                    "managed copy custody diverged on restart".into(),
                ));
            }
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            create_managed_copy(path, &destination, &snapshot, &policy)
                .map_err(|error| LocalServiceError::Workspace(error.to_string()))?;
        }
        destination
    } else {
        path.to_path_buf()
    };
    Ok(PreparedSource {
        source_id: revision.source_id.clone(),
        location_id: revision.location_id.clone(),
        location_revision: revision.location_revision,
        mode: revision.mode,
        host_path,
        base_revision: snapshot.snapshot_id,
        initial_state_digest: snapshot.manifest_digest,
        repository_identity_digest: None,
        display_path: configured.location.display_path.clone(),
    })
}

fn build_registry(
    entries: &[LocalSourceConfig],
) -> Result<(DeviceLocationRegistry, Option<DeviceId>), LocalServiceError> {
    let mut registry = DeviceLocationRegistry::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut device_id: Option<DeviceId> = None;
    for entry in entries {
        if device_id
            .as_ref()
            .is_some_and(|device_id| device_id != &entry.location.device_id)
        {
            return Err(LocalServiceError::Invalid(
                "Source registry contains Locations for multiple Devices".into(),
            ));
        }
        device_id.get_or_insert(entry.location.device_id.clone());
        let expected = entry.filesystem_identity.as_ref().ok_or_else(|| {
            LocalServiceError::Invalid(
                "Source registry lacks persistent filesystem identity".into(),
            )
        })?;
        let canonical = fs::canonicalize(&entry.canonical_path)?;
        if canonical != entry.canonical_path || &filesystem_identity(&canonical)? != expected {
            return Err(LocalServiceError::Invalid(
                "Location filesystem identity changed while the Node was stopped".into(),
            ));
        }
        if seen.insert(entry.source.source_id.clone()) {
            registry.register_source(entry.source.clone())?;
        }
        registry.register_location(entry.location.clone(), &entry.canonical_path)?;
    }
    Ok((registry, device_id))
}

fn filesystem_identity(path: &Path) -> Result<FilesystemIdentity, LocalServiceError> {
    let metadata = fs::metadata(path)?;
    let file_type = if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    };
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_type: file_type.into(),
    })
}

fn load_registry(path: &Path) -> Result<Vec<LocalSourceConfig>, LocalServiceError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LocalServiceError::Invalid(
            "Source registry must be an owner-only regular file".into(),
        ));
    }
    let bytes = fs::read(path)?;
    if bytes.len() > 1024 * 1024 {
        return Err(LocalServiceError::Invalid(
            "Source registry is too large".into(),
        ));
    }
    let file: RegistryFile = serde_json::from_slice(&bytes)
        .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
    Ok(file.entries)
}

fn persist_registry(path: &Path, entries: &[LocalSourceConfig]) -> Result<(), LocalServiceError> {
    write_owner_only(
        path,
        &serde_json::to_vec(&RegistryFile {
            entries: entries.to_vec(),
        })?,
    )
}

fn persist_preparation(
    root: &Path,
    run_id: &str,
    prepared: &[PreparedSource],
) -> Result<(), LocalServiceError> {
    let directory = root.join("runs").join(run_id);
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let path = directory.join("source-custody.json");
    let bytes = serde_jcs::to_vec(prepared)
        .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
    if path.exists() {
        if fs::read(&path)? == bytes {
            return Ok(());
        }
        return Err(LocalServiceError::Workspace(
            "persisted Source custody conflicts with replay".into(),
        ));
    }
    write_owner_only(&path, &bytes)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), LocalServiceError> {
    let parent = path
        .parent()
        .ok_or_else(|| LocalServiceError::Invalid("record path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary)?;
    use std::io::Write as _;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl From<serde_json::Error> for LocalServiceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Invalid(error.to_string())
    }
}

pub fn build_manifest(
    operation: &super::service::ManifestOperation<'_>,
    prepared: &[PreparedSource],
) -> Result<RunManifest, LocalServiceError> {
    let digest = |bytes: &[u8]| Sha256Digest::from_bytes(Sha256::digest(bytes).into());
    let run_id = AnyRunId::parse(operation.run_id.to_owned())
        .map_err(|error| LocalServiceError::Invalid(error.to_string()))?;
    let source_bindings = prepared
        .iter()
        .map(|source| conduit_observability::ManifestSourceBinding {
            source_id: source.source_id.to_string(),
            location_id: source.location_id.to_string(),
            location_revision: source.location_revision,
            workspace_mode: source.mode.as_str().into(),
            repository_identity_digest: source.repository_identity_digest,
            base_revision: source.base_revision.clone(),
            initial_state_digest: source.initial_state_digest,
            bounded_display_path: source.display_path.chars().take(160).collect(),
            opaque_local_path_ref: digest(source.host_path.as_os_str().as_encoded_bytes()),
        })
        .collect();
    let manifest_hash = hex::encode(Sha256::digest(format!(
        "{}:{}",
        operation.operation_id, operation.request_digest
    )));
    RunManifest::new(RunManifestInput {
        manifest_id: conduit_domain::ManifestId::parse(format!("rman_{}", &manifest_hash[..24]))
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        run_id,
        assignment_id: operation
            .assignment_id
            .map(|value| conduit_domain::AssignmentId::parse(value.to_owned()))
            .transpose()
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        operation_id: operation.operation_id.to_owned(),
        request_digest: Sha256Digest::parse(operation.request_digest)
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        idempotency_key_digest: digest(operation.idempotency_key.as_bytes()),
        actor_id: operation.actor_id.to_owned(),
        client_id: operation.client_id.to_owned(),
        admitted_at: conduit_domain::UtcTimestamp::parse(super::service::now())
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        device_id: DeviceId::parse(operation.device_id.to_owned())
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        node_version: env!("CARGO_PKG_VERSION").into(),
        node_protocol_version: "conduit.node/1".into(),
        boot_id: operation.boot_id.to_owned(),
        capability_digest: Sha256Digest::parse(operation.capability_digest)
            .map_err(|error| LocalServiceError::Invalid(error.to_string()))?,
        local_policy_revision: operation.local_policy_revision,
        runtime_kind: operation.runtime_kind.to_owned(),
        runtime_provider_id: operation.runtime_provider.to_owned(),
        runtime_config_digest: digest(operation.runtime_config),
        effective_capabilities: BTreeMap::new(),
        requested_access_scope: operation.access_scope.to_owned(),
        effective_access_scope: operation.access_scope.to_owned(),
        requested_approval_mode: operation.approval_mode.to_owned(),
        effective_approval_mode: operation.approval_mode.to_owned(),
        policy_revision_digest: digest(&operation.local_policy_revision.to_be_bytes()),
        source_bindings,
        adapter_id: operation.adapter_id.map(str::to_owned),
        adapter_version: operation.adapter_version.map(str::to_owned),
        executable_digest: operation.executable_digest,
        model: operation.model.map(str::to_owned),
        effort: operation.effort.map(str::to_owned),
        context_compiler_version: "none".into(),
        instruction_catalog: vec![],
        skill_catalog: vec![],
        capture_policy_digest: digest(b"normalized-visible-events-only"),
        redaction_policy_digest: digest(b"default-secret-redaction"),
        retention_policy_digest: digest(b"R1"),
        evaluation_tags: BTreeMap::new(),
    })
    .map_err(|error| LocalServiceError::Invalid(error.to_string()))
}
