use crate::{
    AdmissionReceipt, Node, NodeError, OperationOffer,
    batching::{
        AckAccumulator, BatchError, EVENT_BATCH_MAX_EVENTS, EventAccumulator, EventBatch,
        HealthState, HealthTracker, replay_batch,
    },
    local::{LocalServices, PreparedSource, SourceRevision, build_manifest},
    transport::{Envelope, TransportError, WssClient},
    verify_operation_commitment,
};
use conduit_adapters::{
    AdapterCatalog, AdapterChild, AdapterEvent, AdapterEventKind, AdapterKind, AdapterOperation,
    AdapterState, ApprovalBridgeOwnership, ApprovalContext, ApprovalRiskClassSet,
    EffectiveAccessScope, EffectiveApprovalPolicy, EffectiveSandboxPolicy, LaunchRequest,
    ProtocolDriver,
};
use conduit_domain::{DeviceId, Sha256Digest};
use conduit_node_store::{
    ControlEffectResult, DeviceIdentity, Direction, OperationState, ReceiveResult, StoreError,
};
use conduit_observability::RawRecord;
use conduit_runtime::{
    DestroyRequest, IoMode, LaunchPlan, NetworkMode, ProcessSupervisor, ResourceLimits,
    RuntimeHandle, RuntimeKind, RuntimeRequest, RuntimeSignal, RuntimeState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Batch(#[from] BatchError),
    #[error("service configuration invalid: {0}")]
    Config(String),
    #[error("service payload unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaunchProfile {
    pub provider_id: String,
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default = "pipes")]
    pub io_mode: IoMode,
    pub timeout_ms: Option<u64>,
}
fn pipes() -> IoMode {
    IoMode::Pipes
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalPolicy {
    pub revision: u64,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub access_scopes: Vec<String>,
    #[serde(default)]
    pub approval_modes: Vec<String>,
    #[serde(default)]
    pub required_approval_risk_classes: Vec<String>,
    #[serde(default)]
    pub launch_profiles: Vec<String>,
    pub max_cpu: Option<f64>,
    pub max_memory_bytes: Option<u64>,
    pub max_storage_bytes: Option<u64>,
    #[serde(default)]
    pub allow_full_access_without_approval: bool,
}
impl LocalPolicy {
    fn evaluate(
        &self,
        operation: &WireOperation,
        launch_profile: &str,
    ) -> Result<(), ServiceError> {
        if operation.access_scope == "full_device" {
            return Err(ServiceError::Unavailable(
                "full_device_capability_unavailable".into(),
            ));
        }
        let provider = normalize_provider(&operation.runtime.provider_id);
        if !self
            .capabilities
            .iter()
            .any(|value| value == &operation.capability)
            || !self.providers.iter().any(|value| value == provider)
            || !self
                .access_scopes
                .iter()
                .any(|value| value == &operation.access_scope)
            || !self
                .approval_modes
                .iter()
                .any(|value| value == &operation.approval_mode)
            || !self
                .launch_profiles
                .iter()
                .any(|value| value == launch_profile)
        {
            return Err(ServiceError::Unavailable("local_policy_denied".into()));
        }
        if matches!(operation.access_scope.as_str(), "full_user" | "full_device")
            && operation.approval_mode == "never"
            && !self.allow_full_access_without_approval
        {
            return Err(ServiceError::Unavailable(
                "local_policy_explicit_full_access_never_required".into(),
            ));
        }
        if operation
            .runtime
            .cpu_limit
            .zip(self.max_cpu)
            .is_some_and(|(v, max)| v > max)
            || operation
                .runtime
                .memory_bytes
                .zip(self.max_memory_bytes)
                .is_some_and(|(v, max)| v > max)
            || operation
                .runtime
                .storage_bytes
                .zip(self.max_storage_bytes)
                .is_some_and(|(v, max)| v > max)
        {
            return Err(ServiceError::Unavailable(
                "local_policy_resource_ceiling".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePolicyConfig {
    #[serde(rename = "localPolicy")]
    pub local_policy: LocalPolicy,
    pub profiles: HashMap<String, LaunchProfile>,
}

pub fn load_launch_profiles(path: &Path) -> Result<NodePolicyConfig, ServiceError> {
    if !path.exists() {
        return Err(ServiceError::Config(
            "owner-only local policy configuration is required for remote work".into(),
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(|e| ServiceError::Config(e.to_string()))?;
    if !meta.file_type().is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(ServiceError::Config(
            "launch profile file must be owner-only regular file".into(),
        ));
    }
    let bytes = fs::read(path).map_err(|e| ServiceError::Config(e.to_string()))?;
    if bytes.len() > 1024 * 1024 {
        return Err(ServiceError::Config("launch profile file too large".into()));
    }
    let mut file: NodePolicyConfig =
        serde_json::from_slice(&bytes).map_err(|e| ServiceError::Config(e.to_string()))?;
    if file.local_policy.revision == 0 {
        return Err(ServiceError::Config(
            "local policy revision must be positive".into(),
        ));
    }
    for profile in file.profiles.values_mut() {
        profile.executable = fs::canonicalize(&profile.executable)
            .map_err(|_| ServiceError::Config("launch profile executable unavailable".into()))?;
        profile.cwd = fs::canonicalize(&profile.cwd)
            .map_err(|_| ServiceError::Config("launch profile cwd unavailable".into()))?;
        if !profile.executable.is_file()
            || profile.argv.len() > 256
            || profile.environment.len() > 128
        {
            return Err(ServiceError::Config("launch profile exceeds bounds".into()));
        }
    }
    Ok(file)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRuntime {
    kind: String,
    provider_id: String,
    configuration_revision: u64,
    cpu_limit: Option<f64>,
    memory_bytes: Option<u64>,
    storage_bytes: Option<u64>,
    #[serde(rename = "gpuCount")]
    _gpu_count: Option<u32>,
    network_mode: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOperation {
    schema_version: u32,
    operation_id: String,
    idempotency_key: String,
    #[serde(default = "default_actor_id")]
    actor_principal_id: String,
    #[serde(default = "default_client_id")]
    client_id: String,
    device_id: String,
    #[serde(rename = "projectId")]
    _project_id: Option<String>,
    #[serde(rename = "sessionId")]
    _session_id: Option<String>,
    assignment_id: Option<String>,
    run_id: Option<String>,
    capability: String,
    source_revisions: Vec<SourceRevision>,
    runtime: WireRuntime,
    access_scope: String,
    approval_mode: String,
    required_approval_risk_classes: Vec<String>,
    #[serde(rename = "connectorPolicyId")]
    _connector_policy_id: String,
    connector_policy_revision: u64,
    arguments: Value,
    payload_digest: String,
    issued_at: String,
    expires_at: String,
    valid_for_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOperationApproval {
    approval_id: String,
    operation_id: String,
    run_id: String,
    operation_digest: String,
    decision: String,
    #[serde(default)]
    reuse_scope: Option<String>,
    controller_epoch: String,
    issued_at: String,
    expires_at: String,
    valid_for_ms: u64,
    receipt_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireOperationControl {
    operation_id: String,
    idempotency_key: String,
    target_run_id: String,
    target_controller_epoch: String,
    target_digest: String,
    expected_state: String,
    expected_revision: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRuntimeControl {
    operation_id: String,
    idempotency_key: String,
    target_run_id: String,
    target_runtime_id: String,
    target_handle_digest: String,
    target_controller_epoch: String,
    target_digest: String,
    expected_state: String,
    expected_revision: String,
    control: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    snapshot_name: Option<String>,
    #[serde(default)]
    discard_authorized: Option<bool>,
    #[serde(default)]
    custody_complete: Option<bool>,
}
fn default_actor_id() -> String {
    "local-owner".into()
}
fn default_client_id() -> String {
    "conduit-node".into()
}

pub struct ManifestOperation<'a> {
    pub operation_id: &'a str,
    pub idempotency_key: &'a str,
    pub request_digest: &'a str,
    pub run_id: &'a str,
    pub assignment_id: Option<&'a str>,
    pub actor_id: &'a str,
    pub client_id: &'a str,
    pub device_id: &'a str,
    pub boot_id: &'a str,
    pub capability_digest: &'a str,
    pub local_policy_revision: u64,
    pub runtime_kind: &'a str,
    pub runtime_provider: &'a str,
    pub runtime_config: &'a [u8],
    pub access_scope: &'a str,
    pub approval_mode: &'a str,
    pub adapter_id: Option<&'a str>,
    pub adapter_version: Option<&'a str>,
    pub executable_digest: Option<Sha256Digest>,
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
    pub context_compiler_version: Option<&'a str>,
    pub context_snapshot_id: Option<&'a str>,
    pub context_snapshot_digest: Option<&'a str>,
    pub context_content_digest: Option<&'a str>,
    pub context_bytes: Option<u64>,
}
struct Active {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    provider_id: String,
    handle: RuntimeHandle,
    journal_state: OperationState,
    controller_epoch: u64,
    revision: u64,
}

struct AgentActive {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    runtime_id: String,
    provider_id: String,
    handle: RuntimeHandle,
    child: AdapterChild,
    driver: ProtocolDriver,
    adapter_kind: AdapterKind,
    actor_principal_id: String,
    client_id: String,
    access_scope: String,
    approval_mode: String,
    effective_required_approval_risk_classes: Vec<String>,
    local_policy_revision: u64,
    controller_epoch: u64,
    revision: u64,
    event_sequence: u64,
    raw_sequence: u64,
    settlement_policy: AgentSettlementPolicy,
    session_state: AgentSessionState,
    idle_timeout_ms: u64,
    lease_expires_at_unix_ms: Option<u64>,
    prepared_sources: Vec<PreparedSource>,
    parent_baseline_id: Value,
    source_baseline_revisions: BTreeMap<String, Value>,
    verification_policy: Value,
}

#[derive(Clone)]
struct RuntimeCustody {
    start_operation_id: String,
    run_id: String,
    request_digest: String,
    provider_id: String,
    handle: RuntimeHandle,
    state: RuntimeState,
    controller_epoch: u64,
    revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSettlementPolicy {
    CloseOnSettle,
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentSessionState {
    Running,
    WaitingInput,
    ClosingCompleted,
    ClosingCancelled,
    ClosingTimedOut,
}

struct PendingAgentApproval {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    adapter_kind: AdapterKind,
    actor_principal_id: String,
    client_id: String,
    access_scope: String,
    approval_mode: String,
    effective_required_approval_risk_classes: Vec<String>,
    local_policy_revision: u64,
    controller_epoch: u64,
    provider_request_id: Value,
    method: String,
    parameters_digest: String,
    arguments_summary: Value,
    expires_at_unix_ms: u64,
}

struct PendingReconciliation {
    id: String,
    control_applied_through: u64,
}

pub struct NodeService {
    node: Arc<Node>,
    identity: Arc<DeviceIdentity>,
    control_url: String,
    device_id: String,
    capability_digest: String,
    node_boot_id: String,
    profiles: HashMap<String, LaunchProfile>,
    local_policy: LocalPolicy,
    local: Arc<LocalServices>,
    supervisor: ProcessSupervisor,
    message_counter: u64,
    active: HashMap<String, Active>,
    agents: HashMap<String, AgentActive>,
    runtime_custody: HashMap<String, RuntimeCustody>,
    pending_reconciliation: Option<PendingReconciliation>,
    event_accumulators: HashMap<String, EventAccumulator>,
    ack_accumulator: AckAccumulator,
    health_tracker: HealthTracker,
    /// The latest health envelope is retained in-process so an unchanged
    /// checkpoint can replay its durable wire identity instead of allocating
    /// another node sequence and outbox row.  A reconnect always emits a new
    /// envelope for the new connection epoch.
    last_health: Option<Envelope>,
    /// ACK-only control frames advance the applied frontier but do not change
    /// semantic health.  Only a non-ACK control frame asks the next health
    /// observation to rebase its frontier; otherwise checkpoints replay the
    /// exact health envelope and avoid an ACK/health feedback allocation loop.
    health_frontier_dirty: bool,
    health_fault: Option<String>,
}
impl NodeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: Arc<Node>,
        identity: Arc<DeviceIdentity>,
        control_url: String,
        device_id: String,
        capability_digest: String,
        node_boot_id: String,
        config: NodePolicyConfig,
        local: Arc<LocalServices>,
        supervisor: ProcessSupervisor,
    ) -> Result<Self, ServiceError> {
        if !device_id.starts_with("dev_")
            || capability_digest.len() != 64
            || node_boot_id.len() < 16
        {
            return Err(ServiceError::Config("invalid transport identity".into()));
        }
        local
            .bind_device(
                DeviceId::parse(device_id.clone())
                    .map_err(|error| ServiceError::Config(error.to_string()))?,
            )
            .map_err(|error| ServiceError::Config(error.to_string()))?;
        for admission in node.store().nonterminal_admissions()? {
            let value: Value = serde_json::from_slice(&admission.operation.manifest)
                .map_err(|_| ServiceError::Config("durable operation manifest corrupt".into()))?;
            let revisions = serde_json::from_value::<Vec<SourceRevision>>(
                value
                    .get("sourceRevisions")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )
            .map_err(|_| ServiceError::Config("durable Source revisions corrupt".into()))?;
            if !revisions.is_empty()
                && let Some(run_id) = value.get("runId").and_then(Value::as_str)
            {
                local
                    .reconcile_worktrees(run_id, &revisions)
                    .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            }
        }
        let recovered = node.recover_nonterminal()?;
        let active = recovered
            .into_iter()
            .map(|item| {
                (
                    item.operation_id.clone(),
                    Active {
                        key: item.key,
                        operation_id: item.operation_id,
                        run_id: item.run_id,
                        request_digest: item.request_digest,
                        provider_id: item.provider_id,
                        handle: item.handle,
                        journal_state: item.journal_state,
                        controller_epoch: 1,
                        revision: 1,
                    },
                )
            })
            .collect();
        let message_counter = node.store().transport_positions()?.node_sent_through;
        let mut runtime_custody = HashMap::new();
        for admission in node.store().admissions()? {
            let Ok(runtime) = serde_json::from_slice::<RuntimeRequest>(&admission.runtime_request)
            else {
                continue;
            };
            let Some(runtime_id) = admission.operation.runtime_id.as_deref() else {
                continue;
            };
            if runtime_id != runtime.runtime_id {
                continue;
            }
            let handle = node.runtime_handle(&admission)?;
            let state = node
                .inspect_runtime(&admission.provider_id, &handle)
                .map(|receipt| receipt.state)
                .unwrap_or(RuntimeState::Uncertain);
            runtime_custody.insert(
                runtime.runtime_id.clone(),
                RuntimeCustody {
                    start_operation_id: admission.operation.operation_id,
                    run_id: runtime.run_id,
                    request_digest: admission.operation.request_digest,
                    provider_id: admission.provider_id,
                    handle,
                    state,
                    controller_epoch: 1,
                    revision: 1,
                },
            );
        }
        Ok(Self {
            node,
            identity,
            control_url,
            device_id,
            capability_digest,
            node_boot_id,
            profiles: config.profiles,
            local_policy: config.local_policy,
            local,
            supervisor,
            message_counter,
            active,
            agents: HashMap::new(),
            runtime_custody,
            pending_reconciliation: None,
            event_accumulators: HashMap::new(),
            ack_accumulator: AckAccumulator::default(),
            health_tracker: HealthTracker::default(),
            last_health: None,
            health_frontier_dirty: false,
            health_fault: None,
        })
    }
    fn message_id(&mut self) -> String {
        self.message_counter = self.message_counter.saturating_add(1);
        format!(
            "nmsg_{}_{:016}",
            &self.capability_digest[..8],
            self.message_counter
        )
    }

    fn health_state(&self, remote_work_allowed: bool) -> HealthState {
        let node_state = if self.health_fault.is_some() {
            "degraded"
        } else if !remote_work_allowed {
            "reconciling"
        } else if !self.active.is_empty() || !self.agents.is_empty() {
            "busy"
        } else {
            "ready"
        };
        HealthState {
            node_state: node_state.into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: self.active.len(),
            active_agent_runs: self.agents.len(),
            active_runtimes: self.active.len() + self.agents.len(),
        }
    }

    fn queue_health_if_due(
        &mut self,
        client: &mut WssClient,
        force: bool,
    ) -> Result<bool, ServiceError> {
        self.queue_health_if_due_at(client, force, Instant::now())
    }

    fn queue_health_if_due_at(
        &mut self,
        client: &mut WssClient,
        force: bool,
        at: Instant,
    ) -> Result<bool, ServiceError> {
        let state = self.health_state(client.session.remote_work_allowed());
        let force = force || self.health_frontier_dirty;
        if !self.health_tracker.should_emit(&state, at, force) {
            return Ok(false);
        }
        let applied = self
            .node
            .store()
            .inbound_applied_through(Direction::ControlToNode)?;
        let applied_wire = applied.to_string();
        let replay_unchanged = !force
            && self.health_tracker.unchanged_checkpoint_due(&state, at)
            && self.last_health.as_ref().is_some_and(|envelope| {
                envelope.connection_epoch == client.session.epoch().to_string()
            });
        if replay_unchanged {
            // `last_health` is present by construction of the predicate.  A
            // missing value is still handled defensively as a fresh health
            // frame so a future state restoration cannot suppress health.
            if let Some(envelope) = self.last_health.as_ref() {
                client.replay_envelope(envelope)?;
                self.health_tracker.record(state, at);
                return Ok(true);
            }
        }
        let payload = json!({
            "observedAt": now(),
            "nodeState": state.node_state,
            "journalState": state.journal_state,
            "storageState": state.storage_state,
            "controlAppliedThrough": applied_wire,
            "activeCommands": state.active_commands,
            "activeAgentRuns": state.active_agent_runs,
            "activeRuntimes": state.active_runtimes,
        });
        let id = self.message_id();
        let envelope = client
            .session
            .queue_outbound(&id, "device.health", None, payload, 1)?;
        self.last_health = Some(envelope);
        self.health_frontier_dirty = false;
        self.health_tracker.record(state, at);
        Ok(true)
    }

    fn queue_event_batch(
        &mut self,
        client: &mut WssClient,
        batch: EventBatch,
    ) -> Result<(), ServiceError> {
        let id = self.message_id();
        client.session.queue_outbound(
            &id,
            "event.batch",
            batch.operation_id,
            batch.payload,
            if batch.priority { 1 } else { 0 },
        )?;
        Ok(())
    }

    fn flush_due_event_batches(&mut self, client: &mut WssClient) -> Result<(), ServiceError> {
        let now = Instant::now();
        let mut ready = Vec::new();
        for accumulator in self.event_accumulators.values_mut() {
            if let Some(batch) = accumulator.flush_due(now)? {
                ready.push(batch);
            }
        }
        for batch in ready {
            self.queue_event_batch(client, batch)?;
        }
        Ok(())
    }

    fn flush_all_event_batches(&mut self, client: &mut WssClient) -> Result<(), ServiceError> {
        let mut ready = Vec::new();
        for accumulator in self.event_accumulators.values_mut() {
            if let Some(batch) = accumulator.flush()? {
                ready.push(batch);
            }
        }
        for batch in ready {
            self.queue_event_batch(client, batch)?;
        }
        Ok(())
    }

    fn note_control_applied(&mut self, sequence: u64) {
        self.ack_accumulator.note(sequence, Instant::now());
    }

    fn flush_ack_if_due(
        &mut self,
        client: &mut WssClient,
        force: bool,
    ) -> Result<(), ServiceError> {
        let now = Instant::now();
        if !force && !self.ack_accumulator.should_flush(now) {
            return Ok(());
        }
        let Some(through) = self.ack_accumulator.take() else {
            return Ok(());
        };
        let payload = json!({
            "direction": "control_to_node",
            "throughSequence": through.to_string(),
        });
        let id = self.message_id();
        client
            .session
            .queue_outbound(&id, "transport.ack", None, payload, 0)?;
        Ok(())
    }
    pub fn run_forever(mut self) {
        let mut delay = Duration::from_secs(1);
        loop {
            match self.run_connection() {
                Ok(()) => delay = Duration::from_secs(1),
                Err(e) => eprintln!("conduit-node transport: {e}"),
            };
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }
    fn run_connection(&mut self) -> Result<(), ServiceError> {
        let mut client = WssClient::connect(
            &self.control_url,
            self.node.store().clone(),
            &self.identity,
            &self.device_id,
            &self.capability_digest,
            &self.node_boot_id,
        )?;
        // A successful authenticated connection is the recovery observation
        // for a transient transport fault.  Any later local fault sets this
        // again before the connection is abandoned.
        self.health_fault = None;
        self.flush_all_event_batches(&mut client)?;
        self.flush_ack_if_due(&mut client, true)?;
        let positions = self.node.store().transport_positions()?;
        client.flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))?;
        if client.reconciliation_required() {
            let retained = if positions.node_sent_through == 0 {
                "0"
            } else {
                "1"
            };
            let mut runs = self
                .active
                .values()
                .take(256)
                .map(|active| {
                    let handle_digest = hex::encode(Sha256::digest(
                        serde_jcs::to_vec(&active.handle)
                            .map_err(|_| TransportError::Malformed)?,
                    ));
                    Ok(json!({"runId":active.run_id,"operationId":active.operation_id,"state":active.journal_state,"requestDigest":active.request_digest,"runtimeHandleDigest":handle_digest,"lastEventSequence":"0"}))
                })
                .collect::<Result<Vec<_>, TransportError>>()?;
            runs.extend(self.agents.values().map(|agent| json!({"runId":agent.run_id,"operationId":agent.operation_id,"state":"running","requestDigest":agent.request_digest,"lastEventSequence":agent.event_sequence.to_string()})));
            let retained_event_ranges = self.agents.values().filter(|agent| agent.event_sequence > 0).map(|agent| json!({"runId":agent.run_id,"fromSequence":"1","throughSequence":agent.event_sequence.to_string()})).collect::<Vec<_>>();
            let unresolved = self.active.len() + self.agents.len();
            let journal_generation = self.node.store().journal_generation()?;
            let control_applied = self
                .node
                .store()
                .inbound_applied_through(Direction::ControlToNode)?;
            let payload = json!({"nodeBootId":self.node_boot_id,"journalGeneration":journal_generation.to_string(),"capabilityDigest":self.capability_digest,"lastControlSequenceApplied":control_applied.to_string(),"controlAppliedThrough":control_applied.to_string(),"lastNodeSequenceAcknowledged":positions.node_acknowledged_through.to_string(),"lastNodeSequenceRetained":retained,"runs":runs,"retainedEventRanges":retained_event_ranges,"unresolvedCount":unresolved,"truncated":unresolved>256,"storageHealth":"healthy"});
            let id = self.message_id();
            client
                .session
                .queue_outbound(&id, "reconcile.summary", None, payload, 0)?;
            // Reconnect itself is a semantic recovery observation even when
            // the peer still requires a reconciliation plan.  Report the
            // bounded `reconciling` state now, then emit the ready/busy state
            // again when `reconcile.complete` is durably committed.
            self.queue_health_if_due(&mut client, true)?;
            client.flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))?;
        } else {
            client.session.mark_reconciliation_complete();
            self.queue_health_if_due(&mut client, true)?;
        }
        let mut keepalive = Instant::now();
        loop {
            if keepalive.elapsed() >= Duration::from_secs(30) {
                if let Err(error) = client.protocol_ping() {
                    self.health_fault = Some("protocol_keepalive_failed".into());
                    let _ = self.queue_health_if_due(&mut client, true);
                    return Err(error.into());
                }
                keepalive = Instant::now();
            }
            let polled = match client.poll() {
                Ok(value) => value,
                Err(error) => {
                    self.health_fault = Some("transport_receive_failed".into());
                    let _ = self.queue_health_if_due(&mut client, true);
                    return Err(error.into());
                }
            };
            if let Some((frame, result)) = polled
                && let Err(error) = self.dispatch(&mut client, frame, result)
            {
                self.health_fault = Some("control_dispatch_failed".into());
                let _ = self.queue_health_if_due(&mut client, true);
                return Err(error);
            }
            if let Err(error) = self.poll_active(&mut client) {
                self.health_fault = Some("local_runtime_poll_failed".into());
                let _ = self.queue_health_if_due(&mut client, true);
                return Err(error);
            }
            self.flush_due_event_batches(&mut client)?;
            self.flush_ack_if_due(&mut client, false)?;
            self.queue_health_if_due(&mut client, false)?;
            let positions = self.node.store().transport_positions()?;
            client.flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))?;
        }
    }
    fn dispatch(
        &mut self,
        client: &mut WssClient,
        frame: Envelope,
        result: ReceiveResult,
    ) -> Result<(), ServiceError> {
        let seq = frame
            .sequence
            .parse::<u64>()
            .map_err(|_| TransportError::Malformed)?;
        if let ReceiveResult::Gap { expected } = result {
            let payload = json!({"direction":"control_to_node","expectedSequence":expected.to_string(),"receivedSequence":seq.to_string()});
            let id = self.message_id();
            client
                .session
                .queue_outbound(&id, "transport.replay_required", None, payload, 0)?;
            return Ok(());
        }
        if matches!(result, ReceiveResult::Duplicate) && frame.kind != "transport.ack" {
            self.note_control_applied(seq);
            self.flush_ack_if_due(client, false)?;
            return Ok(());
        }
        if !client.session.control_frame_allowed(&frame.kind, seq) {
            return Err(ServiceError::Unavailable("reconciliation_required".into()));
        }
        match frame.kind.as_str() {
            "transport.ack" => {
                let direction = frame.payload["direction"]
                    .as_str()
                    .ok_or(TransportError::Malformed)?;
                let through = frame.payload["throughSequence"]
                    .as_str()
                    .and_then(|v| v.parse().ok())
                    .ok_or(TransportError::Malformed)?;
                if direction != "node_to_control" {
                    return Err(TransportError::Malformed.into());
                }
                self.node
                    .store()
                    .ack_outbound(Direction::NodeToControl, through)?;
            }
            "transport.replay_required" => {
                if frame.payload["direction"] != "node_to_control" {
                    return Err(TransportError::Malformed.into());
                }
                let from = frame.payload["expectedSequence"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or(TransportError::Malformed)?;
                let through = self.node.store().transport_positions()?.node_sent_through;
                client.replay_range(from, through)?;
            }
            "transport.error" => {}
            "reconcile.plan" => {
                if let Err(error) = self.reconcile(client, &frame.payload, seq) {
                    match error {
                        ServiceError::Unavailable(reason) => {
                            let payload = json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":"reconcile.plan","reason":reason}});
                            let id = self.message_id();
                            client.session.queue_outbound(
                                &id,
                                "transport.error",
                                frame.correlation_id.clone(),
                                payload,
                                0,
                            )?;
                        }
                        other => return Err(other),
                    }
                }
            }
            "operation.offer" => {
                if let Err(error) = self.offer(client, &frame.payload) {
                    match error {
                        ServiceError::Unavailable(reason) => {
                            self.reject_offer(client, &frame.payload, &reason)?;
                        }
                        other => return Err(other),
                    }
                }
            }
            "operation.input" | "operation.cancel" => {
                if let Err(reason) = self.control_agent(client, &frame.kind, &frame.payload) {
                    let payload = json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":frame.kind,"reason":bounded(reason,192)}});
                    let id = self.message_id();
                    client.session.queue_outbound(
                        &id,
                        "transport.error",
                        frame.correlation_id.clone(),
                        payload,
                        0,
                    )?;
                }
            }
            "runtime.control" => {
                if let Err(reason) = self.control_runtime(client, &frame.payload) {
                    let payload = json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":frame.kind,"reason":bounded(reason,192)}});
                    let id = self.message_id();
                    client.session.queue_outbound(
                        &id,
                        "transport.error",
                        frame.correlation_id.clone(),
                        payload,
                        0,
                    )?;
                }
            }
            "operation.approval" => {
                if let Err(reason) = self.apply_agent_approval(client, &frame.payload) {
                    let payload = json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":frame.kind,"reason":bounded(reason.to_string(),192)}});
                    let id = self.message_id();
                    client.session.queue_outbound(
                        &id,
                        "transport.error",
                        frame.correlation_id.clone(),
                        payload,
                        0,
                    )?;
                }
            }
            _ => {
                let payload = json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":frame.kind}});
                let id = self.message_id();
                client.session.queue_outbound(
                    &id,
                    "transport.error",
                    frame.correlation_id,
                    payload,
                    0,
                )?;
            }
        }
        self.node
            .store()
            .mark_inbound_applied(Direction::ControlToNode, seq)?;
        self.maybe_complete_reconciliation(client)?;
        if frame.kind != "transport.ack" {
            // `reconcile.complete` emits its recovery/ready observation from
            // `maybe_complete_reconciliation`; avoid allocating a second
            // health sequence for the same control frame below.
            if frame.kind != "reconcile.complete" {
                self.health_frontier_dirty = true;
            }
            self.note_control_applied(seq);
            self.flush_ack_if_due(client, false)?;
        }
        self.queue_health_if_due(client, false)?;
        Ok(())
    }

    fn apply_agent_approval(
        &mut self,
        _client: &mut WssClient,
        payload: &Value,
    ) -> Result<(), ServiceError> {
        let receipt: WireOperationApproval =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::Malformed)?;
        if !matches!(receipt.decision.as_str(), "approved" | "denied") {
            return Err(ServiceError::Unavailable(
                "approval_receipt_authority_mismatch".into(),
            ));
        }
        let issued = OffsetDateTime::parse(&receipt.issued_at, &Rfc3339)
            .map_err(|_| ServiceError::Unavailable("approval_receipt_time_invalid".into()))?;
        let expires = OffsetDateTime::parse(&receipt.expires_at, &Rfc3339)
            .map_err(|_| ServiceError::Unavailable("approval_receipt_time_invalid".into()))?;
        let observed = OffsetDateTime::now_utc();
        if expires <= observed
            || issued >= expires
            || issued > observed + time::Duration::minutes(5)
            || expires - issued > time::Duration::milliseconds(receipt.valid_for_ms as i64)
        {
            return Err(ServiceError::Unavailable("approval_receipt_expired".into()));
        }
        let mut receipt_commitment =
            serde_json::to_value(&receipt).map_err(|_| TransportError::Malformed)?;
        receipt_commitment
            .as_object_mut()
            .ok_or(TransportError::Malformed)?
            .remove("receiptDigest");
        let expected_receipt_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&receipt_commitment).map_err(|_| TransportError::Malformed)?,
        ));
        if expected_receipt_digest != receipt.receipt_digest {
            return Err(ServiceError::Unavailable(
                "approval_receipt_digest_mismatch".into(),
            ));
        }
        let journal = self
            .node
            .store()
            .agent_approval(&receipt.approval_id)?
            .ok_or_else(|| ServiceError::Unavailable("approval_request_unknown".into()))?;
        if journal.operation_digest != receipt.operation_digest {
            return Err(ServiceError::Unavailable(
                "approval_commitment_mismatch".into(),
            ));
        }
        if u64::try_from(expires.unix_timestamp_nanos().max(0) / 1_000_000).unwrap_or(u64::MAX)
            > journal.expires_at_unix_ms
            || unix_ms_now() > journal.expires_at_unix_ms
        {
            return Err(ServiceError::Unavailable(
                "approval_receipt_extended_deadline".into(),
            ));
        }
        let agent = self
            .agents
            .get_mut(&receipt.operation_id)
            .ok_or_else(|| ServiceError::Unavailable("approval_agent_not_active".into()))?;
        if agent.run_id != receipt.run_id || agent.key != journal.idempotency_key {
            return Err(ServiceError::Unavailable("approval_target_mismatch".into()));
        }
        if receipt.controller_epoch.parse::<u64>().ok() != Some(agent.controller_epoch) {
            return Err(ServiceError::Unavailable(
                "approval_controller_epoch_mismatch".into(),
            ));
        }
        let receipt_authority = receipt.receipt_digest.as_bytes();
        if journal.state == "applied" {
            if journal.resolution_authority.as_deref() != Some(receipt_authority) {
                return Err(ServiceError::Unavailable(
                    "approval_receipt_conflict".into(),
                ));
            }
            return Ok(());
        }
        if journal.state == "resolved" {
            if journal.resolution_authority.as_deref() != Some(receipt_authority) {
                return Err(ServiceError::Unavailable(
                    "approval_receipt_conflict".into(),
                ));
            }
            let frame =
                conduit_adapters::ProtocolFrame(journal.resolution.ok_or_else(|| {
                    ServiceError::Unavailable("approval_response_missing".into())
                })?);
            agent
                .child
                .write(&frame)
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            self.node
                .store()
                .mark_agent_approval_applied_and_resume(&receipt.approval_id, &agent.key)?;
            return Ok(());
        }
        let request_id: Value = serde_json::from_slice(&journal.provider_request_id)
            .map_err(|_| TransportError::Malformed)?;
        let allow = receipt.decision == "approved";
        let frame = if agent.adapter_kind == AdapterKind::Codex {
            agent
                .driver
                .resolve_codex_approval(
                    &request_id,
                    &journal.method,
                    &journal.parameters_digest,
                    allow,
                    unix_ms_now(),
                )
                .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?
        } else {
            agent
                .driver
                .approval_response(&request_id, allow)
                .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?
        };
        self.node.store().record_agent_approval_resolution(
            &receipt.approval_id,
            &frame.0,
            receipt_authority,
        )?;
        agent
            .child
            .write(&frame)
            .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        self.node
            .store()
            .mark_agent_approval_applied_and_resume(&receipt.approval_id, &agent.key)?;
        Ok(())
    }
    fn reject_offer(
        &mut self,
        client: &mut WssClient,
        payload: &Value,
        reason: &str,
    ) -> Result<(), ServiceError> {
        let operation = payload.get("operation").ok_or(TransportError::Malformed)?;
        let operation_id = operation["operationId"]
            .as_str()
            .ok_or(TransportError::Malformed)?;
        let key = operation["idempotencyKey"]
            .as_str()
            .ok_or(TransportError::Malformed)?;
        let request_digest = operation["payloadDigest"]
            .as_str()
            .ok_or(TransportError::Malformed)?;
        let manifest = serde_jcs::to_vec(operation).map_err(|_| TransportError::Malformed)?;
        verify_operation_commitment(&manifest, request_digest)?;
        let expired = reason == "operation_offer_expired";
        let decision = if expired { "expired" } else { "rejected" };
        let journal_state = decision;
        let reason_code = if expired {
            "operation_offer_expired"
        } else {
            reason
        };
        let mut admission = json!({"operationId":operation_id,"idempotencyKey":key,"requestDigest":request_digest,"decision":decision,"journalState":journal_state,"localPolicyRevision":self.local_policy.revision,"reasonCode":reason_code});
        let receipt_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&admission).map_err(|_| TransportError::Malformed)?,
        ));
        admission["receiptDigest"] = Value::String(receipt_digest);
        let encoded = serde_jcs::to_vec(&admission).map_err(|_| TransportError::Malformed)?;
        let saved = self.node.store().record_rejection(
            operation_id,
            key,
            request_digest,
            &manifest,
            self.local_policy.revision,
            if expired {
                OperationState::Expired
            } else {
                OperationState::Rejected
            },
            &encoded,
        )?;
        let durable: Value =
            serde_json::from_slice(&saved).map_err(|_| TransportError::Malformed)?;
        let message_id = self.message_id();
        client.session.queue_outbound(
            &message_id,
            "operation.admission",
            Some(operation_id.to_owned()),
            durable,
            0,
        )?;
        Ok(())
    }
    fn reconcile(
        &mut self,
        client: &mut WssClient,
        payload: &Value,
        plan_sequence: u64,
    ) -> Result<(), ServiceError> {
        let id = payload["reconciliationId"]
            .as_str()
            .ok_or(TransportError::Malformed)?;
        client.session.persist_plan(id, payload)?;
        for range in payload["nodeReplay"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            let from = range["from"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .ok_or(TransportError::Malformed)?;
            let through = range["through"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .ok_or(TransportError::Malformed)?;
            client.replay_range(from, through)?;
        }
        let mut control_applied_through = plan_sequence;
        let already_applied = self
            .node
            .store()
            .inbound_applied_through(Direction::ControlToNode)?;
        for range in payload["controlReplay"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            let requested_from = range["from"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(TransportError::Malformed)?;
            let through = range["through"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(TransportError::Malformed)?;
            if requested_from == 0 || through < requested_from {
                return Err(TransportError::Malformed.into());
            }
            control_applied_through = control_applied_through.max(through);
            let from = requested_from.max(already_applied.saturating_add(1));
            if from <= through {
                let request = json!({"direction":"control_to_node","expectedSequence":from.to_string(),"receivedSequence":through.to_string()});
                let message_id = self.message_id();
                client.session.queue_outbound(
                    &message_id,
                    "transport.replay_required",
                    None,
                    request,
                    0,
                )?;
            }
        }
        for request in payload["eventReplay"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            let run_id = request["runId"].as_str().ok_or(TransportError::Malformed)?;
            let mut from = request["from"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(TransportError::Malformed)?;
            let through = request["through"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(TransportError::Malformed)?;
            while from <= through {
                let end = through.min(from.saturating_add(EVENT_BATCH_MAX_EVENTS as u64 - 1));
                let frames = self
                    .node
                    .store()
                    .event_range(run_id, from, end)
                    .map_err(|_| {
                        ServiceError::Unavailable("event_replay_range_unavailable".into())
                    })?;
                if frames.is_empty() {
                    return Err(ServiceError::Unavailable(
                        "event_replay_range_unavailable".into(),
                    ));
                }
                let events = frames
                    .iter()
                    .map(|frame| {
                        serde_json::from_slice::<Value>(&frame.frame)
                            .map(|event| (frame.sequence, event))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransportError::Malformed)?;
                let actual_through = frames.last().map_or(from, |frame| frame.sequence);
                let batch = replay_batch(run_id, events)
                    .map_err(|_| ServiceError::Unavailable("event_replay_batch_invalid".into()))?;
                self.queue_event_batch(client, batch)?;
                if actual_through >= through {
                    break;
                }
                from = actual_through.saturating_add(1);
            }
        }
        for run_id in payload["statusRunIds"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            self.replay_run_status(client, run_id.as_str().ok_or(TransportError::Malformed)?)?;
        }
        for operation_id in payload["cancelOperationIds"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            self.reconcile_cancel(
                client,
                operation_id.as_str().ok_or(TransportError::Malformed)?,
                false,
            )?;
        }
        for run_id in payload
            .get("quarantineRunIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let run_id = run_id.as_str().ok_or(TransportError::Malformed)?;
            let operation_id = self
                .node
                .store()
                .admissions()?
                .into_iter()
                .find_map(|admission| {
                    serde_json::from_slice::<RuntimeRequest>(&admission.runtime_request)
                        .ok()
                        .filter(|runtime| runtime.run_id == run_id)
                        .map(|_| admission.operation.operation_id)
                })
                .ok_or_else(|| ServiceError::Unavailable("quarantine_run_unavailable".into()))?;
            self.reconcile_cancel(client, &operation_id, true)?;
        }
        self.verify_terminal_confirmations(
            payload
                .get("confirmTerminalReceiptDigests")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )?;
        self.pending_reconciliation = Some(PendingReconciliation {
            id: id.to_owned(),
            control_applied_through,
        });
        Ok(())
    }

    fn maybe_complete_reconciliation(
        &mut self,
        client: &mut WssClient,
    ) -> Result<(), ServiceError> {
        let Some(pending) = self.pending_reconciliation.as_ref() else {
            return Ok(());
        };
        if self
            .node
            .store()
            .inbound_applied_through(Direction::ControlToNode)?
            < pending.control_applied_through
        {
            return Ok(());
        }
        let pending = self
            .pending_reconciliation
            .take()
            .expect("pending reconciliation was checked");
        client.session.complete_plan(&pending.id)?;
        let positions = self.node.store().transport_positions()?;
        let applied = self
            .node
            .store()
            .inbound_applied_through(Direction::ControlToNode)?;
        let response = json!({"reconciliationId":pending.id,"lastControlSequenceApplied":applied.to_string(),"controlAppliedThrough":applied.to_string(),"lastNodeSequenceAcknowledged":positions.node_acknowledged_through.to_string(),"unresolvedRunIds":[]});
        let message_id = self.message_id();
        client
            .session
            .queue_outbound(&message_id, "reconcile.complete", None, response, 0)?;
        self.queue_health_if_due(client, true)?;
        Ok(())
    }
    fn offer(&mut self, client: &mut WssClient, payload: &Value) -> Result<(), ServiceError> {
        let operation_value = payload
            .get("operation")
            .cloned()
            .ok_or(TransportError::Malformed)?;
        let op: WireOperation = serde_json::from_value(operation_value.clone())
            .map_err(|_| TransportError::Malformed)?;
        if op.schema_version != 1
            || op.device_id != self.device_id
            || op.connector_policy_revision == 0
            || op.runtime.configuration_revision == 0
        {
            return Err(TransportError::Malformed.into());
        }
        enforce_reviewer_runtime(&op)?;
        let issued = OffsetDateTime::parse(&op.issued_at, &Rfc3339)
            .map_err(|_| TransportError::Malformed)?;
        let expires = OffsetDateTime::parse(&op.expires_at, &Rfc3339)
            .map_err(|_| TransportError::Malformed)?;
        let validity_end = issued
            .checked_add(time::Duration::milliseconds(op.valid_for_ms as i64))
            .ok_or(TransportError::Malformed)?;
        let observed = OffsetDateTime::now_utc();
        if expires > validity_end || observed > expires || observed > validity_end {
            return Err(ServiceError::Unavailable("operation_offer_expired".into()));
        }
        let is_agent = op.capability == "agent.run.start";
        let (settlement_policy, idle_timeout_ms, lease_expires_at_unix_ms) = if is_agent {
            agent_session_policy(&op.arguments)?
        } else {
            (AgentSettlementPolicy::CloseOnSettle, 0, None)
        };
        let profile_id = if is_agent {
            op.arguments
                .get("adapterId")
                .and_then(Value::as_str)
                .ok_or_else(|| ServiceError::Unavailable("adapter_id_required".into()))?
        } else {
            op.arguments
                .get("launchProfileId")
                .and_then(Value::as_str)
                .ok_or_else(|| ServiceError::Unavailable("device_launch_profile_required".into()))?
        };
        // Device-local authority is evaluated before resolving Sources or
        // probing executables so a local deny cannot be bypassed or obscured by
        // a later availability failure.
        self.local_policy.evaluate(&op, profile_id)?;
        let selected = normalize_provider(&op.runtime.provider_id);
        let manifest =
            serde_jcs::to_vec(&operation_value).map_err(|_| TransportError::Malformed)?;
        let run_id = op
            .run_id
            .clone()
            .unwrap_or_else(|| format!("lrun_{}", &op.payload_digest[..16]));
        let runtime_id = format!(
            "rt_{}",
            &hex::encode(Sha256::digest(format!(
                "{}:{}",
                op.operation_id, op.payload_digest
            )))[..16]
        );
        let prepared_sources = self
            .local
            .prepare_sources(&run_id, &op.source_revisions)
            .map_err(|error| ServiceError::Unavailable(source_reason(&error.to_string())))?;
        let source_baseline_revisions = op
            .arguments
            .get("sourceBaselineRevisions")
            .and_then(Value::as_object)
            .map(|items| {
                items
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let parent_baseline_id = op
            .arguments
            .get("parentBaselineId")
            .cloned()
            .unwrap_or(Value::Null);
        if !parent_baseline_id.is_null() && !parent_baseline_id.is_string() {
            return Err(ServiceError::Unavailable(
                "parent_baseline_id_invalid".into(),
            ));
        }
        let verification_policy = op
            .arguments
            .get("verificationPolicy")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !verification_policy.is_object() {
            return Err(ServiceError::Unavailable(
                "verification_policy_invalid".into(),
            ));
        }
        let runtime_kind = parse_kind(&op.runtime.kind)?;
        let workspaces = prepared_sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let guest = if matches!(
                    runtime_kind,
                    RuntimeKind::Native | RuntimeKind::RestrictedNative
                ) {
                    source.host_path.clone()
                } else {
                    PathBuf::from(format!("/workspace/source-{index}"))
                };
                source.attachment(guest)
            })
            .collect::<Vec<_>>();
        let (launch, agent_launch, effective_required_approval_risk_classes) = if is_agent {
            let kind = parse_adapter(profile_id)?;
            let cwd = workspaces
                .first()
                .map(|workspace| workspace.guest_path.clone())
                .unwrap_or_else(|| {
                    if matches!(
                        runtime_kind,
                        RuntimeKind::Native | RuntimeKind::RestrictedNative
                    ) {
                        self.local.agent_scratch(&run_id)
                    } else {
                        PathBuf::from("/workspace")
                    }
                });
            let request = LaunchRequest {
                cwd,
                prompt: op
                    .arguments
                    .get("prompt")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                native_session_id: op
                    .arguments
                    .get("nativeSessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                model: op
                    .arguments
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                effort: op
                    .arguments
                    .get("effort")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                session_data_dir: matches!(
                    runtime_kind,
                    RuntimeKind::Native | RuntimeKind::RestrictedNative
                )
                .then(|| self.local.agent_session_dir(&run_id)),
            };
            let (required_risk_classes, effective_required_approval_risk_classes) =
                effective_approval_risk_classes(
                    &op.required_approval_risk_classes,
                    &self.local_policy.required_approval_risk_classes,
                )?;
            let approval_context = ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::try_from(op.approval_mode.as_str())
                    .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?,
                bridge: if kind == AdapterKind::Codex {
                    ApprovalBridgeOwnership::Typed
                } else {
                    ApprovalBridgeOwnership::Unavailable
                },
                required_risk_classes,
            };
            let access_scope = EffectiveAccessScope::try_from(op.access_scope.as_str())
                .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?;
            let sandbox_policy = match (access_scope, runtime_kind) {
                (EffectiveAccessScope::ReadOnly, _) => EffectiveSandboxPolicy::ReadOnly,
                (_, RuntimeKind::RestrictedNative | RuntimeKind::Container | RuntimeKind::Vm) => {
                    EffectiveSandboxPolicy::External
                }
                (
                    EffectiveAccessScope::SelectedSources | EffectiveAccessScope::ProjectFull,
                    RuntimeKind::Native,
                ) => EffectiveSandboxPolicy::WorkspaceWrite,
                (
                    EffectiveAccessScope::FullUser | EffectiveAccessScope::FullDevice,
                    RuntimeKind::Native,
                ) => EffectiveSandboxPolicy::DangerFullAccess,
            };
            let (spec, driver) =
                if matches!(runtime_kind, RuntimeKind::Container | RuntimeKind::Vm) {
                    AdapterCatalog::launch_in_guest_with_effective_authority(
                        kind,
                        &request,
                        access_scope,
                        sandbox_policy,
                        approval_context,
                    )
                } else {
                    AdapterCatalog::launch_with_effective_authority(
                        kind,
                        &request,
                        access_scope,
                        sandbox_policy,
                        approval_context,
                    )
                }
                .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?;
            let launch = LaunchPlan {
                executable: spec.executable.clone(),
                argv: spec.args.clone(),
                cwd: spec.cwd.clone(),
                environment: BTreeMap::new(),
                io_mode: IoMode::Pipes,
                timeout_ms: op.arguments.get("timeoutMs").and_then(Value::as_u64),
            };
            (
                launch,
                Some((spec, driver, kind)),
                effective_required_approval_risk_classes,
            )
        } else {
            let profile = self
                .profiles
                .get(profile_id)
                .ok_or_else(|| {
                    ServiceError::Unavailable("device_launch_profile_unavailable".into())
                })?
                .clone();
            if selected != profile.provider_id {
                return Err(ServiceError::Unavailable(
                    "launch_profile_provider_mismatch".into(),
                ));
            }
            let cwd = prepared_sources.first().map_or(profile.cwd, |source| {
                if matches!(
                    runtime_kind,
                    RuntimeKind::Native | RuntimeKind::RestrictedNative
                ) {
                    source.host_path.clone()
                } else {
                    PathBuf::from("/workspace/source-0")
                }
            });
            (
                LaunchPlan {
                    executable: profile.executable,
                    argv: profile.argv,
                    cwd,
                    environment: profile.environment,
                    io_mode: profile.io_mode,
                    timeout_ms: profile.timeout_ms,
                },
                None,
                Vec::new(),
            )
        };
        let spec_digest = hex::encode(Sha256::digest(
            [
                serde_jcs::to_vec(&op.runtime).map_err(|_| TransportError::Malformed)?,
                serde_jcs::to_vec(&launch).map_err(|_| TransportError::Malformed)?,
            ]
            .concat(),
        ));
        let runtime = RuntimeRequest {
            runtime_id: runtime_id.clone(),
            run_id: run_id.clone(),
            kind: runtime_kind,
            provider_selector: op.runtime.provider_id.clone(),
            spec_digest,
            image: op
                .arguments
                .get("image")
                .and_then(Value::as_str)
                .map(str::to_owned),
            resources: ResourceLimits {
                cpu: op.runtime.cpu_limit,
                memory_bytes: op.runtime.memory_bytes,
                pid_limit: None,
                storage_bytes: op.runtime.storage_bytes,
            },
            network: parse_network(op.runtime.network_mode.as_deref().unwrap_or("open"))?,
            workspaces,
        };
        let probe = agent_launch
            .as_ref()
            .map(|(_, _, kind)| AdapterCatalog::discover(*kind));
        let executable_digest = matches!(
            runtime_kind,
            RuntimeKind::Native | RuntimeKind::RestrictedNative
        )
        .then(|| hash_file(&launch.executable))
        .transpose()?;
        let manifest_record = build_manifest(
            &ManifestOperation {
                operation_id: &op.operation_id,
                idempotency_key: &op.idempotency_key,
                request_digest: &op.payload_digest,
                run_id: &run_id,
                assignment_id: op.assignment_id.as_deref(),
                actor_id: &op.actor_principal_id,
                client_id: &op.client_id,
                device_id: &op.device_id,
                boot_id: &self.node_boot_id,
                capability_digest: &self.capability_digest,
                local_policy_revision: self.local_policy.revision,
                runtime_kind: &op.runtime.kind,
                runtime_provider: &op.runtime.provider_id,
                runtime_config: &serde_jcs::to_vec(&op.runtime)
                    .map_err(|_| TransportError::Malformed)?,
                access_scope: &op.access_scope,
                approval_mode: &op.approval_mode,
                adapter_id: is_agent.then_some(profile_id),
                adapter_version: probe.as_ref().and_then(|probe| probe.version.as_deref()),
                executable_digest,
                model: op.arguments.get("model").and_then(Value::as_str),
                effort: op.arguments.get("effort").and_then(Value::as_str),
                context_compiler_version: op
                    .arguments
                    .get("contextCompilerVersion")
                    .and_then(Value::as_str),
                context_snapshot_id: op
                    .arguments
                    .get("contextSnapshotId")
                    .and_then(Value::as_str),
                context_snapshot_digest: op
                    .arguments
                    .get("contextSnapshotDigest")
                    .and_then(Value::as_str),
                context_content_digest: op
                    .arguments
                    .get("contextSnapshotContentDigest")
                    .and_then(Value::as_str),
                context_bytes: op
                    .arguments
                    .get("contextSnapshotBytes")
                    .and_then(Value::as_u64),
            },
            &prepared_sources,
        )
        .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        self.local
            .commit_manifest(&manifest_record)
            .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        let offer = OperationOffer {
            operation_id: op.operation_id.clone(),
            idempotency_key: op.idempotency_key.clone(),
            request_digest: op.payload_digest.clone(),
            manifest,
            local_policy_revision: self.local_policy.revision,
            runtime,
            launch,
        };
        let receipt = self
            .node
            .admit(&offer, selected, &op.access_scope, &op.approval_mode)?;
        let decision = match receipt.disposition.as_str() {
            "admitted" => "admitted",
            "uncertain" => "uncertain",
            _ => "duplicate_replay",
        };
        let admission_payload = admission_payload(&receipt, decision)?;
        let msg = self.message_id();
        client.session.queue_outbound(
            &msg,
            "operation.admission",
            Some(op.operation_id.clone()),
            admission_payload,
            0,
        )?;
        if decision == "admitted" {
            if let Some((spec, driver, kind)) = agent_launch {
                if !matches!(runtime_kind, RuntimeKind::Native) || selected != "native" {
                    let interactive = match self.node.start_interactive(&op.idempotency_key) {
                        Ok(interactive) => interactive,
                        Err(error) => {
                            self.queue_start_failure(client, &op, &error.to_string())?;
                            return Ok(());
                        }
                    };
                    let handle = interactive.receipt.handle.clone();
                    let mut child = match AdapterChild::from_child(interactive.child) {
                        Ok(child) => child,
                        Err(error) => {
                            let _ = self.node.signal_runtime(
                                selected,
                                &handle,
                                RuntimeSignal::ForceStop,
                            );
                            self.node.store().transition_operation(
                                &op.idempotency_key,
                                OperationState::Running,
                                OperationState::Failed,
                                Some(&runtime_id),
                                handle.process_identity.as_deref(),
                                Some(error.to_string().as_bytes()),
                            )?;
                            self.queue_start_failure(client, &op, &error.to_string())?;
                            return Ok(());
                        }
                    };
                    if let Err(error) = child.initialize(&spec) {
                        let _ = child.terminate();
                        let _ =
                            self.node
                                .signal_runtime(selected, &handle, RuntimeSignal::ForceStop);
                        self.node.store().transition_operation(
                            &op.idempotency_key,
                            OperationState::Running,
                            OperationState::Failed,
                            Some(&runtime_id),
                            handle.process_identity.as_deref(),
                            Some(error.to_string().as_bytes()),
                        )?;
                        self.queue_start_failure(client, &op, &error.to_string())?;
                        return Ok(());
                    }
                    self.node.store().record_agent_session(
                        &op.idempotency_key,
                        agent_settlement_policy_name(settlement_policy),
                        1,
                        lease_expires_at_unix_ms,
                    )?;
                    let status = running_status_payload(
                        &op.operation_id,
                        &run_id,
                        &op.payload_digest,
                        &runtime_id,
                        selected,
                        &handle,
                        1,
                        1,
                        true,
                        "adapter_started",
                    )?;
                    let msg = self.message_id();
                    client.session.queue_outbound(
                        &msg,
                        "operation.status",
                        Some(op.operation_id.clone()),
                        status,
                        0,
                    )?;
                    self.runtime_custody.insert(
                        runtime_id.clone(),
                        RuntimeCustody {
                            start_operation_id: op.operation_id.clone(),
                            run_id: run_id.clone(),
                            request_digest: op.payload_digest.clone(),
                            provider_id: selected.to_owned(),
                            handle: handle.clone(),
                            state: RuntimeState::Running,
                            controller_epoch: 1,
                            revision: 1,
                        },
                    );
                    self.agents.insert(
                        op.operation_id.clone(),
                        AgentActive {
                            key: op.idempotency_key,
                            operation_id: op.operation_id,
                            run_id,
                            request_digest: op.payload_digest,
                            runtime_id,
                            provider_id: selected.to_owned(),
                            handle,
                            child,
                            driver,
                            adapter_kind: kind,
                            actor_principal_id: op.actor_principal_id,
                            client_id: op.client_id,
                            access_scope: op.access_scope,
                            approval_mode: op.approval_mode,
                            effective_required_approval_risk_classes:
                                effective_required_approval_risk_classes.clone(),
                            local_policy_revision: self.local_policy.revision,
                            controller_epoch: 1,
                            revision: 1,
                            event_sequence: 0,
                            raw_sequence: 0,
                            settlement_policy,
                            session_state: AgentSessionState::Running,
                            idle_timeout_ms,
                            lease_expires_at_unix_ms,
                            prepared_sources: prepared_sources.clone(),
                            parent_baseline_id: parent_baseline_id.clone(),
                            source_baseline_revisions: source_baseline_revisions.clone(),
                            verification_policy: verification_policy.clone(),
                        },
                    );
                    return Ok(());
                }
                self.node.store().transition_operation(
                    &op.idempotency_key,
                    OperationState::Admitted,
                    OperationState::Starting,
                    Some(&runtime_id),
                    None,
                    None,
                )?;
                let prepared = match self.supervisor.reserve(
                    &offer.runtime,
                    "native",
                    spec.executable.clone(),
                    false,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        self.node.store().transition_operation(
                            &op.idempotency_key,
                            OperationState::Starting,
                            OperationState::Failed,
                            Some(&runtime_id),
                            None,
                            Some(error.to_string().as_bytes()),
                        )?;
                        self.queue_start_failure(client, &op, &error.to_string())?;
                        return Ok(());
                    }
                };
                let mut child = match AdapterChild::spawn_uninitialized(&spec) {
                    Ok(child) => child,
                    Err(error) => {
                        self.node.store().transition_operation(
                            &op.idempotency_key,
                            OperationState::Starting,
                            OperationState::Failed,
                            Some(&runtime_id),
                            None,
                            Some(error.to_string().as_bytes()),
                        )?;
                        self.queue_start_failure(client, &op, &error.to_string())?;
                        return Ok(());
                    }
                };
                let custody =
                    match self
                        .supervisor
                        .adopt_external(&prepared, &offer.launch, child.id())
                    {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            let _ = child.terminate();
                            self.node.store().transition_operation(
                                &op.idempotency_key,
                                OperationState::Starting,
                                OperationState::Failed,
                                Some(&runtime_id),
                                None,
                                Some(error.to_string().as_bytes()),
                            )?;
                            self.queue_start_failure(client, &op, &error.to_string())?;
                            return Ok(());
                        }
                    };
                if let Err(error) = child.initialize(&spec) {
                    let status = child.terminate().ok();
                    let _ = self
                        .supervisor
                        .mark_external_stopped(&runtime_id, status.and_then(|value| value.code()));
                    self.node.store().transition_operation(
                        &op.idempotency_key,
                        OperationState::Starting,
                        OperationState::Failed,
                        Some(&runtime_id),
                        custody.handle.process_identity.as_deref(),
                        Some(error.to_string().as_bytes()),
                    )?;
                    self.queue_start_failure(client, &op, &error.to_string())?;
                    return Ok(());
                }
                let process_identity =
                    custody.handle.process_identity.clone().ok_or_else(|| {
                        ServiceError::Unavailable("adapter_process_identity_unavailable".into())
                    })?;
                self.node.store().transition_operation(
                    &op.idempotency_key,
                    OperationState::Starting,
                    OperationState::Running,
                    Some(&runtime_id),
                    Some(&process_identity),
                    None,
                )?;
                self.node.store().record_agent_session(
                    &op.idempotency_key,
                    agent_settlement_policy_name(settlement_policy),
                    1,
                    lease_expires_at_unix_ms,
                )?;
                let status = running_status_payload(
                    &op.operation_id,
                    &run_id,
                    &op.payload_digest,
                    &runtime_id,
                    "native",
                    &custody.handle,
                    1,
                    1,
                    true,
                    "adapter_started",
                )?;
                let msg = self.message_id();
                client.session.queue_outbound(
                    &msg,
                    "operation.status",
                    Some(op.operation_id.clone()),
                    status,
                    0,
                )?;
                self.runtime_custody.insert(
                    runtime_id.clone(),
                    RuntimeCustody {
                        start_operation_id: op.operation_id.clone(),
                        run_id: run_id.clone(),
                        request_digest: op.payload_digest.clone(),
                        provider_id: "native".into(),
                        handle: custody.handle.clone(),
                        state: RuntimeState::Running,
                        controller_epoch: 1,
                        revision: 1,
                    },
                );
                self.agents.insert(
                    op.operation_id.clone(),
                    AgentActive {
                        key: op.idempotency_key,
                        operation_id: op.operation_id,
                        run_id,
                        request_digest: op.payload_digest,
                        runtime_id,
                        provider_id: "native".into(),
                        handle: custody.handle,
                        child,
                        driver,
                        adapter_kind: kind,
                        actor_principal_id: op.actor_principal_id,
                        client_id: op.client_id,
                        access_scope: op.access_scope,
                        approval_mode: op.approval_mode,
                        effective_required_approval_risk_classes,
                        local_policy_revision: self.local_policy.revision,
                        controller_epoch: 1,
                        revision: 1,
                        event_sequence: 0,
                        raw_sequence: 0,
                        settlement_policy,
                        session_state: AgentSessionState::Running,
                        idle_timeout_ms,
                        lease_expires_at_unix_ms,
                        prepared_sources,
                        parent_baseline_id,
                        source_baseline_revisions,
                        verification_policy,
                    },
                );
                return Ok(());
            }
            let started = match self.node.start(&op.idempotency_key) {
                Ok(started) => started,
                Err(error) => {
                    self.queue_start_failure(client, &op, &error.to_string())?;
                    return Ok(());
                }
            };
            let status = running_status_payload(
                &op.operation_id,
                &run_id,
                &op.payload_digest,
                &runtime_id,
                selected,
                &started.handle,
                1,
                1,
                false,
                "runtime_started",
            )?;
            let msg = self.message_id();
            client.session.queue_outbound(
                &msg,
                "operation.status",
                Some(op.operation_id.clone()),
                status,
                0,
            )?;
            self.runtime_custody.insert(
                runtime_id.clone(),
                RuntimeCustody {
                    start_operation_id: op.operation_id.clone(),
                    run_id: run_id.clone(),
                    request_digest: op.payload_digest.clone(),
                    provider_id: selected.into(),
                    handle: started.handle.clone(),
                    state: RuntimeState::Running,
                    controller_epoch: 1,
                    revision: 1,
                },
            );
            self.active.insert(
                op.operation_id.clone(),
                Active {
                    key: op.idempotency_key,
                    operation_id: op.operation_id,
                    run_id,
                    request_digest: op.payload_digest,
                    provider_id: selected.into(),
                    handle: started.handle,
                    journal_state: OperationState::Running,
                    controller_epoch: 1,
                    revision: 1,
                },
            );
        }
        Ok(())
    }
    fn queue_start_failure(
        &mut self,
        client: &mut WssClient,
        operation: &WireOperation,
        reason: &str,
    ) -> Result<(), ServiceError> {
        let state = self
            .node
            .store()
            .operation(&operation.idempotency_key)?
            .ok_or(conduit_node_store::StoreError::NotFound)?
            .state;
        let terminal = match state {
            OperationState::Failed => "failed",
            OperationState::Uncertain => "uncertain",
            _ => {
                return Err(ServiceError::Unavailable(
                    "runtime_start_state_invalid".into(),
                ));
            }
        };
        let run_id = operation
            .run_id
            .clone()
            .unwrap_or_else(|| format!("lrun_{}", &operation.payload_digest[..16]));
        let mut payload = json!({"operationId":operation.operation_id,"runId":run_id,"state":terminal,"requestDigest":operation.payload_digest,"lastRunEventSequence":"0","reasonCode":"runtime_start_failed","resultSummary":{"error":reason.chars().take(256).collect::<String>()},"observedAt":now()});
        let digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
        ));
        payload["receiptDigest"] = Value::String(digest);
        let id = self.message_id();
        client.session.queue_outbound(
            &id,
            "operation.terminal",
            Some(operation.operation_id.clone()),
            payload,
            0,
        )?;
        Ok(())
    }
    fn poll_active(&mut self, client: &mut WssClient) -> Result<(), ServiceError> {
        self.poll_agents(client)?;
        let ids = self.active.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let Some(active) = self.active.get(&id) else {
                continue;
            };
            let state = self
                .node
                .inspect_runtime(&active.provider_id, &active.handle)?;
            if let Some(custody) = self.runtime_custody.get_mut(&active.handle.runtime_id) {
                custody.state = state.state;
            }
            if state.state == RuntimeState::Stopped {
                let terminal = if state.exit_code == Some(0) {
                    OperationState::Completed
                } else {
                    OperationState::Failed
                };
                if active.journal_state != OperationState::Finishing {
                    self.node.store().transition_operation(
                        &active.key,
                        active.journal_state,
                        OperationState::Finishing,
                        None,
                        None,
                        None,
                    )?;
                }
                let mut payload = json!({"operationId":active.operation_id,"runId":active.run_id,"state":if terminal==OperationState::Completed{"completed"}else{"failed"},"requestDigest":active.request_digest,"lastRunEventSequence":"0","observedAt":now()});
                let digest = hex::encode(Sha256::digest(
                    serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
                ));
                payload["receiptDigest"] = Value::String(digest);
                let bytes = serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?;
                self.node
                    .terminal(&active.key, OperationState::Finishing, terminal, &bytes)?;
                let msg = self.message_id();
                client.session.queue_outbound(
                    &msg,
                    "operation.terminal",
                    Some(id.clone()),
                    payload,
                    0,
                )?;
                self.active.remove(&id);
            }
        }
        Ok(())
    }

    fn control_agent(
        &mut self,
        client: &mut WssClient,
        kind: &str,
        payload: &Value,
    ) -> Result<(), String> {
        let control: WireOperationControl = serde_json::from_value(payload.clone())
            .map_err(|_| "operation_control_malformed".to_owned())?;
        let expected_revision = control
            .expected_revision
            .parse::<u64>()
            .map_err(|_| "operation_expected_revision_invalid".to_owned())?;
        let controller_epoch = control
            .target_controller_epoch
            .parse::<u64>()
            .map_err(|_| "operation_controller_epoch_invalid".to_owned())?;
        let request_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(payload).map_err(|_| "operation_control_malformed".to_owned())?,
        ));
        let (_, agent) = self
            .agents
            .iter_mut()
            .find(|(_, agent)| agent.run_id == control.target_run_id)
            .ok_or_else(|| "target_agent_run_unavailable".to_owned())?;
        let handle_digest =
            runtime_handle_digest(&agent.handle).map_err(|error| error.to_string())?;
        let target_digest = custody_target_digest(
            true,
            &agent.run_id,
            &agent.operation_id,
            &agent.request_digest,
            &agent.runtime_id,
            &handle_digest,
            agent.controller_epoch,
        )
        .map_err(|error| error.to_string())?;
        let observed = match agent.session_state {
            AgentSessionState::Running => adapter_operation_state(agent.driver.state()),
            AgentSessionState::WaitingInput => "waiting_input",
            AgentSessionState::ClosingCompleted
            | AgentSessionState::ClosingCancelled
            | AgentSessionState::ClosingTimedOut => "finishing",
        };
        if control.operation_id == agent.operation_id
            || control.target_digest != target_digest
            || controller_epoch != agent.controller_epoch
        {
            return Err("operation_control_target_mismatch".into());
        }
        let command = if kind == "operation.cancel" {
            "cancel"
        } else {
            control.mode.as_deref().unwrap_or("input")
        };
        if self
            .node
            .store()
            .control_effect(&control.idempotency_key)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            if expected_revision != agent.revision {
                return Err(format!(
                    "target_revision_stale:expected={expected_revision}:observed={}",
                    agent.revision,
                ));
            }
            if control.expected_state != observed {
                return Err(format!(
                    "target_state_stale:expected={}:observed={observed}",
                    control.expected_state
                ));
            }
        }
        match self
            .node
            .store()
            .reserve_control_effect(
                &control.operation_id,
                &control.idempotency_key,
                &request_digest,
                &control.target_run_id,
                Some(&agent.runtime_id),
                &control.target_digest,
                controller_epoch,
                expected_revision,
                command,
            )
            .map_err(|error| error.to_string())?
        {
            ControlEffectResult::Replay(record) => {
                let receipt = record
                    .receipt
                    .ok_or_else(|| "control_receipt_missing".to_owned())?;
                let replay: Value = serde_json::from_slice(&receipt)
                    .map_err(|_| "control_receipt_corrupt".to_owned())?;
                let status = replay
                    .get("targetStatus")
                    .cloned()
                    .ok_or_else(|| "control_status_receipt_missing".to_owned())?;
                let terminal = replay
                    .get("controlTerminal")
                    .cloned()
                    .ok_or_else(|| "control_terminal_receipt_missing".to_owned())?;
                let status_message_id = format!("nmsg_x{}s", &request_digest[..23]);
                client
                    .session
                    .queue_outbound(
                        &status_message_id,
                        "operation.status",
                        Some(agent.operation_id.clone()),
                        status,
                        0,
                    )
                    .map_err(|error| error.to_string())?;
                let terminal_message_id = format!("nmsg_x{}t", &request_digest[..23]);
                client
                    .session
                    .queue_outbound(
                        &terminal_message_id,
                        "operation.terminal",
                        Some(control.operation_id),
                        terminal,
                        0,
                    )
                    .map_err(|error| error.to_string())?;
                return Ok(());
            }
            ControlEffectResult::Uncertain(_) => {
                return Err("ambiguous_control_effect_pending_recovery".into());
            }
            ControlEffectResult::Reserved(_) => {}
        }

        let prior_session_state = agent.session_state;
        let mut close = false;
        let mut cancelled = false;
        if command == "cancel" {
            cancelled = true;
            if prior_session_state == AgentSessionState::WaitingInput {
                agent.child.terminate().map_err(|error| error.to_string())?;
            } else {
                match agent.driver.command(AdapterOperation::Cancel, None) {
                    Ok(frames) => {
                        for frame in frames {
                            agent
                                .child
                                .write(&frame)
                                .map_err(|error| error.to_string())?;
                        }
                    }
                    Err(conduit_adapters::AdapterError::UnsupportedOperation { .. }) => {
                        agent.child.terminate().map_err(|error| error.to_string())?;
                    }
                    Err(error) => return Err(error.to_string()),
                }
                agent.child.terminate().map_err(|error| error.to_string())?;
            }
        } else if command == "close" {
            let frames = agent
                .driver
                .command(AdapterOperation::Close, None)
                .map_err(|error| error.to_string())?;
            for frame in frames {
                agent
                    .child
                    .write(&frame)
                    .map_err(|error| error.to_string())?;
            }
            agent.child.terminate().map_err(|error| error.to_string())?;
            close = true;
        } else {
            let operation = match command {
                "input" => AdapterOperation::Send,
                "follow_up" => AdapterOperation::FollowUp,
                "steer" => AdapterOperation::Steer,
                _ => return Err("operation_input_mode_unknown".into()),
            };
            let frames = agent
                .driver
                .command(operation, control.content.as_deref())
                .map_err(|error| error.to_string())?;
            for frame in frames {
                agent
                    .child
                    .write(&frame)
                    .map_err(|error| error.to_string())?;
            }
            if prior_session_state == AgentSessionState::WaitingInput {
                self.node
                    .store()
                    .transition_operation(
                        &agent.key,
                        OperationState::WaitingInput,
                        OperationState::Running,
                        None,
                        None,
                        None,
                    )
                    .map_err(|error| error.to_string())?;
                agent.session_state = AgentSessionState::Running;
            }
        }
        let session_from = match prior_session_state {
            AgentSessionState::Running => "running",
            AgentSessionState::WaitingInput => "waiting_input",
            AgentSessionState::ClosingCompleted
            | AgentSessionState::ClosingCancelled
            | AgentSessionState::ClosingTimedOut => return Err("agent_session_closing".into()),
        };
        let session_to = if cancelled {
            "cancelled"
        } else if close {
            "closed"
        } else {
            "running"
        };
        let next_lease = if session_to == "running" {
            agent
                .lease_expires_at_unix_ms
                .map(|lease| lease.min(unix_ms_now().saturating_add(agent.idle_timeout_ms)))
        } else {
            None
        };
        let session = self
            .node
            .store()
            .transition_agent_session(
                &agent.key,
                session_from,
                agent.revision,
                session_to,
                next_lease,
            )
            .map_err(|error| error.to_string())?;
        agent.revision = session.revision;
        agent.lease_expires_at_unix_ms = session.lease_expires_at_unix_ms;
        if close || cancelled {
            agent.session_state = if cancelled {
                AgentSessionState::ClosingCancelled
            } else {
                AgentSessionState::ClosingCompleted
            };
            self.node
                .store()
                .begin_agent_finalization(&agent.key)
                .map_err(|error| error.to_string())?;
        }
        let state = if close {
            "finishing"
        } else if cancelled {
            "cancelled"
        } else {
            "running"
        };
        let mut receipt = json!({
            "operationId": agent.operation_id,
            "runId": agent.run_id,
            "requestDigest": agent.request_digest,
            "state": state,
            "controllerEpoch": agent.controller_epoch.to_string(),
            "revision": agent.revision.to_string(),
            "phase": format!("control_{command}"),
            "observedAt": now(),
        });
        if state == "running" {
            receipt = running_status_payload(
                &agent.operation_id,
                &agent.run_id,
                &agent.request_digest,
                &agent.runtime_id,
                &agent.provider_id,
                &agent.handle,
                agent.controller_epoch,
                agent.revision,
                true,
                &format!("control_{command}"),
            )
            .map_err(|error| error.to_string())?;
        }
        let terminal = control_terminal_payload(
            &control.operation_id,
            &agent.run_id,
            &request_digest,
            agent.event_sequence,
        )
        .map_err(|error| error.to_string())?;
        let durable_receipt = json!({
            "targetStatus": receipt.clone(),
            "controlTerminal": terminal.clone(),
        });
        let encoded = serde_jcs::to_vec(&durable_receipt)
            .map_err(|_| "control_receipt_invalid".to_owned())?;
        self.node
            .store()
            .complete_control_effect(&control.idempotency_key, true, &encoded)
            .map_err(|error| error.to_string())?;
        let status_message_id = format!("nmsg_x{}s", &request_digest[..23]);
        client
            .session
            .queue_outbound(
                &status_message_id,
                "operation.status",
                Some(agent.operation_id.clone()),
                receipt,
                0,
            )
            .map_err(|error| error.to_string())?;
        let terminal_message_id = format!("nmsg_x{}t", &request_digest[..23]);
        client
            .session
            .queue_outbound(
                &terminal_message_id,
                "operation.terminal",
                Some(control.operation_id),
                terminal,
                0,
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn control_runtime(&mut self, client: &mut WssClient, payload: &Value) -> Result<(), String> {
        let control: WireRuntimeControl = serde_json::from_value(payload.clone())
            .map_err(|_| "runtime_control_malformed".to_owned())?;
        let controller_epoch = control
            .target_controller_epoch
            .parse::<u64>()
            .map_err(|_| "runtime_controller_epoch_invalid".to_owned())?;
        let expected_revision = control
            .expected_revision
            .parse::<u64>()
            .map_err(|_| "runtime_expected_revision_invalid".to_owned())?;
        let request_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(payload).map_err(|_| "runtime_control_malformed".to_owned())?,
        ));
        let custody = self
            .runtime_custody
            .get(&control.target_runtime_id)
            .cloned()
            .ok_or_else(|| "target_runtime_unavailable".to_owned())?;
        let handle_digest =
            runtime_handle_digest(&custody.handle).map_err(|error| error.to_string())?;
        let target_digest = custody_target_digest(
            false,
            &custody.run_id,
            &custody.start_operation_id,
            &custody.request_digest,
            &custody.handle.runtime_id,
            &handle_digest,
            custody.controller_epoch,
        )
        .map_err(|error| error.to_string())?;
        if control.operation_id == custody.start_operation_id
            || control.target_run_id != custody.run_id
            || control.target_handle_digest != handle_digest
            || control.target_digest != target_digest
            || controller_epoch != custody.controller_epoch
        {
            return Err("runtime_control_target_mismatch".into());
        }
        if matches!(control.control.as_str(), "snapshot" | "restore")
            && control.snapshot_name.is_none()
        {
            return Err("runtime_snapshot_name_required".into());
        }
        if self
            .node
            .store()
            .control_effect(&control.idempotency_key)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            if expected_revision != custody.revision {
                return Err(format!(
                    "runtime_revision_stale:expected={expected_revision}:observed={}",
                    custody.revision,
                ));
            }
            let observed = self
                .node
                .inspect_runtime(&custody.provider_id, &custody.handle)
                .map_err(|error| error.to_string())?;
            if runtime_state_name(observed.state) != control.expected_state {
                return Err(format!(
                    "runtime_state_stale:expected={}:observed={}",
                    control.expected_state,
                    runtime_state_name(observed.state),
                ));
            }
        }
        match self
            .node
            .store()
            .reserve_control_effect(
                &control.operation_id,
                &control.idempotency_key,
                &request_digest,
                &control.target_run_id,
                Some(&control.target_runtime_id),
                &control.target_digest,
                controller_epoch,
                expected_revision,
                &control.control,
            )
            .map_err(|error| error.to_string())?
        {
            ControlEffectResult::Replay(record) => {
                let receipt = record
                    .receipt
                    .ok_or_else(|| "runtime_control_receipt_missing".to_owned())?;
                let replay: Value = serde_json::from_slice(&receipt)
                    .map_err(|_| "runtime_control_receipt_corrupt".to_owned())?;
                let message_id = format!("nmsg_x{}", &request_digest[..24]);
                client
                    .session
                    .queue_outbound(
                        &message_id,
                        "runtime.control_result",
                        Some(control.operation_id),
                        replay,
                        0,
                    )
                    .map_err(|error| error.to_string())?;
                return Ok(());
            }
            ControlEffectResult::Uncertain(_) => {
                return Err("ambiguous_control_effect_pending_recovery".into());
            }
            ControlEffectResult::Reserved(_) => {}
        }
        let observed = self
            .node
            .inspect_runtime(&custody.provider_id, &custody.handle)
            .map_err(|error| error.to_string())?;

        let mut result = json!({});
        let next_state = match control.control.as_str() {
            "input" | "steer" => {
                let agent = self
                    .agents
                    .values_mut()
                    .find(|agent| agent.runtime_id == control.target_runtime_id)
                    .ok_or_else(|| "runtime_input_requires_active_agent".to_owned())?;
                let operation = if control.control == "steer" {
                    AdapterOperation::Steer
                } else {
                    AdapterOperation::Send
                };
                let frames = agent
                    .driver
                    .command(operation, control.content.as_deref())
                    .map_err(|error| error.to_string())?;
                for frame in frames {
                    agent
                        .child
                        .write(&frame)
                        .map_err(|error| error.to_string())?;
                }
                observed.state
            }
            "pause" => {
                self.node
                    .signal_runtime(&custody.provider_id, &custody.handle, RuntimeSignal::Pause)
                    .map_err(|error| error.to_string())?
                    .state
            }
            "resume" => {
                self.node
                    .signal_runtime(&custody.provider_id, &custody.handle, RuntimeSignal::Resume)
                    .map_err(|error| error.to_string())?
                    .state
            }
            "cancel" => {
                self.node
                    .signal_runtime(
                        &custody.provider_id,
                        &custody.handle,
                        RuntimeSignal::ForceStop,
                    )
                    .map_err(|error| error.to_string())?
                    .state
            }
            "stop" => {
                self.node
                    .signal_runtime(
                        &custody.provider_id,
                        &custody.handle,
                        RuntimeSignal::GracefulStop,
                    )
                    .map_err(|error| error.to_string())?
                    .state
            }
            "snapshot" => {
                let name = control
                    .snapshot_name
                    .as_deref()
                    .ok_or_else(|| "runtime_snapshot_name_required".to_owned())?;
                let receipt = self
                    .node
                    .snapshot_runtime(&custody.provider_id, &custody.handle, name)
                    .map_err(|error| error.to_string())?;
                result = serde_json::to_value(receipt)
                    .map_err(|_| "runtime_snapshot_receipt_invalid".to_owned())?;
                observed.state
            }
            "restore" => {
                let name = control
                    .snapshot_name
                    .as_deref()
                    .ok_or_else(|| "runtime_snapshot_name_required".to_owned())?;
                self.node
                    .restore_runtime_snapshot(&custody.provider_id, &custody.handle, name)
                    .map_err(|error| error.to_string())?
                    .state
            }
            "destroy" => {
                let receipt = self
                    .node
                    .destroy_runtime(
                        &custody.provider_id,
                        &custody.handle,
                        &DestroyRequest {
                            discard_authorized: control.discard_authorized.unwrap_or(false),
                            custody_complete: control.custody_complete.unwrap_or(false),
                        },
                    )
                    .map_err(|error| error.to_string())?;
                result = serde_json::to_value(receipt)
                    .map_err(|_| "runtime_destroy_receipt_invalid".to_owned())?;
                RuntimeState::Destroyed
            }
            _ => return Err("runtime_control_unknown".into()),
        };
        let revision = custody.revision.saturating_add(1);
        if let Some(record) = self.runtime_custody.get_mut(&control.target_runtime_id) {
            record.state = next_state;
            record.revision = revision;
        }
        let mut receipt = json!({
            "operationId": control.operation_id,
            "requestDigest": request_digest,
            "targetRunId": control.target_run_id,
            "targetRuntimeId": control.target_runtime_id,
            "targetControllerEpoch": control.target_controller_epoch,
            "targetDigest": control.target_digest,
            "expectedState": control.expected_state,
            "expectedRevision": control.expected_revision,
            "control": control.control,
            "state": runtime_state_name(next_state),
            "revision": revision.to_string(),
            "processCountDelta": 0,
            "result": result,
            "observedAt": now(),
        });
        let receipt_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&receipt)
                .map_err(|_| "runtime_control_receipt_invalid".to_owned())?,
        ));
        receipt["receiptDigest"] = Value::String(receipt_digest);
        let encoded = serde_jcs::to_vec(&receipt)
            .map_err(|_| "runtime_control_receipt_invalid".to_owned())?;
        self.node
            .store()
            .complete_control_effect(&control.idempotency_key, true, &encoded)
            .map_err(|error| error.to_string())?;
        let message_id = format!("nmsg_x{}", &request_digest[..24]);
        client
            .session
            .queue_outbound(
                &message_id,
                "runtime.control_result",
                Some(control.operation_id),
                receipt,
                0,
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn poll_agents(&mut self, client: &mut WssClient) -> Result<(), ServiceError> {
        struct PendingEvent {
            key: String,
            run_id: String,
            operation_id: String,
            sequence: u64,
            event: AdapterEvent,
        }
        struct PendingTerminal {
            id: String,
            state: OperationState,
            reason: Option<String>,
            last_sequence: u64,
            exit_code: Option<i32>,
        }
        struct PendingStatus {
            operation_id: String,
            payload: Value,
        }
        let ids = self.agents.keys().cloned().collect::<Vec<_>>();
        let mut events = Vec::new();
        let mut terminals = Vec::new();
        let mut approvals = Vec::new();
        let mut statuses = Vec::new();
        let mut raw_events: HashMap<String, (String, Vec<RawRecord>)> = HashMap::new();
        for id in &ids {
            let Some(agent) = self.agents.get_mut(id) else {
                continue;
            };
            if agent.driver.state() != AdapterState::Failed {
                for journal in self.node.store().unqueued_agent_approvals(&agent.key)? {
                    let request_payload = journal.request_payload.ok_or_else(|| {
                        ServiceError::Unavailable("approval_request_payload_missing".into())
                    })?;
                    let payload: Value = serde_json::from_slice(&request_payload)
                        .map_err(|_| TransportError::Malformed)?;
                    let correlation_id = payload
                        .get("operationId")
                        .and_then(Value::as_str)
                        .ok_or(TransportError::Malformed)?
                        .to_owned();
                    let message_id = journal.approval_id.replacen("appr_", "nmsg_", 1);
                    client.session.queue_outbound(
                        &message_id,
                        "operation.approval_request",
                        Some(correlation_id),
                        payload,
                        0,
                    )?;
                    self.node
                        .store()
                        .mark_agent_approval_requested(&journal.approval_id)?;
                }
                for journal in self.node.store().resolved_agent_approvals(&agent.key)? {
                    let frame =
                        conduit_adapters::ProtocolFrame(journal.resolution.ok_or_else(|| {
                            ServiceError::Unavailable("approval_response_missing".into())
                        })?);
                    agent
                        .child
                        .write(&frame)
                        .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                    self.node
                        .store()
                        .mark_agent_approval_applied_and_resume(&journal.approval_id, &agent.key)?;
                }
                let (expired_frames, expired_events) = agent
                    .driver
                    .expire_codex_approvals(unix_ms_now())
                    .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?;
                for (frame, event) in expired_frames.into_iter().zip(expired_events) {
                    let provider_request_id = event
                        .data
                        .as_ref()
                        .and_then(|data| data.get("providerRequestId"))
                        .ok_or(TransportError::Malformed)?;
                    let encoded_id = serde_jcs::to_vec(provider_request_id)
                        .map_err(|_| TransportError::Malformed)?;
                    let journal = self
                        .node
                        .store()
                        .agent_approval_for_provider_request(&agent.key, &encoded_id)?
                        .ok_or_else(|| {
                            ServiceError::Unavailable("approval_request_unknown".into())
                        })?;
                    let timeout_authority = format!("local_timeout:{}", journal.expires_at_unix_ms);
                    self.node.store().record_agent_approval_resolution(
                        &journal.approval_id,
                        &frame.0,
                        timeout_authority.as_bytes(),
                    )?;
                    agent
                        .child
                        .write(&frame)
                        .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                    self.node
                        .store()
                        .mark_agent_approval_applied_and_resume(&journal.approval_id, &agent.key)?;
                    agent.event_sequence = agent.event_sequence.saturating_add(1);
                    events.push(PendingEvent {
                        key: agent.key.clone(),
                        run_id: agent.run_id.clone(),
                        operation_id: agent.operation_id.clone(),
                        sequence: agent.event_sequence,
                        event,
                    });
                }
            }
            for _ in 0..128 {
                let record = match agent.child.try_read_record() {
                    Ok(Some(record)) => {
                        agent.raw_sequence = agent.raw_sequence.saturating_add(1);
                        raw_events
                            .entry(agent.run_id.clone())
                            .or_insert_with(|| (agent.operation_id.clone(), Vec::new()))
                            .1
                            .push(RawRecord {
                                local_sequence: agent.raw_sequence,
                                monotonic_ns: 0,
                                direction: "adapter".into(),
                                bytes: record.clone(),
                            });
                        record
                    }
                    Ok(None) => break,
                    Err(error) => {
                        agent.raw_sequence = agent.raw_sequence.saturating_add(1);
                        raw_events
                            .entry(agent.run_id.clone())
                            .or_insert_with(|| (agent.operation_id.clone(), Vec::new()))
                            .1
                            .push(RawRecord {
                                local_sequence: agent.raw_sequence,
                                monotonic_ns: 0,
                                direction: "adapter_error".into(),
                                bytes: error.to_string().into_bytes(),
                            });
                        agent.event_sequence = agent.event_sequence.saturating_add(1);
                        events.push(PendingEvent {
                            key: agent.key.clone(),
                            run_id: agent.run_id.clone(),
                            operation_id: agent.operation_id.clone(),
                            sequence: agent.event_sequence,
                            event: adapter_error_event("adapter_frame_error", &error.to_string()),
                        });
                        break;
                    }
                };
                match agent.driver.on_record(&record) {
                    Ok((frames, normalized)) => {
                        for frame in frames {
                            agent
                                .child
                                .write(&frame)
                                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                        }
                        for event in normalized {
                            if event.kind == AdapterEventKind::ApprovalRequest
                                && event
                                    .data
                                    .as_ref()
                                    .and_then(|data| data.get("preAuthorized"))
                                    .and_then(Value::as_bool)
                                    == Some(false)
                                && let Some(data) = event.data.as_ref()
                            {
                                let provider_request_id = data
                                    .get("providerRequestId")
                                    .cloned()
                                    .ok_or(TransportError::Malformed)?;
                                let method = data
                                    .get("method")
                                    .and_then(Value::as_str)
                                    .ok_or(TransportError::Malformed)?
                                    .to_owned();
                                let parameters_digest = data
                                    .get("parametersDigest")
                                    .and_then(Value::as_str)
                                    .ok_or(TransportError::Malformed)?
                                    .to_owned();
                                let expires_at_unix_ms = data
                                    .get("expiresAtUnixMs")
                                    .and_then(Value::as_u64)
                                    .ok_or(TransportError::Malformed)?;
                                let arguments_summary = data
                                    .get("argumentsSummary")
                                    .cloned()
                                    .ok_or(TransportError::Malformed)?;
                                approvals.push(PendingAgentApproval {
                                    key: agent.key.clone(),
                                    operation_id: agent.operation_id.clone(),
                                    run_id: agent.run_id.clone(),
                                    request_digest: agent.request_digest.clone(),
                                    adapter_kind: agent.adapter_kind,
                                    actor_principal_id: agent.actor_principal_id.clone(),
                                    client_id: agent.client_id.clone(),
                                    access_scope: agent.access_scope.clone(),
                                    approval_mode: agent.approval_mode.clone(),
                                    effective_required_approval_risk_classes: agent
                                        .effective_required_approval_risk_classes
                                        .clone(),
                                    local_policy_revision: agent.local_policy_revision,
                                    controller_epoch: agent.controller_epoch,
                                    provider_request_id,
                                    method,
                                    parameters_digest,
                                    arguments_summary,
                                    expires_at_unix_ms,
                                });
                            }
                            agent.event_sequence = agent.event_sequence.saturating_add(1);
                            events.push(PendingEvent {
                                key: agent.key.clone(),
                                run_id: agent.run_id.clone(),
                                operation_id: agent.operation_id.clone(),
                                sequence: agent.event_sequence,
                                event,
                            });
                        }
                    }
                    Err(error) => {
                        agent.event_sequence = agent.event_sequence.saturating_add(1);
                        events.push(PendingEvent {
                            key: agent.key.clone(),
                            run_id: agent.run_id.clone(),
                            operation_id: agent.operation_id.clone(),
                            sequence: agent.event_sequence,
                            event: adapter_error_event(
                                "adapter_protocol_error",
                                &error.to_string(),
                            ),
                        });
                    }
                }
            }
            let adapter_state = agent.driver.state();
            if adapter_state == AdapterState::Completed
                && agent.session_state == AgentSessionState::Running
            {
                match agent.settlement_policy {
                    AgentSettlementPolicy::CloseOnSettle => {
                        if let Ok(frames) = agent.driver.command(AdapterOperation::Close, None) {
                            for frame in frames {
                                agent.child.write(&frame).map_err(|error| {
                                    ServiceError::Unavailable(error.to_string())
                                })?;
                            }
                        }
                        let session = self.node.store().transition_agent_session(
                            &agent.key,
                            "running",
                            agent.revision,
                            "closed",
                            None,
                        )?;
                        agent.revision = session.revision;
                        agent.session_state = AgentSessionState::ClosingCompleted;
                        let handle_digest = runtime_handle_digest(&agent.handle)?;
                        let target_digest = custody_target_digest(
                            true,
                            &agent.run_id,
                            &agent.operation_id,
                            &agent.request_digest,
                            &agent.runtime_id,
                            &handle_digest,
                            agent.controller_epoch,
                        )?;
                        let runtime_target_digest = custody_target_digest(
                            false,
                            &agent.run_id,
                            &agent.operation_id,
                            &agent.request_digest,
                            &agent.runtime_id,
                            &handle_digest,
                            agent.controller_epoch,
                        )?;
                        statuses.push(PendingStatus {
                            operation_id: agent.operation_id.clone(),
                            payload: json!({
                                "operationId": agent.operation_id,
                                "runId": agent.run_id,
                                "requestDigest": agent.request_digest,
                                "state": "finishing",
                                "controllerEpoch": agent.controller_epoch.to_string(),
                                "revision": agent.revision.to_string(),
                                "phase": "workspace_capture",
                                "targetRuntimeId": agent.runtime_id,
                                "targetDigest": target_digest,
                                "runtimeTargetDigest": runtime_target_digest,
                                "selectedRuntimeProvider": agent.provider_id,
                                "runtimeHandleDigest": handle_digest,
                                "observedAt": now(),
                            }),
                        });
                        self.node.store().begin_agent_finalization(&agent.key)?;
                        agent
                            .child
                            .terminate()
                            .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                    }
                    AgentSettlementPolicy::Persistent => {
                        let idle_deadline = unix_ms_now().saturating_add(agent.idle_timeout_ms);
                        let lease_deadline = agent
                            .lease_expires_at_unix_ms
                            .map_or(idle_deadline, |lease| lease.min(idle_deadline));
                        self.node.store().transition_operation(
                            &agent.key,
                            OperationState::Running,
                            OperationState::WaitingInput,
                            None,
                            None,
                            None,
                        )?;
                        let session = self.node.store().transition_agent_session(
                            &agent.key,
                            "running",
                            agent.revision,
                            "waiting_input",
                            Some(lease_deadline),
                        )?;
                        agent.revision = session.revision;
                        agent.session_state = AgentSessionState::WaitingInput;
                        agent.lease_expires_at_unix_ms = Some(lease_deadline);
                        let handle_digest = runtime_handle_digest(&agent.handle)?;
                        let target_digest = custody_target_digest(
                            true,
                            &agent.run_id,
                            &agent.operation_id,
                            &agent.request_digest,
                            &agent.runtime_id,
                            &handle_digest,
                            agent.controller_epoch,
                        )?;
                        let runtime_target_digest = custody_target_digest(
                            false,
                            &agent.run_id,
                            &agent.operation_id,
                            &agent.request_digest,
                            &agent.runtime_id,
                            &handle_digest,
                            agent.controller_epoch,
                        )?;
                        statuses.push(PendingStatus {
                            operation_id: agent.operation_id.clone(),
                            payload: json!({
                                "operationId": agent.operation_id,
                                "runId": agent.run_id,
                                "requestDigest": agent.request_digest,
                                "state": "waiting_input",
                                "controllerEpoch": agent.controller_epoch.to_string(),
                                "revision": agent.revision.to_string(),
                                "phase": "agent_settled",
                                "targetRuntimeId": agent.runtime_id,
                                "targetDigest": target_digest,
                                "runtimeTargetDigest": runtime_target_digest,
                                "selectedRuntimeProvider": agent.provider_id,
                                "runtimeHandleDigest": handle_digest,
                                "observedAt": now(),
                            }),
                        });
                    }
                }
            } else if agent.session_state == AgentSessionState::WaitingInput
                && agent
                    .lease_expires_at_unix_ms
                    .is_some_and(|deadline| unix_ms_now() >= deadline)
            {
                let session = self.node.store().transition_agent_session(
                    &agent.key,
                    "waiting_input",
                    agent.revision,
                    "timed_out",
                    None,
                )?;
                agent.revision = session.revision;
                agent.session_state = AgentSessionState::ClosingTimedOut;
                self.node.store().begin_agent_finalization(&agent.key)?;
                let exit = agent
                    .child
                    .terminate()
                    .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                terminals.push(PendingTerminal {
                    id: id.clone(),
                    state: OperationState::TimedOut,
                    reason: Some("agent_session_idle_timeout".into()),
                    last_sequence: agent.event_sequence,
                    exit_code: exit.code(),
                });
                continue;
            }
            let exit = if adapter_state == AdapterState::Failed {
                Some(
                    agent
                        .child
                        .terminate()
                        .map_err(|error| ServiceError::Unavailable(error.to_string()))?,
                )
            } else {
                agent
                    .child
                    .try_wait()
                    .map_err(|error| ServiceError::Unavailable(error.to_string()))?
            };
            if let Some(exit) = exit {
                let (state, reason) = match agent.session_state {
                    AgentSessionState::ClosingCancelled => {
                        (OperationState::Cancelled, Some("agent_cancelled".into()))
                    }
                    AgentSessionState::ClosingTimedOut => (
                        OperationState::TimedOut,
                        Some("agent_session_idle_timeout".into()),
                    ),
                    AgentSessionState::ClosingCompleted => (OperationState::Completed, None),
                    AgentSessionState::Running | AgentSessionState::WaitingInput => {
                        match (adapter_state, exit.success()) {
                            (AdapterState::Completed, true) => (OperationState::Completed, None),
                            (AdapterState::Cancelled, _) => {
                                (OperationState::Cancelled, Some("adapter_cancelled".into()))
                            }
                            (AdapterState::Failed, _) => (
                                OperationState::Failed,
                                Some("adapter_protocol_error".into()),
                            ),
                            _ => (
                                OperationState::Failed,
                                Some(
                                    if exit.success() {
                                        "adapter_protocol_incomplete"
                                    } else {
                                        "adapter_crash"
                                    }
                                    .into(),
                                ),
                            ),
                        }
                    }
                };
                terminals.push(PendingTerminal {
                    id: id.clone(),
                    state,
                    reason,
                    last_sequence: agent.event_sequence,
                    exit_code: exit.code(),
                });
            }
        }
        // Commit raw provider records before normalizing or cloud batching.
        // A parser/redaction/queue failure must not erase the authoritative
        // Device-local byte stream that was already read from the adapter.
        for (run_id, (stream_id, records)) in &raw_events {
            self.local
                .append_raw_segments(run_id, stream_id, records)
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        }
        let terminal_ids = terminals
            .iter()
            .map(|pending| pending.id.clone())
            .collect::<BTreeSet<_>>();
        for pending in approvals {
            if approval_projection_allowed(&pending.operation_id, &terminal_ids) {
                self.queue_agent_approval(client, pending)?;
            }
        }
        for pending in statuses {
            let message_id = self.message_id();
            client.session.queue_outbound(
                &message_id,
                "operation.status",
                Some(pending.operation_id),
                pending.payload,
                0,
            )?;
        }
        for pending in events {
            let payload = visible_adapter_payload(&pending.event);
            let normalized = self
                .local
                .append_visible_event(
                    &pending.run_id,
                    &self.device_id,
                    pending.sequence,
                    &self.node_boot_id,
                    &pending.operation_id,
                    adapter_event_name(pending.event.kind),
                    payload,
                )
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            let encoded = serde_jcs::to_vec(&normalized).map_err(|_| TransportError::Malformed)?;
            let digest = normalized
                .get("eventDigest")
                .and_then(Value::as_str)
                .ok_or(TransportError::Malformed)?;
            self.node.store().append_operation_event(
                &pending.key,
                &pending.run_id,
                normalized["eventId"]
                    .as_str()
                    .ok_or(TransportError::Malformed)?,
                digest,
                &encoded,
                if matches!(
                    pending.event.kind,
                    AdapterEventKind::Error | AdapterEventKind::AdapterError
                ) {
                    0
                } else {
                    1
                },
            )?;
            let priority = adapter_event_priority(pending.event.kind)
                || normalized_event_priority(&normalized);
            let ready = self
                .event_accumulators
                .entry(pending.run_id.clone())
                .or_insert_with(|| {
                    EventAccumulator::new(
                        pending.run_id.clone(),
                        Some(pending.operation_id.clone()),
                    )
                })
                .push(pending.sequence, normalized, priority, Instant::now())?;
            for batch in ready {
                self.queue_event_batch(client, batch)?;
            }
        }
        // Terminal/approval/error records above are priority-flushed.  Flush
        // any remaining normal deltas before finalizing a Run so a terminal
        // receipt can never overtake an earlier local event.
        self.flush_all_event_batches(client)?;
        for pending in terminals {
            if let Some(agent) = self.agents.get(&pending.id) {
                if let Some(custody) = self.runtime_custody.get_mut(&agent.runtime_id) {
                    custody.state = RuntimeState::Stopped;
                }
                if matches!(agent.provider_id.as_str(), "native" | "restricted_native") {
                    self.supervisor
                        .mark_external_stopped(&agent.runtime_id, pending.exit_code)
                        .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                } else {
                    self.stop_reconciled_runtime(&agent.provider_id, &agent.handle, false)?;
                }
            }
            self.finish_agent(
                client,
                &pending.id,
                pending.state,
                pending.reason.as_deref(),
                pending.last_sequence,
            )?;
        }
        Ok(())
    }

    fn queue_agent_approval(
        &mut self,
        client: &mut WssClient,
        pending: PendingAgentApproval,
    ) -> Result<(), ServiceError> {
        let controller_epoch = pending.controller_epoch;
        let commitment = json!({
            "domain": "conduit.agent-approval.v1",
            "operationId": pending.operation_id,
            "runId": pending.run_id,
            "requestDigest": pending.request_digest,
            "providerRequestId": pending.provider_request_id,
            "method": pending.method,
            "parametersDigest": pending.parameters_digest,
            "argumentsSummary": pending.arguments_summary,
            "approvalExpiresAtUnixMs": pending.expires_at_unix_ms,
            "adapterId": pending.adapter_kind.as_str(),
            "accessScope": pending.access_scope,
            "approvalMode": pending.approval_mode,
            "effectiveRequiredApprovalRiskClasses": pending.effective_required_approval_risk_classes,
            "controllerEpoch": controller_epoch.to_string(),
            "localPolicyRevision": pending.local_policy_revision,
        });
        let operation_digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&commitment).map_err(|_| TransportError::Malformed)?,
        ));
        let approval_id = format!("appr_x{}", &operation_digest[..24]);
        let provider_request_id = serde_jcs::to_vec(&pending.provider_request_id)
            .map_err(|_| TransportError::Malformed)?;
        let issued_at_unix_ms = unix_ms_now();
        let (issued_at, expires_at, valid_for_ms) =
            approval_request_window_at(issued_at_unix_ms, pending.expires_at_unix_ms)?;
        let payload = json!({
            "approvalId": approval_id,
            "operationId": pending.operation_id,
            "runId": pending.run_id,
            "requesterPrincipalId": pending.actor_principal_id,
            "clientId": pending.client_id,
            "deviceId": self.device_id,
            "operationDigest": operation_digest,
            "providerRequestId": pending.provider_request_id,
            "method": pending.method,
            "parametersDigest": pending.parameters_digest,
            "argumentsSummary": pending.arguments_summary,
            "adapterId": pending.adapter_kind.as_str(),
            "accessScope": pending.access_scope,
            "approvalMode": pending.approval_mode,
            "effectiveRequiredApprovalRiskClasses": pending.effective_required_approval_risk_classes,
            "controllerEpoch": controller_epoch.to_string(),
            "localPolicyRevision": pending.local_policy_revision,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "validForMs": valid_for_ms,
        });
        let request_payload = serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?;
        self.node.store().record_agent_approval(
            &approval_id,
            &pending.key,
            &operation_digest,
            &provider_request_id,
            &pending.method,
            &pending.parameters_digest,
            pending.expires_at_unix_ms,
            &request_payload,
        )?;
        let message_id = format!("nmsg_x{}", &operation_digest[..24]);
        client.session.queue_outbound(
            &message_id,
            "operation.approval_request",
            Some(pending.operation_id),
            payload,
            0,
        )?;
        self.node
            .store()
            .mark_agent_approval_requested(&approval_id)?;
        Ok(())
    }

    fn finish_agent(
        &mut self,
        client: &mut WssClient,
        id: &str,
        terminal: OperationState,
        reason: Option<&str>,
        last_sequence: u64,
    ) -> Result<(), ServiceError> {
        let Some(agent) = self.agents.get(id) else {
            return Ok(());
        };
        self.node.store().begin_agent_finalization(&agent.key)?;
        let key = agent.key.clone();
        let operation_id = agent.operation_id.clone();
        let run_id = agent.run_id.clone();
        let request_digest = agent.request_digest.clone();
        let state = match terminal {
            OperationState::Completed => "completed",
            OperationState::Cancelled => "cancelled",
            OperationState::TimedOut => "timed_out",
            _ => "failed",
        };
        let mut payload = json!({"operationId":operation_id,"runId":run_id,"state":state,"requestDigest":request_digest,"lastRunEventSequence":last_sequence.to_string(),"observedAt":now()});
        if terminal == OperationState::Completed {
            let capture = self
                .local
                .capture_workspace(&agent.prepared_sources, &agent.source_baseline_revisions)
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            let required_checks = agent
                .verification_policy
                .get("requiredChecks")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let checks = if required_checks.is_empty() {
                vec!["workspace_capture".to_owned()]
            } else {
                required_checks
            };
            let verification = checks
                .into_iter()
                .map(|check_id| {
                    let status = match check_id.as_str() {
                        "workspace_capture" => "passed",
                        "workspace_clean" if capture.all_clean => "passed",
                        "workspace_clean" => "failed",
                        _ => "unavailable",
                    };
                    let observed_digest = hex::encode(Sha256::digest(
                        format!(
                            "conduit.verification-observation.v1\n{}\n{}\n{}",
                            check_id, status, capture.capture_digest
                        )
                        .as_bytes(),
                    ));
                    json!({
                        "checkId": check_id,
                        "status": status,
                        "evidenceRefs": [],
                        "observedDigest": observed_digest,
                    })
                })
                .collect::<Vec<_>>();
            payload["resultSummary"] = json!({
                "submission": {
                    "expectedNodeRevision": agent.revision,
                    "terminalReceiptDigest": capture.capture_digest,
                    "parentBaselineId": agent.parent_baseline_id,
                    "sourceChanges": capture.source_changes,
                    "unchangedSources": capture.unchanged_sources,
                    "applicationOrder": capture.application_order,
                    "artifactCommitments": [],
                    "provenance": {
                        "adapterId": agent.adapter_kind.as_str(),
                        "evidenceLevel": "observed",
                        "settlement": "protocol_completed",
                    },
                    "custody": capture.custody,
                    "verification": verification,
                }
            });
        }
        if let Some(reason) = reason {
            payload["reasonCode"] = Value::String(reason.into());
            payload["resultSummary"]["adapterTerminal"] = Value::String(reason.into());
        }
        let digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
        ));
        payload["receiptDigest"] = Value::String(digest);
        let bytes = serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?;
        self.node
            .terminal(&key, OperationState::Finishing, terminal, &bytes)?;
        self.agents
            .remove(id)
            .expect("agent remained present until durable terminalization");
        let message_id = self.message_id();
        client.session.queue_outbound(
            &message_id,
            "operation.terminal",
            Some(operation_id),
            payload,
            0,
        )?;
        Ok(())
    }

    fn replay_run_status(
        &mut self,
        client: &mut WssClient,
        run_id: &str,
    ) -> Result<(), ServiceError> {
        let admission = self
            .node
            .store()
            .admissions()?
            .into_iter()
            .find(|admission| {
                serde_json::from_slice::<RuntimeRequest>(&admission.runtime_request)
                    .is_ok_and(|request| request.run_id == run_id)
            })
            .ok_or_else(|| ServiceError::Unavailable("status_run_unavailable".into()))?;
        if admission.operation.state.terminal() {
            let mut payload = admission
                .operation
                .receipt
                .as_deref()
                .and_then(|receipt| serde_json::from_slice::<Value>(receipt).ok())
                .filter(|payload| {
                    payload
                        .get("receiptDigest")
                        .and_then(Value::as_str)
                        .is_some()
                });
            if payload.is_none() {
                let state = terminal_state_name(admission.operation.state);
                let mut rebuilt = json!({"operationId":admission.operation.operation_id,"runId":run_id,"state":state,"requestDigest":admission.operation.request_digest,"lastRunEventSequence":admission.operation.last_event_sequence.to_string(),"reasonCode":"durable_terminal_replay","observedAt":now()});
                let digest = hex::encode(Sha256::digest(
                    serde_jcs::to_vec(&rebuilt).map_err(|_| TransportError::Malformed)?,
                ));
                rebuilt["receiptDigest"] = Value::String(digest);
                let bytes = serde_jcs::to_vec(&rebuilt).map_err(|_| TransportError::Malformed)?;
                self.node.store().transition_operation(
                    &admission.operation.idempotency_key,
                    admission.operation.state,
                    admission.operation.state,
                    None,
                    None,
                    Some(&bytes),
                )?;
                payload = Some(rebuilt);
            }
            let message_id = self.message_id();
            client.session.queue_outbound(
                &message_id,
                "operation.terminal",
                Some(admission.operation.operation_id),
                payload.ok_or(TransportError::Malformed)?,
                0,
            )?;
            return Ok(());
        }
        let status = if let Some(active) = self.active.get(&admission.operation.operation_id) {
            running_status_payload(
                &active.operation_id,
                &active.run_id,
                &active.request_digest,
                &active.handle.runtime_id,
                &active.provider_id,
                &active.handle,
                active.controller_epoch,
                active.revision,
                false,
                "reconciled_status",
            )?
        } else if let Some(agent) = self.agents.get(&admission.operation.operation_id) {
            running_status_payload(
                &agent.operation_id,
                &agent.run_id,
                &agent.request_digest,
                &agent.runtime_id,
                &agent.provider_id,
                &agent.handle,
                agent.controller_epoch,
                agent.revision,
                true,
                "reconciled_status",
            )?
        } else {
            json!({
                "operationId": admission.operation.operation_id,
                "runId": run_id,
                "requestDigest": admission.operation.request_digest,
                "state": admission.operation.state,
                "controllerEpoch": "1",
                "revision": "1",
                "phase": "reconciled_status",
                "observedAt": now(),
            })
        };
        let message_id = self.message_id();
        client.session.queue_outbound(
            &message_id,
            "operation.status",
            Some(admission.operation.operation_id),
            status,
            0,
        )?;
        Ok(())
    }

    fn reconcile_cancel(
        &mut self,
        client: &mut WssClient,
        operation_id: &str,
        quarantine: bool,
    ) -> Result<(), ServiceError> {
        let (key, run_id, request_digest, current) = if let Some(active) =
            self.active.get(operation_id)
        {
            self.stop_reconciled_runtime(&active.provider_id, &active.handle, quarantine)?;
            let active = self
                .active
                .remove(operation_id)
                .expect("runtime was present while it was stopped");
            (
                active.key,
                active.run_id,
                active.request_digest,
                active.journal_state,
            )
        } else if self.agents.contains_key(operation_id) {
            let (runtime_id, provider_id, handle, status) = {
                let agent = self
                    .agents
                    .get_mut(operation_id)
                    .expect("agent was present while it was stopped");
                let status = agent
                    .child
                    .terminate()
                    .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
                (
                    agent.runtime_id.clone(),
                    agent.provider_id.clone(),
                    agent.handle.clone(),
                    status,
                )
            };
            if matches!(provider_id.as_str(), "native" | "restricted_native") {
                self.supervisor
                    .mark_external_stopped(&runtime_id, status.code())
                    .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            } else {
                self.stop_reconciled_runtime(&provider_id, &handle, quarantine)?;
            }
            let agent = self
                .agents
                .remove(operation_id)
                .expect("agent was present after it was stopped");
            (
                agent.key,
                agent.run_id,
                agent.request_digest,
                OperationState::Running,
            )
        } else {
            let admission = self
                .node
                .store()
                .admissions()?
                .into_iter()
                .find(|admission| admission.operation.operation_id == operation_id)
                .ok_or_else(|| ServiceError::Unavailable("cancel_operation_unavailable".into()))?;
            if admission.operation.state.terminal() {
                let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
                    .map_err(|_| TransportError::Malformed)?;
                return self.replay_run_status(client, &runtime.run_id);
            }
            let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
                .map_err(|_| TransportError::Malformed)?;
            if admission.operation.state != OperationState::Admitted {
                let handle = self.node.runtime_handle(&admission)?;
                self.stop_reconciled_runtime(&admission.provider_id, &handle, quarantine)?;
            }
            (
                admission.operation.idempotency_key,
                runtime.run_id,
                admission.operation.request_digest,
                admission.operation.state,
            )
        };
        let terminal = if quarantine {
            OperationState::RecoveryRequired
        } else {
            OperationState::Cancelled
        };
        let reason = if quarantine {
            "reconciliation_quarantine"
        } else {
            "reconciliation_cancel"
        };
        let last_sequence = self
            .node
            .store()
            .operation(&key)?
            .map_or(0, |operation| operation.last_event_sequence);
        let mut receipt = json!({"operationId":operation_id,"runId":run_id,"state":if quarantine{"recovery_required"}else{"cancelled"},"requestDigest":request_digest,"lastRunEventSequence":last_sequence.to_string(),"reasonCode":reason,"observedAt":now()});
        let digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&receipt).map_err(|_| TransportError::Malformed)?,
        ));
        receipt["receiptDigest"] = Value::String(digest);
        let bytes = serde_jcs::to_vec(&receipt).map_err(|_| TransportError::Malformed)?;
        self.node.terminal(&key, current, terminal, &bytes)?;
        let message_id = self.message_id();
        client.session.queue_outbound(
            &message_id,
            "operation.terminal",
            Some(operation_id.to_owned()),
            receipt,
            0,
        )?;
        Ok(())
    }

    fn stop_reconciled_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        quarantine: bool,
    ) -> Result<(), ServiceError> {
        let first_signal = if quarantine {
            conduit_runtime::RuntimeSignal::ForceStop
        } else {
            conduit_runtime::RuntimeSignal::GracefulStop
        };
        self.node
            .signal_runtime(provider_id, handle, first_signal)
            .map_err(|error| {
                ServiceError::Unavailable(format!("runtime_stop_unconfirmed:{error}"))
            })?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let receipt = self
                .node
                .inspect_runtime(provider_id, handle)
                .map_err(|error| {
                    ServiceError::Unavailable(format!("runtime_stop_unconfirmed:{error}"))
                })?;
            if matches!(
                receipt.state,
                RuntimeState::Stopped | RuntimeState::Failed | RuntimeState::Lost
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !quarantine {
            self.node
                .signal_runtime(
                    provider_id,
                    handle,
                    conduit_runtime::RuntimeSignal::ForceStop,
                )
                .map_err(|error| {
                    ServiceError::Unavailable(format!("runtime_force_stop_unconfirmed:{error}"))
                })?;
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                let receipt = self
                    .node
                    .inspect_runtime(provider_id, handle)
                    .map_err(|error| {
                        ServiceError::Unavailable(format!("runtime_force_stop_unconfirmed:{error}"))
                    })?;
                if matches!(
                    receipt.state,
                    RuntimeState::Stopped | RuntimeState::Failed | RuntimeState::Lost
                ) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Err(ServiceError::Unavailable("runtime_stop_unconfirmed".into()))
    }

    fn verify_terminal_confirmations(&self, confirmations: &[Value]) -> Result<(), ServiceError> {
        if confirmations.is_empty() {
            return Ok(());
        }
        let available = self
            .node
            .store()
            .admissions()?
            .into_iter()
            .filter_map(|admission| admission.operation.receipt)
            .filter_map(|receipt| {
                serde_json::from_slice::<Value>(&receipt)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("receiptDigest")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
            })
            .collect::<std::collections::BTreeSet<_>>();
        if confirmations.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|digest| available.contains(digest))
        }) {
            Ok(())
        } else {
            Err(ServiceError::Unavailable(
                "terminal_receipt_confirmation_unknown".into(),
            ))
        }
    }
}
fn admission_payload(r: &AdmissionReceipt, decision: &str) -> Result<Value, ServiceError> {
    let mut payload = json!({"operationId":r.operation_id,"idempotencyKey":r.idempotency_key,"requestDigest":r.request_digest,"decision":decision,"journalState":if decision=="uncertain"{"uncertain"}else{"admitted"},"selectedRuntimeProvider":r.selected_provider,"effectiveAccessScope":r.effective_access_scope,"effectiveApprovalMode":r.effective_approval_policy,"localPolicyRevision":r.local_policy_revision});
    let digest = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
    ));
    payload["receiptDigest"] = Value::String(digest);
    Ok(payload)
}
fn adapter_operation_state(state: AdapterState) -> &'static str {
    match state {
        AdapterState::Starting => "starting",
        AdapterState::Ready | AdapterState::Working => "running",
        AdapterState::WaitingApproval => "waiting_approval",
        AdapterState::Completed => "completed",
        AdapterState::Cancelled => "cancelled",
        AdapterState::Failed => "failed",
        AdapterState::RecoveryRequired => "recovery_required",
    }
}

fn runtime_state_name(state: RuntimeState) -> &'static str {
    match state {
        RuntimeState::Planned => "planned",
        RuntimeState::Preparing => "preparing",
        RuntimeState::Prepared => "prepared",
        RuntimeState::Starting => "starting",
        RuntimeState::Running => "running",
        RuntimeState::Paused => "paused",
        RuntimeState::Stopping => "stopping",
        RuntimeState::Stopped => "stopped",
        RuntimeState::Failed => "failed",
        RuntimeState::Lost => "lost",
        RuntimeState::Uncertain => "uncertain",
        RuntimeState::RecoveryRequired => "recovery_required",
        RuntimeState::Destroying => "destroying",
        RuntimeState::Destroyed => "destroyed",
    }
}

fn approval_projection_allowed(
    operation_id: &str,
    terminal_operation_ids: &BTreeSet<String>,
) -> bool {
    !terminal_operation_ids.contains(operation_id)
}

fn terminal_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Completed => "completed",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
        OperationState::TimedOut => "timed_out",
        OperationState::Lost => "lost",
        OperationState::Uncertain => "uncertain",
        OperationState::RecoveryRequired => "recovery_required",
        OperationState::Rejected => "rejected",
        OperationState::Expired => "expired",
        _ => "failed",
    }
}

fn adapter_event_name(kind: AdapterEventKind) -> &'static str {
    match kind {
        AdapterEventKind::PromptAccepted => "adapter.prompt_accepted",
        AdapterEventKind::Session => "adapter.session",
        AdapterEventKind::State => "adapter.state",
        AdapterEventKind::AssistantMessage => "adapter.assistant_message",
        AdapterEventKind::AssistantMessageDelta => "adapter.assistant_message_delta",
        AdapterEventKind::ToolCall => "adapter.tool_call",
        AdapterEventKind::ToolResult => "adapter.tool_result",
        AdapterEventKind::Command => "adapter.command",
        AdapterEventKind::FileEffect => "adapter.file_effect",
        AdapterEventKind::ApprovalRequest => "adapter.approval_request",
        AdapterEventKind::Usage => "adapter.usage",
        AdapterEventKind::Subagent => "adapter.subagent",
        AdapterEventKind::Completed => "adapter.completed",
        AdapterEventKind::Error => "adapter.error",
        AdapterEventKind::AdapterError => "adapter.protocol_error",
    }
}

/// Events that represent an effect boundary are never held behind the
/// normal 100ms accumulator timer.  Assistant text deltas and usage samples
/// remain ordinary progress events; their individual normalized records are
/// retained in one bounded batch and concatenate byte-for-byte locally.
fn adapter_event_priority(kind: AdapterEventKind) -> bool {
    matches!(
        kind,
        AdapterEventKind::ApprovalRequest
            | AdapterEventKind::Completed
            | AdapterEventKind::Error
            | AdapterEventKind::AdapterError
            | AdapterEventKind::ToolCall
            | AdapterEventKind::ToolResult
            | AdapterEventKind::Command
            | AdapterEventKind::FileEffect
    )
}

fn normalized_event_priority(event: &Value) -> bool {
    event
        .get("eventType")
        .and_then(Value::as_str)
        .is_some_and(|event_type| {
            [
                "approval.",
                "terminal.",
                "error.",
                "tool.",
                "command.",
                "file.",
                "change_set.",
                "changeset.",
                "verification.",
            ]
            .iter()
            .any(|prefix| event_type.starts_with(prefix))
        })
}

fn visible_adapter_payload(event: &AdapterEvent) -> Value {
    let data = event.data.as_ref().map(|data| {
        let encoded = serde_jcs::to_vec(data).unwrap_or_default();
        if encoded.len() <= 2_048 {
            data.clone()
        } else {
            json!({
                "contentOmitted": true,
                "byteCount": encoded.len(),
                "contentDigest": hex::encode(Sha256::digest(&encoded)),
            })
        }
    });
    let mut payload = json!({
        "kind": event.kind,
        "vendorType": event.vendor_type,
        "nativeSessionId": event.native_session_id,
        "correlationId": event.correlation_id,
        // AdapterEvent already bounds text at MAX_EVENT_TEXT_BYTES.  Do not
        // apply a second 4KiB truncation here: adjacent assistant deltas must
        // remain reconstructible from the local normalized stream.
        "text": event.text,
        "data": data,
    });
    strip_hidden_reasoning(&mut payload);
    payload
}

fn strip_hidden_reasoning(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| {
                !matches!(
                    key.as_str(),
                    "reasoning"
                        | "chainOfThought"
                        | "chain_of_thought"
                        | "encrypted_content"
                        | "encryptedContent"
                )
            });
            for (key, value) in object.iter_mut() {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "authorization"
                        | "cookie"
                        | "password"
                        | "secret"
                        | "token"
                        | "apikey"
                        | "api_key"
                        | "credential"
                ) {
                    *value = Value::String("[REDACTED:credential]".into());
                    continue;
                }
                strip_hidden_reasoning(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                strip_hidden_reasoning(value);
            }
        }
        _ => {}
    }
}

fn adapter_error_event(vendor_type: &str, message: &str) -> AdapterEvent {
    AdapterEvent {
        kind: AdapterEventKind::AdapterError,
        vendor_type: bounded(vendor_type, 128),
        native_session_id: None,
        correlation_id: None,
        text: Some(bounded(message, 1024)),
        data: None,
    }
}
fn normalize_provider(v: &str) -> &str {
    match v {
        "native.linux" => "native",
        "restricted-native.linux" => "restricted_native",
        "incus.kvm" => "incus_kvm",
        v => v,
    }
}
fn parse_kind(v: &str) -> Result<RuntimeKind, ServiceError> {
    match v {
        "native" => Ok(RuntimeKind::Native),
        "restricted_native" => Ok(RuntimeKind::RestrictedNative),
        "container" => Ok(RuntimeKind::Container),
        "vm" => Ok(RuntimeKind::Vm),
        _ => Err(ServiceError::Config("unknown runtime kind".into())),
    }
}
fn parse_network(v: &str) -> Result<NetworkMode, ServiceError> {
    match v {
        "open" => Ok(NetworkMode::Open),
        "restricted" => Ok(NetworkMode::Restricted),
        "offline" => Ok(NetworkMode::Offline),
        "lan_explicit" => Ok(NetworkMode::LanExplicit),
        _ => Err(ServiceError::Config("unknown network mode".into())),
    }
}
fn parse_adapter(value: &str) -> Result<AdapterKind, ServiceError> {
    match value {
        "codex" => Ok(AdapterKind::Codex),
        "claude_code" | "claude-code" | "claude" => Ok(AdapterKind::ClaudeCode),
        "opencode" => Ok(AdapterKind::OpenCode),
        "pi" => Ok(AdapterKind::Pi),
        "agy" => Ok(AdapterKind::Agy),
        _ => Err(ServiceError::Unavailable("adapter_unknown".into())),
    }
}

fn adapter_reason(error: &conduit_adapters::AdapterError) -> String {
    match error {
        conduit_adapters::AdapterError::ExecutableUnavailable(_) => {
            "adapter_executable_unavailable".into()
        }
        conduit_adapters::AdapterError::UnsupportedOperation { .. } => {
            "adapter_operation_unsupported".into()
        }
        _ => format!("adapter_launch_invalid:{}", bounded(error.to_string(), 192)),
    }
}

fn source_reason(error: &str) -> String {
    if error.contains("location revision is stale") {
        "source_location_stale".into()
    } else if error.contains("was not found") || error.contains("custody is missing") {
        "source_location_missing".into()
    } else if error.contains("base revision is stale")
        || error.contains("snapshot revision is stale")
    {
        "source_revision_stale".into()
    } else if error.contains("required repository object is missing") {
        "source_revision_missing".into()
    } else {
        format!("workspace_attachment_failed:{}", bounded(error, 192))
    }
}

fn hash_file(path: &Path) -> Result<Sha256Digest, ServiceError> {
    use std::io::Read as _;
    let mut file =
        fs::File::open(path).map_err(|error| ServiceError::Unavailable(error.to_string()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

fn bounded(value: impl AsRef<str>, maximum: usize) -> String {
    value.as_ref().chars().take(maximum).collect()
}

fn enforce_reviewer_runtime(operation: &WireOperation) -> Result<(), ServiceError> {
    let role = operation
        .arguments
        .get("role")
        .or_else(|| operation.arguments.get("agentRole"))
        .and_then(Value::as_str);
    if operation.capability != "agent.run.start" || role != Some("reviewer") {
        return Ok(());
    }
    if operation.access_scope != "read_only" {
        return Err(ServiceError::Unavailable(
            "reviewer_access_scope_must_be_read_only".into(),
        ));
    }
    if operation
        .source_revisions
        .iter()
        .any(|source| !matches!(source.mode, crate::local::WorkspaceMode::ReadOnly))
    {
        return Err(ServiceError::Unavailable(
            "reviewer_workspace_must_be_read_only".into(),
        ));
    }
    if operation.runtime.kind == "native"
        || matches!(
            operation.runtime.provider_id.as_str(),
            "native" | "native.linux"
        )
    {
        return Err(ServiceError::Unavailable(
            "reviewer_requires_enforced_runtime_boundary".into(),
        ));
    }
    Ok(())
}

pub(crate) fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn unix_ms_now() -> u64 {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    u64::try_from(nanos.max(0) / 1_000_000).unwrap_or(u64::MAX)
}

fn timestamp_from_unix_ms(value: u64) -> Result<String, ServiceError> {
    let nanos = i128::from(value) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ServiceError::Unavailable("approval_expiry_invalid".into()))?
        .format(&Rfc3339)
        .map_err(|_| ServiceError::Unavailable("approval_expiry_invalid".into()))
}

fn approval_request_window_at(
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(String, String, u64), ServiceError> {
    if expires_at_unix_ms <= issued_at_unix_ms || expires_at_unix_ms - issued_at_unix_ms > 3_600_000
    {
        return Err(ServiceError::Unavailable(
            "approval_request_expired_before_custody".into(),
        ));
    }
    Ok((
        timestamp_from_unix_ms(issued_at_unix_ms)?,
        timestamp_from_unix_ms(expires_at_unix_ms)?,
        expires_at_unix_ms - issued_at_unix_ms,
    ))
}

fn effective_approval_risk_classes(
    operation: &[String],
    local: &[String],
) -> Result<(ApprovalRiskClassSet, Vec<String>), ServiceError> {
    let mut names = BTreeSet::new();
    let mut classes = ApprovalRiskClassSet::EMPTY;
    for source in [operation, local] {
        let mut source_names = BTreeSet::new();
        for name in source {
            if !source_names.insert(name.as_str()) {
                return Err(ServiceError::Unavailable(
                    "approval_risk_class_duplicate".into(),
                ));
            }
        }
    }
    for name in operation.iter().chain(local) {
        let class = ApprovalRiskClassSet::from_name(name)
            .ok_or_else(|| ServiceError::Unavailable("approval_risk_class_invalid".into()))?;
        if names.insert(name.clone()) {
            classes = classes.union(class);
        }
    }
    if names.len() > 10 {
        return Err(ServiceError::Unavailable(
            "approval_risk_class_limit_exceeded".into(),
        ));
    }
    Ok((classes, names.into_iter().collect()))
}

fn runtime_handle_digest(handle: &RuntimeHandle) -> Result<String, ServiceError> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(handle).map_err(|_| TransportError::Malformed)?,
    )))
}

fn custody_target_digest(
    agent_session: bool,
    run_id: &str,
    start_operation_id: &str,
    request_digest: &str,
    runtime_id: &str,
    handle_digest: &str,
    controller_epoch: u64,
) -> Result<String, ServiceError> {
    let domain = if agent_session {
        "conduit.agent-session-target.v1"
    } else {
        "conduit.runtime-custody-target.v1"
    };
    let commitment = json!({
        "domain": domain,
        "runId": run_id,
        "startOperationId": start_operation_id,
        "requestDigest": request_digest,
        "runtimeId": runtime_id,
        "handleDigest": handle_digest,
        "controllerEpoch": controller_epoch.to_string(),
    });
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&commitment).map_err(|_| TransportError::Malformed)?,
    )))
}

#[allow(clippy::too_many_arguments)]
fn running_status_payload(
    operation_id: &str,
    run_id: &str,
    request_digest: &str,
    runtime_id: &str,
    provider_id: &str,
    handle: &RuntimeHandle,
    controller_epoch: u64,
    revision: u64,
    agent_session: bool,
    phase: &str,
) -> Result<Value, ServiceError> {
    let handle_digest = runtime_handle_digest(handle)?;
    let target_digest = custody_target_digest(
        agent_session,
        run_id,
        operation_id,
        request_digest,
        runtime_id,
        &handle_digest,
        controller_epoch,
    )?;
    let runtime_target_digest = custody_target_digest(
        false,
        run_id,
        operation_id,
        request_digest,
        runtime_id,
        &handle_digest,
        controller_epoch,
    )?;
    Ok(json!({
        "operationId": operation_id,
        "runId": run_id,
        "requestDigest": request_digest,
        "state": "running",
        "controllerEpoch": controller_epoch.to_string(),
        "revision": revision.to_string(),
        "phase": phase,
        "targetRuntimeId": runtime_id,
        "targetDigest": target_digest,
        "runtimeTargetDigest": runtime_target_digest,
        "selectedRuntimeProvider": provider_id,
        "runtimeHandleDigest": handle_digest,
        "observedAt": now(),
    }))
}

fn control_terminal_payload(
    operation_id: &str,
    run_id: &str,
    request_digest: &str,
    last_event_sequence: u64,
) -> Result<Value, ServiceError> {
    let mut payload = json!({
        "operationId": operation_id,
        "runId": run_id,
        "state": "completed",
        "requestDigest": request_digest,
        "lastRunEventSequence": last_event_sequence.to_string(),
        "resultSummary": {"controlApplied": true},
        "observedAt": now(),
    });
    let digest = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
    ));
    payload["receiptDigest"] = Value::String(digest);
    Ok(payload)
}

fn agent_session_policy(
    arguments: &Value,
) -> Result<(AgentSettlementPolicy, u64, Option<u64>), ServiceError> {
    match arguments
        .get("settlementPolicy")
        .and_then(Value::as_str)
        .unwrap_or("close_on_settle")
    {
        "close_on_settle" => Ok((AgentSettlementPolicy::CloseOnSettle, 0, None)),
        "persistent" => {
            let lease_ms = arguments
                .get("sessionLeaseMs")
                .and_then(Value::as_u64)
                .ok_or_else(|| ServiceError::Unavailable("agent_session_lease_required".into()))?;
            let idle_timeout_ms = arguments
                .get("idleTimeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(lease_ms);
            if !(1_000..=86_400_000).contains(&lease_ms)
                || !(1_000..=lease_ms).contains(&idle_timeout_ms)
            {
                return Err(ServiceError::Unavailable(
                    "agent_session_lease_invalid".into(),
                ));
            }
            Ok((
                AgentSettlementPolicy::Persistent,
                idle_timeout_ms,
                Some(unix_ms_now().saturating_add(lease_ms)),
            ))
        }
        _ => Err(ServiceError::Unavailable(
            "agent_settlement_policy_invalid".into(),
        )),
    }
}

fn agent_settlement_policy_name(policy: AgentSettlementPolicy) -> &'static str {
    match policy {
        AgentSettlementPolicy::CloseOnSettle => "close_on_settle",
        AgentSettlementPolicy::Persistent => "persistent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_domain::{LocationId, SourceId};
    use conduit_node_store::NodeStore;
    use conduit_runtime::{
        CapabilityReceipt, CollectionReceipt, DestroyReceipt, ExpectedRuntime, PreparedRuntime,
        ReconciliationReceipt, RuntimeError, RuntimeProvider, RuntimeStateReceipt, SnapshotReceipt,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn loopback_http(
        port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), String> {
        let body = body.unwrap_or("");
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer local-synthetic-idle-e2e-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| error.to_string())?;
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| "HTTP response headers missing".to_owned())?;
        let headers = String::from_utf8(response[..header_end].to_vec())
            .map_err(|error| error.to_string())?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| "HTTP response status missing".to_owned())?
            .parse::<u16>()
            .map_err(|error| error.to_string())?;
        let mut response_body = response[header_end + 4..].to_vec();
        if headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            let mut decoded = Vec::new();
            let mut cursor = response_body.as_slice();
            loop {
                let line_end = cursor
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .ok_or_else(|| "HTTP chunk size missing".to_owned())?;
                let size_text = std::str::from_utf8(&cursor[..line_end])
                    .map_err(|error| error.to_string())?
                    .split(';')
                    .next()
                    .unwrap_or("");
                let size =
                    usize::from_str_radix(size_text, 16).map_err(|error| error.to_string())?;
                cursor = &cursor[line_end + 2..];
                if size == 0 {
                    break;
                }
                if cursor.len() < size + 2 || &cursor[size..size + 2] != b"\r\n" {
                    return Err("HTTP chunk body is truncated".into());
                }
                decoded.extend_from_slice(&cursor[..size]);
                cursor = &cursor[size + 2..];
            }
            response_body = decoded;
        }
        Ok((
            status,
            String::from_utf8(response_body).map_err(|error| error.to_string())?,
        ))
    }

    fn run_wrangler(app: &Path, arguments: &[&str]) {
        let output = Command::new(app.join("node_modules/.bin/wrangler"))
            .args(arguments)
            .current_dir(app)
            .env("CI", "true")
            .output()
            .expect("wrangler must start");
        assert!(
            output.status.success(),
            "wrangler command failed: {arguments:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    struct ControlOnlyProvider {
        prepare_calls: AtomicUsize,
        start_calls: AtomicUsize,
        signal_calls: AtomicUsize,
    }

    impl RuntimeProvider for ControlOnlyProvider {
        fn provider_id(&self) -> &str {
            "control_only"
        }
        fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
            Ok(CapabilityReceipt {
                provider_id: self.provider_id().into(),
                provider_version: None,
                capabilities: vec![],
            })
        }
        fn prepare(&self, _request: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::CapabilityUnavailable(
                "start forbidden in control test".into(),
            ))
        }
        fn start(
            &self,
            _prepared: &PreparedRuntime,
            _launch: &LaunchPlan,
        ) -> Result<RuntimeStateReceipt, RuntimeError> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::CapabilityUnavailable(
                "start forbidden in control test".into(),
            ))
        }
        fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
            Ok(RuntimeStateReceipt {
                handle: handle.clone(),
                state: RuntimeState::Running,
                exit_code: None,
                evidence: vec![],
            })
        }
        fn signal(
            &self,
            handle: &RuntimeHandle,
            signal: RuntimeSignal,
        ) -> Result<RuntimeStateReceipt, RuntimeError> {
            self.signal_calls.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeStateReceipt {
                handle: handle.clone(),
                state: if matches!(signal, RuntimeSignal::Pause) {
                    RuntimeState::Paused
                } else {
                    RuntimeState::Running
                },
                exit_code: None,
                evidence: vec![],
            })
        }
        fn snapshot(
            &self,
            _handle: &RuntimeHandle,
            _name: &str,
        ) -> Result<SnapshotReceipt, RuntimeError> {
            Err(RuntimeError::CapabilityUnavailable("snapshot".into()))
        }
        fn collect(&self, _handle: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
            Err(RuntimeError::CapabilityUnavailable("collect".into()))
        }
        fn destroy(
            &self,
            handle: &RuntimeHandle,
            _request: &DestroyRequest,
        ) -> Result<DestroyReceipt, RuntimeError> {
            Ok(DestroyReceipt {
                runtime_id: handle.runtime_id.clone(),
                destroyed: true,
                evidence: "test".into(),
            })
        }
        fn reconcile(
            &self,
            _records: &[ExpectedRuntime],
        ) -> Result<Vec<ReconciliationReceipt>, RuntimeError> {
            Ok(vec![])
        }
    }

    fn completed_long_lived_driver(kind: AdapterKind, cwd: &Path) -> ProtocolDriver {
        let request = LaunchRequest {
            cwd: cwd.to_path_buf(),
            prompt: Some("settle without exiting".into()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: Some(cwd.join("sessions")),
        };
        let mut driver = ProtocolDriver::new(kind, &request).unwrap();
        driver.start().unwrap();
        match kind {
            AdapterKind::Codex => {
                for record in [
                    b"{\"id\":1,\"result\":{\"serverInfo\":{\"name\":\"codex\",\"version\":\"test\"}}}\n".as_slice(),
                    b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-test\"}}}\n".as_slice(),
                    b"{\"id\":3,\"result\":{\"turn\":{\"id\":\"turn-test\"}}}\n".as_slice(),
                    b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-test\",\"status\":{\"type\":\"completed\"}}}}\n".as_slice(),
                ] {
                    driver.on_record(record).unwrap();
                }
            }
            AdapterKind::Pi => {
                driver.on_record(b"{\"type\":\"agent_settled\"}\n").unwrap();
            }
            AdapterKind::OpenCode => {
                for record in [
                    b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{\"loadSession\":true}}}\n".as_slice(),
                    b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sessionId\":\"acp-session-test\"}}\n".as_slice(),
                    b"{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"stopReason\":\"end_turn\"}}\n".as_slice(),
                ] {
                    driver.on_record(record).unwrap();
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(driver.state(), AdapterState::Completed);
        driver
    }

    fn control_envelope(sequence: u64, kind: &str, payload: Value) -> Envelope {
        Envelope {
            protocol: "conduit.node/1".into(),
            message_id: format!("cmsg_service_replay_{sequence:08}"),
            device_id: "dev_policy_01".into(),
            connection_epoch: "1".into(),
            direction: "control_to_node".into(),
            sequence: sequence.to_string(),
            kind: kind.into(),
            correlation_id: None,
            control_applied_through: None,
            payload_digest: hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap())),
            payload,
        }
    }

    fn expired_offer_envelope(sequence: u64) -> Envelope {
        let mut operation = json!({
            "schemaVersion": 1,
            "operationId": format!("op_service_replay_{sequence:08}"),
            "idempotencyKey": format!("service-replay-idempotency-{sequence:08}"),
            "actorPrincipalId": "prin_service_replay01",
            "clientId": "conduit.service-replay-test",
            "deviceId": "dev_policy_01",
            "capability": "runtime.command.start",
            "sourceRevisions": [],
            "runtime": {
                "kind": "native",
                "providerId": "native.linux",
                "configurationRevision": 1
            },
            "accessScope": "project_full",
            "approvalMode": "always",
            "requiredApprovalRiskClasses": [],
            "connectorPolicyId": "cpol_service_replay01",
            "connectorPolicyRevision": 1,
            "arguments": {"launchProfileId": "unused-expired-profile"},
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2020-01-01T00:05:00Z",
            "validForMs": 300000
        });
        let request_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&operation).unwrap()));
        operation["payloadDigest"] = Value::String(request_digest);
        control_envelope(sequence, "operation.offer", json!({"operation": operation}))
    }

    fn operation(scope: &str, approval: &str, cpu: f64) -> WireOperation {
        serde_json::from_value(json!({
            "schemaVersion": 1,
            "operationId": "op_policy_01",
            "idempotencyKey": "policy-idempotency-key",
            "deviceId": "dev_policy_01",
            "capability": "runtime.command.start",
            "sourceRevisions": [],
            "runtime": {
                "kind": "native",
                "providerId": "native.linux",
                "configurationRevision": 1,
                "cpuLimit": cpu
            },
            "accessScope": scope,
            "approvalMode": approval,
            "requiredApprovalRiskClasses": [],
            "connectorPolicyId": "cpol_policy_0001",
            "connectorPolicyRevision": 99,
            "arguments": {"launchProfileId":"safe"},
            "payloadDigest": "11".repeat(32),
            "issuedAt": "2026-09-01T00:00:00Z",
            "expiresAt": "2026-09-01T00:01:00Z",
            "validForMs": 60000
        }))
        .unwrap()
    }
    fn policy(explicit_full_never: bool) -> LocalPolicy {
        LocalPolicy {
            revision: 8,
            capabilities: vec!["runtime.command.start".into()],
            providers: vec!["native".into()],
            access_scopes: vec!["project_full".into(), "full_device".into()],
            approval_modes: vec!["never".into()],
            required_approval_risk_classes: vec![],
            launch_profiles: vec!["safe".into()],
            max_cpu: Some(4.0),
            max_memory_bytes: Some(1024 * 1024),
            max_storage_bytes: Some(1024 * 1024),
            allow_full_access_without_approval: explicit_full_never,
        }
    }

    #[test]
    fn node_service_and_wss_client_accelerated_idle_do_not_eagerly_resend_health() {
        let directory = tempfile::tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let node = Arc::new(Node::new(store.clone()));
        let local = Arc::new(LocalServices::open(directory.path().join("local"), [9; 32]).unwrap());
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            node,
            identity,
            "wss://control.example.invalid/connect".into(),
            "dev_idle_socket_01".into(),
            "aa".repeat(32),
            "node-boot-idle-socket-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor,
        )
        .unwrap();
        let mut session =
            crate::transport::TransportSession::new(store.clone(), "dev_idle_socket_01".into(), 1)
                .unwrap();
        session.mark_reconciliation_complete();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut server = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        let mut client = WssClient::from_test_stream(stream, session, false);
        let started = Instant::now();

        assert!(
            service
                .queue_health_if_due_at(&mut client, true, started)
                .unwrap()
        );
        assert_eq!(client.flush_unacknowledged(1).unwrap(), 1);

        let mut sends_after_one_hour = 0_u64;
        for tick in 1_u64..=24 * 60 * 60 * 10 {
            let at = started + Duration::from_millis(tick * 100);
            service
                .queue_health_if_due_at(&mut client, false, at)
                .unwrap();
            assert_eq!(
                client.flush_unacknowledged(1).unwrap(),
                0,
                "a live socket must not eagerly resend durable unacknowledged frames"
            );
            if tick == 60 * 60 * 10 {
                sends_after_one_hour = 1 + tick / (10 * 60 * 10);
            }
        }

        let mut socket_sends = 0_u64;
        loop {
            match server.read() {
                Ok(tungstenite::Message::Text(_)) => socket_sends += 1,
                Ok(other) => panic!("unexpected idle socket message: {other:?}"),
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("idle socket read failed: {error}"),
            }
        }
        let positions = store.transport_positions().unwrap();
        assert_eq!(
            sends_after_one_hour, 7,
            "initial health plus six checkpoints"
        );
        assert_eq!(
            socket_sends, 145,
            "initial health plus 144 exact 10-minute replays"
        );
        assert_eq!(
            positions.node_sent_through, 1,
            "exact checkpoints allocate no rows"
        );
        assert_eq!(
            positions.node_acknowledged_through, 0,
            "the peer intentionally sent no ACK"
        );
    }

    #[test]
    #[ignore = "invoked by scripts/e2e-node-worker-idle.sh after Wrangler dependencies are installed"]
    fn node_service_wss_worker_route_device_room_accelerated_idle_e2e() {
        let directory = tempfile::tempdir().unwrap();
        let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/control-plane");
        let persist = directory.path().join("wrangler-state");
        let persist_text = persist.to_str().unwrap();
        run_wrangler(
            &app,
            &[
                "d1",
                "migrations",
                "apply",
                "conduit-idle-e2e",
                "--config",
                "wrangler.idle-e2e.jsonc",
                "--local",
                "--persist-to",
                persist_text,
            ],
        );

        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let device_id = "dev_idle_route_e2e01";
        let public_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": identity.public_key_base64url(),
        });
        let fingerprint = hex::encode(Sha256::digest(identity.verifying_key().as_bytes()));
        let sql = format!(
            "INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_idle_route_e2e01','completed','{}','{}','{{}}','{}','{}','{}','challenge','signature','{}','2026-09-02T00:00:00.000Z','2026-09-03T00:00:00.000Z','2026-09-02T00:00:00.000Z');\
             INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES ('{}','enroll_idle_route_e2e01','Synthetic idle E2E','linux','x86_64','0.1.0','conduit.node/1','active','2026-09-02T00:00:00.000Z','2026-09-02T00:00:00.000Z');\
             INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES ('{}','{}','{}','{}','active','2026-09-02T00:00:00.000Z');",
            "11".repeat(32),
            "22".repeat(32),
            identity.key_id(),
            public_jwk,
            fingerprint,
            device_id,
            device_id,
            identity.key_id(),
            device_id,
            public_jwk,
            fingerprint,
        );
        run_wrangler(
            &app,
            &[
                "d1",
                "execute",
                "conduit-idle-e2e",
                "--config",
                "wrangler.idle-e2e.jsonc",
                "--local",
                "--persist-to",
                persist_text,
                "--command",
                &sql,
            ],
        );

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let origin = format!("http://127.0.0.1:{port}");
        let child = Command::new(app.join("node_modules/.bin/wrangler"))
            .args([
                "dev",
                "--config",
                "wrangler.idle-e2e.jsonc",
                "--local",
                "--ip",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--persist-to",
                persist_text,
                "--var",
                &format!("PUBLIC_ORIGIN:{origin}"),
                "--var",
                &format!("OAUTH_ISSUER:{origin}"),
                "--var",
                "WEBAUTHN_RP_ID:127.0.0.1",
            ])
            .current_dir(&app)
            .env("CI", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Wrangler dev must start");
        let _worker = ChildGuard(child);
        let mut ready = false;
        for _ in 0..300 {
            if loopback_http(port, "GET", "/healthz", None).is_ok_and(|(status, _)| status == 200) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(ready, "Wrangler idle E2E worker did not become ready");

        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let node = Arc::new(Node::new(store.clone()));
        let local = Arc::new(LocalServices::open(directory.path().join("local"), [7; 32]).unwrap());
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            node,
            identity.clone(),
            format!("ws://127.0.0.1:{port}/v1/devices/{device_id}/connect"),
            device_id.into(),
            "aa".repeat(32),
            "node-boot-idle-route-e2e-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor,
        )
        .unwrap();
        let mut client = WssClient::connect_loopback(
            &service.control_url,
            store.clone(),
            &identity,
            device_id,
            &service.capability_digest,
            &service.node_boot_id,
        )
        .unwrap();

        let positions = store.transport_positions().unwrap();
        client
            .flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))
            .unwrap();
        let payload = json!({
            "nodeBootId": service.node_boot_id,
            "journalGeneration": store.journal_generation().unwrap().to_string(),
            "capabilityDigest": service.capability_digest,
            "lastControlSequenceApplied": "0",
            "controlAppliedThrough": "0",
            "lastNodeSequenceAcknowledged": "0",
            "lastNodeSequenceRetained": "0",
            "runs": [],
            "retainedEventRanges": [],
            "unresolvedCount": 0,
            "truncated": false,
            "storageHealth": "healthy"
        });
        let message_id = service.message_id();
        client
            .session
            .queue_outbound(&message_id, "reconcile.summary", None, payload, 0)
            .unwrap();
        service.queue_health_if_due(&mut client, true).unwrap();
        client.flush_unacknowledged(1).unwrap();

        let mut reconciled = false;
        for _ in 0..200 {
            if let Some((frame, result)) = client.poll().unwrap() {
                service.dispatch(&mut client, frame, result).unwrap();
            }
            service.flush_ack_if_due(&mut client, true).unwrap();
            let positions = store.transport_positions().unwrap();
            client
                .flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))
                .unwrap();
            if client.session.remote_work_allowed() {
                let positions = store.transport_positions().unwrap();
                if positions.node_acknowledged_through == positions.node_sent_through {
                    reconciled = true;
                    break;
                }
            }
        }
        assert!(reconciled, "real Node/Worker reconciliation did not settle");
        let node_sent_before_idle = store.transport_positions().unwrap().node_sent_through;

        let simulated_start = 1_788_307_200_000_u64;
        let reset_path = format!("/__idle-e2e/devices/{device_id}/reset");
        let (status, _) = loopback_http(
            port,
            "POST",
            &reset_path,
            Some(&format!("{{\"nowMs\":{simulated_start}}}")),
        )
        .unwrap();
        assert_eq!(status, 200);
        client.reset_application_sends();
        let started = Instant::now();
        let next_unacknowledged_sequence = store
            .transport_positions()
            .unwrap()
            .node_acknowledged_through
            .saturating_add(1);
        // Exercise every real 100 ms service poll for the first hour. If the
        // old eager resend loop returns, this alone observes ~36,000 sends.
        for tick in 1_u64..=60 * 60 * 10 {
            let health_sent = service
                .queue_health_if_due_at(
                    &mut client,
                    false,
                    started + Duration::from_millis(tick * 100),
                )
                .unwrap();
            assert_eq!(
                client
                    .flush_unacknowledged(next_unacknowledged_sequence)
                    .unwrap(),
                0
            );
            if health_sent {
                client.await_idle_e2e_settled().unwrap();
            }
        }
        let one_hour_sends = client.application_sends();
        // Continue the same real socket and service clock at each remaining
        // ten-minute checkpoint through 24 hours. The regular Node unit test
        // separately executes all 864,000 poll iterations.
        for checkpoint in 7_u64..=144 {
            let health_sent = service
                .queue_health_if_due_at(
                    &mut client,
                    false,
                    started + Duration::from_secs(checkpoint * 10 * 60),
                )
                .unwrap();
            assert_eq!(
                client
                    .flush_unacknowledged(next_unacknowledged_sequence)
                    .unwrap(),
                0
            );
            assert!(health_sent);
            client.await_idle_e2e_settled().unwrap();
        }
        let inspect_path = format!("/__idle-e2e/devices/{device_id}/inspect");
        let (status, body) = loopback_http(port, "GET", &inspect_path, None).unwrap();
        assert_eq!(status, 200);
        let probe: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(one_hour_sends, 6);
        assert_eq!(client.application_sends(), 144);
        assert_eq!(probe["incomingMessages"], 144);
        assert_eq!(probe["inboundRows"], 6);
        assert_eq!(probe["ackRows"], 1);
        assert_eq!(probe["setAlarm"], 0);
        assert_eq!(probe["alarmInvocations"], 0);
        assert!(probe["alarmAt"].is_null());
        assert_eq!(probe["d1"]["statements"], 72);
        assert_eq!(probe["d1"]["bindingCalls"], 72);
        assert_eq!(probe["d1"]["maxBoundParameters"], 4);
        assert_eq!(probe["d1"]["rowsRead"], 144);
        assert_eq!(probe["d1"]["rowsWritten"], 72);
        assert_eq!(probe["sqlStatements"], 1_152);
        assert_eq!(probe["sqlRowsRead"], 8_784);
        assert_eq!(probe["sqlRowsWritten"], 72);
        assert_eq!(
            store.transport_positions().unwrap().node_sent_through,
            node_sent_before_idle,
            "exact idle checkpoints must not allocate Node outbox rows"
        );
        println!(
            "CONDUIT_NODE_WORKER_IDLE_E2E={}",
            serde_json::json!({
                "oneHourSocketSends": one_hour_sends,
                "twentyFourHourSocketSends": client.application_sends(),
                "deviceRoom": probe,
            })
        );
    }

    #[test]
    fn local_policy_revision_is_independent_and_deny_precedes_connector() {
        let denied = policy(false);
        assert_eq!(denied.revision, 8);
        assert!(matches!(
            denied.evaluate(&operation("full_device", "never", 1.0), "safe"),
            Err(ServiceError::Unavailable(reason)) if reason == "full_device_capability_unavailable"
        ));
        assert!(matches!(
            denied.evaluate(&operation("project_full", "never", 8.0), "safe"),
            Err(ServiceError::Unavailable(reason)) if reason == "local_policy_resource_ceiling"
        ));
        assert!(matches!(
            policy(true).evaluate(&operation("full_device", "never", 1.0), "safe"),
            Err(ServiceError::Unavailable(reason)) if reason == "full_device_capability_unavailable"
        ));
    }

    #[test]
    fn runtime_control_is_exactly_once_and_never_starts_a_process() {
        let directory = tempfile::tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let provider = Arc::new(ControlOnlyProvider {
            prepare_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            signal_calls: AtomicUsize::new(0),
        });
        let mut node = Node::new(store.clone());
        node.register_provider(provider.clone());
        let local = Arc::new(LocalServices::open(directory.path().join("local"), [3; 32]).unwrap());
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            Arc::new(node),
            identity,
            "wss://control.example.invalid/connect".into(),
            "dev_policy_01".into(),
            "aa".repeat(32),
            "node-boot-control-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor,
        )
        .unwrap();
        let handle = RuntimeHandle {
            runtime_id: "rt_control_existing01".into(),
            provider_id: "control_only".into(),
            spec_digest: "22".repeat(32),
            object_id: "existing-object".into(),
            process_identity: Some("pid:4242:start:7".into()),
        };
        let run_id = "run_control_existing01";
        let start_operation_id = "op_control_start0001";
        let request_digest = "11".repeat(32);
        service.runtime_custody.insert(
            handle.runtime_id.clone(),
            RuntimeCustody {
                start_operation_id: start_operation_id.into(),
                run_id: run_id.into(),
                request_digest: request_digest.clone(),
                provider_id: "control_only".into(),
                handle: handle.clone(),
                state: RuntimeState::Running,
                controller_epoch: 1,
                revision: 1,
            },
        );
        let handle_digest = runtime_handle_digest(&handle).unwrap();
        let target_digest = custody_target_digest(
            false,
            run_id,
            start_operation_id,
            &request_digest,
            &handle.runtime_id,
            &handle_digest,
            1,
        )
        .unwrap();
        let payload = json!({
            "operationId":"op_control_pause0001",
            "idempotencyKey":"runtime-control-pause-idempotency-0001",
            "targetRunId":run_id,
            "targetRuntimeId":handle.runtime_id,
            "targetHandleDigest":handle_digest,
            "targetControllerEpoch":"1",
            "targetDigest":target_digest,
            "expectedState":"running",
            "expectedRevision":"1",
            "control":"pause"
        });
        let session =
            crate::transport::TransportSession::new(store.clone(), "dev_policy_01".into(), 1)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut client = WssClient::from_test_stream(stream, session, true);

        service.control_runtime(&mut client, &payload).unwrap();
        service.control_runtime(&mut client, &payload).unwrap();

        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.signal_calls.load(Ordering::SeqCst), 1);
        let record = store
            .control_effect("runtime-control-pause-idempotency-0001")
            .unwrap()
            .unwrap();
        assert_eq!(record.state, "applied");
        let receipt: Value = serde_json::from_slice(record.receipt.as_deref().unwrap()).unwrap();
        let control_request_digest =
            hex::encode(Sha256::digest(serde_jcs::to_vec(&payload).unwrap()));
        assert_eq!(receipt["processCountDelta"], 0);
        assert_eq!(receipt["state"], "paused");
        assert_eq!(receipt["requestDigest"], control_request_digest);
        assert_eq!(receipt["targetControllerEpoch"], "1");
        assert_eq!(receipt["expectedState"], "running");
        assert_eq!(receipt["expectedRevision"], "1");
        assert_eq!(receipt["control"], "pause");
    }

    #[test]
    fn close_on_settle_terminalizes_exit_never_codex_pi_and_acp() {
        for (index, kind) in [AdapterKind::Codex, AdapterKind::Pi, AdapterKind::OpenCode]
            .into_iter()
            .enumerate()
        {
            let directory = tempfile::tempdir().unwrap();
            let store = NodeStore::open(directory.path().join("store")).unwrap();
            let identity = Arc::new(
                DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                    .unwrap(),
            );
            let node = Arc::new(Node::new(store.clone()));
            let local = Arc::new(
                LocalServices::open(directory.path().join("local"), [index as u8 + 1; 32]).unwrap(),
            );
            let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
            let mut service = NodeService::new(
                node,
                identity,
                "wss://control.example.invalid/connect".into(),
                "dev_policy_01".into(),
                "aa".repeat(32),
                format!("node-boot-settle-{index:08}"),
                NodePolicyConfig {
                    local_policy: LocalPolicy {
                        revision: 1,
                        capabilities: vec![],
                        providers: vec![],
                        access_scopes: vec![],
                        approval_modes: vec![],
                        required_approval_risk_classes: vec![],
                        launch_profiles: vec![],
                        max_cpu: None,
                        max_memory_bytes: None,
                        max_storage_bytes: None,
                        allow_full_access_without_approval: false,
                    },
                    profiles: HashMap::new(),
                },
                local,
                supervisor.clone(),
            )
            .unwrap();
            let run_id = format!("run_settle_never_{index:08}");
            let runtime_id = format!("rt_settle_never_{index:08}");
            let operation_id = format!("op_settle_never_{index:08}");
            let key = format!("settle-never-idempotency-{index:08}");
            let request_digest = format!("{:02x}", index + 1).repeat(32);
            let workspace = directory.path().join("captured-workspace");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::write(workspace.join("result.txt"), format!("captured-{index}\n")).unwrap();
            let captured_sources = if index == 2 {
                Vec::new()
            } else {
                vec![PreparedSource {
                    source_id: SourceId::parse("src_settle_capture01").unwrap(),
                    location_id: LocationId::parse("loc_settle_capture01").unwrap(),
                    location_revision: 1,
                    mode: crate::local::WorkspaceMode::ManagedCopy,
                    host_path: workspace,
                    base_revision: "snap_initial_settle_capture01".into(),
                    initial_state_digest: Sha256Digest::from_bytes([index as u8 + 1; 32]),
                    repository_identity_digest: None,
                    display_path: "captured-workspace".into(),
                }]
            };
            let driver = completed_long_lived_driver(kind, directory.path());
            let child_spec = conduit_adapters::LaunchSpec {
                executable: PathBuf::from("/bin/sh"),
                args: vec!["-c".into(), "while :; do sleep 60; done".into()],
                cwd: directory.path().to_path_buf(),
                protocol: match kind {
                    AdapterKind::Codex => conduit_adapters::AdapterProtocol::CodexAppServerV2,
                    AdapterKind::Pi => conduit_adapters::AdapterProtocol::PiRpcJsonl,
                    AdapterKind::OpenCode => {
                        conduit_adapters::AdapterProtocol::AgentClientProtocolV1
                    }
                    _ => unreachable!(),
                },
                initial_frames: vec![],
            };
            let child = AdapterChild::spawn_uninitialized(&child_spec).unwrap();
            let runtime = RuntimeRequest {
                runtime_id: runtime_id.clone(),
                run_id: run_id.clone(),
                kind: RuntimeKind::Native,
                provider_selector: "native".into(),
                spec_digest: "44".repeat(32),
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
            let launch = LaunchPlan {
                executable: child_spec.executable.clone(),
                argv: child_spec.args.clone(),
                cwd: child_spec.cwd.clone(),
                environment: BTreeMap::new(),
                io_mode: IoMode::Pipes,
                timeout_ms: None,
            };
            let prepared = supervisor
                .reserve(&runtime, "native", child_spec.executable.clone(), false)
                .unwrap();
            let custody = supervisor
                .adopt_external(&prepared, &launch, child.id())
                .unwrap();
            let runtime_bytes = serde_jcs::to_vec(&runtime).unwrap();
            let launch_bytes = serde_jcs::to_vec(&launch).unwrap();
            store
                .admit_operation(
                    &operation_id,
                    &key,
                    &request_digest,
                    b"{}",
                    1,
                    "native",
                    "read_only",
                    "always",
                    &runtime_bytes,
                    &launch_bytes,
                    b"{}",
                )
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Admitted,
                    OperationState::Starting,
                    Some(&runtime_id),
                    None,
                    None,
                )
                .unwrap();
            store
                .transition_operation(
                    &key,
                    OperationState::Starting,
                    OperationState::Running,
                    Some(&runtime_id),
                    custody.handle.process_identity.as_deref(),
                    None,
                )
                .unwrap();
            store
                .record_agent_session(&key, "close_on_settle", 1, None)
                .unwrap();
            service.runtime_custody.insert(
                runtime_id.clone(),
                RuntimeCustody {
                    start_operation_id: operation_id.clone(),
                    run_id: run_id.clone(),
                    request_digest: request_digest.clone(),
                    provider_id: "native".into(),
                    handle: custody.handle.clone(),
                    state: RuntimeState::Running,
                    controller_epoch: 1,
                    revision: 1,
                },
            );
            service.agents.insert(
                operation_id.clone(),
                AgentActive {
                    key: key.clone(),
                    operation_id: operation_id.clone(),
                    run_id: run_id.clone(),
                    request_digest,
                    runtime_id: runtime_id.clone(),
                    provider_id: "native".into(),
                    handle: custody.handle,
                    child,
                    driver,
                    adapter_kind: kind,
                    actor_principal_id: "prin_settle_never01".into(),
                    client_id: "conduit.settle-test".into(),
                    access_scope: "read_only".into(),
                    approval_mode: "always".into(),
                    effective_required_approval_risk_classes: vec![],
                    local_policy_revision: 1,
                    controller_epoch: 1,
                    revision: 1,
                    event_sequence: 0,
                    raw_sequence: 0,
                    settlement_policy: AgentSettlementPolicy::CloseOnSettle,
                    session_state: AgentSessionState::Running,
                    idle_timeout_ms: 0,
                    lease_expires_at_unix_ms: None,
                    prepared_sources: captured_sources,
                    parent_baseline_id: Value::Null,
                    source_baseline_revisions: BTreeMap::new(),
                    verification_policy: json!({"requiredChecks":["workspace_clean"]}),
                },
            );
            let session =
                crate::transport::TransportSession::new(store.clone(), "dev_policy_01".into(), 1)
                    .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            let mut client = WssClient::from_test_stream(stream, session, true);

            service.poll_agents(&mut client).unwrap();

            assert!(!service.agents.contains_key(&operation_id), "{kind:?}");
            assert_eq!(
                store.operation(&key).unwrap().unwrap().state,
                OperationState::Completed,
                "{kind:?}",
            );
            assert_eq!(
                store.agent_session(&key).unwrap().unwrap().state,
                "closed",
                "{kind:?}",
            );
            assert_eq!(
                supervisor.inspect(&runtime_id).unwrap().state,
                RuntimeState::Stopped,
                "{kind:?}",
            );
            let outbound = store
                .unacknowledged_outbound(1, 64)
                .unwrap()
                .into_iter()
                .map(|row| serde_json::from_slice::<Envelope>(&row.frame).unwrap())
                .collect::<Vec<_>>();
            assert!(outbound.iter().any(|frame| {
                frame.kind == "operation.status"
                    && frame.payload["state"] == "finishing"
                    && frame.payload["revision"] == "2"
            }));
            let terminal = outbound
                .iter()
                .find(|frame| frame.kind == "operation.terminal")
                .unwrap();
            assert_eq!(
                terminal.payload["resultSummary"]["submission"]["expectedNodeRevision"],
                2
            );
            assert_eq!(
                terminal.payload["resultSummary"]["submission"]["verification"][0]["status"],
                "passed"
            );
            if index == 2 {
                assert_eq!(
                    terminal.payload["resultSummary"]["submission"]["sourceChanges"],
                    json!([])
                );
                assert_eq!(
                    terminal.payload["resultSummary"]["submission"]["unchangedSources"],
                    json!([])
                );
            } else {
                assert_eq!(
                    terminal.payload["resultSummary"]["submission"]["sourceChanges"][0]["state"],
                    "clean"
                );
            }
        }
    }

    #[test]
    fn approval_risk_snapshots_are_validated_and_union_with_local_policy() {
        let (classes, names) = effective_approval_risk_classes(
            &["destructive_delete".into()],
            &["lan_access".into(), "destructive_delete".into()],
        )
        .unwrap();
        assert!(classes.intersects(ApprovalRiskClassSet::DESTRUCTIVE_DELETE));
        assert!(classes.intersects(ApprovalRiskClassSet::LAN_ACCESS));
        assert_eq!(names, vec!["destructive_delete", "lan_access"]);

        assert!(matches!(
            effective_approval_risk_classes(
                &["secret_access".into(), "secret_access".into()],
                &[]
            ),
            Err(ServiceError::Unavailable(reason)) if reason == "approval_risk_class_duplicate"
        ));
        assert!(matches!(
            effective_approval_risk_classes(&["not_a_risk".into()], &[]),
            Err(ServiceError::Unavailable(reason)) if reason == "approval_risk_class_invalid"
        ));
    }

    #[test]
    fn run_manifest_binds_control_plane_context_snapshot() {
        let request_digest = "11".repeat(32);
        let capability_digest = "22".repeat(32);
        let snapshot_digest = "33".repeat(32);
        let content_digest = "44".repeat(32);
        let manifest = build_manifest(
            &ManifestOperation {
                operation_id: "op_context_manifest01",
                idempotency_key: "context-manifest-idempotency-0001",
                request_digest: &request_digest,
                run_id: "run_context_manifest01",
                assignment_id: None,
                actor_id: "prin_context_manifest01",
                client_id: "conduit.context-test",
                device_id: "dev_context_manifest01",
                boot_id: "node-boot-context-manifest01",
                capability_digest: &capability_digest,
                local_policy_revision: 1,
                runtime_kind: "restricted_native",
                runtime_provider: "restricted-native.linux",
                runtime_config: b"{}",
                access_scope: "project_full",
                approval_mode: "always",
                adapter_id: Some("codex"),
                adapter_version: Some("fixture"),
                executable_digest: None,
                model: Some("gpt-5.6-codex"),
                effort: Some("high"),
                context_compiler_version: Some("control-plane-board/v1"),
                context_snapshot_id: Some("ctx_context_manifest01"),
                context_snapshot_digest: Some(&snapshot_digest),
                context_content_digest: Some(&content_digest),
                context_bytes: Some(128),
            },
            &[],
        )
        .unwrap();
        assert_eq!(
            manifest.input.context_compiler_version,
            "control-plane-board/v1"
        );
        assert_eq!(manifest.input.instruction_catalog.len(), 1);
        assert_eq!(
            manifest.input.instruction_catalog[0].item_id,
            "ctx_context_manifest01"
        );
        assert_eq!(
            manifest.input.evaluation_tags["context_snapshot_digest"],
            snapshot_digest
        );
    }

    #[test]
    fn reconciliation_allows_only_preexisting_effectful_control() {
        let directory = tempfile::tempdir().unwrap();
        let store = conduit_node_store::NodeStore::open(directory.path()).unwrap();
        let mut session = crate::transport::TransportSession::new_with_control_frontier(
            store,
            "dev_policy_01".into(),
            1,
            43,
        )
        .unwrap();
        for kind in [
            "operation.offer",
            "operation.input",
            "operation.cancel",
            "operation.approval",
        ] {
            assert!(session.control_frame_allowed(kind, 43));
            assert!(!session.control_frame_allowed(kind, 44));
        }
        assert!(session.control_frame_allowed("reconcile.plan", 44));
        session.mark_reconciliation_complete();
        assert!(session.control_frame_allowed("operation.offer", 44));
    }

    #[test]
    fn service_dispatch_converges_chunked_offer_replay_and_reapplies_duplicate_pending() {
        let directory = tempfile::tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let node = Arc::new(Node::new(store.clone()));
        let local = Arc::new(
            LocalServices::open(directory.path().join("local-services"), [9; 32]).unwrap(),
        );
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            node,
            identity,
            "wss://control.example.invalid/connect".into(),
            "dev_policy_01".into(),
            "ab".repeat(32),
            "node-boot-service-replay-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor,
        )
        .unwrap();
        for sequence in 1..=3 {
            let frame = control_envelope(
                sequence,
                "transport.ack",
                json!({"direction":"node_to_control","throughSequence":"0"}),
            );
            let bytes = serde_json::to_vec(&frame).unwrap();
            store
                .receive(
                    Direction::ControlToNode,
                    &conduit_node_store::TransportFrame {
                        sequence,
                        message_id: frame.message_id,
                        payload_digest: frame.payload_digest,
                        frame: bytes,
                    },
                )
                .unwrap();
            store
                .mark_inbound_applied(Direction::ControlToNode, sequence)
                .unwrap();
        }
        let session = crate::transport::TransportSession::new_with_control_frontier(
            store.clone(),
            "dev_policy_01".into(),
            1,
            43,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut client = WssClient::from_test_stream(stream, session, true);

        let plan = control_envelope(
            44,
            "reconcile.plan",
            json!({
                "reconciliationId":"rec_service_replay01",
                "controlReplay":[{"from":"4","through":"43"}],
                "nodeReplay":[],
                "eventReplay":[],
                "statusRunIds":[],
                "cancelOperationIds":[],
                "quarantineRunIds":[]
            }),
        );
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let (gap_plan, gap) = client.session.receive(&plan_bytes).unwrap();
        assert_eq!(gap, ReceiveResult::Gap { expected: 4 });
        service.dispatch(&mut client, gap_plan, gap).unwrap();

        let first_offer = expired_offer_envelope(4);
        let first_bytes = serde_json::to_vec(&first_offer).unwrap();
        assert_eq!(
            client.session.receive(&first_bytes).unwrap().1,
            ReceiveResult::Applied
        );
        let (pending_offer, pending) = client.session.receive(&first_bytes).unwrap();
        assert_eq!(pending, ReceiveResult::DuplicatePending);
        service
            .dispatch(&mut client, pending_offer, pending)
            .unwrap();
        for sequence in 5..=35 {
            let bytes = serde_json::to_vec(&expired_offer_envelope(sequence)).unwrap();
            let (frame, result) = client.session.receive(&bytes).unwrap();
            service.dispatch(&mut client, frame, result).unwrap();
        }
        let (second_gap_plan, second_gap) = client.session.receive(&plan_bytes).unwrap();
        assert_eq!(second_gap, ReceiveResult::Gap { expected: 36 });
        service
            .dispatch(&mut client, second_gap_plan, second_gap)
            .unwrap();
        for sequence in 36..=43 {
            let bytes = serde_json::to_vec(&expired_offer_envelope(sequence)).unwrap();
            let (frame, result) = client.session.receive(&bytes).unwrap();
            service.dispatch(&mut client, frame, result).unwrap();
        }
        let (replayed_plan, result) = client.session.receive(&plan_bytes).unwrap();
        assert_eq!(result, ReceiveResult::Applied);
        service
            .dispatch(&mut client, replayed_plan, result)
            .unwrap();

        assert!(client.session.remote_work_allowed());
        assert!(service.pending_reconciliation.is_none());
        for sequence in 4..=43 {
            assert_eq!(
                store
                    .operation(&format!("service-replay-idempotency-{sequence:08}"))
                    .unwrap()
                    .unwrap()
                    .state,
                OperationState::Expired
            );
        }
        let first_receipt = store
            .operation("service-replay-idempotency-00000004")
            .unwrap()
            .unwrap()
            .receipt;
        let (applied_duplicate, duplicate) = client.session.receive(&first_bytes).unwrap();
        assert_eq!(duplicate, ReceiveResult::Duplicate);
        service
            .dispatch(&mut client, applied_duplicate, duplicate)
            .unwrap();
        assert_eq!(
            store
                .operation("service-replay-idempotency-00000004")
                .unwrap()
                .unwrap()
                .receipt,
            first_receipt
        );

        let outbound = store
            .unacknowledged_outbound(1, 512)
            .unwrap()
            .into_iter()
            .map(|row| serde_json::from_slice::<Envelope>(&row.frame).unwrap())
            .collect::<Vec<_>>();
        let requested = outbound
            .iter()
            .filter(|frame| frame.kind == "transport.replay_required")
            .map(|frame| frame.payload["expectedSequence"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(requested, ["4", "36"]);
        assert_eq!(
            outbound
                .iter()
                .filter(|frame| frame.kind == "operation.admission")
                .count(),
            40
        );
        assert!(
            outbound
                .iter()
                .any(|frame| frame.kind == "reconcile.complete")
        );

        let cancel = control_envelope(
            45,
            "operation.cancel",
            json!({
                "operationId":"op_service_control_00000045",
                "idempotencyKey":"service-control-idempotency-00000045",
                "targetRunId":"run_service_replay01",
                "targetControllerEpoch":"1",
                "targetDigest":"11".repeat(32),
                "expectedState":"running",
                "expectedRevision":"1"
            }),
        );
        let cancel_bytes = serde_json::to_vec(&cancel).unwrap();
        assert_eq!(
            client.session.receive(&cancel_bytes).unwrap().1,
            ReceiveResult::Applied
        );
        let (pending_cancel, pending) = client.session.receive(&cancel_bytes).unwrap();
        assert_eq!(pending, ReceiveResult::DuplicatePending);
        service
            .dispatch(&mut client, pending_cancel, pending)
            .unwrap();
        assert_eq!(
            store
                .inbound_applied_through(Direction::ControlToNode)
                .unwrap(),
            45
        );
    }

    #[test]
    fn approval_request_window_uses_one_exact_clock_observation() {
        let issued = 1_800_000_000_123;
        let expires = issued + 300_000;
        let (issued_at, expires_at, valid_for_ms) =
            approval_request_window_at(issued, expires).unwrap();
        let issued_parsed = OffsetDateTime::parse(&issued_at, &Rfc3339).unwrap();
        let expires_parsed = OffsetDateTime::parse(&expires_at, &Rfc3339).unwrap();
        assert_eq!(valid_for_ms, 300_000);
        assert_eq!(
            (expires_parsed - issued_parsed).whole_milliseconds(),
            i128::from(valid_for_ms)
        );
    }

    #[test]
    fn terminal_same_poll_suppresses_new_approval_projection() {
        let terminal_ids = BTreeSet::from(["op_terminal01".to_owned()]);
        assert!(!approval_projection_allowed("op_terminal01", &terminal_ids));
        assert!(approval_projection_allowed("op_running01", &terminal_ids));
    }

    #[test]
    fn failed_driver_terminates_waiting_child_before_durable_finalization() {
        let directory = tempfile::tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let node = Arc::new(Node::new(store.clone()));
        let local = Arc::new(
            LocalServices::open(directory.path().join("local-services"), [7; 32]).unwrap(),
        );
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            node,
            identity,
            "wss://control.example.invalid/connect".into(),
            "dev_policy_01".into(),
            "cd".repeat(32),
            "node-boot-adapter-failure-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor.clone(),
        )
        .unwrap();
        let request = LaunchRequest {
            cwd: directory.path().to_path_buf(),
            prompt: Some("exercise provider request reuse".into()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: Some(directory.path().join("sessions")),
        };
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request).unwrap();
        let original = b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"confirm\",\"title\":\"Continue?\"}\n";
        assert_eq!(driver.on_record(original).unwrap().0.len(), 1);
        let (responses, events) = driver
            .on_record(
                b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"input\",\"title\":\"Changed\"}\n",
            )
            .unwrap();
        assert!(responses.is_empty());
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);

        let child_spec = conduit_adapters::LaunchSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), "while :; do sleep 60; done".into()],
            cwd: directory.path().to_path_buf(),
            protocol: conduit_adapters::AdapterProtocol::PiRpcJsonl,
            initial_frames: vec![],
        };
        let child = AdapterChild::spawn_uninitialized(&child_spec).unwrap();
        let runtime_id = "rt_adapter_failure01";
        let runtime = RuntimeRequest {
            runtime_id: runtime_id.into(),
            run_id: "run_adapter_failure01".into(),
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
        let launch = LaunchPlan {
            executable: child_spec.executable.clone(),
            argv: child_spec.args.clone(),
            cwd: child_spec.cwd.clone(),
            environment: BTreeMap::new(),
            io_mode: IoMode::Pipes,
            timeout_ms: None,
        };
        let prepared = supervisor
            .reserve(&runtime, "native", child_spec.executable.clone(), false)
            .unwrap();
        let custody = supervisor
            .adopt_external(&prepared, &launch, child.id())
            .unwrap();
        let operation_id = "op_adapter_failure01";
        let key = "adapter-failure-idempotency-key";
        let request_digest = "11".repeat(32);
        let manifest = build_manifest(
            &ManifestOperation {
                operation_id,
                idempotency_key: key,
                request_digest: &request_digest,
                run_id: &runtime.run_id,
                assignment_id: None,
                actor_id: "prin_adapter_failure01",
                client_id: "conduit.adapter-failure-test",
                device_id: "dev_policy_01",
                boot_id: "node-boot-adapter-failure-0001",
                capability_digest: &"cd".repeat(32),
                local_policy_revision: 1,
                runtime_kind: "native",
                runtime_provider: "native",
                runtime_config: b"{}",
                access_scope: "read_only",
                approval_mode: "always",
                adapter_id: Some("pi"),
                adapter_version: Some("fixture"),
                executable_digest: None,
                model: None,
                effort: None,
                context_compiler_version: None,
                context_snapshot_id: None,
                context_snapshot_digest: None,
                context_content_digest: None,
                context_bytes: None,
            },
            &[],
        )
        .unwrap();
        service.local.commit_manifest(&manifest).unwrap();
        store
            .admit_operation(
                operation_id,
                key,
                &request_digest,
                b"{}",
                1,
                "native",
                "read_only",
                "always",
                b"{}",
                b"{}",
                b"{}",
            )
            .unwrap();
        store
            .transition_operation(
                key,
                OperationState::Admitted,
                OperationState::Starting,
                Some(runtime_id),
                None,
                None,
            )
            .unwrap();
        store
            .transition_operation(
                key,
                OperationState::Starting,
                OperationState::Running,
                Some(runtime_id),
                custody.handle.process_identity.as_deref(),
                None,
            )
            .unwrap();
        service.agents.insert(
            operation_id.into(),
            AgentActive {
                key: key.into(),
                operation_id: operation_id.into(),
                run_id: runtime.run_id.clone(),
                request_digest: request_digest.clone(),
                runtime_id: runtime_id.into(),
                provider_id: "native".into(),
                handle: custody.handle,
                child,
                driver,
                adapter_kind: AdapterKind::Pi,
                actor_principal_id: "prin_adapter_failure01".into(),
                client_id: "conduit.adapter-failure-test".into(),
                access_scope: "read_only".into(),
                approval_mode: "always".into(),
                effective_required_approval_risk_classes: vec![],
                local_policy_revision: 1,
                controller_epoch: 1,
                revision: 1,
                event_sequence: 0,
                raw_sequence: 0,
                settlement_policy: AgentSettlementPolicy::CloseOnSettle,
                session_state: AgentSessionState::Running,
                idle_timeout_ms: 0,
                lease_expires_at_unix_ms: None,
                prepared_sources: vec![],
                parent_baseline_id: Value::Null,
                source_baseline_revisions: BTreeMap::new(),
                verification_policy: json!({}),
            },
        );
        let session =
            crate::transport::TransportSession::new(store.clone(), "dev_policy_01".into(), 1)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut client = WssClient::from_test_stream(stream, session, true);

        service.poll_agents(&mut client).unwrap();

        assert!(!service.agents.contains_key(operation_id));
        assert_eq!(
            store.operation(key).unwrap().unwrap().state,
            OperationState::Failed
        );
        assert_eq!(
            supervisor.inspect(runtime_id).unwrap().state,
            RuntimeState::Stopped
        );
        let outbound = store
            .unacknowledged_outbound(1, 16)
            .unwrap()
            .into_iter()
            .map(|row| serde_json::from_slice::<Envelope>(&row.frame).unwrap())
            .collect::<Vec<_>>();
        let terminal = outbound
            .iter()
            .find(|frame| frame.kind == "operation.terminal")
            .unwrap();
        assert_eq!(terminal.payload["reasonCode"], "adapter_protocol_error");
    }

    #[test]
    fn failed_driver_finalizes_child_exit_while_waiting_for_approval() {
        let directory = tempfile::tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_or_create(directory.path().join("identity/device.ed25519"))
                .unwrap(),
        );
        let node = Arc::new(Node::new(store.clone()));
        let local = Arc::new(
            LocalServices::open(directory.path().join("local-services"), [7; 32]).unwrap(),
        );
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let mut service = NodeService::new(
            node.clone(),
            identity,
            "wss://control.example.invalid/connect".into(),
            "dev_policy_01".into(),
            "cd".repeat(32),
            "node-boot-adapter-failure-0001".into(),
            NodePolicyConfig {
                local_policy: LocalPolicy {
                    revision: 1,
                    capabilities: vec![],
                    providers: vec![],
                    access_scopes: vec![],
                    approval_modes: vec![],
                    required_approval_risk_classes: vec![],
                    launch_profiles: vec![],
                    max_cpu: None,
                    max_memory_bytes: None,
                    max_storage_bytes: None,
                    allow_full_access_without_approval: false,
                },
                profiles: HashMap::new(),
            },
            local,
            supervisor.clone(),
        )
        .unwrap();

        let request = LaunchRequest {
            cwd: directory.path().to_path_buf(),
            prompt: Some("exercise provider request reuse".into()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: Some(directory.path().join("sessions")),
        };
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request).unwrap();
        let (response, _) = driver
            .on_record(
                b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"confirm\",\"title\":\"Continue?\"}\n",
            )
            .unwrap();
        assert_eq!(response.len(), 1);
        let (second_response, events) = driver
            .on_record(
                b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"input\",\"title\":\"Changed\"}\n",
            )
            .unwrap();
        assert!(second_response.is_empty());
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        let failure_event = events[0].clone();

        let child_spec = conduit_adapters::LaunchSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), "IFS= read -r ignored; exit 17".into()],
            cwd: directory.path().to_path_buf(),
            protocol: conduit_adapters::AdapterProtocol::PiRpcJsonl,
            initial_frames: vec![],
        };
        let child = AdapterChild::spawn_uninitialized(&child_spec).unwrap();
        let runtime_id = "rt_adapter_failure01";
        let runtime = RuntimeRequest {
            runtime_id: runtime_id.into(),
            run_id: "run_adapter_failure01".into(),
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
        let launch = LaunchPlan {
            executable: child_spec.executable.clone(),
            argv: child_spec.args.clone(),
            cwd: child_spec.cwd.clone(),
            environment: BTreeMap::new(),
            io_mode: IoMode::Pipes,
            timeout_ms: None,
        };
        let prepared = supervisor
            .reserve(&runtime, "native", child_spec.executable.clone(), false)
            .unwrap();
        let custody = supervisor
            .adopt_external(&prepared, &launch, child.id())
            .unwrap();

        let operation_id = "op_adapter_failure01";
        let key = "adapter-failure-idempotency-key";
        let request_digest = "11".repeat(32);
        let manifest = build_manifest(
            &ManifestOperation {
                operation_id,
                idempotency_key: key,
                request_digest: &request_digest,
                run_id: &runtime.run_id,
                assignment_id: None,
                actor_id: "prin_adapter_failure01",
                client_id: "conduit.adapter-failure-test",
                device_id: "dev_policy_01",
                boot_id: "node-boot-adapter-failure-0001",
                capability_digest: &"cd".repeat(32),
                local_policy_revision: 1,
                runtime_kind: "native",
                runtime_provider: "native",
                runtime_config: b"{}",
                access_scope: "read_only",
                approval_mode: "always",
                adapter_id: Some("pi"),
                adapter_version: Some("fixture"),
                executable_digest: None,
                model: None,
                effort: None,
                context_compiler_version: None,
                context_snapshot_id: None,
                context_snapshot_digest: None,
                context_content_digest: None,
                context_bytes: None,
            },
            &[],
        )
        .unwrap();
        service.local.commit_manifest(&manifest).unwrap();
        store
            .admit_operation(
                operation_id,
                key,
                &request_digest,
                b"{}",
                1,
                "native",
                "read_only",
                "always",
                b"{}",
                b"{}",
                b"{}",
            )
            .unwrap();
        store
            .transition_operation(
                key,
                OperationState::Admitted,
                OperationState::Starting,
                Some(runtime_id),
                None,
                None,
            )
            .unwrap();
        store
            .transition_operation(
                key,
                OperationState::Starting,
                OperationState::Running,
                Some(runtime_id),
                custody.handle.process_identity.as_deref(),
                None,
            )
            .unwrap();
        for suffix in ["pending", "requested"] {
            store
                .record_agent_approval(
                    &format!("appr_xservice_{suffix}01"),
                    key,
                    &"33".repeat(32),
                    format!("\"provider-{suffix}\"").as_bytes(),
                    "extension_ui_request.confirm",
                    &"44".repeat(32),
                    unix_ms_now() + 300_000,
                    format!("{{\"approvalId\":\"appr_xservice_{suffix}01\"}}").as_bytes(),
                )
                .unwrap();
        }
        store
            .mark_agent_approval_requested("appr_xservice_requested01")
            .unwrap();
        assert_eq!(
            store.operation(key).unwrap().unwrap().state,
            OperationState::WaitingApproval
        );
        service.agents.insert(
            operation_id.into(),
            AgentActive {
                key: key.into(),
                operation_id: operation_id.into(),
                run_id: runtime.run_id.clone(),
                request_digest: request_digest.clone(),
                runtime_id: runtime_id.into(),
                provider_id: "native".into(),
                handle: custody.handle,
                child,
                driver,
                adapter_kind: AdapterKind::Pi,
                actor_principal_id: "prin_adapter_failure01".into(),
                client_id: "conduit.adapter-failure-test".into(),
                access_scope: "read_only".into(),
                approval_mode: "always".into(),
                effective_required_approval_risk_classes: vec![],
                local_policy_revision: 1,
                controller_epoch: 1,
                revision: 1,
                event_sequence: 1,
                raw_sequence: 0,
                settlement_policy: AgentSettlementPolicy::CloseOnSettle,
                session_state: AgentSessionState::Running,
                idle_timeout_ms: 0,
                lease_expires_at_unix_ms: None,
                prepared_sources: vec![],
                parent_baseline_id: Value::Null,
                source_baseline_revisions: BTreeMap::new(),
                verification_policy: json!({}),
            },
        );

        let session =
            crate::transport::TransportSession::new(store.clone(), "dev_policy_01".into(), 1)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut client = WssClient::from_test_stream(stream, session, true);

        let normalized = service
            .local
            .append_visible_event(
                &runtime.run_id,
                "dev_policy_01",
                1,
                "node-boot-adapter-failure-0001",
                operation_id,
                adapter_event_name(failure_event.kind),
                visible_adapter_payload(&failure_event),
            )
            .unwrap();
        let encoded = serde_jcs::to_vec(&normalized).unwrap();
        let event_digest = normalized["eventDigest"].as_str().unwrap();
        store
            .append_operation_event(
                key,
                &runtime.run_id,
                normalized["eventId"].as_str().unwrap(),
                event_digest,
                &encoded,
                0,
            )
            .unwrap();

        let trigger = conduit_adapters::ProtocolFrame::json(&json!({"stop":true})).unwrap();
        service
            .agents
            .get_mut(operation_id)
            .unwrap()
            .child
            .write(&trigger)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if service
                .agents
                .get_mut(operation_id)
                .unwrap()
                .child
                .try_wait()
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(Instant::now() < deadline, "adapter fixture did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }

        service.poll_agents(&mut client).unwrap();

        assert!(!service.agents.contains_key(operation_id));
        assert_eq!(
            store.operation(key).unwrap().unwrap().state,
            OperationState::Failed
        );
        assert_eq!(
            supervisor.inspect(runtime_id).unwrap().state,
            RuntimeState::Stopped
        );
        for suffix in ["pending", "requested"] {
            assert_eq!(
                store
                    .agent_approval(&format!("appr_xservice_{suffix}01"))
                    .unwrap()
                    .unwrap()
                    .state,
                "abandoned"
            );
        }

        let outbound = store
            .unacknowledged_outbound(1, 16)
            .unwrap()
            .into_iter()
            .map(|row| serde_json::from_slice::<Envelope>(&row.frame).unwrap())
            .collect::<Vec<_>>();
        let terminal_index = outbound
            .iter()
            .position(|frame| frame.kind == "operation.terminal")
            .unwrap();
        assert_eq!(
            store.event_range(&runtime.run_id, 1, 1).unwrap()[0].sequence,
            1
        );
        assert_eq!(
            outbound[terminal_index].payload["lastRunEventSequence"],
            "1"
        );
        assert_eq!(
            outbound[terminal_index].payload["reasonCode"],
            "adapter_protocol_error"
        );
    }

    #[test]
    fn reviewer_role_fails_closed_without_read_only_scope_workspace_and_runtime() {
        let base = json!({
            "schemaVersion": 1,
            "operationId": "op_reviewer_01",
            "idempotencyKey": "reviewer-idempotency-key",
            "deviceId": "dev_policy_01",
            "capability": "agent.run.start",
            "sourceRevisions": [],
            "runtime": {"kind":"restricted_native","providerId":"restricted_native","configurationRevision":1},
            "accessScope": "read_only",
            "approvalMode": "always",
            "requiredApprovalRiskClasses": [],
            "connectorPolicyId": "cpol_reviewer_0001",
            "connectorPolicyRevision": 99,
            "arguments": {"adapterId":"agy","role":"reviewer"},
            "payloadDigest": "11".repeat(32),
            "issuedAt": "2026-09-01T00:00:00Z",
            "expiresAt": "2026-09-01T00:01:00Z",
            "validForMs": 60000
        });
        let allowed: WireOperation = serde_json::from_value(base.clone()).unwrap();
        enforce_reviewer_runtime(&allowed).unwrap();

        let mut broad = base.clone();
        broad["accessScope"] = json!("project_full");
        assert!(matches!(
            enforce_reviewer_runtime(&serde_json::from_value(broad).unwrap()),
            Err(ServiceError::Unavailable(reason)) if reason == "reviewer_access_scope_must_be_read_only"
        ));

        let mut native = base;
        native["runtime"]["kind"] = json!("native");
        native["runtime"]["providerId"] = json!("native");
        assert!(matches!(
            enforce_reviewer_runtime(&serde_json::from_value(native).unwrap()),
            Err(ServiceError::Unavailable(reason)) if reason == "reviewer_requires_enforced_runtime_boundary"
        ));
    }
}
