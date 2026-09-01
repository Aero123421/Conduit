use crate::{
    AdmissionReceipt, Node, NodeError, OperationOffer,
    local::{LocalServices, SourceRevision, build_manifest},
    transport::{Envelope, TransportError, WssClient},
    verify_operation_commitment,
};
use conduit_adapters::{
    AdapterCatalog, AdapterChild, AdapterEvent, AdapterEventKind, AdapterKind, AdapterOperation,
    AdapterState, LaunchRequest, ProtocolDriver,
};
use conduit_domain::Sha256Digest;
use conduit_node_store::{DeviceIdentity, Direction, OperationState, ReceiveResult, StoreError};
use conduit_runtime::{
    IoMode, LaunchPlan, NetworkMode, ResourceLimits, RuntimeHandle, RuntimeKind, RuntimeRequest,
    RuntimeState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
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
#[serde(rename_all = "camelCase")]
struct WireOperation {
    schema_version: u32,
    operation_id: String,
    idempotency_key: String,
    #[serde(default = "default_actor_id")]
    actor_principal_id: String,
    #[serde(default = "default_client_id")]
    client_id: String,
    device_id: String,
    assignment_id: Option<String>,
    run_id: Option<String>,
    capability: String,
    source_revisions: Vec<SourceRevision>,
    runtime: WireRuntime,
    access_scope: String,
    approval_mode: String,
    connector_policy_revision: u64,
    arguments: Value,
    payload_digest: String,
    issued_at: String,
    expires_at: String,
    valid_for_ms: u64,
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
}
struct Active {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    provider_id: String,
    handle: RuntimeHandle,
    journal_state: OperationState,
}

struct AgentActive {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    child: AdapterChild,
    driver: ProtocolDriver,
    event_sequence: u64,
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
    message_counter: u64,
    active: HashMap<String, Active>,
    agents: HashMap<String, AgentActive>,
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
    ) -> Result<Self, ServiceError> {
        if !device_id.starts_with("dev_")
            || capability_digest.len() != 64
            || node_boot_id.len() < 16
        {
            return Err(ServiceError::Config("invalid transport identity".into()));
        }
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
                    },
                )
            })
            .collect();
        let message_counter = node.store().transport_positions()?.node_sent_through;
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
            message_counter,
            active,
            agents: HashMap::new(),
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
            let payload = json!({"nodeBootId":self.node_boot_id,"journalGeneration":"3","capabilityDigest":self.capability_digest,"lastControlSequenceApplied":positions.control_received_through.to_string(),"lastNodeSequenceAcknowledged":positions.node_acknowledged_through.to_string(),"lastNodeSequenceRetained":retained,"runs":runs,"retainedEventRanges":retained_event_ranges,"unresolvedCount":unresolved,"truncated":unresolved>256,"storageHealth":"healthy"});
            let id = self.message_id();
            client
                .session
                .queue_outbound(&id, "reconcile.summary", None, payload, 0)?;
            client.flush_unacknowledged(positions.node_acknowledged_through.saturating_add(1))?;
        } else {
            client.session.mark_reconciliation_complete()
        }
        let mut heartbeat = Instant::now();
        loop {
            if let Some((frame, result)) = client.poll()? {
                self.dispatch(&mut client, frame, result)?
            }
            self.poll_active(&mut client)?;
            if heartbeat.elapsed() >= Duration::from_secs(30) {
                let payload = json!({"observedAt":now(),"nodeState":if client.session.remote_work_allowed(){"ready"}else{"reconciling"},"journalState":"healthy","storageState":"healthy","activeCommands":self.active.len(),"activeAgentRuns":self.agents.len(),"activeRuntimes":self.active.len()+self.agents.len()});
                let id = self.message_id();
                client
                    .session
                    .queue_outbound(&id, "device.health", None, payload, 1)?;
                heartbeat = Instant::now()
            }
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
            let ack = json!({"direction":"control_to_node","throughSequence":seq.to_string()});
            let ack_id = self.message_id();
            client
                .session
                .queue_outbound(&ack_id, "transport.ack", None, ack, 0)?;
            return Ok(());
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
                if let Err(error) = self.reconcile(client, &frame.payload) {
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
                if !client.session.remote_work_allowed() {
                    return Err(ServiceError::Unavailable("reconciliation_required".into()));
                }
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
                if let Err(reason) = self.control_agent(&frame.kind, &frame.payload) {
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
        if frame.kind != "transport.ack" {
            let ack = json!({"direction":"control_to_node","throughSequence":seq.to_string()});
            let ack_id = self.message_id();
            client
                .session
                .queue_outbound(&ack_id, "transport.ack", None, ack, 0)?;
        }
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
    fn reconcile(&mut self, client: &mut WssClient, payload: &Value) -> Result<(), ServiceError> {
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
        for range in payload["controlReplay"]
            .as_array()
            .ok_or(TransportError::Malformed)?
        {
            let from = range["from"].as_str().ok_or(TransportError::Malformed)?;
            let _through = range["through"].as_str().ok_or(TransportError::Malformed)?;
            let request = json!({"direction":"control_to_node","expectedSequence":from});
            let message_id = self.message_id();
            client.session.queue_outbound(
                &message_id,
                "transport.replay_required",
                None,
                request,
                0,
            )?;
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
                let end = through.min(from.saturating_add(127));
                let frames = self
                    .node
                    .store()
                    .event_range(run_id, from, end)
                    .map_err(|_| {
                        ServiceError::Unavailable("event_replay_range_unavailable".into())
                    })?;
                let events = frames
                    .iter()
                    .map(|frame| serde_json::from_slice::<Value>(&frame.frame))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransportError::Malformed)?;
                let actual_through = frames.last().map_or(from, |frame| frame.sequence);
                let batch = json!({"runId":run_id,"fromSequence":from.to_string(),"throughSequence":actual_through.to_string(),"traceSchema":"conduit.trace/1","events":events});
                let message_id = self.message_id();
                client
                    .session
                    .queue_outbound(&message_id, "event.batch", None, batch, 0)?;
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
                .active
                .values()
                .find(|active| active.run_id == run_id)
                .map(|active| active.operation_id.clone())
                .or_else(|| {
                    self.agents
                        .values()
                        .find(|agent| agent.run_id == run_id)
                        .map(|agent| agent.operation_id.clone())
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
        client.session.complete_plan(id)?;
        let p = self.node.store().transport_positions()?;
        let response = json!({"reconciliationId":id,"lastControlSequenceApplied":p.control_received_through.to_string(),"lastNodeSequenceAcknowledged":p.node_acknowledged_through.to_string(),"unresolvedRunIds":[]});
        let msg = self.message_id();
        client
            .session
            .queue_outbound(&msg, "reconcile.complete", None, response, 0)?;
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
        let runtime_kind = parse_kind(&op.runtime.kind)?;
        if is_agent && (!matches!(runtime_kind, RuntimeKind::Native) || selected != "native") {
            return Err(ServiceError::Unavailable(
                "adapter_runtime_provider_unsupported".into(),
            ));
        }
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
        let (launch, agent_launch) = if is_agent {
            let kind = parse_adapter(profile_id)?;
            let cwd = prepared_sources
                .first()
                .map(|source| source.host_path.clone())
                .unwrap_or_else(|| self.local.agent_scratch(&run_id));
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
                session_data_dir: Some(self.local.agent_session_dir(&run_id)),
            };
            let (spec, driver) = AdapterCatalog::launch(kind, &request)
                .map_err(|error| ServiceError::Unavailable(adapter_reason(&error)))?;
            let launch = LaunchPlan {
                executable: spec.executable.clone(),
                argv: spec.args.clone(),
                cwd: spec.cwd.clone(),
                environment: BTreeMap::new(),
                io_mode: IoMode::Pipes,
                timeout_ms: op.arguments.get("timeoutMs").and_then(Value::as_u64),
            };
            (launch, Some((spec, driver, kind)))
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
        let executable_digest = hash_file(&launch.executable)?;
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
                executable_digest: Some(executable_digest),
                model: op.arguments.get("model").and_then(Value::as_str),
                effort: op.arguments.get("effort").and_then(Value::as_str),
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
            if let Some((spec, driver, _)) = agent_launch {
                self.node.store().transition_operation(
                    &op.idempotency_key,
                    OperationState::Admitted,
                    OperationState::Starting,
                    Some(&runtime_id),
                    None,
                    None,
                )?;
                let child = match AdapterChild::spawn(&spec) {
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
                let process_identity = format!("adapter-pid:{}", child.id());
                self.node.store().transition_operation(
                    &op.idempotency_key,
                    OperationState::Starting,
                    OperationState::Running,
                    Some(&runtime_id),
                    Some(&process_identity),
                    None,
                )?;
                let status = json!({"operationId":op.operation_id,"runId":run_id,"state":"running","phase":"adapter_started","observedAt":now()});
                let msg = self.message_id();
                client.session.queue_outbound(
                    &msg,
                    "operation.status",
                    Some(op.operation_id.clone()),
                    status,
                    0,
                )?;
                self.agents.insert(
                    op.operation_id.clone(),
                    AgentActive {
                        key: op.idempotency_key,
                        operation_id: op.operation_id,
                        run_id,
                        request_digest: op.payload_digest,
                        child,
                        driver,
                        event_sequence: 0,
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
            let status = json!({"operationId":op.operation_id,"runId":run_id,"state":"running","phase":"runtime_started","observedAt":now()});
            let msg = self.message_id();
            client.session.queue_outbound(
                &msg,
                "operation.status",
                Some(op.operation_id.clone()),
                status,
                0,
            )?;
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

    fn control_agent(&mut self, kind: &str, payload: &Value) -> Result<(), String> {
        let run_id = payload
            .get("targetRunId")
            .and_then(Value::as_str)
            .ok_or_else(|| "operation_target_run_required".to_owned())?;
        let expected = payload
            .get("expectedState")
            .and_then(Value::as_str)
            .ok_or_else(|| "operation_expected_state_required".to_owned())?;
        let (_, agent) = self
            .agents
            .iter_mut()
            .find(|(_, agent)| agent.run_id == run_id)
            .ok_or_else(|| "target_agent_run_unavailable".to_owned())?;
        let observed = adapter_operation_state(agent.driver.state());
        if expected != observed {
            return Err(format!(
                "target_state_stale:expected={expected}:observed={observed}"
            ));
        }
        if kind == "operation.cancel" {
            match agent.driver.command(AdapterOperation::Cancel, None) {
                Ok(frames) => {
                    for frame in frames {
                        agent
                            .child
                            .write(&frame)
                            .map_err(|error| error.to_string())?;
                    }
                    if matches!(
                        agent.driver.state(),
                        AdapterState::Ready | AdapterState::Starting
                    ) {
                        agent.child.terminate().map_err(|error| error.to_string())?;
                    }
                }
                Err(conduit_adapters::AdapterError::UnsupportedOperation { .. }) => {
                    // One-shot adapters advertise cancellation through process
                    // custody rather than a vendor protocol message.
                    agent.child.terminate().map_err(|error| error.to_string())?;
                }
                Err(error) => return Err(error.to_string()),
            }
            return Ok(());
        }
        let mode = payload
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("input");
        let content = payload.get("content").and_then(Value::as_str);
        let operation = match mode {
            "input" => AdapterOperation::Send,
            "follow_up" => AdapterOperation::FollowUp,
            "steer" => AdapterOperation::Steer,
            "resume" => {
                return Err("resume_requires_new_agent_run_with_native_session_id".to_owned());
            }
            _ => return Err("operation_input_mode_unknown".into()),
        };
        let frames = agent
            .driver
            .command(operation, content)
            .map_err(|error| error.to_string())?;
        for frame in frames {
            agent
                .child
                .write(&frame)
                .map_err(|error| error.to_string())?;
        }
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
        }
        let ids = self.agents.keys().cloned().collect::<Vec<_>>();
        let mut events = Vec::new();
        let mut terminals = Vec::new();
        for id in &ids {
            let Some(agent) = self.agents.get_mut(id) else {
                continue;
            };
            for _ in 0..128 {
                let record = match agent.child.try_read_record() {
                    Ok(Some(record)) => record,
                    Ok(None) => break,
                    Err(error) => {
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
            if let Some(exit) = agent
                .child
                .try_wait()
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?
            {
                let adapter_state = agent.driver.state();
                let (state, reason) = match (adapter_state, exit.success()) {
                    (AdapterState::Completed, true) => (OperationState::Completed, None),
                    (AdapterState::Cancelled, _) => {
                        (OperationState::Cancelled, Some("adapter_cancelled".into()))
                    }
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
                };
                terminals.push(PendingTerminal {
                    id: id.clone(),
                    state,
                    reason,
                    last_sequence: agent.event_sequence,
                });
            }
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
            let payload = json!({"runId":pending.run_id,"fromSequence":pending.sequence.to_string(),"throughSequence":pending.sequence.to_string(),"traceSchema":"conduit.trace/1","events":[normalized]});
            let message_id = self.message_id();
            client.session.queue_outbound(
                &message_id,
                "event.batch",
                Some(pending.operation_id),
                payload,
                1,
            )?;
        }
        for pending in terminals {
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

    fn finish_agent(
        &mut self,
        client: &mut WssClient,
        id: &str,
        terminal: OperationState,
        reason: Option<&str>,
        last_sequence: u64,
    ) -> Result<(), ServiceError> {
        let Some(agent) = self.agents.remove(id) else {
            return Ok(());
        };
        self.node.store().transition_operation(
            &agent.key,
            OperationState::Running,
            OperationState::Finishing,
            None,
            None,
            None,
        )?;
        let state = match terminal {
            OperationState::Completed => "completed",
            OperationState::Cancelled => "cancelled",
            _ => "failed",
        };
        let mut payload = json!({"operationId":agent.operation_id,"runId":agent.run_id,"state":state,"requestDigest":agent.request_digest,"lastRunEventSequence":last_sequence.to_string(),"observedAt":now()});
        if let Some(reason) = reason {
            payload["reasonCode"] = Value::String(reason.into());
            payload["resultSummary"] = json!({"adapterTerminal":reason});
        }
        let digest = hex::encode(Sha256::digest(
            serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
        ));
        payload["receiptDigest"] = Value::String(digest);
        let bytes = serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?;
        self.node
            .terminal(&agent.key, OperationState::Finishing, terminal, &bytes)?;
        let message_id = self.message_id();
        client.session.queue_outbound(
            &message_id,
            "operation.terminal",
            Some(agent.operation_id),
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
        let status = json!({
            "operationId": admission.operation.operation_id,
            "runId": run_id,
            "state": admission.operation.state,
            "phase": "reconciled_status",
            "observedAt": now(),
        });
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
            self.active.remove(operation_id)
        {
            let _ = self.node.signal_runtime(
                &active.provider_id,
                &active.handle,
                if quarantine {
                    conduit_runtime::RuntimeSignal::ForceStop
                } else {
                    conduit_runtime::RuntimeSignal::GracefulStop
                },
            );
            (
                active.key,
                active.run_id,
                active.request_digest,
                active.journal_state,
            )
        } else if let Some(mut agent) = self.agents.remove(operation_id) {
            agent
                .child
                .terminate()
                .map_err(|error| ServiceError::Unavailable(error.to_string()))?;
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
            return Err(ServiceError::Unavailable(
                "cancel_operation_custody_unavailable".into(),
            ));
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
        "text": event.text.as_deref().map(|text| bounded(text, 4_096)),
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
        // Agy intentionally remains unavailable until its structured protocol
        // is independently verified by conduit-adapters.
        "agy" => Err(ServiceError::Unavailable(
            "adapter_protocol_unverified".into(),
        )),
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

pub(crate) fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            launch_profiles: vec!["safe".into()],
            max_cpu: Some(4.0),
            max_memory_bytes: Some(1024 * 1024),
            max_storage_bytes: Some(1024 * 1024),
            allow_full_access_without_approval: explicit_full_never,
        }
    }
    #[test]
    fn local_policy_revision_is_independent_and_deny_precedes_connector() {
        let denied = policy(false);
        assert_eq!(denied.revision, 8);
        assert!(matches!(
            denied.evaluate(&operation("full_device", "never", 1.0), "safe"),
            Err(ServiceError::Unavailable(reason)) if reason == "local_policy_explicit_full_access_never_required"
        ));
        assert!(matches!(
            denied.evaluate(&operation("project_full", "never", 8.0), "safe"),
            Err(ServiceError::Unavailable(reason)) if reason == "local_policy_resource_ceiling"
        ));
        assert!(
            policy(true)
                .evaluate(&operation("full_device", "never", 1.0), "safe")
                .is_ok()
        );
    }
}
