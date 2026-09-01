use crate::{
    AdmissionReceipt, Node, NodeError, OperationOffer,
    transport::{Envelope, TransportError, WssClient},
    verify_operation_commitment,
};
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
    device_id: String,
    run_id: Option<String>,
    capability: String,
    source_revisions: Vec<Value>,
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
struct Active {
    key: String,
    operation_id: String,
    run_id: String,
    request_digest: String,
    provider_id: String,
    handle: RuntimeHandle,
    journal_state: OperationState,
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
    message_counter: u64,
    active: HashMap<String, Active>,
}
impl NodeService {
    pub fn new(
        node: Arc<Node>,
        identity: Arc<DeviceIdentity>,
        control_url: String,
        device_id: String,
        capability_digest: String,
        node_boot_id: String,
        config: NodePolicyConfig,
    ) -> Result<Self, ServiceError> {
        if !device_id.starts_with("dev_")
            || capability_digest.len() != 64
            || node_boot_id.len() < 16
        {
            return Err(ServiceError::Config("invalid transport identity".into()));
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
            message_counter,
            active,
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
            let runs = self
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
            let payload = json!({"nodeBootId":self.node_boot_id,"journalGeneration":"3","capabilityDigest":self.capability_digest,"lastControlSequenceApplied":positions.control_received_through.to_string(),"lastNodeSequenceAcknowledged":positions.node_acknowledged_through.to_string(),"lastNodeSequenceRetained":retained,"runs":runs,"retainedEventRanges":[],"unresolvedCount":self.active.len(),"truncated":self.active.len()>256,"storageHealth":"healthy"});
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
                let payload = json!({"observedAt":now(),"nodeState":if client.session.remote_work_allowed(){"ready"}else{"reconciling"},"journalState":"healthy","storageState":"healthy","activeCommands":self.active.len(),"activeAgentRuns":0,"activeRuntimes":self.active.len()});
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
        let unsupported = [
            "controlReplay",
            "eventReplay",
            "statusRunIds",
            "cancelOperationIds",
            "quarantineRunIds",
        ]
        .iter()
        .any(|k| payload[*k].as_array().is_some_and(|v| !v.is_empty()));
        if unsupported {
            return Err(ServiceError::Unavailable(
                "reconciliation_plan_contains_unsupported_effects".into(),
            ));
        }
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
        if op.capability == "agent.run.start" {
            return Err(ServiceError::Unavailable(
                "agent_adapter_registry_unavailable".into(),
            ));
        }
        if !op.source_revisions.is_empty() {
            return Err(ServiceError::Unavailable(
                "workspace_resolution_unavailable".into(),
            ));
        }
        let profile_id = op
            .arguments
            .get("launchProfileId")
            .and_then(Value::as_str)
            .ok_or_else(|| ServiceError::Unavailable("device_launch_profile_required".into()))?;
        self.local_policy.evaluate(&op, profile_id)?;
        let profile = self
            .profiles
            .get(profile_id)
            .ok_or_else(|| ServiceError::Unavailable("device_launch_profile_unavailable".into()))?
            .clone();
        let selected = normalize_provider(&op.runtime.provider_id);
        if selected != profile.provider_id {
            return Err(ServiceError::Unavailable(
                "launch_profile_provider_mismatch".into(),
            ));
        }
        let launch = LaunchPlan {
            executable: profile.executable,
            argv: profile.argv,
            cwd: profile.cwd,
            environment: profile.environment,
            io_mode: profile.io_mode,
            timeout_ms: profile.timeout_ms,
        };
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
        let spec_digest = hex::encode(Sha256::digest(
            [
                serde_jcs::to_vec(&op.runtime).map_err(|_| TransportError::Malformed)?,
                serde_jcs::to_vec(&launch).map_err(|_| TransportError::Malformed)?,
            ]
            .concat(),
        ));
        let runtime = RuntimeRequest {
            runtime_id,
            run_id: run_id.clone(),
            kind: parse_kind(&op.runtime.kind)?,
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
            workspaces: vec![],
        };
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
}
fn admission_payload(r: &AdmissionReceipt, decision: &str) -> Result<Value, ServiceError> {
    let mut payload = json!({"operationId":r.operation_id,"idempotencyKey":r.idempotency_key,"requestDigest":r.request_digest,"decision":decision,"journalState":if decision=="uncertain"{"uncertain"}else{"admitted"},"selectedRuntimeProvider":r.selected_provider,"effectiveAccessScope":r.effective_access_scope,"effectiveApprovalMode":r.effective_approval_policy,"localPolicyRevision":r.local_policy_revision});
    let digest = hex::encode(Sha256::digest(
        serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?,
    ));
    payload["receiptDigest"] = Value::String(digest);
    Ok(payload)
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
fn now() -> String {
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
