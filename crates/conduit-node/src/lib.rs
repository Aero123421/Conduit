//! Linux `conduit-node`: outbound transport, durable admission, runtime
//! orchestration, and authenticated local IPC.

pub mod ipc;
pub mod local;
pub mod local_ipc;
pub mod service;
pub mod transport;

use conduit_node_store::{AdmissionResult, NodeStore, OperationState, StoreError};
use conduit_runtime::{
    LaunchPlan, PreparedRuntime, RuntimeError, RuntimeHandle, RuntimeProvider, RuntimeRequest,
    RuntimeState, RuntimeStateReceipt,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("operation rejected: {0}")]
    Rejected(String),
    #[error("runtime failed: {0}")]
    Runtime(String),
    #[error("transport failed: {0}")]
    Transport(String),
    #[error("IPC failed: {0}")]
    Ipc(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationOffer {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub manifest: Vec<u8>,
    pub local_policy_revision: u64,
    pub runtime: RuntimeRequest,
    pub launch: LaunchPlan,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReceipt {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub disposition: String,
    #[serde(rename = "selectedRuntimeProvider")]
    pub selected_provider: String,
    pub effective_access_scope: String,
    #[serde(rename = "effectiveApprovalMode")]
    pub effective_approval_policy: String,
    pub local_policy_revision: u64,
    pub receipt_digest: String,
}
#[derive(Debug, Clone)]
pub struct RecoveredOperation {
    pub key: String,
    pub operation_id: String,
    pub run_id: String,
    pub request_digest: String,
    pub provider_id: String,
    pub handle: RuntimeHandle,
    pub journal_state: OperationState,
}

/// Runtime registry is selected locally. A remote request cannot introduce an
/// arbitrary provider executable or weaken a missing required capability.
pub struct Node {
    store: NodeStore,
    providers: HashMap<String, Arc<dyn RuntimeProvider>>,
}
impl Node {
    pub fn new(store: NodeStore) -> Self {
        Self {
            store,
            providers: HashMap::new(),
        }
    }
    pub fn register_provider(&mut self, provider: Arc<dyn RuntimeProvider>) {
        self.providers
            .insert(provider.provider_id().into(), provider);
    }
    pub fn store(&self) -> &NodeStore {
        &self.store
    }
    pub fn admit(
        &self,
        offer: &OperationOffer,
        provider_id: &str,
        access_scope: &str,
        approval_policy: &str,
    ) -> Result<AdmissionReceipt, NodeError> {
        verify_operation_commitment(&offer.manifest, &offer.request_digest)?;
        if !self.providers.contains_key(provider_id) {
            return Err(NodeError::Rejected("runtime_provider_unavailable".into()));
        }
        if !matches!(
            access_scope,
            "read_only"
                | "selected_sources"
                | "project_full"
                | "full_user"
                | "full_device"
                | "custom"
        ) {
            return Err(NodeError::Rejected("invalid_access_scope".into()));
        }
        if !matches!(
            approval_policy,
            "always" | "outside_scope" | "risk_classes" | "never"
        ) {
            return Err(NodeError::Rejected("invalid_approval_policy".into()));
        }
        if offer.local_policy_revision == 0 {
            return Err(NodeError::Rejected("invalid_policy_revision".into()));
        }
        let runtime_request =
            serde_jcs::to_vec(&offer.runtime).map_err(|e| NodeError::Rejected(e.to_string()))?;
        let launch_plan =
            serde_jcs::to_vec(&offer.launch).map_err(|e| NodeError::Rejected(e.to_string()))?;
        let mut receipt = AdmissionReceipt {
            operation_id: offer.operation_id.clone(),
            idempotency_key: offer.idempotency_key.clone(),
            request_digest: offer.request_digest.clone(),
            disposition: "admitted".into(),
            selected_provider: provider_id.into(),
            effective_access_scope: access_scope.into(),
            effective_approval_policy: approval_policy.into(),
            local_policy_revision: offer.local_policy_revision,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt_commitment(&receipt)?;
        let encoded_receipt =
            serde_jcs::to_vec(&receipt).map_err(|e| NodeError::Rejected(e.to_string()))?;
        match self.store.admit_operation(
            &offer.operation_id,
            &offer.idempotency_key,
            &offer.request_digest,
            &offer.manifest,
            offer.local_policy_revision,
            provider_id,
            access_scope,
            approval_policy,
            &runtime_request,
            &launch_plan,
            &encoded_receipt,
        )? {
            AdmissionResult::Admitted(_) => Ok(receipt),
            AdmissionResult::Replay(saved) => {
                let mut receipt: AdmissionReceipt =
                    serde_json::from_slice(&saved.admission_receipt)
                        .map_err(|_| NodeError::Rejected("durable_admission_corrupt".into()))?;
                receipt.disposition = "duplicate_replay".into();
                Ok(receipt)
            }
            AdmissionResult::Uncertain(saved) => {
                let mut r: AdmissionReceipt = serde_json::from_slice(&saved.admission_receipt)
                    .map_err(|_| NodeError::Rejected("durable_admission_corrupt".into()))?;
                r.disposition = "uncertain".into();
                Ok(r)
            }
        }
    }
    pub fn start(&self, key: &str) -> Result<RuntimeStateReceipt, NodeError> {
        let admission = self
            .store
            .admission(key)?
            .ok_or_else(|| NodeError::Rejected("operation_not_admitted".into()))?;
        let provider = self
            .providers
            .get(&admission.provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?;
        let record = &admission.operation;
        match record.state {
            OperationState::Admitted => {}
            OperationState::Starting | OperationState::Running => {
                return Err(NodeError::Rejected("operation_already_started".into()));
            }
            s if s.terminal() => return Err(NodeError::Rejected("operation_terminal".into())),
            _ => return Err(NodeError::Rejected("operation_not_startable".into())),
        };
        let runtime: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
            .map_err(|_| NodeError::Rejected("durable_runtime_request_corrupt".into()))?;
        let launch: LaunchPlan = serde_json::from_slice(&admission.launch_plan)
            .map_err(|_| NodeError::Rejected("durable_launch_plan_corrupt".into()))?;
        self.store.transition_operation(
            key,
            OperationState::Admitted,
            OperationState::Starting,
            Some(&runtime.runtime_id),
            None,
            None,
        )?;
        let prepared: PreparedRuntime = match provider.prepare(&runtime) {
            Ok(prepared) => prepared,
            Err(error) => {
                let evidence = error.to_string();
                self.store.transition_operation(
                    key,
                    OperationState::Starting,
                    OperationState::Failed,
                    Some(&runtime.runtime_id),
                    None,
                    Some(evidence.as_bytes()),
                )?;
                return Err(NodeError::Runtime(evidence));
            }
        };
        match provider.start(&prepared, &launch) {
            Ok(receipt) => {
                self.store.transition_operation(
                    key,
                    OperationState::Starting,
                    OperationState::Running,
                    Some(&prepared.runtime_id),
                    receipt.handle.process_identity.as_deref(),
                    None,
                )?;
                Ok(receipt)
            }
            Err(error) => {
                let evidence = error.to_string();
                let _ = self.store.transition_operation(
                    key,
                    OperationState::Starting,
                    OperationState::Uncertain,
                    Some(&prepared.runtime_id),
                    None,
                    Some(evidence.as_bytes()),
                );
                Err(NodeError::Runtime(evidence))
            }
        }
    }
    pub fn terminal(
        &self,
        key: &str,
        expected: OperationState,
        state: OperationState,
        receipt: &[u8],
    ) -> Result<(), NodeError> {
        if !state.terminal() {
            return Err(NodeError::Rejected(
                "terminal receipt requires terminal state".into(),
            ));
        }
        self.store
            .transition_operation(key, expected, state, None, None, Some(receipt))?;
        Ok(())
    }
    pub fn inspect_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
    ) -> Result<RuntimeStateReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .inspect(handle)
            .map_err(|e| NodeError::Runtime(e.to_string()))
    }
    pub fn signal_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        signal: conduit_runtime::RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .signal(handle, signal)
            .map_err(|error| NodeError::Runtime(error.to_string()))
    }

    pub fn snapshot_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        name: &str,
    ) -> Result<conduit_runtime::SnapshotReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .snapshot(handle, name)
            .map_err(|error| NodeError::Runtime(error.to_string()))
    }

    pub fn collect_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
    ) -> Result<conduit_runtime::CollectionReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .collect(handle)
            .map_err(|error| NodeError::Runtime(error.to_string()))
    }

    pub fn destroy_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        request: &conduit_runtime::DestroyRequest,
    ) -> Result<conduit_runtime::DestroyReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .destroy(handle, request)
            .map_err(|error| NodeError::Runtime(error.to_string()))
    }

    pub fn runtime_handle(
        &self,
        admission: &conduit_node_store::AdmissionRecord,
    ) -> Result<RuntimeHandle, NodeError> {
        let request: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
            .map_err(|_| NodeError::Rejected("durable_runtime_request_corrupt".into()))?;
        Ok(RuntimeHandle {
            runtime_id: request.runtime_id.clone(),
            provider_id: admission.provider_id.clone(),
            spec_digest: request.spec_digest,
            object_id: match admission.provider_id.as_str() {
                "native" | "restricted_native" => "native-supervisor".into(),
                "docker" | "podman" | "incus_kvm" => {
                    format!("conduit-{}", request.runtime_id.trim_start_matches("rt_"))
                }
                _ => return Err(NodeError::Rejected("runtime_provider_unavailable".into())),
            },
            process_identity: admission.operation.process_identity.clone(),
        })
    }
    pub fn recover_nonterminal(&self) -> Result<Vec<RecoveredOperation>, NodeError> {
        let mut recovered = Vec::new();
        for admission in self.store.nonterminal_admissions()? {
            let operation = admission.operation;
            if operation.state == OperationState::Admitted {
                continue;
            }
            let request: RuntimeRequest = serde_json::from_slice(&admission.runtime_request)
                .map_err(|_| NodeError::Rejected("durable_runtime_request_corrupt".into()))?;
            let is_agent = serde_json::from_slice::<serde_json::Value>(&operation.manifest)
                .ok()
                .and_then(|value| {
                    value
                        .get("capability")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("agent.run.start");
            if is_agent {
                let terminal = if operation.state == OperationState::Running {
                    OperationState::RecoveryRequired
                } else {
                    OperationState::Uncertain
                };
                let evidence = serde_jcs::to_vec(&serde_json::json!({
                    "operationId": operation.operation_id,
                    "runId": request.run_id,
                    "state": terminal,
                    "reasonCode": "adapter_process_restart_recovery_required"
                }))
                .map_err(|error| NodeError::Rejected(error.to_string()))?;
                self.store.transition_operation(
                    &operation.idempotency_key,
                    operation.state,
                    terminal,
                    Some(&request.runtime_id),
                    None,
                    Some(&evidence),
                )?;
                continue;
            }
            let handle = RuntimeHandle {
                runtime_id: request.runtime_id.clone(),
                provider_id: admission.provider_id.clone(),
                spec_digest: request.spec_digest.clone(),
                object_id: match admission.provider_id.as_str() {
                    "native" | "restricted_native" => "native-supervisor".into(),
                    "docker" | "podman" | "incus_kvm" => {
                        format!("conduit-{}", request.runtime_id.trim_start_matches("rt_"))
                    }
                    _ => return Err(NodeError::Rejected("runtime_provider_unavailable".into())),
                },
                process_identity: operation.process_identity.clone(),
            };
            let provider = self
                .providers
                .get(&admission.provider_id)
                .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?;
            let observed = provider.inspect(&handle);
            let observed_state = match observed {
                Ok(receipt) => {
                    if receipt.handle.spec_digest != request.spec_digest
                        || receipt.handle.provider_id != admission.provider_id
                    {
                        RuntimeState::RecoveryRequired
                    } else {
                        if matches!(
                            operation.state,
                            OperationState::Starting
                                | OperationState::WaitingInput
                                | OperationState::WaitingApproval
                        ) {
                            self.store.transition_operation(
                                &operation.idempotency_key,
                                operation.state,
                                OperationState::Running,
                                Some(&request.runtime_id),
                                receipt.handle.process_identity.as_deref(),
                                None,
                            )?;
                        }
                        recovered.push(RecoveredOperation {
                            key: operation.idempotency_key,
                            operation_id: operation.operation_id,
                            run_id: request.run_id,
                            request_digest: operation.request_digest,
                            provider_id: admission.provider_id,
                            handle: receipt.handle,
                            journal_state: if matches!(
                                operation.state,
                                OperationState::Starting
                                    | OperationState::WaitingInput
                                    | OperationState::WaitingApproval
                            ) {
                                OperationState::Running
                            } else {
                                operation.state
                            },
                        });
                        continue;
                    }
                }
                Err(RuntimeError::NotFound) => RuntimeState::Lost,
                Err(RuntimeError::IdentityMismatch | RuntimeError::Uncertain(_)) => {
                    RuntimeState::RecoveryRequired
                }
                Err(
                    RuntimeError::CapabilityUnavailable(_)
                    | RuntimeError::Provider { .. }
                    | RuntimeError::Io(_),
                ) => RuntimeState::Uncertain,
                Err(RuntimeError::Invalid(_) | RuntimeError::Record(_)) => {
                    RuntimeState::RecoveryRequired
                }
            };
            let terminal = match observed_state {
                RuntimeState::Lost => OperationState::Lost,
                RuntimeState::Uncertain => OperationState::Uncertain,
                _ => OperationState::RecoveryRequired,
            };
            let evidence = serde_jcs::to_vec(&serde_json::json!({
                "operationId": operation.operation_id,
                "runtimeId": request.runtime_id,
                "state": terminal,
                "reasonCode": "restart_provider_reconciliation"
            }))
            .map_err(|error| NodeError::Rejected(error.to_string()))?;
            self.store.transition_operation(
                &operation.idempotency_key,
                operation.state,
                terminal,
                Some(&request.runtime_id),
                None,
                Some(&evidence),
            )?;
        }
        Ok(recovered)
    }
}

pub fn verify_operation_commitment(manifest: &[u8], expected: &str) -> Result<(), NodeError> {
    if manifest.len() > 256 * 1024 {
        return Err(NodeError::Rejected("operation_manifest_too_large".into()));
    }
    let mut value: serde_json::Value = serde_json::from_slice(manifest)
        .map_err(|_| NodeError::Rejected("operation_manifest_malformed".into()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| NodeError::Rejected("operation_manifest_malformed".into()))?;
    let embedded = object
        .remove("payloadDigest")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| NodeError::Rejected("request_digest_missing".into()))?;
    if embedded != expected {
        return Err(NodeError::Rejected("request_digest_mismatch".into()));
    }
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|_| NodeError::Rejected("operation_manifest_malformed".into()))?;
    use sha2::{Digest, Sha256};
    let actual = hex::encode(Sha256::digest(canonical));
    if actual != expected {
        return Err(NodeError::Rejected("request_digest_mismatch".into()));
    }
    Ok(())
}
fn receipt_commitment(receipt: &AdmissionReceipt) -> Result<String, NodeError> {
    let mut value =
        serde_json::to_value(receipt).map_err(|e| NodeError::Rejected(e.to_string()))?;
    value
        .as_object_mut()
        .expect("receipt is object")
        .remove("receiptDigest");
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(&value).map_err(|e| NodeError::Rejected(e.to_string()))?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_runtime::{
        IoMode, NativeProvider, NetworkMode, ProcessSupervisor, ResourceLimits, RuntimeKind,
        RuntimeSignal,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    fn offer(cwd: &std::path::Path) -> OperationOffer {
        let mut manifest = json!({
            "operationId": "op_restart_01",
            "payloadDigest": ""
        });
        let mut commitment = manifest.clone();
        commitment.as_object_mut().unwrap().remove("payloadDigest");
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&commitment).unwrap()));
        manifest["payloadDigest"] = serde_json::Value::String(digest.clone());
        OperationOffer {
            operation_id: "op_restart_01".into(),
            idempotency_key: "restart-operation-key-01".into(),
            request_digest: digest,
            manifest: serde_jcs::to_vec(&manifest).unwrap(),
            local_policy_revision: 9,
            runtime: RuntimeRequest {
                runtime_id: "rt_restart_01".into(),
                run_id: "run_restart_01".into(),
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
            },
            launch: LaunchPlan {
                executable: "/bin/sh".into(),
                argv: vec!["-c".into(), "sleep 5".into()],
                cwd: cwd.into(),
                environment: Default::default(),
                io_mode: IoMode::Pipes,
                timeout_ms: Some(10_000),
            },
        }
    }

    #[test]
    fn canonical_operation_commitment_rejects_mutation() {
        let d = tempdir().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&offer(d.path()).manifest).unwrap();
        value["operationId"] = json!("op_changed_01");
        assert!(matches!(
            verify_operation_commitment(
                &serde_json::to_vec(&value).unwrap(),
                value["payloadDigest"].as_str().unwrap()
            ),
            Err(NodeError::Rejected(reason)) if reason == "request_digest_mismatch"
        ));
    }

    #[test]
    fn restart_reconciles_live_process_without_respawn() {
        let d = tempdir().unwrap();
        let store = NodeStore::open(d.path().join("store")).unwrap();
        let supervisor = ProcessSupervisor::open(d.path().join("supervisor")).unwrap();
        let provider: Arc<dyn RuntimeProvider> = Arc::new(NativeProvider::new(supervisor.clone()));
        let request = offer(d.path());
        let mut first = Node::new(store.clone());
        first.register_provider(provider.clone());
        first
            .admit(&request, "native", "project_full", "never")
            .unwrap();
        let started = first.start(&request.idempotency_key).unwrap();
        let identity = started.handle.process_identity.clone();
        drop(first);
        let mut reopened = Node::new(store);
        reopened.register_provider(provider.clone());
        let recovered = reopened.recover_nonterminal().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].handle.process_identity, identity);
        provider
            .signal(&recovered[0].handle, RuntimeSignal::ForceStop)
            .unwrap();
    }
}
