//! Linux `conduit-node`: outbound transport, durable admission, runtime
//! orchestration, and authenticated local IPC.

pub mod ipc;
pub mod transport;

use conduit_node_store::{NodeStore, OperationState, ReserveResult, StoreError};
use conduit_runtime::{
    LaunchPlan, PreparedRuntime, RuntimeProvider, RuntimeRequest, RuntimeStateReceipt,
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
pub struct AdmissionReceipt {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub disposition: String,
    pub selected_provider: String,
    pub effective_access_scope: String,
    pub effective_approval_policy: String,
    pub local_policy_revision: u64,
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
        let result = self.store.reserve_operation(
            &offer.operation_id,
            &offer.idempotency_key,
            &offer.request_digest,
            &offer.manifest,
            offer.local_policy_revision,
        )?;
        let disposition = match result {
            ReserveResult::Reserved(_) => {
                if !self.providers.contains_key(provider_id) {
                    self.store.transition_operation(
                        &offer.idempotency_key,
                        OperationState::Reserved,
                        OperationState::Rejected,
                        None,
                        None,
                        Some(b"runtime_provider_unavailable"),
                    )?;
                    return Err(NodeError::Rejected("runtime_provider_unavailable".into()));
                }
                self.store.transition_operation(
                    &offer.idempotency_key,
                    OperationState::Reserved,
                    OperationState::Admitted,
                    None,
                    None,
                    None,
                )?;
                "admitted"
            }
            ReserveResult::Replay(r) => {
                if r.state.terminal() {
                    "duplicate_terminal_replay"
                } else {
                    "duplicate_replay"
                }
            }
            ReserveResult::Uncertain(_) => "uncertain",
        };
        Ok(AdmissionReceipt {
            operation_id: offer.operation_id.clone(),
            idempotency_key: offer.idempotency_key.clone(),
            request_digest: offer.request_digest.clone(),
            disposition: disposition.into(),
            selected_provider: provider_id.into(),
            effective_access_scope: access_scope.into(),
            effective_approval_policy: approval_policy.into(),
            local_policy_revision: offer.local_policy_revision,
        })
    }
    pub fn start(
        &self,
        offer: &OperationOffer,
        provider_id: &str,
    ) -> Result<RuntimeStateReceipt, NodeError> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?;
        let record = self
            .store
            .operation(&offer.idempotency_key)?
            .ok_or_else(|| NodeError::Rejected("operation_not_admitted".into()))?;
        match record.state {
            OperationState::Admitted => {}
            OperationState::Starting | OperationState::Running => {
                return Err(NodeError::Rejected("operation_already_started".into()));
            }
            s if s.terminal() => return Err(NodeError::Rejected("operation_terminal".into())),
            _ => return Err(NodeError::Rejected("operation_not_startable".into())),
        };
        let prepared: PreparedRuntime = provider
            .prepare(&offer.runtime)
            .map_err(|e| NodeError::Runtime(e.to_string()))?;
        self.store.transition_operation(
            &offer.idempotency_key,
            OperationState::Admitted,
            OperationState::Starting,
            Some(&prepared.runtime_id),
            None,
            None,
        )?;
        match provider.start(&prepared, &offer.launch) {
            Ok(receipt) => {
                self.store.transition_operation(
                    &offer.idempotency_key,
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
                    &offer.idempotency_key,
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
}
