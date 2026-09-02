//! Linux `conduit-node`: outbound transport, durable admission, runtime
//! orchestration, and authenticated local IPC.

pub mod batching;
pub mod ipc;
pub mod local;
pub mod local_ipc;
pub mod privileged;
pub mod service;
pub mod startup;
pub mod transport;

use conduit_node_store::{AdmissionResult, NodeStore, OperationState, StoreError};
use conduit_privileged_protocol::{
    ApprovalEnforcement, HelperReceipt, LocalExecutionPlan, PROTOCOL, PrivilegeTicket,
    PrivilegedOperation, SignedCapability,
};
use conduit_runtime::{
    InteractiveRuntime, LaunchPlan, PreparedRuntime, RuntimeError, RuntimeHandle, RuntimeProvider,
    RuntimeRequest, RuntimeState, RuntimeStateReceipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

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

/// A privilege ticket and helper capability that have been verified against
/// both signing keys and every Device-local execution commitment. Fields are
/// private so callers cannot bypass `verify` and accidentally remove the
/// ordinary Node's fail-closed `full_device` guard.
#[derive(Debug, Clone)]
pub struct VerifiedPrivilegedAdmission {
    ticket: PrivilegeTicket,
    plan: LocalExecutionPlan,
    capability: SignedCapability,
}

impl VerifiedPrivilegedAdmission {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        offer: &OperationOffer,
        approval_policy: &str,
        expected_device_id: &str,
        expected_origin: &str,
        ticket_verification_key: &[u8; 32],
        receipt_verification_key: &[u8; 32],
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        capability: SignedCapability,
    ) -> Result<Self, NodeError> {
        Self::verify_for_operation(
            offer,
            approval_policy,
            expected_device_id,
            expected_origin,
            ticket_verification_key,
            receipt_verification_key,
            &offer.idempotency_key,
            PrivilegedOperation::Start,
            ticket,
            plan,
            capability,
        )
    }

    /// Verifies one action-specific ticket while keeping the immutable Runtime
    /// and local-plan commitment identical across Prepare, Start, and later
    /// exact-target controls. Each effect still receives a distinct ticket;
    /// this method never widens a ticket to another action.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_operation(
        offer: &OperationOffer,
        approval_policy: &str,
        expected_device_id: &str,
        expected_origin: &str,
        ticket_verification_key: &[u8; 32],
        receipt_verification_key: &[u8; 32],
        expected_ticket_idempotency_key: &str,
        expected_operation: PrivilegedOperation,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        capability: SignedCapability,
    ) -> Result<Self, NodeError> {
        Self::verify_for_authority(
            offer,
            approval_policy,
            expected_device_id,
            expected_origin,
            ticket_verification_key,
            receipt_verification_key,
            expected_ticket_idempotency_key,
            &offer.operation_id,
            &offer.request_digest,
            expected_operation,
            ticket,
            plan,
            capability,
        )
    }

    /// Verifies an action-specific ticket issued for a durable control
    /// operation while retaining the original start operation as the Runtime
    /// and local-plan authority. This prevents a control ticket from being
    /// mistaken for, or replayed as, the start ticket.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_control_for_operation(
        offer: &OperationOffer,
        approval_policy: &str,
        expected_device_id: &str,
        expected_origin: &str,
        ticket_verification_key: &[u8; 32],
        receipt_verification_key: &[u8; 32],
        expected_ticket_idempotency_key: &str,
        control_operation_id: &str,
        control_request_digest: &str,
        expected_operation: PrivilegedOperation,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        capability: SignedCapability,
    ) -> Result<Self, NodeError> {
        if !matches!(
            expected_operation,
            PrivilegedOperation::Input
                | PrivilegedOperation::ResizePty
                | PrivilegedOperation::Pause
                | PrivilegedOperation::Resume
                | PrivilegedOperation::GracefulStop
                | PrivilegedOperation::ForceStop
        ) || control_operation_id == offer.operation_id
            || ticket.claims.control_digest.as_deref() != Some(control_request_digest)
        {
            return Err(NodeError::Rejected("privilege_ticket_invalid".into()));
        }
        Self::verify_for_authority(
            offer,
            approval_policy,
            expected_device_id,
            expected_origin,
            ticket_verification_key,
            receipt_verification_key,
            expected_ticket_idempotency_key,
            control_operation_id,
            control_request_digest,
            expected_operation,
            ticket,
            plan,
            capability,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_for_authority(
        offer: &OperationOffer,
        approval_policy: &str,
        expected_device_id: &str,
        expected_origin: &str,
        ticket_verification_key: &[u8; 32],
        receipt_verification_key: &[u8; 32],
        expected_ticket_idempotency_key: &str,
        expected_ticket_operation_id: &str,
        expected_operation_request_digest: &str,
        expected_operation: PrivilegedOperation,
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
        capability: SignedCapability,
    ) -> Result<Self, NodeError> {
        ticket
            .verify(ticket_verification_key)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        ticket
            .claims
            .validate(&ticket.key_id)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        capability
            .verify(receipt_verification_key)
            .map_err(|_| NodeError::Rejected("privileged_helper_registration_missing".into()))?;
        plan.validate()
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let plan_digest = plan
            .digest()
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let launch_digest = digest_jcs(&offer.launch)?;
        let idempotency_key_digest =
            hex::encode(Sha256::digest(expected_ticket_idempotency_key.as_bytes()));
        let now = OffsetDateTime::now_utc();
        let not_before = OffsetDateTime::parse(&ticket.claims.issued_at, &Rfc3339)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let expires_at = OffsetDateTime::parse(&ticket.claims.expires_at, &Rfc3339)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        if now < not_before {
            return Err(NodeError::Rejected("privilege_ticket_invalid".into()));
        }
        if now >= expires_at {
            return Err(NodeError::Rejected("privilege_ticket_expired".into()));
        }
        let claims = &ticket.claims;
        let helper = &capability.claims;
        if !helper.supports_full_device() {
            return Err(NodeError::Rejected(
                "full_device_capability_unavailable".into(),
            ));
        }
        let exact = claims.protocol == PROTOCOL
            && helper.protocol == PROTOCOL
            && claims.public_origin == expected_origin
            && claims.helper_installation_id == helper.installation_id
            && claims.helper_key_id == helper.receipt_key_id
            && claims.helper_policy_revision == helper.policy_revision
            && claims.helper_policy_digest == helper.policy_digest
            && claims.device_id == expected_device_id
            && claims.expected_uid == unsafe { libc::geteuid() }
            && claims.operation_id == expected_ticket_operation_id
            && claims.idempotency_key_digest == idempotency_key_digest
            && claims.operation_request_digest == expected_operation_request_digest
            && claims.run_id == offer.runtime.run_id
            && claims.runtime_id == offer.runtime.runtime_id
            && claims.runtime_spec_digest == offer.runtime.spec_digest
            && claims.launch_plan_digest == launch_digest
            && claims.local_execution_plan_digest == plan_digest
            && claims.device_policy_revision == offer.local_policy_revision
            && claims.access_scope == "full_device"
            && claims.approval_mode == approval_policy
            && claims.allowed_operation == expected_operation
            && claims.controller_epoch > 0
            && plan.operation_id == offer.operation_id
            && plan.run_id == offer.runtime.run_id
            && plan.runtime_id == offer.runtime.runtime_id
            && plan.helper_protocol == PROTOCOL;
        if !exact {
            return Err(NodeError::Rejected("privilege_ticket_invalid".into()));
        }
        if matches!(
            claims.approval_enforcement,
            ApprovalEnforcement::Unavailable
        ) {
            return Err(NodeError::Rejected(
                "full_device_approval_enforcement_unavailable".into(),
            ));
        }
        if approval_policy == "never" && !helper.never_opt_in {
            return Err(NodeError::Rejected(
                "full_device_never_local_opt_in_required".into(),
            ));
        }
        Ok(Self {
            ticket,
            plan,
            capability,
        })
    }

    pub fn ticket(&self) -> &PrivilegeTicket {
        &self.ticket
    }

    pub fn plan(&self) -> &LocalExecutionPlan {
        &self.plan
    }

    pub fn capability(&self) -> &SignedCapability {
        &self.capability
    }
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
        if access_scope == "full_device" {
            return Err(NodeError::Rejected(
                "full_device_capability_unavailable".into(),
            ));
        }
        self.admit_inner(offer, provider_id, access_scope, approval_policy)
    }

    pub fn admit_privileged_pending(
        &self,
        offer: &OperationOffer,
        provider_id: &str,
        approval_policy: &str,
        capability: &SignedCapability,
        receipt_verification_key: &[u8; 32],
    ) -> Result<AdmissionReceipt, NodeError> {
        capability
            .verify(receipt_verification_key)
            .map_err(|_| NodeError::Rejected("privileged_helper_registration_missing".into()))?;
        let helper = &capability.claims;
        if capability.key_id != helper.receipt_key_id
            || helper.protocol != PROTOCOL
            || !helper.supports_full_device()
        {
            return Err(NodeError::Rejected(
                "full_device_capability_unavailable".into(),
            ));
        }
        if provider_id != "privileged-native"
            || offer.runtime.kind != conduit_runtime::RuntimeKind::Native
        {
            return Err(NodeError::Rejected("runtime_provider_unavailable".into()));
        }
        self.admit_inner(offer, provider_id, "full_device", approval_policy)
    }

    pub fn bind_privileged_authority(
        &self,
        offer: &OperationOffer,
        authority: &VerifiedPrivilegedAdmission,
    ) -> Result<(), NodeError> {
        let ticket = authority.ticket();
        let capability = authority.capability();
        let signed_ticket =
            serde_jcs::to_vec(ticket).map_err(|error| NodeError::Rejected(error.to_string()))?;
        let local_plan = serde_jcs::to_vec(authority.plan())
            .map_err(|error| NodeError::Rejected(error.to_string()))?;
        let ticket_digest = ticket
            .digest()
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        self.store.bind_privileged_operation(
            &offer.idempotency_key,
            &ticket.claims.helper_installation_id,
            ticket.claims.helper_policy_revision,
            &ticket.claims.helper_policy_digest,
            &capability.claims.receipt_key_id,
            &ticket.claims.ticket_id,
            &ticket_digest,
            &signed_ticket,
            &ticket.claims.runtime_spec_digest,
            &ticket.claims.launch_plan_digest,
            &ticket.claims.local_execution_plan_digest,
            &local_plan,
            ticket.claims.controller_epoch,
        )?;
        Ok(())
    }

    pub fn verify_and_record_privileged_receipt(
        &self,
        offer: &OperationOffer,
        receipt: &HelperReceipt,
        receipt_verification_key: &[u8; 32],
        ticket_verification_key: &[u8; 32],
    ) -> Result<String, NodeError> {
        receipt
            .verify(receipt_verification_key)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let binding = self
            .store
            .privileged_binding(&offer.idempotency_key)?
            .ok_or_else(|| NodeError::Rejected("privilege_ticket_required".into()))?;
        let claims = &receipt.claims;
        let ticket_record = self
            .store
            .privilege_ticket_for_operation(&offer.idempotency_key, &claims.ticket_id)?
            .ok_or_else(|| NodeError::Rejected("privilege_ticket_required".into()))?;
        let signed_ticket = ticket_record
            .signed_ticket
            .as_deref()
            .ok_or_else(|| NodeError::Rejected("privilege_ticket_required".into()))?;
        let ticket: PrivilegeTicket = serde_json::from_slice(signed_ticket)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        ticket
            .verify(ticket_verification_key)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        ticket
            .claims
            .validate(&ticket.key_id)
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let ticket_digest = ticket
            .digest()
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let ticket_operation_allows_transition = match ticket.claims.allowed_operation {
            PrivilegedOperation::Prepare => {
                matches!(claims.transition.as_str(), "admitted" | "prepared")
            }
            PrivilegedOperation::Start => matches!(
                claims.transition.as_str(),
                "unit_created"
                    | "running"
                    | "completed"
                    | "failed"
                    | "timed_out"
                    | "uncertain"
                    | "recovery_required"
            ),
            PrivilegedOperation::Input => claims.transition == "input_applied",
            PrivilegedOperation::ResizePty => claims.transition == "pty_resized",
            PrivilegedOperation::Pause => claims.transition == "paused",
            PrivilegedOperation::Resume => {
                matches!(claims.transition.as_str(), "resumed" | "running")
            }
            PrivilegedOperation::GracefulStop | PrivilegedOperation::ForceStop => matches!(
                claims.transition.as_str(),
                "stopping" | "completed" | "failed" | "cancelled" | "timed_out"
            ),
            PrivilegedOperation::Inspect | PrivilegedOperation::Reconcile => matches!(
                claims.transition.as_str(),
                "running"
                    | "paused"
                    | "completed"
                    | "failed"
                    | "cancelled"
                    | "timed_out"
                    | "uncertain"
                    | "recovery_required"
            ),
        };
        let is_control_ticket = matches!(
            ticket.claims.allowed_operation,
            PrivilegedOperation::Input
                | PrivilegedOperation::ResizePty
                | PrivilegedOperation::Pause
                | PrivilegedOperation::Resume
                | PrivilegedOperation::GracefulStop
                | PrivilegedOperation::ForceStop
        );
        let operation_binding_matches = claims.operation_id == ticket.claims.operation_id
            && claims.request_digest == ticket.claims.operation_request_digest
            && if is_control_ticket {
                ticket.claims.control_digest.is_some()
            } else {
                ticket.claims.operation_id == offer.operation_id
                    && ticket.claims.operation_request_digest == offer.request_digest
            };
        let exact = receipt.key_id == binding.helper_key_id
            && claims.protocol == PROTOCOL
            && claims.installation_id == binding.installation_id
            && claims.receipt_key_id == binding.helper_key_id
            && claims.policy_revision == binding.policy_revision
            && claims.policy_digest == binding.policy_digest
            && claims.ticket_id == ticket.claims.ticket_id
            && claims.ticket_digest == ticket_digest
            && ticket_record.ticket_digest.as_deref() == Some(ticket_digest.as_str())
            && operation_binding_matches
            && claims.run_id == offer.runtime.run_id
            && claims.runtime_id == offer.runtime.runtime_id
            && claims.runtime_spec_digest == binding.runtime_spec_digest
            && claims.launch_plan_digest == binding.launch_plan_digest
            && claims.local_execution_plan_digest == binding.local_plan_digest
            && claims.controller_epoch == ticket.claims.controller_epoch
            && claims.control_request_digest == ticket.claims.control_digest
            && ticket_operation_allows_transition
            && claims.unit_name.starts_with("conduit-elevated-")
            && claims.unit_name.ends_with(".service");
        if !exact
            || (matches!(claims.transition.as_str(), "running" | "resumed")
                && (claims.effective_uid != Some(0) || claims.effective_gid != Some(0)))
        {
            return Err(NodeError::Rejected("privilege_ticket_invalid".into()));
        }
        let receipt_digest = receipt
            .digest()
            .map_err(|_| NodeError::Rejected("privilege_ticket_invalid".into()))?;
        let encoded =
            serde_jcs::to_vec(receipt).map_err(|error| NodeError::Rejected(error.to_string()))?;
        self.store.append_privileged_receipt(
            &offer.idempotency_key,
            &receipt_digest,
            &claims.ticket_id,
            &ticket_digest,
            &claims.runtime_id,
            claims.state_revision,
            &claims.transition,
            claims.previous_receipt_digest.as_deref(),
            &encoded,
        )?;
        Ok(receipt_digest)
    }

    fn admit_inner(
        &self,
        offer: &OperationOffer,
        provider_id: &str,
        access_scope: &str,
        approval_policy: &str,
    ) -> Result<AdmissionReceipt, NodeError> {
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

    /// Starts a structured adapter through the selected Runtime Provider while
    /// retaining stdin/stdout custody for the protocol layer. Admission,
    /// Runtime reservation and journal transitions are identical to `start`;
    /// the provider, not the adapter, constructs the isolation command.
    pub fn start_interactive(&self, key: &str) -> Result<InteractiveRuntime, NodeError> {
        let admission = self
            .store
            .admission(key)?
            .ok_or_else(|| NodeError::Rejected("operation_not_admitted".into()))?;
        let provider = self
            .providers
            .get(&admission.provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?;
        if admission.operation.state != OperationState::Admitted {
            return Err(NodeError::Rejected("operation_not_startable".into()));
        }
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
        let prepared = match provider.prepare(&runtime) {
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
        match provider.start_interactive(&prepared, &launch) {
            Ok(interactive) => {
                self.store.transition_operation(
                    key,
                    OperationState::Starting,
                    OperationState::Running,
                    Some(&prepared.runtime_id),
                    interactive.receipt.handle.process_identity.as_deref(),
                    None,
                )?;
                Ok(interactive)
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

    pub fn restore_runtime_snapshot(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        name: &str,
    ) -> Result<RuntimeStateReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .restore_snapshot(handle, name)
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

    pub fn archive_runtime(
        &self,
        provider_id: &str,
        handle: &RuntimeHandle,
        target: &std::path::Path,
    ) -> Result<conduit_runtime::SnapshotReceipt, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .archive(handle, target)
            .map_err(|error| NodeError::Runtime(error.to_string()))
    }

    pub fn restore_runtime(
        &self,
        provider_id: &str,
        archive: &std::path::Path,
        request: &RuntimeRequest,
    ) -> Result<conduit_runtime::PreparedRuntime, NodeError> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?
            .restore(archive, request)
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
                "privileged-native" => {
                    let receipt = self
                        .store
                        .privileged_receipts(&admission.operation.idempotency_key)?
                        .into_iter()
                        .last()
                        .ok_or_else(|| {
                            NodeError::Rejected("privileged_runtime_recovery_required".into())
                        })?;
                    let signed: HelperReceipt = serde_json::from_slice(&receipt.signed_receipt)
                        .map_err(|_| {
                            NodeError::Rejected("privileged_runtime_recovery_required".into())
                        })?;
                    if signed.claims.runtime_id != request.runtime_id
                        || signed.claims.unit_name.is_empty()
                    {
                        return Err(NodeError::Rejected(
                            "privileged_runtime_recovery_required".into(),
                        ));
                    }
                    signed.claims.unit_name
                }
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
            if admission.provider_id == "privileged-native" {
                // The ordinary provider registry cannot inspect root-owned
                // systemd custody.  NodeService reconciles these admissions
                // only after the helper is authenticated and the Control
                // Plane has re-established the pinned ticket issuer keys.
                // Inventing an unsigned recovery receipt here would destroy
                // the evidence chain and make a healthy invocation
                // impossible to attach after restart.
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
            if is_agent {
                let provider = self
                    .providers
                    .get(&admission.provider_id)
                    .ok_or_else(|| NodeError::Rejected("runtime_provider_unavailable".into()))?;
                let (fence_confirmed, reason) =
                    fence_agent_after_restart(provider.as_ref(), &handle);
                let terminal = if operation.state == OperationState::Running {
                    OperationState::RecoveryRequired
                } else {
                    OperationState::Uncertain
                };
                let mut evidence = serde_json::json!({
                    "operationId": operation.operation_id,
                    "runId": request.run_id,
                    "state": if terminal == OperationState::RecoveryRequired {
                        "recovery_required"
                    } else {
                        "uncertain"
                    },
                    "requestDigest": operation.request_digest,
                    "lastRunEventSequence": operation.last_event_sequence.to_string(),
                    "reasonCode": reason,
                    "resultSummary": {
                        "adapterSession": "unrecoverable",
                        "automaticReplay": false,
                        "fenceConfirmed": fence_confirmed
                    },
                    "observedAt": time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .map_err(|error| NodeError::Rejected(error.to_string()))?
                });
                let receipt_digest = value_commitment(&evidence)?;
                evidence["receiptDigest"] = serde_json::Value::String(receipt_digest);
                let evidence = serde_jcs::to_vec(&evidence)
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

fn fence_agent_after_restart(
    provider: &dyn RuntimeProvider,
    handle: &RuntimeHandle,
) -> (bool, &'static str) {
    let observed = match provider.inspect(handle) {
        Ok(receipt) => receipt,
        Err(RuntimeError::NotFound) => return (true, "adapter_process_restart_not_live"),
        Err(RuntimeError::IdentityMismatch | RuntimeError::Uncertain(_)) => {
            return (false, "adapter_process_identity_ambiguous");
        }
        Err(_) => return (false, "adapter_process_inspection_failed"),
    };
    if matches!(
        observed.state,
        RuntimeState::Stopped | RuntimeState::Failed | RuntimeState::Lost
    ) {
        return (true, "adapter_process_restart_not_live");
    }
    if provider
        .signal(&observed.handle, conduit_runtime::RuntimeSignal::ForceStop)
        .is_err()
    {
        return (false, "adapter_process_fence_signal_failed");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match provider.inspect(&observed.handle) {
            Ok(receipt)
                if matches!(
                    receipt.state,
                    RuntimeState::Stopped | RuntimeState::Failed | RuntimeState::Lost
                ) =>
            {
                return (true, "adapter_process_fenced_after_node_restart");
            }
            Err(RuntimeError::NotFound) => {
                return (true, "adapter_process_fenced_after_node_restart");
            }
            Err(RuntimeError::IdentityMismatch | RuntimeError::Uncertain(_)) => {
                return (false, "adapter_process_identity_ambiguous");
            }
            Err(_) => return (false, "adapter_process_fence_inspection_failed"),
            Ok(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(_) => return (false, "adapter_process_fence_unconfirmed"),
        }
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

fn digest_jcs(value: &impl Serialize) -> Result<String, NodeError> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|error| NodeError::Rejected(error.to_string()))?,
    )))
}

fn value_commitment(value: &serde_json::Value) -> Result<String, NodeError> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(value).map_err(|error| NodeError::Rejected(error.to_string()))?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_privileged_protocol::{
        CapabilityClaims, FileIdentity, PrivilegeTicketClaims, ResourceCeilings, SignedClaims,
        StdioMode,
    };
    use conduit_runtime::{
        IoMode, NativeProvider, NetworkMode, ProcessSupervisor, ResourceLimits, RuntimeKind,
        RuntimeSignal,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
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

    fn agent_offer(cwd: &std::path::Path) -> OperationOffer {
        let mut request = offer(cwd);
        let mut manifest = json!({
            "operationId": request.operation_id,
            "capability": "agent.run.start",
            "runId": request.runtime.run_id,
            "arguments": {
                "adapterId": "codex",
                "nativeSessionId": "thread-restart-01"
            },
            "payloadDigest": ""
        });
        let mut commitment = manifest.clone();
        commitment.as_object_mut().unwrap().remove("payloadDigest");
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&commitment).unwrap()));
        manifest["payloadDigest"] = serde_json::Value::String(digest.clone());
        request.request_digest = digest;
        request.manifest = serde_jcs::to_vec(&manifest).unwrap();
        request
    }

    fn privileged_authority(
        request: &OperationOffer,
    ) -> (
        SigningKey,
        SigningKey,
        PrivilegeTicket,
        LocalExecutionPlan,
        SignedCapability,
    ) {
        let ticket_key = SigningKey::from_bytes(&[7; 32]);
        let receipt_key = SigningKey::from_bytes(&[9; 32]);
        let resources = ResourceCeilings {
            cpu_quota_per_sec_usec: None,
            memory_max_bytes: None,
            tasks_max: None,
            io_weight: None,
            runtime_max_usec: None,
        };
        let file = |path: &str| FileIdentity {
            opaque_path_id: path.into(),
            device: 1,
            inode: 1,
            mode: 0o100755,
            uid: unsafe { libc::geteuid() },
            size: 1,
            sha256: "11".repeat(32),
        };
        let plan = LocalExecutionPlan {
            plan_version: 1,
            runtime_id: request.runtime.runtime_id.clone(),
            run_id: request.runtime.run_id.clone(),
            operation_id: request.operation_id.clone(),
            executable: file("opaque-executable"),
            interpreter: None,
            argv: vec!["probe".into()],
            cwd: file("opaque-cwd"),
            systemd_unit: format!("conduit-elevated-{}.service", request.runtime.runtime_id),
            adapter_id: None,
            launch_profile_id: Some("test-profile".into()),
            environment: BTreeMap::new(),
            environment_value_digests: BTreeMap::new(),
            workspaces: vec![],
            credentials: vec![],
            stdio: StdioMode::Pipes,
            resources: resources.clone(),
            helper_protocol: PROTOCOL.into(),
            helper_min_version: "0.1.0".into(),
        };
        let observed = OffsetDateTime::now_utc();
        let capability = SignedClaims::sign(
            "hkey_test0001",
            CapabilityClaims {
                protocol: PROTOCOL.into(),
                helper_version: "0.1.0".into(),
                installation_id: "phinst_test0001".into(),
                receipt_key_id: "hkey_test0001".into(),
                policy_revision: 3,
                policy_digest: "22".repeat(32),
                enabled: true,
                observed_at: observed.format(&Rfc3339).unwrap(),
                systemd_system_manager: true,
                socket_peer_credentials: true,
                transient_units: true,
                cgroup_v2: true,
                freeze: true,
                pidfd: true,
                openat2: true,
                execveat: true,
                pty: true,
                stream_replay: true,
                never_opt_in: true,
                unrestricted_launch_opt_in: true,
                unavailable_reason: None,
            },
            &receipt_key,
        )
        .unwrap();
        let ticket = SignedClaims::sign(
            "pkey_test0001",
            PrivilegeTicketClaims {
                schema_version: 1,
                protocol: PROTOCOL.into(),
                ticket_id: "ptkt_test0001".into(),
                issuer_kind: "control_plane".into(),
                issuer_key_id: "pkey_test0001".into(),
                audience: "conduit-privileged-helper".into(),
                public_origin: "https://control.invalid".into(),
                helper_installation_id: "phinst_test0001".into(),
                helper_key_id: "hkey_test0001".into(),
                helper_policy_revision: 3,
                helper_policy_digest: "22".repeat(32),
                device_id: "dev_test0001".into(),
                device_key_id: "dkey_test0001".into(),
                device_policy_revision: request.local_policy_revision,
                device_revision: 1,
                expected_uid: unsafe { libc::geteuid() },
                operation_id: request.operation_id.clone(),
                idempotency_key_digest: hex::encode(Sha256::digest(
                    request.idempotency_key.as_bytes(),
                )),
                operation_request_digest: request.request_digest.clone(),
                run_manifest_digest: "99".repeat(32),
                run_id: request.runtime.run_id.clone(),
                runtime_id: request.runtime.runtime_id.clone(),
                runtime_spec_digest: request.runtime.spec_digest.clone(),
                launch_plan_digest: digest_jcs(&request.launch).unwrap(),
                control_digest: None,
                local_execution_plan_digest: plan.digest().unwrap(),
                controller_epoch: 4,
                connector_policy_id: Some("cpol_test0001".into()),
                connector_policy_revision: 2,
                project_id: None,
                project_revision: None,
                assignment_id: None,
                project_agent_id: None,
                project_agent_revision: None,
                runtime_configuration_revision: 1,
                access_scope: "full_device".into(),
                approval_mode: "never".into(),
                approval_receipt_digest: None,
                approval_enforcement: ApprovalEnforcement::ExactCommand,
                required_approval_risk_classes: vec![],
                allowed_operation: PrivilegedOperation::Start,
                resource_ceilings: resources,
                issued_at: (observed - time::Duration::seconds(1))
                    .format(&Rfc3339)
                    .unwrap(),
                expires_at: (observed + time::Duration::minutes(1))
                    .format(&Rfc3339)
                    .unwrap(),
                nonce: "ticket-nonce-test0001".into(),
                max_use_count: 1,
            },
            &ticket_key,
        )
        .unwrap();
        (ticket_key, receipt_key, ticket, plan, capability)
    }

    #[test]
    fn privileged_authority_is_exact_and_signature_bound() {
        let directory = tempdir().unwrap();
        let request = offer(directory.path());
        let (ticket_key, receipt_key, ticket, plan, capability) = privileged_authority(&request);
        VerifiedPrivilegedAdmission::verify(
            &request,
            "never",
            "dev_test0001",
            "https://control.invalid",
            ticket_key.verifying_key().as_bytes(),
            receipt_key.verifying_key().as_bytes(),
            ticket.clone(),
            plan.clone(),
            capability.clone(),
        )
        .unwrap();

        let mut changed = ticket;
        changed.claims.runtime_id = "rt_other0001".into();
        assert!(matches!(
            VerifiedPrivilegedAdmission::verify(
                &request,
                "never",
                "dev_test0001",
                "https://control.invalid",
                ticket_key.verifying_key().as_bytes(),
                receipt_key.verifying_key().as_bytes(),
                changed,
                plan,
                capability,
            ),
            Err(NodeError::Rejected(reason)) if reason == "privilege_ticket_invalid"
        ));
    }

    #[test]
    fn privileged_admission_fails_closed_for_each_missing_host_capability() {
        let directory = tempdir().unwrap();
        let request = offer(directory.path());
        let (ticket_key, receipt_key, ticket, plan, capability) = privileged_authority(&request);
        let mutations: [fn(&mut CapabilityClaims); 11] = [
            |claims| claims.enabled = false,
            |claims| claims.systemd_system_manager = false,
            |claims| claims.socket_peer_credentials = false,
            |claims| claims.transient_units = false,
            |claims| claims.cgroup_v2 = false,
            |claims| claims.freeze = false,
            |claims| claims.pidfd = false,
            |claims| claims.openat2 = false,
            |claims| claims.execveat = false,
            |claims| claims.pty = false,
            |claims| claims.stream_replay = false,
        ];
        for mutate in mutations {
            let mut claims = capability.claims.clone();
            mutate(&mut claims);
            claims.unavailable_reason = claims.full_device_unavailable_reason().map(str::to_owned);
            let unavailable =
                SignedClaims::sign(capability.key_id.clone(), claims, &receipt_key).unwrap();
            assert!(matches!(
                VerifiedPrivilegedAdmission::verify(
                    &request,
                    "never",
                    "dev_test0001",
                    "https://control.invalid",
                    ticket_key.verifying_key().as_bytes(),
                    receipt_key.verifying_key().as_bytes(),
                    ticket.clone(),
                    plan.clone(),
                    unavailable.clone(),
                ),
                Err(NodeError::Rejected(reason)) if reason == "full_device_capability_unavailable"
            ));
            let node = Node::new(NodeStore::open(directory.path().join("node")).unwrap());
            assert!(matches!(
                node.admit_privileged_pending(
                    &request,
                    "privileged-native",
                    "never",
                    &unavailable,
                    receipt_key.verifying_key().as_bytes(),
                ),
                Err(NodeError::Rejected(reason)) if reason == "full_device_capability_unavailable"
            ));
        }

        let mut degraded = capability.claims;
        degraded.unavailable_reason = Some("local_storage_degraded".into());
        let degraded = SignedClaims::sign(capability.key_id, degraded, &receipt_key).unwrap();
        assert!(matches!(
            VerifiedPrivilegedAdmission::verify(
                &request,
                "never",
                "dev_test0001",
                "https://control.invalid",
                ticket_key.verifying_key().as_bytes(),
                receipt_key.verifying_key().as_bytes(),
                ticket,
                plan,
                degraded,
            ),
            Err(NodeError::Rejected(reason)) if reason == "full_device_capability_unavailable"
        ));
    }

    #[test]
    fn privileged_authority_never_widens_an_action_ticket() {
        let directory = tempdir().unwrap();
        let request = offer(directory.path());
        let (ticket_key, receipt_key, ticket, plan, capability) = privileged_authority(&request);
        assert!(matches!(
            VerifiedPrivilegedAdmission::verify_for_operation(
                &request,
                "never",
                "dev_test0001",
                "https://control.invalid",
                ticket_key.verifying_key().as_bytes(),
                receipt_key.verifying_key().as_bytes(),
                &request.idempotency_key,
                PrivilegedOperation::Prepare,
                ticket.clone(),
                plan.clone(),
                capability.clone(),
            ),
            Err(NodeError::Rejected(reason)) if reason == "privilege_ticket_invalid"
        ));

        let prepare = SignedClaims::sign(
            ticket.key_id,
            PrivilegeTicketClaims {
                allowed_operation: PrivilegedOperation::Prepare,
                ticket_id: "ptkt_prepare0001".into(),
                nonce: "ticket-nonce-prepare0001".into(),
                ..ticket.claims
            },
            &ticket_key,
        )
        .unwrap();
        VerifiedPrivilegedAdmission::verify_for_operation(
            &request,
            "never",
            "dev_test0001",
            "https://control.invalid",
            ticket_key.verifying_key().as_bytes(),
            receipt_key.verifying_key().as_bytes(),
            &request.idempotency_key,
            PrivilegedOperation::Prepare,
            prepare,
            plan,
            capability,
        )
        .unwrap();
    }

    #[test]
    fn privileged_control_authority_uses_distinct_operation_and_digest() {
        let directory = tempdir().unwrap();
        let request = offer(directory.path());
        let (ticket_key, receipt_key, ticket, plan, capability) = privileged_authority(&request);
        let control_operation_id = "op_controlticket0001";
        let control_idempotency_key = "idem-control-ticket-0001";
        let control_digest = "ab".repeat(32);
        let control = SignedClaims::sign(
            ticket.key_id,
            PrivilegeTicketClaims {
                ticket_id: "ptkt_control0001".into(),
                operation_id: control_operation_id.into(),
                idempotency_key_digest: hex::encode(Sha256::digest(
                    control_idempotency_key.as_bytes(),
                )),
                operation_request_digest: control_digest.clone(),
                control_digest: Some(control_digest.clone()),
                allowed_operation: PrivilegedOperation::Input,
                nonce: "ticket-nonce-control0001".into(),
                ..ticket.claims
            },
            &ticket_key,
        )
        .unwrap();
        VerifiedPrivilegedAdmission::verify_control_for_operation(
            &request,
            "never",
            "dev_test0001",
            "https://control.invalid",
            ticket_key.verifying_key().as_bytes(),
            receipt_key.verifying_key().as_bytes(),
            control_idempotency_key,
            control_operation_id,
            &control_digest,
            PrivilegedOperation::Input,
            control.clone(),
            plan.clone(),
            capability.clone(),
        )
        .unwrap();
        assert!(matches!(
            VerifiedPrivilegedAdmission::verify_control_for_operation(
                &request,
                "never",
                "dev_test0001",
                "https://control.invalid",
                ticket_key.verifying_key().as_bytes(),
                receipt_key.verifying_key().as_bytes(),
                control_idempotency_key,
                "op_othercontrol0001",
                &control_digest,
                PrivilegedOperation::Input,
                control,
                plan,
                capability,
            ),
            Err(NodeError::Rejected(reason)) if reason == "privilege_ticket_invalid"
        ));
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

    #[test]
    fn generic_restart_defers_privileged_custody_without_unsigned_state_change() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let request = offer(directory.path());
        let runtime = serde_jcs::to_vec(&request.runtime).unwrap();
        let launch = serde_jcs::to_vec(&request.launch).unwrap();
        store
            .admit_operation(
                &request.operation_id,
                &request.idempotency_key,
                &request.request_digest,
                &request.manifest,
                request.local_policy_revision,
                "privileged-native",
                "full_device",
                "always",
                &runtime,
                &launch,
                br#"{"receipt":"admitted"}"#,
            )
            .unwrap();
        store
            .transition_operation(
                &request.idempotency_key,
                OperationState::Admitted,
                OperationState::Starting,
                Some(&request.runtime.runtime_id),
                None,
                None,
            )
            .unwrap();
        store
            .transition_operation(
                &request.idempotency_key,
                OperationState::Starting,
                OperationState::Running,
                Some(&request.runtime.runtime_id),
                Some("root-owned-systemd-invocation"),
                None,
            )
            .unwrap();

        let restarted = Node::new(store.clone());
        assert!(restarted.recover_nonterminal().unwrap().is_empty());
        let unchanged = store.operation(&request.idempotency_key).unwrap().unwrap();
        assert_eq!(unchanged.state, OperationState::Running);
        assert_eq!(
            unchanged.process_identity.as_deref(),
            Some("root-owned-systemd-invocation")
        );
        assert!(unchanged.receipt.is_none());
    }

    #[test]
    fn restart_with_running_agent_fences_process_and_persists_recovery_required_receipt() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path().join("store")).unwrap();
        let supervisor = ProcessSupervisor::open(directory.path().join("supervisor")).unwrap();
        let provider: Arc<dyn RuntimeProvider> = Arc::new(NativeProvider::new(supervisor));
        let request = agent_offer(directory.path());
        let mut first = Node::new(store.clone());
        first.register_provider(provider.clone());
        first
            .admit(&request, "native", "project_full", "never")
            .unwrap();
        let started = first.start(&request.idempotency_key).unwrap();
        assert_eq!(started.state, RuntimeState::Running);
        drop(first);

        let mut restarted = Node::new(store.clone());
        restarted.register_provider(provider.clone());
        assert!(restarted.recover_nonterminal().unwrap().is_empty());

        let recovered = store.operation(&request.idempotency_key).unwrap().unwrap();
        assert_eq!(recovered.state, OperationState::RecoveryRequired);
        let receipt: serde_json::Value =
            serde_json::from_slice(recovered.receipt.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["operationId"], request.operation_id);
        assert_eq!(receipt["runId"], request.runtime.run_id);
        assert_eq!(receipt["requestDigest"], request.request_digest);
        assert_eq!(receipt["state"], "recovery_required");
        assert_eq!(receipt["lastRunEventSequence"], "0");
        assert_eq!(receipt["resultSummary"]["automaticReplay"], false);
        assert_eq!(receipt["resultSummary"]["fenceConfirmed"], true);
        let digest = receipt["receiptDigest"].as_str().unwrap().to_owned();
        let mut committed = receipt;
        committed.as_object_mut().unwrap().remove("receiptDigest");
        assert_eq!(value_commitment(&committed).unwrap(), digest);
        let stopped = provider.inspect(&started.handle).unwrap();
        assert_eq!(stopped.state, RuntimeState::Stopped);
    }
}
