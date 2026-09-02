//! Node-side custody for the optional Linux Full Device helper.
//!
//! Constructing this value proves only local helper authenticity. `active()`
//! remains false until the Control Plane returns an exact Owner-approved
//! registration and issuer key set. This keeps provider discovery from
//! accidentally widening admission.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_node_store::DeviceIdentity;
use conduit_privileged_helper::HelperClient;
use conduit_privileged_protocol::{PrivilegeTicket, PrivilegedOperation, SignedCapability};
use conduit_runtime::{PrivilegedNativeProvider, PrivilegedTicketSource, RuntimeError};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::Path,
    sync::{Arc, Mutex, RwLock},
};

#[derive(Debug, thiserror::Error)]
pub enum PrivilegedNodeError {
    #[error("privileged_helper_registration_missing")]
    RegistrationMissing,
    #[error("privileged_helper_policy_mismatch")]
    PolicyMismatch,
    #[error("privileged_helper_protocol_unsupported")]
    ProtocolUnsupported,
    #[error("privilege_ticket_invalid")]
    TicketInvalid,
    #[error("privileged helper failed: {0}")]
    Helper(String),
    #[error("privileged configuration invalid: {0}")]
    Config(String),
}

#[derive(Default)]
pub struct TicketQueue {
    tickets: Mutex<BTreeMap<(String, PrivilegedOperation), VecDeque<PrivilegeTicket>>>,
}

impl TicketQueue {
    pub fn insert(&self, ticket: PrivilegeTicket) -> Result<(), PrivilegedNodeError> {
        if ticket.claims.max_use_count != 1 {
            return Err(PrivilegedNodeError::TicketInvalid);
        }
        let key = (
            ticket.claims.runtime_id.clone(),
            ticket.claims.allowed_operation.clone(),
        );
        self.tickets
            .lock()
            .map_err(|_| PrivilegedNodeError::TicketInvalid)?
            .entry(key)
            .or_default()
            .push_back(ticket);
        Ok(())
    }
}

impl PrivilegedTicketSource for TicketQueue {
    fn ticket(
        &self,
        runtime_id: &str,
        operation: PrivilegedOperation,
    ) -> Result<PrivilegeTicket, RuntimeError> {
        self.tickets
            .lock()
            .map_err(|_| RuntimeError::Record("privileged ticket queue poisoned".into()))?
            .get_mut(&(runtime_id.to_owned(), operation))
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| {
                RuntimeError::CapabilityUnavailable("fresh exact privilege ticket".into())
            })
    }
}

#[derive(Default)]
struct RegistrationState {
    active: bool,
    issuer_keys: BTreeMap<String, [u8; 32]>,
    owner_decision_digest: Option<String>,
}

pub struct PrivilegedNodeRuntime {
    bundle: Value,
    capability: SignedCapability,
    receipt_key: VerifyingKey,
    provider: Arc<PrivilegedNativeProvider>,
    ticket_queue: Arc<TicketQueue>,
    registration: RwLock<RegistrationState>,
}

impl PrivilegedNodeRuntime {
    pub fn connect(
        socket: &Path,
        bundle_path: &Path,
        device_id: &str,
        node_boot_id: &str,
        identity: &DeviceIdentity,
    ) -> Result<Arc<Self>, PrivilegedNodeError> {
        let bytes = fs::read(bundle_path)
            .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(PrivilegedNodeError::Config(
                "registration bundle bound".into(),
            ));
        }
        let bundle: Value = serde_json::from_slice(&bytes)
            .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?;
        let object = bundle
            .as_object()
            .ok_or_else(|| PrivilegedNodeError::Config("registration bundle object".into()))?;
        if object.get("protocol").and_then(Value::as_str)
            != Some(conduit_privileged_protocol::PROTOCOL)
        {
            return Err(PrivilegedNodeError::RegistrationMissing);
        }
        let bundle_device = string(object.get("deviceId"), "deviceId")?;
        let installation_id = string(object.get("installationId"), "installationId")?;
        let expected_uid = object
            .get("expectedUid")
            .or_else(|| object.get("uid"))
            .and_then(Value::as_u64)
            .ok_or_else(|| PrivilegedNodeError::Config("expectedUid".into()))?;
        if bundle_device != device_id
            || expected_uid != unsafe { libc::geteuid() } as u64
            || object.get("deviceKeyId").and_then(Value::as_str) != Some(identity.key_id())
        {
            return Err(PrivilegedNodeError::RegistrationMissing);
        }
        let jwk = object
            .get("receiptPublicJwk")
            .and_then(Value::as_object)
            .ok_or_else(|| PrivilegedNodeError::Config("receiptPublicJwk".into()))?;
        if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
            || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        {
            return Err(PrivilegedNodeError::Config("receipt JWK".into()));
        }
        let raw: [u8; 32] = URL_SAFE_NO_PAD
            .decode(string(jwk.get("x"), "receiptPublicJwk.x")?)
            .map_err(|_| PrivilegedNodeError::Config("receipt JWK encoding".into()))?
            .try_into()
            .map_err(|_| PrivilegedNodeError::Config("receipt JWK length".into()))?;
        let receipt_key = VerifyingKey::from_bytes(&raw)
            .map_err(|_| PrivilegedNodeError::Config("receipt JWK key".into()))?;
        let capability: SignedCapability = serde_json::from_value(
            object
                .get("signedCapability")
                .cloned()
                .ok_or_else(|| PrivilegedNodeError::Config("signedCapability".into()))?,
        )
        .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?;
        capability
            .verify(receipt_key.as_bytes())
            .map_err(|_| PrivilegedNodeError::RegistrationMissing)?;
        if jwk.get("kid").and_then(Value::as_str) != Some(capability.key_id.as_str()) {
            return Err(PrivilegedNodeError::RegistrationMissing);
        }
        let policy: conduit_privileged_protocol::SignedClaims<
            conduit_privileged_protocol::RootPolicy,
        > = serde_json::from_value(
            object
                .get("signedPolicyAttestation")
                .cloned()
                .ok_or_else(|| PrivilegedNodeError::Config("signedPolicyAttestation".into()))?,
        )
        .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?;
        policy
            .verify(receipt_key.as_bytes())
            .map_err(|_| PrivilegedNodeError::RegistrationMissing)?;
        let policy_digest = policy
            .claims
            .digest()
            .map_err(|_| PrivilegedNodeError::PolicyMismatch)?;
        if capability.claims.installation_id != installation_id
            || capability.claims.receipt_key_id != capability.key_id
            || policy.key_id != capability.key_id
            || policy.claims.installation_id != installation_id
            || policy.claims.device_id != device_id
            || policy.claims.uid as u64 != expected_uid
            || policy.claims.origin
                != object
                    .get("origin")
                    .and_then(Value::as_str)
                    .ok_or(PrivilegedNodeError::PolicyMismatch)?
            || capability.claims.policy_revision
                != object
                    .get("policyRevision")
                    .and_then(Value::as_u64)
                    .ok_or(PrivilegedNodeError::PolicyMismatch)?
            || capability.claims.policy_digest
                != string(object.get("policyDigest"), "policyDigest")?
            || policy.claims.revision != capability.claims.policy_revision
            || policy_digest != capability.claims.policy_digest
        {
            return Err(PrivilegedNodeError::PolicyMismatch);
        }
        let client = HelperClient::connect_and_authenticate_with(
            socket,
            device_id,
            node_boot_id,
            |challenge| Ok(identity.sign_bytes(challenge)),
        )
        .map_err(|error| PrivilegedNodeError::Helper(error.to_string()))?;
        if client.installation_id() != installation_id
            || client.policy_revision() != capability.claims.policy_revision
        {
            return Err(PrivilegedNodeError::PolicyMismatch);
        }
        let observed = client
            .probe()
            .map_err(|error| PrivilegedNodeError::Helper(error.to_string()))?;
        observed
            .verify(receipt_key.as_bytes())
            .map_err(|_| PrivilegedNodeError::RegistrationMissing)?;
        if observed.claims.installation_id != capability.claims.installation_id
            || observed.claims.receipt_key_id != capability.claims.receipt_key_id
            || observed.claims.policy_revision != capability.claims.policy_revision
            || observed.claims.policy_digest != capability.claims.policy_digest
            || observed.claims.enabled != capability.claims.enabled
        {
            return Err(PrivilegedNodeError::PolicyMismatch);
        }
        let ticket_queue = Arc::new(TicketQueue::default());
        let provider = Arc::new(
            PrivilegedNativeProvider::new(client, receipt_key)
                .with_ticket_source(ticket_queue.clone()),
        );
        Ok(Arc::new(Self {
            bundle,
            capability: observed,
            receipt_key,
            provider,
            ticket_queue,
            registration: RwLock::new(RegistrationState::default()),
        }))
    }

    pub fn provider(&self) -> Arc<PrivilegedNativeProvider> {
        self.provider.clone()
    }

    pub fn capability(&self) -> &SignedCapability {
        &self.capability
    }

    pub fn receipt_key(&self) -> &[u8; 32] {
        self.receipt_key.as_bytes()
    }

    pub fn active(&self) -> bool {
        self.registration.read().is_ok_and(|state| state.active)
    }

    pub fn issuer_key(&self, key_id: &str) -> Option<[u8; 32]> {
        self.registration
            .read()
            .ok()
            .and_then(|state| state.issuer_keys.get(key_id).copied())
    }

    pub fn queue_ticket(&self, ticket: PrivilegeTicket) -> Result<(), PrivilegedNodeError> {
        self.ticket_queue.insert(ticket)
    }

    /// Verifies that the remote registration result names the exact local
    /// helper evidence before activating ticket verification keys.
    pub fn activate_registration(&self, payload: &Value) -> Result<(), PrivilegedNodeError> {
        let value = payload
            .as_object()
            .ok_or(PrivilegedNodeError::RegistrationMissing)?;
        if value.get("status").and_then(Value::as_str) != Some("active")
            || value.get("installationId").and_then(Value::as_str)
                != Some(self.capability.claims.installation_id.as_str())
            || value.get("helperKeyId").and_then(Value::as_str)
                != Some(self.capability.claims.receipt_key_id.as_str())
            || value.get("helperPolicyRevision").and_then(Value::as_u64)
                != Some(self.capability.claims.policy_revision)
            || value.get("helperPolicyDigest").and_then(Value::as_str)
                != Some(self.capability.claims.policy_digest.as_str())
        {
            return Err(PrivilegedNodeError::PolicyMismatch);
        }
        let mut keys = BTreeMap::new();
        let issuer_keys = value
            .get("issuerKeys")
            .and_then(Value::as_array)
            .ok_or(PrivilegedNodeError::RegistrationMissing)?;
        if issuer_keys.is_empty() || issuer_keys.len() > 4 {
            return Err(PrivilegedNodeError::RegistrationMissing);
        }
        for item in issuer_keys {
            let item = item
                .as_object()
                .ok_or(PrivilegedNodeError::RegistrationMissing)?;
            if !matches!(
                item.get("status").and_then(Value::as_str),
                Some("active" | "retiring")
            ) {
                return Err(PrivilegedNodeError::RegistrationMissing);
            }
            let id = string(item.get("keyId"), "issuer key id")?.to_owned();
            let jwk = item
                .get("publicJwk")
                .and_then(Value::as_object)
                .ok_or(PrivilegedNodeError::RegistrationMissing)?;
            if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
                || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return Err(PrivilegedNodeError::RegistrationMissing);
            }
            let raw: [u8; 32] = URL_SAFE_NO_PAD
                .decode(string(jwk.get("x"), "issuer JWK x")?)
                .map_err(|_| PrivilegedNodeError::RegistrationMissing)?
                .try_into()
                .map_err(|_| PrivilegedNodeError::RegistrationMissing)?;
            if hex::encode(Sha256::digest(raw))
                != string(item.get("fingerprint"), "issuer fingerprint")?
            {
                return Err(PrivilegedNodeError::RegistrationMissing);
            }
            keys.insert(id, raw);
        }
        let mut state = self
            .registration
            .write()
            .map_err(|_| PrivilegedNodeError::RegistrationMissing)?;
        state.active = true;
        state.issuer_keys = keys;
        state.owner_decision_digest =
            Some(string(value.get("ownerDecisionDigest"), "ownerDecisionDigest")?.to_owned());
        Ok(())
    }

    pub fn registration_payload(
        &self,
        request_id: &str,
        device_policy_revision: u64,
        device_policy_summary: Value,
        previous_device_policy_digest: Option<&str>,
        connection_epoch: u64,
        identity: &DeviceIdentity,
    ) -> Result<Value, PrivilegedNodeError> {
        let object = self
            .bundle
            .as_object()
            .ok_or(PrivilegedNodeError::RegistrationMissing)?;
        let mut payload = json!({
            "requestId": request_id,
            "registrationBundle": self.bundle,
            "devicePolicy": {
                "revision": device_policy_revision,
                "policyDigest": hex::encode(Sha256::digest(serde_jcs::to_vec(&device_policy_summary).map_err(|error| PrivilegedNodeError::Config(error.to_string()))?)),
                "previousPolicyDigest": previous_device_policy_digest,
                "publicSummary": device_policy_summary,
                "signature": "pending"
            },
            "deviceKeyId": identity.key_id(),
            "deviceSignature": "pending"
        });
        let device_policy = payload["devicePolicy"].clone();
        let device_unsigned = json!({
            "deviceId": object.get("deviceId").cloned().ok_or(PrivilegedNodeError::RegistrationMissing)?,
            "revision": device_policy_revision,
            "policyDigest": device_policy["policyDigest"],
            "previousPolicyDigest": previous_device_policy_digest,
            "publicSummary": device_policy["publicSummary"]
        });
        payload["devicePolicy"]["signature"] = Value::String(
            identity.sign(
                &serde_jcs::to_vec(&device_unsigned)
                    .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?,
            ),
        );
        let mut unsigned = payload.clone();
        unsigned
            .as_object_mut()
            .expect("payload object")
            .remove("deviceSignature");
        let transcript = json!({
            "domain": "conduit.privilege.installation_attestation.v1",
            "deviceId": object.get("deviceId").cloned().ok_or(PrivilegedNodeError::RegistrationMissing)?,
            "connectionEpoch": connection_epoch.to_string(),
            "payload": unsigned,
        });
        payload["deviceSignature"] = Value::String(
            identity.sign(
                &serde_jcs::to_vec(&transcript)
                    .map_err(|error| PrivilegedNodeError::Config(error.to_string()))?,
            ),
        );
        Ok(payload)
    }
}

fn string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, PrivilegedNodeError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| PrivilegedNodeError::Config(field.into()))
}
