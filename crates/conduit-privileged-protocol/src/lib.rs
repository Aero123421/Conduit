//! Shared, versioned contract between the Control Plane, the unprivileged Node,
//! and the networkless Linux privileged helper.
//!
//! Signatures cover RFC 8785 canonical JSON claims. The helper protocol never
//! accepts a shell command string, an OAuth credential, or an unbounded map.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const PROTOCOL: &str = "conduit.privileged/1";
pub const MAX_PACKET_BYTES: usize = 65_536;
pub const MAX_ARGV: usize = 256;
pub const MAX_ENVIRONMENT_KEYS: usize = 128;
pub const MAX_ATTACHMENTS: usize = 128;
pub const MAX_DESCRIPTORS: usize = 32;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("canonical JSON failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("invalid Ed25519 public key")]
    PublicKey,
    #[error("invalid Ed25519 signature")]
    Signature,
    #[error("privileged protocol validation failed: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedClaims<T> {
    pub key_id: String,
    pub claims: T,
    pub signature: String,
}

impl<T: Serialize> SignedClaims<T> {
    pub fn sign(
        key_id: impl Into<String>,
        claims: T,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let bytes = serde_jcs::to_vec(&claims)?;
        Ok(Self {
            key_id: key_id.into(),
            signature: URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()),
            claims,
        })
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| ProtocolError::PublicKey)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProtocolError::Signature)?;
        let signature = Signature::from_slice(&raw).map_err(|_| ProtocolError::Signature)?;
        key.verify(&serde_jcs::to_vec(&self.claims)?, &signature)
            .map_err(|_| ProtocolError::Signature)
    }

    pub fn digest(&self) -> Result<String, ProtocolError> {
        Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(self)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalEnforcement {
    ExactCommand,
    AdapterMediated,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCeilings {
    pub cpu_quota_per_sec_usec: Option<u64>,
    pub memory_max_bytes: Option<u64>,
    pub tasks_max: Option<u32>,
    pub io_weight: Option<u16>,
    pub runtime_max_usec: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivilegeTicketClaims {
    pub schema_version: u16,
    pub protocol: String,
    pub ticket_id: String,
    pub issuer_kind: String,
    pub issuer_key_id: String,
    pub audience: String,
    pub public_origin: String,
    pub helper_installation_id: String,
    pub helper_key_id: String,
    pub helper_policy_revision: u64,
    pub helper_policy_digest: String,
    pub device_id: String,
    pub device_key_id: String,
    pub device_policy_revision: u64,
    pub device_revision: u64,
    pub expected_uid: u32,
    pub operation_id: String,
    pub idempotency_key_digest: String,
    pub operation_request_digest: String,
    pub run_manifest_digest: String,
    pub run_id: String,
    pub runtime_id: String,
    pub runtime_spec_digest: String,
    pub launch_plan_digest: String,
    pub control_digest: Option<String>,
    pub local_execution_plan_digest: String,
    pub controller_epoch: u64,
    pub connector_policy_id: Option<String>,
    pub connector_policy_revision: u64,
    pub project_id: Option<String>,
    pub project_revision: Option<u64>,
    pub assignment_id: Option<String>,
    pub project_agent_id: Option<String>,
    pub project_agent_revision: Option<u64>,
    pub runtime_configuration_revision: u64,
    pub access_scope: String,
    pub approval_mode: String,
    pub approval_receipt_digest: Option<String>,
    pub approval_enforcement: ApprovalEnforcement,
    pub required_approval_risk_classes: Vec<String>,
    pub allowed_operation: PrivilegedOperation,
    pub resource_ceilings: ResourceCeilings,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub max_use_count: u16,
}

impl PrivilegeTicketClaims {
    /// Enforce the canonical claims before a caller evaluates any
    /// action-specific authority.
    pub fn validate(&self, envelope_key_id: &str) -> Result<(), ProtocolError> {
        if self.schema_version != 1
            || self.protocol != PROTOCOL
            || self.issuer_kind != "control_plane"
            || self.issuer_key_id != envelope_key_id
            || self.max_use_count != 1
            || self.device_revision == 0
            || self.device_policy_revision == 0
            || self.runtime_configuration_revision == 0
            || self.run_manifest_digest.len() != 64
            || self
                .control_digest
                .as_ref()
                .is_some_and(|value| value.len() != 64)
        {
            return Err(ProtocolError::Invalid(
                "privilege ticket canonical binding".into(),
            ));
        }
        let mut risks = self.required_approval_risk_classes.clone();
        risks.sort();
        risks.dedup();
        if risks.len() != self.required_approval_risk_classes.len() {
            return Err(ProtocolError::Invalid(
                "duplicate approval risk class".into(),
            ));
        }
        Ok(())
    }
}

pub type PrivilegeTicket = SignedClaims<PrivilegeTicketClaims>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedOperation {
    Prepare,
    Start,
    Inspect,
    Input,
    ResizePty,
    Pause,
    Resume,
    GracefulStop,
    ForceStop,
    Reconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileIdentity {
    pub opaque_path_id: String,
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBinding {
    pub location_id: String,
    pub opaque_path_id: String,
    pub expected_identity_digest: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialDescriptor {
    pub projection_id: String,
    pub revision: u64,
    pub target_name: String,
    pub descriptor_index: u16,
    pub size: u64,
    pub sha256: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioMode {
    Pipes,
    Pty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalExecutionPlan {
    pub plan_version: u16,
    pub runtime_id: String,
    pub run_id: String,
    pub operation_id: String,
    pub executable: FileIdentity,
    pub interpreter: Option<FileIdentity>,
    pub argv: Vec<String>,
    pub cwd: FileIdentity,
    pub systemd_unit: String,
    pub adapter_id: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub environment_value_digests: BTreeMap<String, String>,
    pub workspaces: Vec<WorkspaceBinding>,
    pub credentials: Vec<CredentialDescriptor>,
    pub stdio: StdioMode,
    pub resources: ResourceCeilings,
    pub helper_protocol: String,
    pub helper_min_version: String,
}

impl LocalExecutionPlan {
    pub fn digest(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(self)?)))
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV {
            return Err(ProtocolError::Invalid("argv bound".into()));
        }
        if self.environment.len() > MAX_ENVIRONMENT_KEYS
            || self.workspaces.len() > MAX_ATTACHMENTS
            || self.credentials.len() > MAX_DESCRIPTORS
        {
            return Err(ProtocolError::Invalid("plan collection bound".into()));
        }
        for key in self
            .environment
            .keys()
            .chain(self.environment_value_digests.keys())
        {
            validate_environment_key(key)?;
        }
        if self
            .environment
            .keys()
            .any(|key| dangerous_environment_key(key))
        {
            return Err(ProtocolError::Invalid("dangerous environment key".into()));
        }
        if !self.systemd_unit.starts_with("conduit-elevated-")
            || !self.systemd_unit.ends_with(".service")
        {
            return Err(ProtocolError::Invalid("systemd unit name".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootPolicy {
    pub policy_version: u16,
    pub installation_id: String,
    pub device_id: String,
    pub uid: u32,
    pub revision: u64,
    pub enabled: bool,
    pub origin: String,
    pub ticket_key_ids: Vec<String>,
    pub allowed_operations: Vec<PrivilegedOperation>,
    pub allowed_adapters: Vec<String>,
    pub allowed_launch_profiles: Vec<String>,
    pub ceilings: ResourceCeilings,
    pub allow_never: bool,
    pub allow_unrestricted_launch: bool,
    pub allow_persistent_sessions: bool,
    pub allow_offline_control: bool,
    pub receipt_retention_seconds: u64,
}

impl RootPolicy {
    pub fn digest(&self) -> Result<String, ProtocolError> {
        Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(self)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityClaims {
    pub protocol: String,
    pub helper_version: String,
    pub installation_id: String,
    pub receipt_key_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub enabled: bool,
    pub observed_at: String,
    pub systemd_system_manager: bool,
    pub socket_peer_credentials: bool,
    pub transient_units: bool,
    pub cgroup_v2: bool,
    pub freeze: bool,
    pub pidfd: bool,
    pub openat2: bool,
    pub execveat: bool,
    pub pty: bool,
    pub stream_replay: bool,
    pub never_opt_in: bool,
    pub unrestricted_launch_opt_in: bool,
    pub unavailable_reason: Option<String>,
}

pub type SignedCapability = SignedClaims<CapabilityClaims>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptClaims {
    pub protocol: String,
    pub receipt_id: String,
    pub installation_id: String,
    pub receipt_key_id: String,
    pub helper_version: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub ticket_id: String,
    pub ticket_digest: String,
    pub operation_id: String,
    pub request_digest: String,
    pub run_id: String,
    pub runtime_id: String,
    pub runtime_spec_digest: String,
    pub launch_plan_digest: String,
    pub local_execution_plan_digest: String,
    pub control_request_digest: Option<String>,
    pub controller_epoch: u64,
    pub state_revision: u64,
    pub transition: String,
    pub unit_name: String,
    pub invocation_id: Option<String>,
    pub cgroup: Option<String>,
    pub main_pid: Option<u32>,
    pub process_birth: Option<String>,
    pub effective_uid: Option<u32>,
    pub effective_gid: Option<u32>,
    pub stdout_cursor: u64,
    pub stderr_cursor: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub observed_at: String,
    pub previous_receipt_digest: Option<String>,
}

pub type HelperReceipt = SignedClaims<ReceiptClaims>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeClaims {
    pub protocol: String,
    pub installation_id: String,
    pub device_id: String,
    pub uid: u32,
    pub pid: u32,
    pub pid_start: String,
    pub node_boot_id: String,
    pub client_nonce: String,
    pub helper_nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlTarget {
    pub runtime_id: String,
    pub unit_name: String,
    pub invocation_id: String,
    pub controller_epoch: u64,
    pub expected_state_revision: u64,
    pub runtime_handle_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum HelperRequest {
    Hello {
        protocol_versions: Vec<String>,
        device_id: String,
        node_boot_id: String,
        nonce: String,
    },
    Prove {
        challenge: ChallengeClaims,
        signature: String,
    },
    Probe,
    Prepare {
        ticket: PrivilegeTicket,
        plan: LocalExecutionPlan,
    },
    Start {
        ticket: PrivilegeTicket,
        plan_digest: String,
    },
    Inspect {
        target: ControlTarget,
    },
    Input {
        ticket: PrivilegeTicket,
        target: ControlTarget,
        descriptor_index: u16,
    },
    ResizePty {
        ticket: PrivilegeTicket,
        target: ControlTarget,
        rows: u16,
        columns: u16,
    },
    Control {
        ticket: PrivilegeTicket,
        target: ControlTarget,
        operation: PrivilegedOperation,
    },
    Reconcile {
        runtime_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum HelperResponse {
    Challenge(ChallengeClaims),
    Accepted {
        protocol: String,
        installation_id: String,
        policy_revision: u64,
    },
    Capability(SignedCapability),
    Receipt(HelperReceipt),
    Receipts(Vec<HelperReceipt>),
    Error {
        code: String,
        retryable: bool,
    },
}

pub fn decode_packet<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
        return Err(ProtocolError::Invalid("packet size".into()));
    }
    serde_json::from_slice(bytes).map_err(ProtocolError::Canonical)
}

pub fn key_id(prefix: &str, public_key: &[u8; 32]) -> String {
    format!(
        "{prefix}_{}",
        hex::encode(&Sha256::digest(public_key)[..16])
    )
}

pub fn dangerous_environment_key(key: &str) -> bool {
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || matches!(
            key,
            "GCONV_PATH"
                | "BASH_ENV"
                | "ENV"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "NODE_OPTIONS"
                | "RUBYOPT"
                | "PERL5OPT"
        )
}

fn validate_environment_key(key: &str) -> Result<(), ProtocolError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit()))
    {
        return Err(ProtocolError::Invalid("environment key".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn signed_claims_detect_mutation() {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let claims = ChallengeClaims {
            protocol: PROTOCOL.into(),
            installation_id: "phinst_example0001".into(),
            device_id: "dev_example0001".into(),
            uid: 1000,
            pid: 42,
            pid_start: "100".into(),
            node_boot_id: "boot-example".into(),
            client_nonce: "nonce-a".into(),
            helper_nonce: "nonce-b".into(),
            issued_at: "2026-09-03T00:00:00Z".into(),
            expires_at: "2026-09-03T00:01:00Z".into(),
        };
        let mut signed = SignedClaims::sign("hkey_example", claims, &key).unwrap();
        signed.verify(key.verifying_key().as_bytes()).unwrap();
        signed.claims.pid = 43;
        assert!(signed.verify(key.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn rejects_loader_environment() {
        assert!(dangerous_environment_key("LD_PRELOAD"));
        assert!(dangerous_environment_key("NODE_OPTIONS"));
        assert!(!dangerous_environment_key("LANG"));
    }
}
