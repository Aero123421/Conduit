use std::collections::BTreeMap;

use conduit_crypto::canonical_sha256;
use conduit_domain::{
    AnyRunId, ArtifactId, AssignmentId, ContentObjectId, ContextSnapshotId, DeviceId, EventId,
    ManifestId, Sha256Digest, U64Decimal, UtcTimestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Explicit,
    Observed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Metadata,
    ProjectContent,
    RawLog,
    CredentialReference,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RetentionClass {
    R0,
    R1,
    R2,
    R3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestSourceBinding {
    pub source_id: String,
    pub location_id: String,
    pub location_revision: u64,
    pub workspace_mode: String,
    pub repository_identity_digest: Option<Sha256Digest>,
    pub base_revision: String,
    pub initial_state_digest: Sha256Digest,
    pub bounded_display_path: String,
    pub opaque_local_path_ref: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub item_id: String,
    pub kind: String,
    pub content_digest: Sha256Digest,
    pub byte_count: u64,
    pub eligibility: String,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunManifestInput {
    pub manifest_id: ManifestId,
    pub run_id: AnyRunId,
    pub assignment_id: Option<AssignmentId>,
    pub operation_id: String,
    pub request_digest: Sha256Digest,
    pub idempotency_key_digest: Sha256Digest,
    pub actor_id: String,
    pub client_id: String,
    pub admitted_at: UtcTimestamp,
    pub device_id: DeviceId,
    pub node_version: String,
    pub node_protocol_version: String,
    pub boot_id: String,
    pub capability_digest: Sha256Digest,
    pub local_policy_revision: u64,
    pub runtime_kind: String,
    pub runtime_provider_id: String,
    pub runtime_config_digest: Sha256Digest,
    pub effective_capabilities: BTreeMap<String, bool>,
    pub requested_access_scope: String,
    pub effective_access_scope: String,
    pub requested_approval_mode: String,
    pub effective_approval_mode: String,
    pub policy_revision_digest: Sha256Digest,
    pub source_bindings: Vec<ManifestSourceBinding>,
    pub adapter_id: Option<String>,
    pub adapter_version: Option<String>,
    pub executable_digest: Option<Sha256Digest>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub context_compiler_version: String,
    pub instruction_catalog: Vec<CatalogEntry>,
    pub skill_catalog: Vec<CatalogEntry>,
    pub capture_policy_digest: Sha256Digest,
    pub redaction_policy_digest: Sha256Digest,
    pub retention_policy_digest: Sha256Digest,
    pub evaluation_tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunManifest {
    pub input: RunManifestInput,
    pub manifest_digest: Sha256Digest,
}

impl RunManifest {
    pub fn new(mut input: RunManifestInput) -> Result<Self, conduit_crypto::CanonicalJsonError> {
        input
            .source_bindings
            .sort_by(|a, b| a.source_id.cmp(&b.source_id));
        input
            .instruction_catalog
            .sort_by(|a, b| a.item_id.cmp(&b.item_id));
        input
            .skill_catalog
            .sort_by(|a, b| a.item_id.cmp(&b.item_id));
        let manifest_digest = canonical_sha256(&input)?;
        Ok(Self {
            input,
            manifest_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceContextSnapshot {
    pub context_snapshot_id: ContextSnapshotId,
    pub run_id: AnyRunId,
    pub input_operation_id: String,
    pub mode: String,
    pub controller_epoch: u64,
    pub project_context_revision: Option<u64>,
    pub session_revision: Option<u64>,
    pub selected_record_ids: Vec<String>,
    pub instruction_catalog_digest: Sha256Digest,
    pub skill_catalog_digest: Sha256Digest,
    pub compiler_version: String,
    pub item_manifest_digest: Sha256Digest,
    pub compiled_bytes: u64,
    pub compiled_content_digest: Sha256Digest,
    pub snapshot_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventDraft {
    pub event_id: EventId,
    pub event_type: String,
    pub source_component: String,
    pub observed_at: UtcTimestamp,
    #[serde(rename = "monotonicNanos")]
    pub monotonic_ns: Option<U64Decimal>,
    pub boot_id: String,
    pub correlation_id: String,
    pub parent_event_id: Option<EventId>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub evidence_level: EvidenceLevel,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedEvent {
    pub schema_version: u8,
    pub kind: String,
    pub event_id: EventId,
    pub run_id: AnyRunId,
    pub device_id: DeviceId,
    pub sequence: U64Decimal,
    pub event_type: String,
    #[serde(rename = "source")]
    pub source_component: String,
    pub observed_at: UtcTimestamp,
    #[serde(rename = "monotonicNanos")]
    pub monotonic_ns: Option<U64Decimal>,
    #[serde(rename = "nodeBootId")]
    pub boot_id: String,
    pub correlation_id: String,
    pub parent_event_id: Option<EventId>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub evidence_level: EvidenceLevel,
    pub sensitivity: Sensitivity,
    #[serde(rename = "retentionClass")]
    pub retention: RetentionClass,
    pub payload: serde_json::Value,
    pub payload_digest: Sha256Digest,
    pub event_digest: Sha256Digest,
    pub previous_chain_hash: Sha256Digest,
    pub chain_hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionRecord {
    pub rule_id: String,
    pub rule_version: u32,
    pub replacement_category: String,
    pub keyed_digest: Option<Sha256Digest>,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentObjectDescriptor {
    pub object_id: ContentObjectId,
    pub run_id: AnyRunId,
    pub content_kind: String,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub uncompressed_bytes: u64,
    pub stored_bytes: u64,
    pub plaintext_digest: Sha256Digest,
    pub stored_digest: Sha256Digest,
    pub opaque_locator: String,
    pub created_at: UtcTimestamp,
    pub expires_at: Option<UtcTimestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentObjectSet {
    pub objects: Vec<ContentObjectDescriptor>,
    pub aggregate_digest: Sha256Digest,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawSegmentDescriptor {
    pub segment_id: String,
    pub run_id: AnyRunId,
    pub stream_id: String,
    pub first_local_sequence: u64,
    pub last_local_sequence: u64,
    pub record_count: u64,
    pub uncompressed_bytes: u64,
    pub stored_digest: Sha256Digest,
    pub opaque_locator: String,
    pub gap_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub artifact_id: ArtifactId,
    pub run_id: AnyRunId,
    pub kind: String,
    pub content_object_ids: Vec<ContentObjectId>,
    pub content_digest: Sha256Digest,
    pub verification_refs: Vec<String>,
    pub custody_receipt_ids: Vec<String>,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TracePage {
    pub events: Vec<NormalizedEvent>,
    pub next_cursor: Option<String>,
    pub evidence_state: EvidenceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    ContentRedacted,
    RawNotCaptured,
    RetentionGap,
    SegmentCorrupt,
    EventChainMismatch,
    LocalStoreUnavailable,
    UploadIncomplete,
}
