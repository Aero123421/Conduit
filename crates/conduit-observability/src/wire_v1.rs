//! Serde representations of the authoritative `trace-v1` wire records.
//!
//! These records intentionally live under `wire_v1`: the operational trace-store
//! types predate the published contract and remain available at the crate root.
//! Keeping the version in the module path makes conversions explicit and avoids
//! silently assigning v1 semantics to older durable data.

use conduit_domain::{
    AnyRunId, ArtifactId, AssignmentId, ChangeSetId, CollaborationSessionId, ContentObjectId,
    ContextSnapshotId, DeviceId, EventId, ManifestId, MessageId, OperationId, PrincipalId,
    ProjectAgentId, ProjectId, Sha256Digest, SourceId, U64Decimal, UtcTimestamp,
};
use serde::{Deserialize, Serialize};

use crate::{EvidenceLevel, EvidenceState, RetentionClass, Sensitivity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record {
    RunManifest(Box<RunManifest>),
    ContextSnapshot(Box<TraceContextSnapshot>),
    NormalizedEvent(Box<NormalizedEvent>),
    ContentObject(Box<ContentObject>),
    SegmentDescriptor(Box<SegmentDescriptor>),
    TraceCursor(Box<TraceCursor>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunManifest {
    pub schema_version: u8,
    pub kind: RunManifestKind,
    pub manifest_id: ManifestId,
    pub manifest_digest: Sha256Digest,
    pub run_id: AnyRunId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<AssignmentId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<CollaborationSessionId>,
    pub operation_id: OperationId,
    pub request_digest: Sha256Digest,
    pub idempotency_key_digest: Sha256Digest,
    pub actor_principal_id: PrincipalId,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_agent_id: Option<ProjectAgentId>,
    pub created_at: UtcTimestamp,
    pub admitted_at: UtcTimestamp,
    pub device: DeviceManifest,
    pub runtime: RuntimeManifest,
    pub authority: AuthorityManifest,
    pub sources: Vec<SourceManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterManifest>,
    pub context: ContextSelection,
    pub instructions: InstructionCatalog,
    pub skills: SkillCatalog,
    pub capture: CapturePolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<EvaluationTags>,
}

impl RunManifest {
    pub fn validate(&self) -> Result<(), WireValidationError> {
        require_v1(self.schema_version)?;
        if self.sources.len() > 128 {
            return Err(WireValidationError::Limit("sources"));
        }
        self.instructions.validate()?;
        self.skills.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunManifestKind {
    #[serde(rename = "run_manifest")]
    RunManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceManifest {
    pub device_id: DeviceId,
    pub display_label: String,
    pub node_version: String,
    pub node_protocol_version: String,
    pub os: OperatingSystem,
    pub arch: String,
    pub node_boot_id: String,
    pub capability_digest: Sha256Digest,
    pub local_policy_revision: u64,
    pub storage_profile_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Windows,
    Macos,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeManifest {
    pub kind: RuntimeKind,
    pub provider_id: String,
    pub provider_version: String,
    pub capability_receipt_digest: Sha256Digest,
    pub configuration_revision: u64,
    pub identity_class: String,
    pub resources: RuntimeResources,
    pub network_mode: NetworkMode,
    pub isolation: IsolationCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_reference: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Native,
    RestrictedNative,
    Container,
    Vm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeResources {
    pub cpu: serde_json::Number,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub gpu_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Open,
    Restricted,
    Offline,
    LanExplicit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationCapabilities {
    pub distinct_os_identity: bool,
    pub filesystem_restricted: bool,
    pub process_namespace: bool,
    pub network_isolated: bool,
    pub container_boundary: bool,
    pub vm_boundary: bool,
    pub elevation_available: bool,
    pub host_control_socket_exposed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityManifest {
    pub requested_access_scope: AccessScope,
    pub effective_access_scope: AccessScope,
    pub requested_approval_mode: ApprovalMode,
    pub effective_approval_mode: ApprovalMode,
    pub connector_policy_id: String,
    pub connector_policy_revision: u64,
    pub project_policy_revision: u64,
    pub device_policy_revision: u64,
    #[serde(default)]
    pub approved_risk_classes: Vec<String>,
    pub operation_expires_at: UtcTimestamp,
    pub admitted_valid_for_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessScope {
    ReadOnly,
    SelectedSources,
    ProjectFull,
    FullUser,
    FullDevice,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Always,
    OutsideScope,
    RiskClasses,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceManifest {
    pub source_id: SourceId,
    pub location_id: conduit_domain::LocationId,
    pub location_revision: u64,
    pub workspace_mode: WorkspaceMode,
    pub path: OpaquePathReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_identity_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty_state_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty_summary: Option<DirtySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_features: Option<GitFeatures>,
    pub initial_state: InitialSourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_state_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    ReadOnly,
    Direct,
    Worktree,
    ManagedCopy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePathReference {
    pub reference: String,
    pub display_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirtySummary {
    #[serde(default)]
    pub changed: u64,
    #[serde(default)]
    pub untracked: u64,
    #[serde(default)]
    pub conflicted: u64,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitFeatures {
    #[serde(default)]
    pub submodules: bool,
    #[serde(default)]
    pub lfs: bool,
    #[serde(default)]
    pub sparse_checkout: bool,
    #[serde(default)]
    pub partial_clone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitialSourceState {
    GitCommit,
    BoundedManifest,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterManifest {
    pub adapter_id: String,
    pub contract_version: String,
    pub implementation_version: String,
    pub executable: ExecutableIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper: Option<ExecutableIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<ExecutableIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    pub requested_model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_model: Option<String>,
    pub requested_effort: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_effort: Option<String>,
    pub authentication_state: AuthenticationState,
    pub authentication_evidence: EvidenceLevel,
    pub capability_receipt_digest: Sha256Digest,
    pub launch_plan_digest: Sha256Digest,
    pub tool_catalog_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_session_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub path: OpaquePathReference,
    pub identity_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    Authenticated,
    NeedsLogin,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextSelection {
    pub project_context_revision: u64,
    pub session_revision: u64,
    pub assignment_message_revision: u64,
    pub message_ids: Vec<MessageId>,
    pub artifact_ids: Vec<ArtifactId>,
    pub change_set_ids: Vec<ChangeSetId>,
    pub compiler: IdentityVersion,
    pub configuration_digest: Sha256Digest,
    pub estimated_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityVersion {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstructionCatalog {
    pub catalog_digest: Sha256Digest,
    pub discovery_filenames: Vec<String>,
    pub per_file_byte_limit: u64,
    pub aggregate_byte_limit: u64,
    pub discovered_bytes: u64,
    pub items: Vec<InstructionItem>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl InstructionCatalog {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.discovery_filenames.len() > 32 || self.items.len() > 4096 || self.errors.len() > 128
        {
            return Err(WireValidationError::Limit("instruction catalog"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstructionItem {
    pub instruction_id: String,
    pub kind: String,
    pub path: OpaquePathReference,
    pub content_digest: Sha256Digest,
    pub bytes: u64,
    pub discovery_source: String,
    pub scope: String,
    pub precedence: u16,
    pub eligible: bool,
    pub initial_state: InstructionInitialState,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionInitialState {
    Discovered,
    Skipped,
    Unsupported,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillCatalog {
    pub catalog_digest: Sha256Digest,
    pub items: Vec<SkillItem>,
}

impl SkillCatalog {
    fn validate(&self) -> Result<(), WireValidationError> {
        if self.items.len() > 4096 {
            return Err(WireValidationError::Limit("skill catalog"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillItem {
    pub skill_id: String,
    pub name: String,
    pub description_digest: Sha256Digest,
    pub skill_file_digest: Sha256Digest,
    pub skill_file_bytes: u64,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility_digest: Option<Sha256Digest>,
    pub discovery_scope: String,
    pub eligible_adapters: Vec<String>,
    pub eligibility: SkillEligibility,
    pub precedence: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<SkillResource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillEligibility {
    Eligible,
    Ineligible,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillResource {
    pub kind: SkillResourceKind,
    pub relative_path: String,
    pub content_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillResourceKind {
    Script,
    Reference,
    Template,
    Asset,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePolicy {
    pub policy_id: String,
    pub revision: u64,
    pub redaction_policy_id: String,
    pub redaction_policy_revision: u64,
    pub retention_policy_id: String,
    pub retention_policy_revision: u64,
    pub visible_messages: CaptureMode,
    pub tool_arguments: CaptureMode,
    pub tool_results: CaptureMode,
    pub command_output: CaptureMode,
    pub file_diffs: CaptureMode,
    pub raw_provider_protocol: CaptureMode,
    pub screenshots: CaptureMode,
    pub max_inline_payload_bytes: u64,
    pub max_content_object_bytes: u64,
    pub max_segment_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    None,
    Hash,
    Summary,
    Bounded,
    FullLocal,
    UploadAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationTags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experiment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_group: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceContextSnapshot {
    pub schema_version: u8,
    pub kind: ContextSnapshotKind,
    pub snapshot_id: ContextSnapshotId,
    pub snapshot_digest: Sha256Digest,
    pub run_id: AnyRunId,
    pub input_operation_id: OperationId,
    pub mode: ContextMode,
    pub controller_epoch: U64Decimal,
    pub project_context_revision: u64,
    pub session_revision: u64,
    pub instruction_catalog_digest: Sha256Digest,
    pub skill_catalog_digest: Sha256Digest,
    pub compiler: IdentityVersion,
    pub items: Vec<ContextItem>,
    pub estimated_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_tokens: Option<u64>,
    pub capture_policy_id: String,
    pub redaction_policy_id: String,
    pub compiled_content_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiled_content_ref: Option<ContentReference>,
    pub created_at: UtcTimestamp,
}

impl TraceContextSnapshot {
    pub fn validate(&self) -> Result<(), WireValidationError> {
        require_v1(self.schema_version)?;
        if self.items.len() > 16_384 {
            return Err(WireValidationError::Limit("items"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextSnapshotKind {
    #[serde(rename = "context_snapshot")]
    ContextSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMode {
    Initial,
    Answer,
    FollowUp,
    Steer,
    Resume,
    QueuedInstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextItem {
    pub item_type: String,
    pub source_id: String,
    pub source_revision: u64,
    pub precedence: u16,
    pub content_digest: Sha256Digest,
    pub bytes: u64,
    pub state: ContextItemState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextItemState {
    Included,
    Summarized,
    Referenced,
    Omitted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentReference {
    pub object_id: ContentObjectId,
    pub content_digest: Sha256Digest,
    pub bytes: u64,
    pub sensitivity: Sensitivity,
    pub retention_class: RetentionClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    Complete,
    Redacted,
    Partial,
    Corrupt,
    Missing,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedEvent {
    pub schema_version: u8,
    pub kind: NormalizedEventKind,
    pub event_id: EventId,
    pub run_id: AnyRunId,
    pub device_id: DeviceId,
    pub sequence: U64Decimal,
    pub event_type: String,
    #[serde(rename = "source")]
    pub source_component: String,
    pub observed_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monotonic_nanos: Option<U64Decimal>,
    pub node_boot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub evidence_level: EvidenceLevel,
    pub sensitivity: Sensitivity,
    pub retention_class: RetentionClass,
    pub payload_digest: Sha256Digest,
    pub event_digest: Sha256Digest,
    pub previous_chain_hash: Sha256Digest,
    pub chain_hash: Sha256Digest,
    pub payload: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_reference: Option<ContentReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizedEventKind {
    #[serde(rename = "normalized_event")]
    NormalizedEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionRecord {
    pub rule_id: String,
    pub rule_version: String,
    pub content_class: String,
    pub replacement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyed_digest: Option<Sha256Digest>,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentObject {
    pub schema_version: u8,
    pub kind: ContentObjectKind,
    pub object_id: ContentObjectId,
    pub run_id: AnyRunId,
    pub content_kind: String,
    pub sensitivity: Sensitivity,
    pub retention_class: RetentionClass,
    pub compression: Compression,
    pub uncompressed_bytes: u64,
    pub stored_bytes: u64,
    pub content_digest: Sha256Digest,
    pub stored_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions: Vec<RedactionRecord>,
    pub storage_provider: StorageProvider,
    pub opaque_locator: String,
    pub state: ContentState,
    pub created_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentObjectKind {
    #[serde(rename = "content_object")]
    ContentObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    None,
    DeviceAtRest,
    Envelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProvider {
    Device,
    R2,
    ExportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentDescriptor {
    pub schema_version: u8,
    pub kind: SegmentDescriptorKind,
    pub segment_id: String,
    pub run_id: AnyRunId,
    pub stream_id: String,
    pub from_sequence: U64Decimal,
    pub through_sequence: U64Decimal,
    pub record_count: u64,
    pub compression: Compression,
    pub uncompressed_bytes: u64,
    pub stored_bytes: u64,
    pub content_digest: Sha256Digest,
    pub stored_digest: Sha256Digest,
    pub storage_provider: StorageProvider,
    pub opaque_locator: String,
    pub state: ContentState,
    pub created_at: UtcTimestamp,
    pub finalized_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_state: Option<EvidenceState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentDescriptorKind {
    #[serde(rename = "segment_descriptor")]
    SegmentDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceCursor {
    pub schema_version: u8,
    pub kind: TraceCursorKind,
    pub device_id: DeviceId,
    pub run_id: AnyRunId,
    pub provider: String,
    pub position: U64Decimal,
    pub store_generation: U64Decimal,
    pub filter_digest: Sha256Digest,
    pub capture_policy_revision: u64,
    pub mac: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceCursorKind {
    #[serde(rename = "trace_cursor")]
    TraceCursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireValidationError {
    #[error("schemaVersion must be 1")]
    SchemaVersion,
    #[error("schema collection limit exceeded: {0}")]
    Limit(&'static str),
}

fn require_v1(version: u8) -> Result<(), WireValidationError> {
    if version == 1 {
        Ok(())
    } else {
        Err(WireValidationError::SchemaVersion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn example(path: &str) -> Value {
        serde_json::from_str(path).expect("authoritative example is JSON")
    }

    #[test]
    fn run_manifest_fixture_is_exact_serde_wire_shape() {
        let expected = example(include_str!(
            "../../../spec/examples/trace/run-manifest-codex-native.json"
        ));
        let record: RunManifest = serde_json::from_value(expected.clone()).unwrap();
        record.validate().unwrap();
        assert_eq!(serde_json::to_value(record).unwrap(), expected);
    }

    #[test]
    fn context_snapshot_fixture_is_exact_serde_wire_shape() {
        let expected = example(include_str!(
            "../../../spec/examples/trace/context-snapshot-initial.json"
        ));
        let record: TraceContextSnapshot = serde_json::from_value(expected.clone()).unwrap();
        record.validate().unwrap();
        assert_eq!(serde_json::to_value(record).unwrap(), expected);
    }

    #[test]
    fn fixture_output_validates_against_authoritative_schema() {
        let schema: Value = example(include_str!("../../../spec/schemas/trace-v1.schema.json"));
        let validator = jsonschema::validator_for(&schema).unwrap();
        for fixture in [
            include_str!("../../../spec/examples/trace/run-manifest-codex-native.json"),
            include_str!("../../../spec/examples/trace/context-snapshot-initial.json"),
            include_str!("../../../spec/examples/trace/event-instruction-effective-set.json"),
            include_str!("../../../spec/examples/trace/event-skill-script-completed.json"),
            include_str!("../../../spec/examples/trace/event-verification-failed.json"),
        ] {
            let value = example(fixture);
            let record: Record = serde_json::from_value(value).unwrap();
            let output = serde_json::to_value(record).unwrap();
            assert!(validator.is_valid(&output));
        }
    }

    #[test]
    fn event_fixtures_round_trip_exactly() {
        for fixture in [
            include_str!("../../../spec/examples/trace/event-instruction-effective-set.json"),
            include_str!("../../../spec/examples/trace/event-skill-script-completed.json"),
            include_str!("../../../spec/examples/trace/event-verification-failed.json"),
        ] {
            let expected = example(fixture);
            let record: NormalizedEvent = serde_json::from_value(expected.clone()).unwrap();
            assert_eq!(serde_json::to_value(record).unwrap(), expected);
        }
    }
}
