//! Serde records for the authoritative `changeset-v1` contract.
//!
//! The crate's acceptance service keeps its established operational model. This
//! module is the explicit persistence/transport boundary for v1 records, so a
//! caller cannot accidentally serialize the older service state as a v1 record.

use conduit_domain::{
    AnyRunId, ArtifactId, AssignmentId, BaselineId, ChangeSetId, CollaborationSessionId, DeviceId,
    LocationId, OperationId, PrincipalId, ProjectAgentId, ProjectId, Sha256Digest, SourceId,
    UtcTimestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record {
    BaselineRevision(Box<BaselineRevision>),
    RunWorkspace(Box<RunWorkspace>),
    ChangeSet(Box<ChangeSet>),
    Review(Box<Review>),
    AcceptancePrepareReceipt(Box<AcceptancePrepareReceipt>),
    AcceptanceReceipt(Box<AcceptanceReceipt>),
    MaterializationReceipt(Box<MaterializationReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunWorkspace {
    pub schema_version: u8,
    pub kind: RunWorkspaceKind,
    pub workspace_id: String,
    pub run_id: AnyRunId,
    pub device_id: DeviceId,
    pub parent_type: WorkspaceParentType,
    pub parent_id: String,
    pub parent_digest: Sha256Digest,
    pub sources: Vec<WorkspaceSourceState>,
    pub state: WorkspaceState,
    pub workspace_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_at: Option<UtcTimestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunWorkspaceKind {
    #[serde(rename = "run_workspace")]
    RunWorkspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceParentType {
    Baseline,
    ChangeSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    ReadOnly,
    Direct,
    Worktree,
    ManagedCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Preparing,
    Ready,
    Dirty,
    Diverged,
    Conflicted,
    Missing,
    RecoveryRequired,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseMode {
    ExclusiveWriter,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePathReference {
    pub reference: String,
    pub display_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "sourceType",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WorkspaceSourceState {
    Git {
        source_id: SourceId,
        location_id: LocationId,
        location_revision: u64,
        workspace_mode: WorkspaceMode,
        path: OpaquePathReference,
        repository_identity_digest: Sha256Digest,
        base_commit: String,
        branch: String,
        worktree_identity_digest: Sha256Digest,
        lease_mode: LeaseMode,
        start_status_digest: Sha256Digest,
        state: WorkspaceState,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_status_digest: Option<Sha256Digest>,
        #[serde(skip_serializing_if = "Option::is_none")]
        divergence_reason: Option<String>,
    },
    ManagedFolder {
        source_id: SourceId,
        location_id: LocationId,
        location_revision: u64,
        workspace_mode: WorkspaceMode,
        path: OpaquePathReference,
        base_snapshot_id: String,
        base_manifest_digest: Sha256Digest,
        workspace_identity_digest: Sha256Digest,
        lease_mode: LeaseMode,
        state: WorkspaceState,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_manifest_digest: Option<Sha256Digest>,
        #[serde(skip_serializing_if = "Option::is_none")]
        divergence_reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineRevision {
    pub schema_version: u8,
    pub kind: BaselineRevisionKind,
    pub baseline_id: BaselineId,
    pub project_id: ProjectId,
    pub session_id: CollaborationSessionId,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor_baseline_id: Option<BaselineId>,
    pub state: BaselineState,
    pub sources: Vec<BaselineSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_change_set_id: Option<ChangeSetId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance_operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_by_principal_id: Option<PrincipalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_by_client_id: Option<String>,
    pub baseline_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineRevisionKind {
    #[serde(rename = "baseline_revision")]
    BaselineRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    Active,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "sourceType",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BaselineSource {
    Git {
        source_id: SourceId,
        repository_identity_digest: Sha256Digest,
        object_format: GitObjectFormat,
        commit: String,
        tree_digest: String,
        state_digest: Sha256Digest,
        custody: Vec<CustodyReceipt>,
        materializations: Vec<MaterializationState>,
    },
    ManagedFolder {
        source_id: SourceId,
        snapshot_id: String,
        manifest_digest: Sha256Digest,
        state_digest: Sha256Digest,
        custody: Vec<CustodyReceipt>,
        materializations: Vec<MaterializationState>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyReceipt {
    pub custody_class: CustodyClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub content_digest: Sha256Digest,
    pub state: CustodyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub observed_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
    pub receipt_digest: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyClass {
    DeviceRef,
    DeviceArchive,
    RemoteRef,
    ReplicatedDevice,
    R2Artifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyState {
    Healthy,
    Degraded,
    Missing,
    Pending,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterializationState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub location_id: LocationId,
    pub state: MaterializationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_digest: Option<Sha256Digest>,
    pub observed_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationStatus {
    Materialized,
    Pending,
    Unavailable,
    Diverged,
    Conflicted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSet {
    pub schema_version: u8,
    pub kind: ChangeSetKind,
    pub change_set_id: ChangeSetId,
    pub project_id: ProjectId,
    pub session_id: CollaborationSessionId,
    pub producing_run_id: AnyRunId,
    pub producing_assignment_id: AssignmentId,
    pub parent_baseline_id: BaselineId,
    pub parent_baseline_revision: u64,
    pub parent_baseline_digest: Sha256Digest,
    #[serde(default)]
    pub parent_change_set_ids: Vec<ChangeSetId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_change_set_id: Option<ChangeSetId>,
    pub state: ChangeSetState,
    pub source_changes: Vec<SourceChange>,
    pub unchanged_sources: Vec<UnchangedSource>,
    pub application_order: Vec<ApplicationStep>,
    pub required_verification_policy_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_ids: Vec<String>,
    pub artifact_ids: Vec<ArtifactId>,
    pub change_set_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_at: Option<UtcTimestamp>,
}

impl ChangeSet {
    pub fn validate(&self) -> Result<(), WireValidationError> {
        require_v1(self.schema_version)?;
        if self.source_changes.is_empty() || self.source_changes.len() > 1024 {
            return Err(WireValidationError::Cardinality("sourceChanges"));
        }
        if self.application_order.is_empty() || self.application_order.len() > 1024 {
            return Err(WireValidationError::Cardinality("applicationOrder"));
        }
        if self.parent_change_set_ids.len() > 64
            || self.verification_ids.len() > 4096
            || self.artifact_ids.len() > 4096
        {
            return Err(WireValidationError::Cardinality("change set references"));
        }
        let mut sources = std::collections::BTreeSet::new();
        if self
            .source_changes
            .iter()
            .any(|source| !sources.insert(source.source_id()))
        {
            return Err(WireValidationError::DuplicateSource);
        }
        let ordered = self
            .application_order
            .iter()
            .map(|step| &step.source_id)
            .collect::<std::collections::BTreeSet<_>>();
        if ordered != sources || self.application_order.len() != sources.len() {
            return Err(WireValidationError::ApplicationOrder);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeSetKind {
    #[serde(rename = "change_set")]
    ChangeSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSetState {
    Draft,
    Proposed,
    UnderReview,
    ChangesRequested,
    Approved,
    Accepted,
    Rejected,
    Withdrawn,
    Superseded,
    Stale,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "sourceType",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SourceChange {
    Git {
        source_id: SourceId,
        repository_identity_digest: Sha256Digest,
        origin_device_id: DeviceId,
        origin_location_id: LocationId,
        base_commit: String,
        base_tree: String,
        head_commit: String,
        head_tree: String,
        merge_base: String,
        commits: Vec<String>,
        commit_graph_digest: Sha256Digest,
        diff_digest: Sha256Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        patch_artifact_id: Option<ArtifactId>,
        changed_paths: ChangedPathSummary,
        git_features: GitFeatureState,
        verification_ids: Vec<String>,
        custody: Vec<CustodyReceipt>,
        source_change_digest: Sha256Digest,
    },
    ManagedFolder {
        source_id: SourceId,
        origin_device_id: DeviceId,
        origin_location_id: LocationId,
        base_snapshot_id: String,
        base_manifest_digest: Sha256Digest,
        result_snapshot_id: String,
        result_manifest_digest: Sha256Digest,
        operations: Vec<FileOperation>,
        changed_paths: ChangedPathSummary,
        verification_ids: Vec<String>,
        custody: Vec<CustodyReceipt>,
        source_change_digest: Sha256Digest,
    },
}

impl SourceChange {
    pub fn source_id(&self) -> &SourceId {
        match self {
            Self::Git { source_id, .. } | Self::ManagedFolder { source_id, .. } => source_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangedPathSummary {
    pub added: u64,
    pub modified: u64,
    pub deleted: u64,
    pub renamed: u64,
    pub type_changed: u64,
    pub conflicted: u64,
    pub untracked: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitFeatureState {
    pub submodules: SubmoduleState,
    pub lfs: LfsState,
    pub sparse_checkout: bool,
    pub partial_clone: bool,
    pub shallow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmoduleState {
    None,
    Recorded,
    RecursiveRecorded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LfsState {
    NotUsed,
    Required,
    PointerOnly,
    SkipSmudge,
    ObjectsMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileOperation {
    pub operation: FileOperationKind,
    pub path_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_path_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_type: Option<FileType>,
    pub after_type: FileType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_available: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationKind {
    Create,
    Modify,
    Delete,
    Rename,
    TypeChange,
    ModeChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Missing,
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnchangedSource {
    pub source_id: SourceId,
    pub state_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationStep {
    pub order: u64,
    pub source_id: SourceId,
    pub source_change_digest: Sha256Digest,
    #[serde(default)]
    pub depends_on: Vec<SourceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub schema_version: u8,
    pub kind: ReviewKind,
    pub review_id: String,
    pub project_id: ProjectId,
    pub session_id: CollaborationSessionId,
    pub change_set_id: ChangeSetId,
    pub change_set_digest: Sha256Digest,
    pub reviewer_type: ReviewerType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_principal_id: Option<PrincipalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_project_agent_id: Option<ProjectAgentId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_run_id: Option<AnyRunId>,
    pub verdict: ReviewVerdict,
    pub findings: Vec<ReviewFinding>,
    pub verification_ids: Vec<String>,
    pub review_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewKind {
    #[serde(rename = "review")]
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerType {
    Human,
    ProjectAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    Approved,
    ChangesRequested,
    Rejected,
    UnableToReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewFinding {
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<SourceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_artifact_ids: Vec<ArtifactId>,
    pub state: FindingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Open,
    Resolved,
    Dismissed,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptancePrepareReceipt {
    pub schema_version: u8,
    pub kind: AcceptancePrepareKind,
    pub operation_id: OperationId,
    pub device_id: DeviceId,
    pub session_id: CollaborationSessionId,
    pub change_set_id: ChangeSetId,
    pub change_set_digest: Sha256Digest,
    pub expected_baseline_id: BaselineId,
    pub expected_baseline_revision: u64,
    pub expected_baseline_digest: Sha256Digest,
    pub state: PrepareState,
    pub prepared_sources: Vec<PreparedSource>,
    pub receipt_digest: Sha256Digest,
    pub prepared_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptancePrepareKind {
    #[serde(rename = "acceptance_prepare_receipt")]
    AcceptancePrepareReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepareState {
    Prepared,
    Aborted,
    Conflict,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSource {
    pub source_id: SourceId,
    pub source_change_digest: Sha256Digest,
    pub prepared_reference: String,
    pub target_state_digest: Sha256Digest,
    pub custody: Vec<CustodyReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceReceipt {
    pub schema_version: u8,
    pub kind: AcceptanceKind,
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub session_id: CollaborationSessionId,
    pub change_set_id: ChangeSetId,
    pub change_set_digest: Sha256Digest,
    pub prepare_receipt_digest: Sha256Digest,
    pub previous_baseline_id: BaselineId,
    pub previous_baseline_revision: u64,
    pub new_baseline_id: BaselineId,
    pub new_baseline_revision: u64,
    pub new_baseline_digest: Sha256Digest,
    pub state: AcceptanceState,
    pub accepted_by_principal_id: PrincipalId,
    pub accepted_by_client_id: String,
    pub receipt_digest: Sha256Digest,
    pub accepted_at: UtcTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<UtcTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptanceKind {
    #[serde(rename = "acceptance_receipt")]
    AcceptanceReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceState {
    Committed,
    FinalizationPending,
    Finalized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterializationReceipt {
    pub schema_version: u8,
    pub kind: MaterializationKind,
    pub operation_id: OperationId,
    pub device_id: DeviceId,
    pub session_id: CollaborationSessionId,
    pub baseline_id: BaselineId,
    pub baseline_revision: u64,
    pub baseline_digest: Sha256Digest,
    pub mode: MaterializationMode,
    pub sources: Vec<MaterializedSource>,
    pub state: MaterializationReceiptState,
    pub receipt_digest: Sha256Digest,
    pub observed_at: UtcTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationKind {
    #[serde(rename = "materialization_receipt")]
    MaterializationReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationMode {
    SessionRef,
    CreateBranch,
    FastForward,
    ManagedFolderApply,
    Replicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationReceiptState {
    Complete,
    Partial,
    Conflicted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterializedSource {
    pub source_id: SourceId,
    pub target_location_id: LocationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_old_state_digest: Option<Sha256Digest>,
    pub target_state_digest: Sha256Digest,
    pub state: MaterializedSourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializedSourceState {
    Materialized,
    Pending,
    Conflicted,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireValidationError {
    #[error("schemaVersion must be 1")]
    SchemaVersion,
    #[error("schema collection cardinality is invalid: {0}")]
    Cardinality(&'static str),
    #[error("sourceChanges contains a duplicate Source")]
    DuplicateSource,
    #[error("applicationOrder must contain every changed Source exactly once")]
    ApplicationOrder,
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

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("authoritative example is JSON")
    }

    #[test]
    fn change_set_fixture_is_exact_serde_wire_shape() {
        let expected = json(include_str!(
            "../../../spec/examples/changeset/change-set-multi-source.json"
        ));
        let record: ChangeSet = serde_json::from_value(expected.clone()).unwrap();
        record.validate().unwrap();
        assert_eq!(serde_json::to_value(record).unwrap(), expected);
    }

    #[test]
    fn related_record_fixtures_round_trip_exactly() {
        for fixture in [
            include_str!("../../../spec/examples/changeset/baseline-initial.json"),
            include_str!("../../../spec/examples/changeset/review-approved.json"),
            include_str!("../../../spec/examples/changeset/acceptance-prepared.json"),
            include_str!("../../../spec/examples/changeset/acceptance-committed.json"),
            include_str!("../../../spec/examples/changeset/materialization-finalized.json"),
        ] {
            let expected = json(fixture);
            let record: Record = serde_json::from_value(expected.clone()).unwrap();
            assert_eq!(serde_json::to_value(record).unwrap(), expected);
        }
    }

    #[test]
    fn serde_outputs_validate_against_authoritative_schema() {
        let schema = json(include_str!(
            "../../../spec/schemas/changeset-v1.schema.json"
        ));
        let validator = jsonschema::validator_for(&schema).unwrap();
        for fixture in [
            include_str!("../../../spec/examples/changeset/baseline-initial.json"),
            include_str!("../../../spec/examples/changeset/change-set-multi-source.json"),
            include_str!("../../../spec/examples/changeset/review-approved.json"),
            include_str!("../../../spec/examples/changeset/acceptance-prepared.json"),
            include_str!("../../../spec/examples/changeset/acceptance-committed.json"),
            include_str!("../../../spec/examples/changeset/materialization-finalized.json"),
        ] {
            let value = json(fixture);
            let record: Record = serde_json::from_value(value).unwrap();
            let output = serde_json::to_value(record).unwrap();
            assert!(validator.is_valid(&output));
        }
    }
}
