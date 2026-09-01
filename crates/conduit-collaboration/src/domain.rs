use std::collections::BTreeMap;

use conduit_domain::{
    AssignmentId, ChangeSetId, CollaborationSessionId, ContextSnapshotId, DeviceId, MessageId,
    PrincipalId, ProjectAgentId, ProjectId, RunId, Sha256Digest, SourceId, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CollaborationError> {
        let value = value.into();
        validate_opaque_id(&value, "task_")?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Planner,
    Implementer,
    Reviewer,
    Tester,
    Researcher,
    Integrator,
}

impl AgentRole {
    pub const fn source_permission(self) -> SourcePermission {
        match self {
            Self::Reviewer | Self::Researcher => SourcePermission::ReadOnly,
            Self::Planner => SourcePermission::ReadOnly,
            Self::Implementer | Self::Tester | Self::Integrator => SourcePermission::ReadWrite,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePermission {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessScope {
    Restricted,
    FullProject,
    FullUser,
    FullDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    Always,
    OnRisk,
    OnRequest,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    LoginRequired,
    CapabilityMissing,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectAgent {
    pub project_agent_id: ProjectAgentId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub adapter_id: String,
    pub role: AgentRole,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub device_preference: Option<DeviceId>,
    pub runtime_preference: String,
    pub access_default: AccessScope,
    pub approval_default: ApprovalPolicy,
    pub readiness: ReadinessState,
    pub capability_receipt_digest: Option<Sha256Digest>,
    pub current_run: Option<RunId>,
    pub recent_runs: Vec<RunId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageOrigin {
    Human,
    McpClient,
    Agent,
    System,
    ImportedLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionIntent {
    Reference,
    ProposedAssignment,
    Assignment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuredMention {
    pub project_agent_id: ProjectAgentId,
    pub intent: MentionIntent,
    pub source_component_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageRevision {
    pub message_id: MessageId,
    pub revision: u64,
    pub session_id: CollaborationSessionId,
    pub author: PrincipalId,
    pub origin: MessageOrigin,
    pub body_digest: Sha256Digest,
    pub body: String,
    pub mentions: Vec<StructuredMention>,
    pub attachment_ids: Vec<String>,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Draft,
    Queued,
    Active,
    WaitingInput,
    WaitingApproval,
    ReadyForReview,
    Accepted,
    Rejected,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentTransition {
    pub from: AssignmentState,
    pub to: AssignmentState,
    pub actor: PrincipalId,
    pub reason_code: String,
    pub at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRevisionSelection {
    pub source_id: SourceId,
    pub state_digest: Sha256Digest,
    pub permission: SourcePermission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assignment {
    pub assignment_id: AssignmentId,
    pub session_id: CollaborationSessionId,
    pub source_message_id: Option<MessageId>,
    pub primary_assignee: ProjectAgentId,
    pub objective: String,
    pub constraints: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub context_snapshot_id: ContextSnapshotId,
    pub source_revisions: Vec<SourceRevisionSelection>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub runtime_kind: String,
    pub device_id: Option<DeviceId>,
    pub access_scope: AccessScope,
    pub approval_policy: ApprovalPolicy,
    pub state: AssignmentState,
    pub transitions: Vec<AssignmentTransition>,
    pub orchestration: OrchestrationLineage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrchestrationLineage {
    pub root_assignment_id: AssignmentId,
    pub parent_assignment_id: Option<AssignmentId>,
    pub depth: u16,
    pub run_count: u32,
    pub cost_microunits: u64,
    pub elapsed_seconds: u64,
    pub visited_agents: Vec<ProjectAgentId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrchestrationLimits {
    pub max_depth: u16,
    pub max_runs: u32,
    pub max_cost_microunits: u64,
    pub max_elapsed_seconds: u64,
    pub max_concurrent_runs_per_agent: u16,
    pub allow_cycles: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Backlog,
    Ready,
    InProgress,
    Blocked,
    Review,
    Done,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Task {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub title: String,
    pub status: TaskStatus,
    pub dependencies: Vec<TaskId>,
    pub message_ids: Vec<MessageId>,
    pub assignment_ids: Vec<AssignmentId>,
    pub run_ids: Vec<RunId>,
    pub change_set_ids: Vec<ChangeSetId>,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOperationKind {
    AdditionalInstruction,
    ReadOnlyQuestion,
    ImmediateSteer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentInputOperation {
    pub operation_id: String,
    pub assignment_id: AssignmentId,
    pub kind: InputOperationKind,
    pub context_snapshot_id: ContextSnapshotId,
    pub content_digest: Sha256Digest,
    pub actor: PrincipalId,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CollaborationError {
    #[error("identifier is invalid")]
    InvalidId,
    #[error("field exceeds its byte bound")]
    FieldTooLarge,
    #[error("record was not found")]
    NotFound,
    #[error("record already exists")]
    AlreadyExists,
    #[error("revision compare-and-swap failed")]
    RevisionConflict,
    #[error("structured assignment mention is invalid")]
    InvalidAssignmentMention,
    #[error("assignment state transition is invalid")]
    InvalidTransition,
    #[error("agent is not ready")]
    AgentNotReady,
    #[error("agent concurrency limit was reached")]
    ConcurrencyLimit,
    #[error("orchestration depth limit was reached")]
    DepthLimit,
    #[error("orchestration run limit was reached")]
    RunLimit,
    #[error("orchestration cost limit was reached")]
    CostLimit,
    #[error("orchestration time limit was reached")]
    TimeLimit,
    #[error("orchestration cycle is forbidden")]
    CycleForbidden,
    #[error("task dependency cycle is forbidden")]
    TaskDependencyCycle,
    #[error("digest operation failed")]
    Digest,
    #[error("collaboration store is unavailable")]
    StoreUnavailable,
}

pub(crate) fn validate_bounds(value: &str, max: usize) -> Result<(), CollaborationError> {
    if value.is_empty() || value.len() > max {
        Err(CollaborationError::FieldTooLarge)
    } else {
        Ok(())
    }
}

fn validate_opaque_id(value: &str, prefix: &str) -> Result<(), CollaborationError> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(CollaborationError::InvalidId)?;
    if !(8..=128).contains(&suffix.len())
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Err(CollaborationError::InvalidId)
    } else {
        Ok(())
    }
}

pub(crate) fn valid_transition(from: AssignmentState, to: AssignmentState) -> bool {
    use AssignmentState::*;
    matches!(
        (from, to),
        (Draft, Queued | Cancelled)
            | (Queued, Active | Cancelled | Failed)
            | (
                Active,
                WaitingInput | WaitingApproval | ReadyForReview | Failed | Cancelled
            )
            | (WaitingInput, Active | Cancelled | Failed)
            | (WaitingApproval, Active | Cancelled | Failed)
            | (ReadyForReview, Accepted | Rejected | Active)
            | (Rejected, Active)
    )
}

pub type TaskMap = BTreeMap<TaskId, Task>;
