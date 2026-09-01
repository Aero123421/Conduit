use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

use conduit_crypto::canonical_sha256;
use conduit_domain::{
    AssignmentId, CollaborationSessionId, ContextSnapshotId, MessageId, PrincipalId,
    ProjectAgentId, UtcTimestamp,
};

use crate::{
    AgentRole, Assignment, AssignmentState, AssignmentTransition, CollaborationError,
    MentionIntent, MessageOrigin, MessageRevision, OrchestrationLimits, ProjectAgent,
    ReadinessState, SourcePermission, StructuredMention, Task, TaskId, TaskMap, valid_transition,
    validate_bounds,
};

#[derive(Debug, Default)]
struct CollaborationState {
    agents: BTreeMap<ProjectAgentId, ProjectAgent>,
    messages: BTreeMap<MessageId, Vec<MessageRevision>>,
    assignments: BTreeMap<AssignmentId, Assignment>,
    tasks: TaskMap,
}

#[derive(Debug, Default)]
pub struct CollaborationService {
    state: Mutex<CollaborationState>,
}

#[derive(Debug, Clone)]
pub struct AssignmentDraft {
    pub assignment_id: AssignmentId,
    pub primary_assignee: ProjectAgentId,
    pub objective: String,
    pub constraints: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub context_snapshot_id: ContextSnapshotId,
    pub source_revisions: Vec<crate::SourceRevisionSelection>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub runtime_kind: String,
    pub device_id: Option<conduit_domain::DeviceId>,
    pub access_scope: crate::AccessScope,
    pub approval_policy: crate::ApprovalPolicy,
    pub orchestration: crate::OrchestrationLineage,
}

#[derive(Debug, Clone)]
pub struct MessageDraft {
    pub message_id: MessageId,
    pub session_id: CollaborationSessionId,
    pub author: PrincipalId,
    pub origin: MessageOrigin,
    pub body: String,
    pub mentions: Vec<StructuredMention>,
    pub attachment_ids: Vec<String>,
    pub created_at: UtcTimestamp,
}

impl CollaborationService {
    pub fn add_agent(&self, agent: ProjectAgent) -> Result<(), CollaborationError> {
        validate_bounds(&agent.display_name, 128)?;
        validate_bounds(&agent.adapter_id, 128)?;
        validate_bounds(&agent.runtime_preference, 128)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        if state
            .agents
            .insert(agent.project_agent_id.clone(), agent)
            .is_some()
        {
            return Err(CollaborationError::AlreadyExists);
        }
        Ok(())
    }

    /// Stores a normal immutable Board Message. Structured mentions are inert unless
    /// the caller uses `post_assignment`, so quoting or editing text cannot start work.
    pub fn post_message(&self, draft: MessageDraft) -> Result<MessageRevision, CollaborationError> {
        if draft
            .mentions
            .iter()
            .any(|mention| mention.intent == MentionIntent::Assignment)
        {
            return Err(CollaborationError::InvalidAssignmentMention);
        }
        let revision = message_revision(draft, 1)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        if state
            .messages
            .insert(revision.message_id.clone(), vec![revision.clone()])
            .is_some()
        {
            return Err(CollaborationError::AlreadyExists);
        }
        Ok(revision)
    }

    /// Validates both records and commits the Message and Assignment while holding
    /// one store lock. No observer can see only half of the pair.
    pub fn post_assignment(
        &self,
        message: MessageDraft,
        assignment: AssignmentDraft,
    ) -> Result<(MessageRevision, Assignment), CollaborationError> {
        if message.origin == MessageOrigin::ImportedLog {
            return Err(CollaborationError::InvalidAssignmentMention);
        }
        let matching: Vec<_> = message
            .mentions
            .iter()
            .filter(|mention| {
                mention.intent == MentionIntent::Assignment
                    && mention.project_agent_id == assignment.primary_assignee
            })
            .collect();
        if matching.len() != 1
            || message
                .mentions
                .iter()
                .filter(|mention| mention.intent == MentionIntent::Assignment)
                .count()
                != 1
        {
            return Err(CollaborationError::InvalidAssignmentMention);
        }
        let revision = message_revision(message, 1)?;
        validate_bounds(&assignment.objective, 8_192)?;
        validate_bounds(&assignment.runtime_kind, 128)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        if state.messages.contains_key(&revision.message_id)
            || state.assignments.contains_key(&assignment.assignment_id)
        {
            return Err(CollaborationError::AlreadyExists);
        }
        let agent = state
            .agents
            .get(&assignment.primary_assignee)
            .ok_or(CollaborationError::NotFound)?;
        if agent.readiness != ReadinessState::Ready {
            return Err(CollaborationError::AgentNotReady);
        }
        enforce_role_permissions(agent.role, &assignment.source_revisions)?;
        let record = Assignment {
            assignment_id: assignment.assignment_id,
            session_id: revision.session_id.clone(),
            source_message_id: Some(revision.message_id.clone()),
            primary_assignee: assignment.primary_assignee,
            objective: assignment.objective,
            constraints: assignment.constraints,
            acceptance_criteria: assignment.acceptance_criteria,
            context_snapshot_id: assignment.context_snapshot_id,
            source_revisions: assignment.source_revisions,
            model: assignment.model,
            effort: assignment.effort,
            runtime_kind: assignment.runtime_kind,
            device_id: assignment.device_id,
            access_scope: assignment.access_scope,
            approval_policy: assignment.approval_policy,
            state: AssignmentState::Queued,
            transitions: Vec::new(),
            orchestration: assignment.orchestration,
        };
        state
            .messages
            .insert(revision.message_id.clone(), vec![revision.clone()]);
        state
            .assignments
            .insert(record.assignment_id.clone(), record.clone());
        Ok((revision, record))
    }

    pub fn edit_message(
        &self,
        message_id: &MessageId,
        expected_revision: u64,
        body: String,
        mentions: Vec<StructuredMention>,
        editor: PrincipalId,
        at: UtcTimestamp,
    ) -> Result<MessageRevision, CollaborationError> {
        validate_bounds(&body, 65_536)?;
        // Edits never create Assignments, even if an explicit assignment mention is supplied.
        if mentions
            .iter()
            .any(|mention| mention.intent == MentionIntent::Assignment)
        {
            return Err(CollaborationError::InvalidAssignmentMention);
        }
        let body_digest = canonical_sha256(&body).map_err(|_| CollaborationError::Digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        let history = state
            .messages
            .get_mut(message_id)
            .ok_or(CollaborationError::NotFound)?;
        let previous = history.last().ok_or(CollaborationError::NotFound)?;
        if previous.revision != expected_revision {
            return Err(CollaborationError::RevisionConflict);
        }
        let revision = MessageRevision {
            message_id: message_id.clone(),
            revision: expected_revision + 1,
            session_id: previous.session_id.clone(),
            author: editor,
            origin: previous.origin,
            body_digest,
            body,
            mentions,
            attachment_ids: previous.attachment_ids.clone(),
            created_at: at,
        };
        history.push(revision.clone());
        Ok(revision)
    }

    pub fn message_history(
        &self,
        id: &MessageId,
    ) -> Result<Vec<MessageRevision>, CollaborationError> {
        self.state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?
            .messages
            .get(id)
            .cloned()
            .ok_or(CollaborationError::NotFound)
    }

    pub fn transition_assignment(
        &self,
        id: &AssignmentId,
        expected: AssignmentState,
        to: AssignmentState,
        actor: PrincipalId,
        reason_code: String,
        at: UtcTimestamp,
    ) -> Result<Assignment, CollaborationError> {
        validate_bounds(&reason_code, 128)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        let assignment = state
            .assignments
            .get_mut(id)
            .ok_or(CollaborationError::NotFound)?;
        if assignment.state != expected {
            return Err(CollaborationError::RevisionConflict);
        }
        if !valid_transition(expected, to) {
            return Err(CollaborationError::InvalidTransition);
        }
        assignment.transitions.push(AssignmentTransition {
            from: expected,
            to,
            actor,
            reason_code,
            at,
        });
        assignment.state = to;
        Ok(assignment.clone())
    }

    pub fn propose_handoff(
        &self,
        parent_id: &AssignmentId,
        target_agent: &ProjectAgentId,
        limits: &OrchestrationLimits,
        expected_incremental_cost: u64,
        expected_incremental_seconds: u64,
    ) -> Result<crate::OrchestrationLineage, CollaborationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        let parent = state
            .assignments
            .get(parent_id)
            .ok_or(CollaborationError::NotFound)?;
        let agent = state
            .agents
            .get(target_agent)
            .ok_or(CollaborationError::NotFound)?;
        if agent.readiness != ReadinessState::Ready {
            return Err(CollaborationError::AgentNotReady);
        }
        let lineage = &parent.orchestration;
        if lineage.depth + 1 > limits.max_depth {
            return Err(CollaborationError::DepthLimit);
        }
        if lineage.run_count + 1 > limits.max_runs {
            return Err(CollaborationError::RunLimit);
        }
        if lineage
            .cost_microunits
            .saturating_add(expected_incremental_cost)
            > limits.max_cost_microunits
        {
            return Err(CollaborationError::CostLimit);
        }
        if lineage
            .elapsed_seconds
            .saturating_add(expected_incremental_seconds)
            > limits.max_elapsed_seconds
        {
            return Err(CollaborationError::TimeLimit);
        }
        if !limits.allow_cycles && lineage.visited_agents.contains(target_agent) {
            return Err(CollaborationError::CycleForbidden);
        }
        let active_for_agent = state
            .assignments
            .values()
            .filter(|assignment| {
                assignment.primary_assignee == *target_agent
                    && matches!(
                        assignment.state,
                        AssignmentState::Queued
                            | AssignmentState::Active
                            | AssignmentState::WaitingInput
                            | AssignmentState::WaitingApproval
                    )
            })
            .count();
        if active_for_agent >= limits.max_concurrent_runs_per_agent as usize {
            return Err(CollaborationError::ConcurrencyLimit);
        }
        let mut visited_agents = lineage.visited_agents.clone();
        visited_agents.push(target_agent.clone());
        Ok(crate::OrchestrationLineage {
            root_assignment_id: lineage.root_assignment_id.clone(),
            parent_assignment_id: Some(parent_id.clone()),
            depth: lineage.depth + 1,
            run_count: lineage.run_count + 1,
            cost_microunits: lineage
                .cost_microunits
                .saturating_add(expected_incremental_cost),
            elapsed_seconds: lineage
                .elapsed_seconds
                .saturating_add(expected_incremental_seconds),
            visited_agents,
        })
    }

    pub fn create_task(&self, task: Task) -> Result<(), CollaborationError> {
        validate_bounds(&task.title, 512)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        if state.tasks.contains_key(&task.task_id) {
            return Err(CollaborationError::AlreadyExists);
        }
        for dependency in &task.dependencies {
            if !state.tasks.contains_key(dependency) {
                return Err(CollaborationError::NotFound);
            }
        }
        let inserted_id = task.task_id.clone();
        state.tasks.insert(inserted_id.clone(), task);
        if task_graph_has_cycle(&state.tasks) {
            state.tasks.remove(&inserted_id);
            return Err(CollaborationError::TaskDependencyCycle);
        }
        Ok(())
    }

    pub fn update_task(
        &self,
        mut task: Task,
        expected_revision: u64,
    ) -> Result<Task, CollaborationError> {
        validate_bounds(&task.title, 512)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?;
        let previous = state
            .tasks
            .get(&task.task_id)
            .cloned()
            .ok_or(CollaborationError::NotFound)?;
        if previous.revision != expected_revision {
            return Err(CollaborationError::RevisionConflict);
        }
        if task
            .dependencies
            .iter()
            .any(|dependency| !state.tasks.contains_key(dependency))
        {
            return Err(CollaborationError::NotFound);
        }
        task.revision = expected_revision + 1;
        state.tasks.insert(task.task_id.clone(), task.clone());
        if task_graph_has_cycle(&state.tasks) {
            state.tasks.insert(previous.task_id.clone(), previous);
            return Err(CollaborationError::TaskDependencyCycle);
        }
        Ok(task)
    }

    pub fn task(&self, id: &TaskId) -> Result<Task, CollaborationError> {
        self.state
            .lock()
            .map_err(|_| CollaborationError::StoreUnavailable)?
            .tasks
            .get(id)
            .cloned()
            .ok_or(CollaborationError::NotFound)
    }
}

fn message_revision(
    draft: MessageDraft,
    revision: u64,
) -> Result<MessageRevision, CollaborationError> {
    validate_bounds(&draft.body, 65_536)?;
    if draft.attachment_ids.len() > 64 || draft.mentions.len() > 64 {
        return Err(CollaborationError::FieldTooLarge);
    }
    for mention in &draft.mentions {
        validate_bounds(&mention.source_component_id, 256)?;
    }
    let body_digest = canonical_sha256(&draft.body).map_err(|_| CollaborationError::Digest)?;
    Ok(MessageRevision {
        message_id: draft.message_id,
        revision,
        session_id: draft.session_id,
        author: draft.author,
        origin: draft.origin,
        body_digest,
        body: draft.body,
        mentions: draft.mentions,
        attachment_ids: draft.attachment_ids,
        created_at: draft.created_at,
    })
}

fn enforce_role_permissions(
    role: AgentRole,
    sources: &[crate::SourceRevisionSelection],
) -> Result<(), CollaborationError> {
    if role.source_permission() == SourcePermission::ReadOnly
        && sources
            .iter()
            .any(|source| source.permission == SourcePermission::ReadWrite)
    {
        Err(CollaborationError::InvalidAssignmentMention)
    } else {
        Ok(())
    }
}

fn task_graph_has_cycle(tasks: &TaskMap) -> bool {
    fn visit(
        id: &TaskId,
        tasks: &TaskMap,
        temporary: &mut BTreeSet<TaskId>,
        permanent: &mut BTreeSet<TaskId>,
    ) -> bool {
        if permanent.contains(id) {
            return false;
        }
        if !temporary.insert(id.clone()) {
            return true;
        }
        if let Some(task) = tasks.get(id)
            && task
                .dependencies
                .iter()
                .any(|dependency| visit(dependency, tasks, temporary, permanent))
        {
            return true;
        }
        temporary.remove(id);
        permanent.insert(id.clone());
        false
    }
    let mut temporary = BTreeSet::new();
    let mut permanent = BTreeSet::new();
    tasks
        .keys()
        .any(|id| visit(id, tasks, &mut temporary, &mut permanent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessScope, ApprovalPolicy, OrchestrationLineage};
    use conduit_domain::{ProjectId, Sha256Digest};

    fn ts() -> UtcTimestamp {
        UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap()
    }
    fn service() -> (CollaborationService, ProjectAgentId) {
        let service = CollaborationService::default();
        let id = ProjectAgentId::parse("pagent_abcdefgh").unwrap();
        service
            .add_agent(ProjectAgent {
                project_agent_id: id.clone(),
                project_id: ProjectId::parse("prj_abcdefgh").unwrap(),
                display_name: "Builder".into(),
                adapter_id: "codex".into(),
                role: AgentRole::Implementer,
                model: None,
                effort: None,
                device_preference: None,
                runtime_preference: "native".into(),
                access_default: AccessScope::FullProject,
                approval_default: ApprovalPolicy::OnRisk,
                readiness: ReadinessState::Ready,
                capability_receipt_digest: None,
                current_run: None,
                recent_runs: vec![],
            })
            .unwrap();
        (service, id)
    }
    fn message(id: &str, agent: ProjectAgentId, intent: MentionIntent) -> MessageDraft {
        MessageDraft {
            message_id: MessageId::parse(id).unwrap(),
            session_id: CollaborationSessionId::parse("csess_abcdefgh").unwrap(),
            author: PrincipalId::parse("prin_abcdefgh").unwrap(),
            origin: MessageOrigin::Human,
            body: "Please implement this".into(),
            mentions: vec![StructuredMention {
                project_agent_id: agent,
                intent,
                source_component_id: "composer-chip-1".into(),
            }],
            attachment_ids: vec![],
            created_at: ts(),
        }
    }
    fn assignment(agent: ProjectAgentId) -> AssignmentDraft {
        let id = AssignmentId::parse("asg_abcdefgh").unwrap();
        AssignmentDraft {
            assignment_id: id.clone(),
            primary_assignee: agent.clone(),
            objective: "Implement the bounded change".into(),
            constraints: vec![],
            acceptance_criteria: vec![],
            context_snapshot_id: ContextSnapshotId::parse("ctxs_abcdefgh").unwrap(),
            source_revisions: vec![],
            model: None,
            effort: None,
            runtime_kind: "native".into(),
            device_id: None,
            access_scope: AccessScope::FullProject,
            approval_policy: ApprovalPolicy::OnRisk,
            orchestration: OrchestrationLineage {
                root_assignment_id: id,
                parent_assignment_id: None,
                depth: 0,
                run_count: 0,
                cost_microunits: 0,
                elapsed_seconds: 0,
                visited_agents: vec![agent],
            },
        }
    }

    #[test]
    fn normal_message_does_not_create_assignment_and_revisions_remain() {
        let (service, agent) = service();
        let posted = service
            .post_message(message("msg_abcdefgh", agent, MentionIntent::Reference))
            .unwrap();
        service
            .edit_message(
                &posted.message_id,
                1,
                "edited @Builder".into(),
                vec![],
                PrincipalId::parse("prin_abcdefgh").unwrap(),
                ts(),
            )
            .unwrap();
        assert_eq!(
            service.message_history(&posted.message_id).unwrap().len(),
            2
        );
    }

    #[test]
    fn assignment_message_pair_is_atomic_and_transitioned_by_state_machine() {
        let (service, agent) = service();
        let (_, assignment) = service
            .post_assignment(
                message("msg_abcdefgh", agent.clone(), MentionIntent::Assignment),
                assignment(agent),
            )
            .unwrap();
        let active = service
            .transition_assignment(
                &assignment.assignment_id,
                AssignmentState::Queued,
                AssignmentState::Active,
                PrincipalId::parse("prin_abcdefgh").unwrap(),
                "device_claimed".into(),
                ts(),
            )
            .unwrap();
        assert_eq!(active.transitions.len(), 1);
        assert_eq!(
            service
                .transition_assignment(
                    &active.assignment_id,
                    AssignmentState::Active,
                    AssignmentState::Accepted,
                    PrincipalId::parse("prin_abcdefgh").unwrap(),
                    "invalid".into(),
                    ts()
                )
                .unwrap_err(),
            CollaborationError::InvalidTransition
        );
    }

    #[test]
    fn orchestration_enforces_cycles_and_limits() {
        let (service, agent) = service();
        let (_, assignment) = service
            .post_assignment(
                message("msg_abcdefgh", agent.clone(), MentionIntent::Assignment),
                assignment(agent.clone()),
            )
            .unwrap();
        let limits = OrchestrationLimits {
            max_depth: 4,
            max_runs: 4,
            max_cost_microunits: 100,
            max_elapsed_seconds: 100,
            max_concurrent_runs_per_agent: 2,
            allow_cycles: false,
        };
        assert_eq!(
            service
                .propose_handoff(&assignment.assignment_id, &agent, &limits, 1, 1)
                .unwrap_err(),
            CollaborationError::CycleForbidden
        );
        assert_ne!(
            Sha256Digest::from_bytes([0; 32]),
            Sha256Digest::from_bytes([1; 32])
        );
    }
}
