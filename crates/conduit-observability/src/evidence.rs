use std::collections::{BTreeMap, BTreeSet};

use conduit_crypto::{canonical_sha256, sha256_bytes};
use conduit_domain::{AnyRunId, Sha256Digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{EvidenceLevel, NormalizedEvent, RetentionClass, Sensitivity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSearchRecord {
    pub run_id: AnyRunId,
    pub assignment_id: Option<String>,
    pub device_id: String,
    pub runtime_class: String,
    pub adapter_id: Option<String>,
    pub model: Option<String>,
    pub terminal_state: Option<String>,
    pub failure_classes: Vec<FailureClass>,
    pub searchable_labels: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RunSearchQuery {
    pub text: Option<String>,
    pub device_id: Option<String>,
    pub runtime_class: Option<String>,
    pub terminal_state: Option<String>,
    pub failure_class: Option<FailureClass>,
    pub max_results: usize,
}

pub fn search_runs(records: &[RunSearchRecord], query: &RunSearchQuery) -> Vec<RunSearchRecord> {
    let needle = query.text.as_deref().unwrap_or("").to_lowercase();
    records
        .iter()
        .filter(|record| {
            query
                .device_id
                .as_ref()
                .is_none_or(|value| record.device_id == *value)
                && query
                    .runtime_class
                    .as_ref()
                    .is_none_or(|value| record.runtime_class == *value)
                && query
                    .terminal_state
                    .as_ref()
                    .is_none_or(|value| record.terminal_state.as_ref() == Some(value))
                && query
                    .failure_class
                    .is_none_or(|value| record.failure_classes.contains(&value))
                && (needle.is_empty()
                    || record
                        .searchable_labels
                        .iter()
                        .any(|label| label.to_lowercase().contains(&needle)))
        })
        .take(query.max_results.clamp(1, 1_000))
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct EventSearchQuery {
    pub event_type_prefix: Option<String>,
    pub component: Option<String>,
    pub evidence_level: Option<EvidenceLevel>,
    pub minimum_sequence: Option<u64>,
    pub max_results: usize,
}

pub fn search_events(events: &[NormalizedEvent], query: &EventSearchQuery) -> Vec<NormalizedEvent> {
    events
        .iter()
        .filter(|event| {
            query
                .event_type_prefix
                .as_ref()
                .is_none_or(|value| event.event_type.starts_with(value))
                && query
                    .component
                    .as_ref()
                    .is_none_or(|value| event.source_component == *value)
                && query
                    .evidence_level
                    .is_none_or(|value| event.evidence_level == value)
                && query
                    .minimum_sequence
                    .is_none_or(|value| event.sequence.get() >= value)
        })
        .take(query.max_results.clamp(1, 1_000))
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    AssignmentContext,
    SourceWorkspace,
    RuntimeProvisioning,
    ResourceAdmission,
    Authentication,
    AdapterProtocol,
    ModelProvider,
    ToolCommand,
    PolicyApproval,
    InstructionConflict,
    SkillProcedure,
    TestVerification,
    DeviceRecovery,
    StorageTraceIntegrity,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureObservation {
    pub run_id: AnyRunId,
    pub class: FailureClass,
    pub stable_code: String,
    pub component: String,
    pub evidence_refs: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureCluster {
    pub cluster_id: String,
    pub class: FailureClass,
    pub stable_code: String,
    pub component: String,
    pub run_ids: Vec<AnyRunId>,
    pub mean_confidence: f32,
}

pub fn cluster_failures(observations: &[FailureObservation]) -> Vec<FailureCluster> {
    let mut grouped: BTreeMap<(FailureClass, String, String), Vec<&FailureObservation>> =
        BTreeMap::new();
    for observation in observations {
        grouped
            .entry((
                observation.class,
                observation.stable_code.clone(),
                observation.component.clone(),
            ))
            .or_default()
            .push(observation);
    }
    grouped
        .into_iter()
        .map(|((class, stable_code, component), values)| {
            let identity = format!("{class:?}\n{stable_code}\n{component}");
            FailureCluster {
                cluster_id: format!(
                    "failure-{}",
                    &sha256_bytes(identity.as_bytes()).to_string()[..20]
                ),
                class,
                stable_code,
                component,
                run_ids: values.iter().map(|value| value.run_id.clone()).collect(),
                mean_confidence: values.iter().map(|value| value.confidence).sum::<f32>()
                    / values.len() as f32,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Followed,
    Violated,
    Unknown,
    NotRelevant,
    Passed,
    Failed,
    Regressed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstructionEvidenceItem {
    pub instruction_id: String,
    pub version_digest: Sha256Digest,
    pub discovered: bool,
    pub eligible: bool,
    pub loaded: bool,
    pub skipped_reason: Option<String>,
    pub truncated: bool,
    pub overridden_by: Option<String>,
    pub outcome: EvidenceOutcome,
    pub evidence_level: EvidenceLevel,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillEvidenceItem {
    pub skill_id: String,
    pub version_digest: Sha256Digest,
    pub discovered: bool,
    pub eligible: bool,
    pub triggered: bool,
    pub loaded: bool,
    pub resource_used: bool,
    pub procedure_outcome: EvidenceOutcome,
    pub verification_outcome: EvidenceOutcome,
    pub efficiency_delta_millis: Option<i64>,
    pub regression: bool,
    pub evidence_level: EvidenceLevel,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReport<T> {
    pub run_id: AnyRunId,
    pub items: Vec<T>,
    pub explicit_count: u64,
    pub observed_count: u64,
    pub inferred_count: u64,
    pub unknown_count: u64,
}

pub fn instruction_report(
    run_id: AnyRunId,
    items: Vec<InstructionEvidenceItem>,
) -> EvidenceReport<InstructionEvidenceItem> {
    report(run_id, items, |item| item.evidence_level)
}
pub fn skill_report(
    run_id: AnyRunId,
    items: Vec<SkillEvidenceItem>,
) -> EvidenceReport<SkillEvidenceItem> {
    report(run_id, items, |item| item.evidence_level)
}
fn report<T>(
    run_id: AnyRunId,
    items: Vec<T>,
    level: impl Fn(&T) -> EvidenceLevel,
) -> EvidenceReport<T> {
    let mut counts = [0u64; 4];
    for item in &items {
        counts[level(item) as usize] += 1;
    }
    EvidenceReport {
        run_id,
        items,
        explicit_count: counts[EvidenceLevel::Explicit as usize],
        observed_count: counts[EvidenceLevel::Observed as usize],
        inferred_count: counts[EvidenceLevel::Inferred as usize],
        unknown_count: counts[EvidenceLevel::Unknown as usize],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComparisonFactors {
    pub task_digest: Sha256Digest,
    pub base_state_digest: Sha256Digest,
    pub project_context_revision: u64,
    pub session_context_revision: u64,
    pub environment_digest: Sha256Digest,
    pub device_class: String,
    pub runtime_class: String,
    pub adapter_version: String,
    pub model: String,
    pub effort: String,
    pub access_policy_digest: Sha256Digest,
    pub approval_policy_digest: Sha256Digest,
    pub instruction_catalog_digest: Sha256Digest,
    pub skill_catalog_digest: Sha256Digest,
    pub verification_policy_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunOutcome {
    pub run_id: AnyRunId,
    pub factors: ComparisonFactors,
    pub success: bool,
    pub score: Option<f64>,
    pub duration_millis: u64,
    pub reported_usage: Option<u64>,
    pub human_corrections: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonDesign {
    Observational,
    Matched,
    Controlled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComparisonResult {
    pub left_run_id: AnyRunId,
    pub right_run_id: AnyRunId,
    pub requested_design: ComparisonDesign,
    pub effective_design: ComparisonDesign,
    pub unmatched_confounders: Vec<String>,
    pub causal_claim_allowed: bool,
    pub success_delta: i8,
    pub score_delta: Option<f64>,
    pub duration_delta_millis: i128,
    pub usage_delta: Option<i128>,
}

pub fn compare_runs(
    left: &RunOutcome,
    right: &RunOutcome,
    requested: ComparisonDesign,
) -> ComparisonResult {
    let confounders = factor_differences(&left.factors, &right.factors);
    let effective = if requested == ComparisonDesign::Controlled && confounders.is_empty() {
        ComparisonDesign::Controlled
    } else if requested != ComparisonDesign::Observational && confounders.is_empty() {
        ComparisonDesign::Matched
    } else {
        ComparisonDesign::Observational
    };
    ComparisonResult {
        left_run_id: left.run_id.clone(),
        right_run_id: right.run_id.clone(),
        requested_design: requested,
        effective_design: effective,
        causal_claim_allowed: effective == ComparisonDesign::Controlled,
        unmatched_confounders: confounders,
        success_delta: i8::from(right.success) - i8::from(left.success),
        score_delta: left
            .score
            .zip(right.score)
            .map(|(left, right)| right - left),
        duration_delta_millis: right.duration_millis as i128 - left.duration_millis as i128,
        usage_delta: left
            .reported_usage
            .zip(right.reported_usage)
            .map(|(left, right)| right as i128 - left as i128),
    }
}

fn factor_differences(left: &ComparisonFactors, right: &ComparisonFactors) -> Vec<String> {
    let mut differences = Vec::new();
    macro_rules! compare {
        ($field:ident) => {
            if left.$field != right.$field {
                differences.push(stringify!($field).into());
            }
        };
    }
    compare!(task_digest);
    compare!(base_state_digest);
    compare!(project_context_revision);
    compare!(session_context_revision);
    compare!(environment_digest);
    compare!(device_class);
    compare!(runtime_class);
    compare!(adapter_version);
    compare!(model);
    compare!(effort);
    compare!(access_policy_digest);
    compare!(approval_policy_digest);
    compare!(instruction_catalog_digest);
    compare!(skill_catalog_digest);
    compare!(verification_policy_digest);
    differences
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionRolloutState {
    Candidate,
    Canary,
    Default,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateImprovement {
    pub proposal_id: String,
    pub target_kind: String,
    pub current_version_digest: Sha256Digest,
    pub candidate_version_digest: Sha256Digest,
    pub supporting_comparison_ids: Vec<String>,
    pub regression_checks: Vec<String>,
    pub rollout_state: VersionRolloutState,
    pub automatic_apply: bool,
}

impl CandidateImprovement {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.automatic_apply
            || self.supporting_comparison_ids.is_empty()
            || self.regression_checks.is_empty()
        {
            Err(EvidenceError::UnsafeImprovementProposal)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OTelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    pub start_time_unix_nano: Option<u64>,
    pub attributes: BTreeMap<String, Value>,
    pub events: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OTelExportBatch {
    pub conduit_schema_version: String,
    pub exporter_version: String,
    pub semantic_convention_version: String,
    pub spans: Vec<OTelSpan>,
    pub omitted_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OTelExporter {
    pub exporter_version: String,
    pub semantic_convention_version: String,
    pub include_project_content: bool,
}

impl OTelExporter {
    pub fn export(&self, run_id: &AnyRunId, events: &[NormalizedEvent]) -> OTelExportBatch {
        let mut spans = Vec::new();
        let mut omitted = BTreeSet::new();
        for event in events {
            let mut attributes = BTreeMap::from([
                (
                    "conduit.run.id".into(),
                    Value::String(run_id.as_str().into()),
                ),
                (
                    "conduit.event.type".into(),
                    Value::String(event.event_type.clone()),
                ),
                (
                    "conduit.evidence.level".into(),
                    Value::String(format!("{:?}", event.evidence_level).to_lowercase()),
                ),
            ]);
            if event.event_type == "agent.usage"
                && let Some(model) = event.payload.get("model")
            {
                attributes.insert("gen_ai.request.model".into(), model.clone());
            }
            let export_payload = self.include_project_content
                && event.sensitivity <= Sensitivity::ProjectContent
                && event.retention != RetentionClass::R3;
            let events = if export_payload {
                vec![json!({"name": event.event_type, "attributes": event.payload})]
            } else {
                omitted.insert("event.payload".into());
                vec![]
            };
            spans.push(OTelSpan {
                trace_id: sha256_bytes(run_id.as_str().as_bytes()).to_string()[..32].into(),
                span_id: event.event_digest.to_string()[..16].into(),
                name: event.event_type.clone(),
                start_time_unix_nano: event.monotonic_ns.map(U64DecimalExt::get_value),
                attributes,
                events,
            });
        }
        OTelExportBatch {
            conduit_schema_version: "conduit.trace/1".into(),
            exporter_version: self.exporter_version.clone(),
            semantic_convention_version: self.semantic_convention_version.clone(),
            spans,
            omitted_fields: omitted.into_iter().collect(),
        }
    }
}

trait U64DecimalExt {
    fn get_value(self) -> u64;
}
impl U64DecimalExt for conduit_domain::U64Decimal {
    fn get_value(self) -> u64 {
        self.get()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("improvement proposal lacks reviewable evidence or asks for automatic application")]
    UnsafeImprovementProposal,
    #[error("evidence digest failed")]
    Digest,
}

pub fn evidence_bundle_digest<T: Serialize>(records: &T) -> Result<Sha256Digest, EvidenceError> {
    canonical_sha256(records).map_err(|_| EvidenceError::Digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }
    fn factors() -> ComparisonFactors {
        ComparisonFactors {
            task_digest: digest(1),
            base_state_digest: digest(2),
            project_context_revision: 1,
            session_context_revision: 1,
            environment_digest: digest(3),
            device_class: "x86_64".into(),
            runtime_class: "native".into(),
            adapter_version: "codex/1".into(),
            model: "gpt".into(),
            effort: "high".into(),
            access_policy_digest: digest(4),
            approval_policy_digest: digest(5),
            instruction_catalog_digest: digest(6),
            skill_catalog_digest: digest(7),
            verification_policy_digest: digest(8),
        }
    }

    #[test]
    fn comparison_downgrades_causal_claim_when_any_factor_is_unmatched() {
        let left = RunOutcome {
            run_id: AnyRunId::parse("run_abcdefgh").unwrap(),
            factors: factors(),
            success: false,
            score: Some(0.0),
            duration_millis: 100,
            reported_usage: Some(10),
            human_corrections: 1,
        };
        let mut right = left.clone();
        right.run_id = AnyRunId::parse("run_ijklmnop").unwrap();
        right.success = true;
        right.factors.model = "other".into();
        let result = compare_runs(&left, &right, ComparisonDesign::Controlled);
        assert_eq!(result.effective_design, ComparisonDesign::Observational);
        assert!(!result.causal_claim_allowed);
        assert_eq!(result.unmatched_confounders, vec!["model"]);
    }

    #[test]
    fn inferred_skill_use_is_counted_separately() {
        let report = skill_report(
            AnyRunId::parse("run_abcdefgh").unwrap(),
            vec![SkillEvidenceItem {
                skill_id: "skill".into(),
                version_digest: digest(1),
                discovered: true,
                eligible: true,
                triggered: false,
                loaded: false,
                resource_used: false,
                procedure_outcome: EvidenceOutcome::Unknown,
                verification_outcome: EvidenceOutcome::Passed,
                efficiency_delta_millis: None,
                regression: false,
                evidence_level: EvidenceLevel::Inferred,
                evidence_refs: vec![],
            }],
        );
        assert_eq!(report.explicit_count, 0);
        assert_eq!(report.inferred_count, 1);
    }
}
