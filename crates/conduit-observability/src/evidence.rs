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
    events: &[NormalizedEvent],
) -> Result<EvidenceReport<InstructionEvidenceItem>, EvidenceError> {
    validate_receipts(
        &run_id,
        items
            .iter()
            .map(|item| (item.evidence_level, &item.evidence_refs)),
        events,
    )?;
    Ok(report(run_id, items, |item| item.evidence_level))
}
pub fn skill_report(
    run_id: AnyRunId,
    items: Vec<SkillEvidenceItem>,
    events: &[NormalizedEvent],
) -> Result<EvidenceReport<SkillEvidenceItem>, EvidenceError> {
    for item in &items {
        if item.resource_used && !item.loaded || item.loaded && !item.triggered {
            return Err(EvidenceError::InvalidEvidenceState);
        }
    }
    validate_receipts(
        &run_id,
        items
            .iter()
            .map(|item| (item.evidence_level, &item.evidence_refs)),
        events,
    )?;
    Ok(report(run_id, items, |item| item.evidence_level))
}

fn validate_receipts<'a>(
    run_id: &AnyRunId,
    items: impl Iterator<Item = (EvidenceLevel, &'a Vec<String>)>,
    events: &[NormalizedEvent],
) -> Result<(), EvidenceError> {
    for (level, references) in items {
        if matches!(level, EvidenceLevel::Explicit | EvidenceLevel::Observed)
            && references.is_empty()
        {
            return Err(EvidenceError::EvidenceReceiptRequired);
        }
        for reference in references {
            let event = events
                .iter()
                .find(|event| event.event_id.as_str() == reference)
                .ok_or(EvidenceError::EvidenceReceiptMissing)?;
            if event.run_id != *run_id || event.evidence_level > level {
                return Err(EvidenceError::EvidenceReceiptMismatch);
            }
        }
    }
    Ok(())
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
                start_time_unix_nano: utc_timestamp_nanos(event.observed_at.as_str()),
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("improvement proposal lacks reviewable evidence or asks for automatic application")]
    UnsafeImprovementProposal,
    #[error("explicit or observed evidence requires a receipt")]
    EvidenceReceiptRequired,
    #[error("evidence receipt was not found")]
    EvidenceReceiptMissing,
    #[error("evidence receipt belongs to another Run or is weaker than claimed")]
    EvidenceReceiptMismatch,
    #[error("evidence state transitions are inconsistent")]
    InvalidEvidenceState,
    #[error("evidence digest failed")]
    Digest,
}

fn utc_timestamp_nanos(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let (clock, fractional) = time.split_once('.').map_or((time, ""), |parts| parts);
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next()?.parse().ok()?;
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    if seconds < 0 {
        return None;
    }
    let mut fraction = fractional
        .as_bytes()
        .iter()
        .take(9)
        .try_fold(0u64, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value * 10 + u64::from(byte - b'0'))
        })?;
    for _ in fractional.len().min(9)..9 {
        fraction *= 10;
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(fraction)
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
            &[],
        )
        .unwrap();
        assert_eq!(report.explicit_count, 0);
        assert_eq!(report.inferred_count, 1);
    }

    #[test]
    fn explicit_evidence_requires_a_receipt() {
        let result = instruction_report(
            AnyRunId::parse("run_abcdefgh").unwrap(),
            vec![InstructionEvidenceItem {
                instruction_id: "instruction".into(),
                version_digest: digest(1),
                discovered: true,
                eligible: true,
                loaded: true,
                skipped_reason: None,
                truncated: false,
                overridden_by: None,
                outcome: EvidenceOutcome::Followed,
                evidence_level: EvidenceLevel::Explicit,
                evidence_refs: vec![],
            }],
            &[],
        );
        assert_eq!(result.unwrap_err(), EvidenceError::EvidenceReceiptRequired);
    }

    #[test]
    fn otel_timestamp_uses_wall_clock_not_monotonic_boot_time() {
        assert_eq!(utc_timestamp_nanos("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            utc_timestamp_nanos("1970-01-01T00:00:01.5Z"),
            Some(1_500_000_000)
        );
    }
}
