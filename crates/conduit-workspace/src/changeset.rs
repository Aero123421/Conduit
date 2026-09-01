use std::collections::{BTreeMap, BTreeSet};

use conduit_crypto::canonical_sha256;
use conduit_domain::{
    BaselineId, ChangeSetId, DeviceId, LocationId, OperationId, PrincipalId, RunId, Sha256Digest,
    SourceId, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BaselineSourceState {
    Git {
        repository_identity_digest: Sha256Digest,
        commit: String,
        tree_digest: Sha256Digest,
    },
    ManagedFolder {
        snapshot_id: String,
        manifest_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyReceipt {
    pub receipt_id: String,
    pub source_id: SourceId,
    pub device_id: DeviceId,
    pub class: CustodyClass,
    pub state_digest: Sha256Digest,
    pub healthy: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineEntry {
    pub source_id: SourceId,
    pub state: BaselineSourceState,
    pub custody_receipts: Vec<CustodyReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineRevision {
    pub baseline_id: BaselineId,
    pub revision: u64,
    pub predecessor: Option<BaselineId>,
    pub entries: Vec<BaselineEntry>,
    pub vector_digest: Sha256Digest,
    pub accepted_change_set: Option<ChangeSetId>,
    pub acceptance_operation: Option<OperationId>,
    pub accepting_principal: Option<PrincipalId>,
    pub accepted_at: Option<UtcTimestamp>,
    pub materialization: BTreeMap<LocationId, MaterializationState>,
}

impl BaselineRevision {
    pub fn initial(
        baseline_id: BaselineId,
        mut entries: Vec<BaselineEntry>,
    ) -> Result<Self, ChangeSetError> {
        normalize_entries(&mut entries)?;
        let vector_digest = canonical_sha256(&entries)?;
        Ok(Self {
            baseline_id,
            revision: 1,
            predecessor: None,
            entries,
            vector_digest,
            accepted_change_set: None,
            acceptance_operation: None,
            accepting_principal: None,
            accepted_at: None,
            materialization: BTreeMap::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationState {
    Pending,
    Finalized,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceChange {
    Git {
        source_id: SourceId,
        repository_identity_digest: Sha256Digest,
        base_commit: String,
        base_tree: Sha256Digest,
        head_commit: Option<String>,
        head_tree: Option<Sha256Digest>,
        commit_ids: Vec<String>,
        diff_digest: Option<Sha256Digest>,
        changed_paths: Vec<String>,
        clean: bool,
        conflicted: bool,
        missing_objects: Vec<String>,
        unresolved_untracked: Vec<String>,
        custody_receipts: Vec<CustodyReceipt>,
    },
    ManagedFolder {
        source_id: SourceId,
        base_snapshot_id: String,
        base_manifest_digest: Sha256Digest,
        result_snapshot_id: Option<String>,
        result_manifest_digest: Option<Sha256Digest>,
        operation_manifest_digest: Option<Sha256Digest>,
        conflicted: bool,
        unavailable_content: bool,
        custody_receipts: Vec<CustodyReceipt>,
    },
}

impl SourceChange {
    pub fn source_id(&self) -> &SourceId {
        match self {
            Self::Git { source_id, .. } | Self::ManagedFolder { source_id, .. } => source_id,
        }
    }

    fn acceptable(&self) -> Result<(), ChangeSetError> {
        match self {
            Self::Git {
                head_commit,
                head_tree,
                clean,
                conflicted,
                missing_objects,
                unresolved_untracked,
                custody_receipts,
                ..
            } => {
                if !clean
                    || head_commit.is_none()
                    || head_tree.is_none()
                    || !unresolved_untracked.is_empty()
                {
                    return Err(ChangeSetError::Draft);
                }
                if *conflicted {
                    return Err(ChangeSetError::Conflicted);
                }
                if !missing_objects.is_empty() {
                    return Err(ChangeSetError::ObjectMissing);
                }
                require_custody(custody_receipts)
            }
            Self::ManagedFolder {
                result_snapshot_id,
                result_manifest_digest,
                operation_manifest_digest,
                conflicted,
                unavailable_content,
                custody_receipts,
                ..
            } => {
                if result_snapshot_id.is_none()
                    || result_manifest_digest.is_none()
                    || operation_manifest_digest.is_none()
                {
                    return Err(ChangeSetError::Draft);
                }
                if *conflicted {
                    return Err(ChangeSetError::Conflicted);
                }
                if *unavailable_content {
                    return Err(ChangeSetError::ObjectMissing);
                }
                require_custody(custody_receipts)
            }
        }
    }

    fn resulting_state(&self) -> Result<BaselineSourceState, ChangeSetError> {
        self.acceptable()?;
        Ok(match self {
            Self::Git {
                repository_identity_digest,
                head_commit,
                head_tree,
                ..
            } => BaselineSourceState::Git {
                repository_identity_digest: *repository_identity_digest,
                commit: head_commit.clone().ok_or(ChangeSetError::Draft)?,
                tree_digest: head_tree.ok_or(ChangeSetError::Draft)?,
            },
            Self::ManagedFolder {
                result_snapshot_id,
                result_manifest_digest,
                ..
            } => BaselineSourceState::ManagedFolder {
                snapshot_id: result_snapshot_id.clone().ok_or(ChangeSetError::Draft)?,
                manifest_digest: result_manifest_digest.ok_or(ChangeSetError::Draft)?,
            },
        })
    }

    fn receipts(&self) -> &[CustodyReceipt] {
        match self {
            Self::Git {
                custody_receipts, ..
            }
            | Self::ManagedFolder {
                custody_receipts, ..
            } => custody_receipts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationResult {
    pub check_id: String,
    pub target_digest: Sha256Digest,
    pub passed: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSet {
    change_set_id: ChangeSetId,
    parent_baseline_id: BaselineId,
    parent_baseline_revision: u64,
    producing_run: RunId,
    parent_change_sets: Vec<ChangeSetId>,
    supersedes: Option<ChangeSetId>,
    source_changes: Vec<SourceChange>,
    unchanged_sources: Vec<SourceId>,
    application_order: Vec<SourceId>,
    required_checks: Vec<String>,
    verification: Vec<VerificationResult>,
    artifact_commitments: Vec<Sha256Digest>,
    draft: bool,
    digest: Sha256Digest,
}

#[derive(Debug, Clone)]
pub struct ChangeSetInput {
    pub change_set_id: ChangeSetId,
    pub parent_baseline_id: BaselineId,
    pub parent_baseline_revision: u64,
    pub producing_run: RunId,
    pub parent_change_sets: Vec<ChangeSetId>,
    pub supersedes: Option<ChangeSetId>,
    pub source_changes: Vec<SourceChange>,
    pub unchanged_sources: Vec<SourceId>,
    pub application_order: Vec<SourceId>,
    pub required_checks: Vec<String>,
    pub verification: Vec<VerificationResult>,
    pub artifact_commitments: Vec<Sha256Digest>,
}

impl ChangeSet {
    pub fn assemble(mut input: ChangeSetInput) -> Result<Self, ChangeSetError> {
        input
            .source_changes
            .sort_by(|a, b| a.source_id().cmp(b.source_id()));
        unique_sources(input.source_changes.iter().map(SourceChange::source_id))?;
        unique_sources(input.application_order.iter())?;
        let changed: BTreeSet<_> = input
            .source_changes
            .iter()
            .map(SourceChange::source_id)
            .collect();
        if input
            .application_order
            .iter()
            .any(|source| !changed.contains(source))
            || input.application_order.len() != changed.len()
        {
            return Err(ChangeSetError::InvalidApplicationOrder);
        }
        let draft = input
            .source_changes
            .iter()
            .any(|change| change.acceptable().is_err());
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DigestInput<'a> {
            change_set_id: &'a ChangeSetId,
            parent_baseline_id: &'a BaselineId,
            parent_baseline_revision: u64,
            producing_run: &'a RunId,
            parent_change_sets: &'a [ChangeSetId],
            supersedes: &'a Option<ChangeSetId>,
            source_changes: &'a [SourceChange],
            unchanged_sources: &'a [SourceId],
            application_order: &'a [SourceId],
            required_checks: &'a [String],
            artifact_commitments: &'a [Sha256Digest],
        }
        let digest = canonical_sha256(&DigestInput {
            change_set_id: &input.change_set_id,
            parent_baseline_id: &input.parent_baseline_id,
            parent_baseline_revision: input.parent_baseline_revision,
            producing_run: &input.producing_run,
            parent_change_sets: &input.parent_change_sets,
            supersedes: &input.supersedes,
            source_changes: &input.source_changes,
            unchanged_sources: &input.unchanged_sources,
            application_order: &input.application_order,
            required_checks: &input.required_checks,
            artifact_commitments: &input.artifact_commitments,
        })?;
        Ok(Self {
            change_set_id: input.change_set_id,
            parent_baseline_id: input.parent_baseline_id,
            parent_baseline_revision: input.parent_baseline_revision,
            producing_run: input.producing_run,
            parent_change_sets: input.parent_change_sets,
            supersedes: input.supersedes,
            source_changes: input.source_changes,
            unchanged_sources: input.unchanged_sources,
            application_order: input.application_order,
            required_checks: input.required_checks,
            verification: input.verification,
            artifact_commitments: input.artifact_commitments,
            draft,
            digest,
        })
    }

    pub fn id(&self) -> &ChangeSetId {
        &self.change_set_id
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
    pub fn is_draft(&self) -> bool {
        self.draft
    }
    pub fn source_changes(&self) -> &[SourceChange] {
        &self.source_changes
    }

    fn verify_acceptance(&self) -> Result<(), ChangeSetError> {
        if self.draft {
            return Err(ChangeSetError::Draft);
        }
        for required in &self.required_checks {
            if !self.verification.iter().any(|result| {
                result.check_id == *required && result.passed && result.target_digest == self.digest
            }) {
                return Err(ChangeSetError::VerificationRequired(required.clone()));
            }
        }
        for change in &self.source_changes {
            change.acceptable()?;
        }
        Ok(())
    }
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
pub struct Review {
    pub review_id: String,
    pub change_set_id: ChangeSetId,
    pub change_set_digest: Sha256Digest,
    pub reviewer: PrincipalId,
    pub verdict: ReviewVerdict,
    pub finding_ids: Vec<String>,
    pub reviewed_at: UtcTimestamp,
}

impl Review {
    pub fn applies_to(&self, change_set: &ChangeSet) -> bool {
        self.change_set_id == *change_set.id() && self.change_set_digest == change_set.digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptancePreparedReceipt {
    pub operation_id: OperationId,
    pub change_set_id: ChangeSetId,
    pub change_set_digest: Sha256Digest,
    pub expected_baseline_id: BaselineId,
    pub expected_revision: u64,
    pub preparation_refs: BTreeMap<SourceId, String>,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreparationState {
    Prepared(AcceptancePreparedReceipt),
    Committed(BaselineId),
    Finalized(BaselineId),
    Aborted,
}

#[derive(Debug)]
pub struct AcceptanceService {
    current: BaselineRevision,
    preparations: BTreeMap<OperationId, PreparationState>,
}

impl AcceptanceService {
    pub fn new(current: BaselineRevision) -> Self {
        Self {
            current,
            preparations: BTreeMap::new(),
        }
    }
    pub fn current(&self) -> &BaselineRevision {
        &self.current
    }

    pub fn prepare(
        &mut self,
        operation_id: OperationId,
        change_set: &ChangeSet,
        expected_digest: Sha256Digest,
        reviews: &[Review],
        require_approval: bool,
    ) -> Result<AcceptancePreparedReceipt, ChangeSetError> {
        if change_set.digest() != expected_digest {
            return Err(ChangeSetError::DigestMismatch);
        }
        if change_set.parent_baseline_id != self.current.baseline_id
            || change_set.parent_baseline_revision != self.current.revision
        {
            return Err(ChangeSetError::BaselineConflict);
        }
        change_set.verify_acceptance()?;
        if require_approval
            && !reviews.iter().any(|review| {
                review.applies_to(change_set) && review.verdict == ReviewVerdict::Approved
            })
        {
            return Err(ChangeSetError::ReviewRequired);
        }
        if let Some(state) = self.preparations.get(&operation_id) {
            return match state {
                PreparationState::Prepared(receipt) => Ok(receipt.clone()),
                _ => Err(ChangeSetError::AcceptanceStateConflict),
            };
        }
        let preparation_refs = change_set
            .source_changes
            .iter()
            .map(|change| {
                let source = change.source_id().clone();
                let reference = format!(
                    "refs/conduit/acceptance-prepares/{}/{source}",
                    operation_id.as_str()
                );
                (source, reference)
            })
            .collect();
        #[derive(Serialize)]
        struct ReceiptCore<'a> {
            operation: &'a OperationId,
            change_set: &'a ChangeSetId,
            digest: Sha256Digest,
            baseline: &'a BaselineId,
            revision: u64,
        }
        let receipt_digest = canonical_sha256(&ReceiptCore {
            operation: &operation_id,
            change_set: change_set.id(),
            digest: change_set.digest(),
            baseline: &self.current.baseline_id,
            revision: self.current.revision,
        })?;
        let receipt = AcceptancePreparedReceipt {
            operation_id: operation_id.clone(),
            change_set_id: change_set.id().clone(),
            change_set_digest: change_set.digest(),
            expected_baseline_id: self.current.baseline_id.clone(),
            expected_revision: self.current.revision,
            preparation_refs,
            receipt_digest,
        };
        self.preparations
            .insert(operation_id, PreparationState::Prepared(receipt.clone()));
        Ok(receipt)
    }

    /// Models the single Control Plane transaction: exact Baseline CAS and the full vector update.
    pub fn commit(
        &mut self,
        receipt: &AcceptancePreparedReceipt,
        change_set: &ChangeSet,
        next_baseline_id: BaselineId,
        accepting_principal: PrincipalId,
        accepted_at: UtcTimestamp,
        materialization_locations: Vec<LocationId>,
    ) -> Result<BaselineRevision, ChangeSetError> {
        if receipt.change_set_digest != change_set.digest()
            || receipt.change_set_id != *change_set.id()
        {
            return Err(ChangeSetError::DigestMismatch);
        }
        if self.current.baseline_id != receipt.expected_baseline_id
            || self.current.revision != receipt.expected_revision
        {
            return Err(ChangeSetError::BaselineConflict);
        }
        match self.preparations.get(&receipt.operation_id) {
            Some(PreparationState::Prepared(stored))
                if stored.receipt_digest == receipt.receipt_digest => {}
            _ => return Err(ChangeSetError::AcceptanceStateConflict),
        }
        let mut entries: BTreeMap<SourceId, BaselineEntry> = self
            .current
            .entries
            .iter()
            .cloned()
            .map(|entry| (entry.source_id.clone(), entry))
            .collect();
        for change in &change_set.source_changes {
            entries.insert(
                change.source_id().clone(),
                BaselineEntry {
                    source_id: change.source_id().clone(),
                    state: change.resulting_state()?,
                    custody_receipts: change.receipts().to_vec(),
                },
            );
        }
        let mut entries: Vec<_> = entries.into_values().collect();
        normalize_entries(&mut entries)?;
        let vector_digest = canonical_sha256(&entries)?;
        let materialization = materialization_locations
            .into_iter()
            .map(|location| (location, MaterializationState::Pending))
            .collect();
        let next = BaselineRevision {
            baseline_id: next_baseline_id.clone(),
            revision: self.current.revision + 1,
            predecessor: Some(self.current.baseline_id.clone()),
            entries,
            vector_digest,
            accepted_change_set: Some(change_set.id().clone()),
            acceptance_operation: Some(receipt.operation_id.clone()),
            accepting_principal: Some(accepting_principal),
            accepted_at: Some(accepted_at),
            materialization,
        };
        self.current = next.clone();
        self.preparations.insert(
            receipt.operation_id.clone(),
            PreparationState::Committed(next_baseline_id),
        );
        Ok(next)
    }

    pub fn finalize(&mut self, operation_id: &OperationId) -> Result<(), ChangeSetError> {
        let state = self
            .preparations
            .get(operation_id)
            .cloned()
            .ok_or(ChangeSetError::AcceptanceStateConflict)?;
        match state {
            PreparationState::Committed(baseline) | PreparationState::Finalized(baseline) => {
                for value in self.current.materialization.values_mut() {
                    *value = MaterializationState::Finalized;
                }
                self.preparations
                    .insert(operation_id.clone(), PreparationState::Finalized(baseline));
                Ok(())
            }
            _ => Err(ChangeSetError::AcceptanceStateConflict),
        }
    }

    pub fn abort(&mut self, operation_id: &OperationId) -> Result<(), ChangeSetError> {
        match self.preparations.get(operation_id) {
            Some(PreparationState::Prepared(_)) | Some(PreparationState::Aborted) => {
                self.preparations
                    .insert(operation_id.clone(), PreparationState::Aborted);
                Ok(())
            }
            _ => Err(ChangeSetError::AcceptanceStateConflict),
        }
    }
}

/// A separate effect from acceptance. Callers bind exact expected target state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MaterializationRequest {
    FastForward {
        operation_id: OperationId,
        change_set_digest: Sha256Digest,
        location_id: LocationId,
        target_ref: String,
        expected_old_commit: String,
        accepted_head: String,
    },
    CreateBranch {
        operation_id: OperationId,
        change_set_digest: Sha256Digest,
        location_id: LocationId,
        target_ref: String,
        expected_old_commit: Option<String>,
        accepted_head: String,
    },
    ManagedFolderApply {
        operation_id: OperationId,
        change_set_digest: Sha256Digest,
        location_id: LocationId,
        expected_manifest: Sha256Digest,
        result_manifest: Sha256Digest,
    },
}

/// Pushing is intentionally another authorization and idempotency boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PushRequest {
    pub operation_id: OperationId,
    pub change_set_digest: Sha256Digest,
    pub remote_identity: String,
    pub refspec: String,
    pub expected_remote_commit: Option<String>,
    pub force: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChangeSetError {
    #[error("source IDs must be unique")]
    DuplicateSource,
    #[error("application order must list each changed Source exactly once")]
    InvalidApplicationOrder,
    #[error("change set remains draft")]
    Draft,
    #[error("change set contains a conflict")]
    Conflicted,
    #[error("required immutable object or snapshot is missing")]
    ObjectMissing,
    #[error("custody receipts are insufficient")]
    CustodyInsufficient,
    #[error("required verification did not pass: {0}")]
    VerificationRequired(String),
    #[error("change set digest does not match")]
    DigestMismatch,
    #[error("review for the exact digest is required")]
    ReviewRequired,
    #[error("baseline revision compare-and-swap failed")]
    BaselineConflict,
    #[error("acceptance operation is in an incompatible state")]
    AcceptanceStateConflict,
    #[error("digest computation failed")]
    Digest,
}

impl From<conduit_crypto::CanonicalJsonError> for ChangeSetError {
    fn from(_: conduit_crypto::CanonicalJsonError) -> Self {
        Self::Digest
    }
}

fn require_custody(receipts: &[CustodyReceipt]) -> Result<(), ChangeSetError> {
    let healthy_ref = receipts
        .iter()
        .any(|receipt| receipt.healthy && receipt.class == CustodyClass::DeviceRef);
    let healthy_archive = receipts
        .iter()
        .any(|receipt| receipt.healthy && receipt.class == CustodyClass::DeviceArchive);
    if healthy_ref && healthy_archive {
        Ok(())
    } else {
        Err(ChangeSetError::CustodyInsufficient)
    }
}

fn unique_sources<'a>(
    mut sources: impl Iterator<Item = &'a SourceId>,
) -> Result<(), ChangeSetError> {
    let mut seen = BTreeSet::new();
    if sources.any(|source| !seen.insert(source)) {
        Err(ChangeSetError::DuplicateSource)
    } else {
        Ok(())
    }
}

fn normalize_entries(entries: &mut [BaselineEntry]) -> Result<(), ChangeSetError> {
    entries.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    unique_sources(entries.iter().map(|entry| &entry.source_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }
    fn source(value: &str) -> SourceId {
        SourceId::parse(value).unwrap()
    }
    fn custody(source_id: SourceId) -> Vec<CustodyReceipt> {
        [CustodyClass::DeviceRef, CustodyClass::DeviceArchive]
            .into_iter()
            .enumerate()
            .map(|(i, class)| CustodyReceipt {
                receipt_id: format!("receipt-{i}"),
                source_id: source_id.clone(),
                device_id: DeviceId::parse("dev_abcdefgh").unwrap(),
                class,
                state_digest: digest(3),
                healthy: true,
            })
            .collect()
    }
    fn baseline() -> BaselineRevision {
        BaselineRevision::initial(
            BaselineId::parse("bln_abcdefgh").unwrap(),
            vec![BaselineEntry {
                source_id: source("src_abcdefgh"),
                state: BaselineSourceState::Git {
                    repository_identity_digest: digest(1),
                    commit: "a".repeat(40),
                    tree_digest: digest(2),
                },
                custody_receipts: custody(source("src_abcdefgh")),
            }],
        )
        .unwrap()
    }
    fn proposed(id: &str) -> ChangeSet {
        let sid = source("src_abcdefgh");
        ChangeSet::assemble(ChangeSetInput {
            change_set_id: ChangeSetId::parse(id).unwrap(),
            parent_baseline_id: BaselineId::parse("bln_abcdefgh").unwrap(),
            parent_baseline_revision: 1,
            producing_run: RunId::parse("run_abcdefgh").unwrap(),
            parent_change_sets: vec![],
            supersedes: None,
            source_changes: vec![SourceChange::Git {
                source_id: sid.clone(),
                repository_identity_digest: digest(1),
                base_commit: "a".repeat(40),
                base_tree: digest(2),
                head_commit: Some("b".repeat(40)),
                head_tree: Some(digest(4)),
                commit_ids: vec!["b".repeat(40)],
                diff_digest: Some(digest(5)),
                changed_paths: vec!["README".into()],
                clean: true,
                conflicted: false,
                missing_objects: vec![],
                unresolved_untracked: vec![],
                custody_receipts: custody(sid.clone()),
            }],
            unchanged_sources: vec![],
            application_order: vec![sid],
            required_checks: vec![],
            verification: vec![],
            artifact_commitments: vec![],
        })
        .unwrap()
    }

    #[test]
    fn draft_cannot_prepare_and_review_is_exact_digest() {
        let mut input = proposed("chg_abcdefgh");
        input.draft = true;
        let mut service = AcceptanceService::new(baseline());
        assert_eq!(
            service
                .prepare(
                    OperationId::parse("op_abcdefgh").unwrap(),
                    &input,
                    input.digest(),
                    &[],
                    false
                )
                .unwrap_err(),
            ChangeSetError::Draft
        );
        let review = Review {
            review_id: "rev-one".into(),
            change_set_id: ChangeSetId::parse("chg_abcdefgh").unwrap(),
            change_set_digest: digest(9),
            reviewer: PrincipalId::parse("prin_abcdefgh").unwrap(),
            verdict: ReviewVerdict::Approved,
            finding_ids: vec![],
            reviewed_at: UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap(),
        };
        assert!(!review.applies_to(&proposed("chg_abcdefgh")));
    }

    #[test]
    fn acceptance_is_prepare_cas_finalize_and_stales_competing_parent() {
        let change = proposed("chg_abcdefgh");
        let competing = proposed("chg_ijklmnop");
        let mut service = AcceptanceService::new(baseline());
        let op = OperationId::parse("op_abcdefgh").unwrap();
        let receipt = service
            .prepare(op.clone(), &change, change.digest(), &[], false)
            .unwrap();
        service
            .commit(
                &receipt,
                &change,
                BaselineId::parse("bln_ijklmnop").unwrap(),
                PrincipalId::parse("prin_abcdefgh").unwrap(),
                UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap(),
                vec![],
            )
            .unwrap();
        assert_eq!(
            service
                .prepare(
                    OperationId::parse("op_ijklmnop").unwrap(),
                    &competing,
                    competing.digest(),
                    &[],
                    false
                )
                .unwrap_err(),
            ChangeSetError::BaselineConflict
        );
        service.finalize(&op).unwrap();
        assert_eq!(
            service.current().accepted_change_set.as_ref(),
            Some(change.id())
        );
    }
}
