use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

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
                let state = self.resulting_state_unchecked()?;
                let state_digest = canonical_sha256(&state)?;
                require_custody(self.source_id(), state_digest, custody_receipts)
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
                let state = self.resulting_state_unchecked()?;
                let state_digest = canonical_sha256(&state)?;
                require_custody(self.source_id(), state_digest, custody_receipts)
            }
        }
    }

    fn resulting_state(&self) -> Result<BaselineSourceState, ChangeSetError> {
        self.acceptable()?;
        self.resulting_state_unchecked()
    }

    fn resulting_state_unchecked(&self) -> Result<BaselineSourceState, ChangeSetError> {
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
        let digest = change_set_digest(&DigestInput {
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
        let recomputed = change_set_digest(&DigestInput {
            change_set_id: &self.change_set_id,
            parent_baseline_id: &self.parent_baseline_id,
            parent_baseline_revision: self.parent_baseline_revision,
            producing_run: &self.producing_run,
            parent_change_sets: &self.parent_change_sets,
            supersedes: &self.supersedes,
            source_changes: &self.source_changes,
            unchanged_sources: &self.unchanged_sources,
            application_order: &self.application_order,
            required_checks: &self.required_checks,
            artifact_commitments: &self.artifact_commitments,
        })?;
        if recomputed != self.digest {
            return Err(ChangeSetError::DigestMismatch);
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceFinalizedReceipt {
    pub operation_id: OperationId,
    pub baseline_id: BaselineId,
    pub baseline_vector_digest: Sha256Digest,
    pub finalized_locations: Vec<LocationId>,
    pub device_receipts: Vec<DeviceMaterializationReceipt>,
    pub receipt_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceMaterializationReceipt {
    pub receipt_id: String,
    pub location_id: LocationId,
    pub device_id: DeviceId,
    pub baseline_id: BaselineId,
    pub baseline_vector_digest: Sha256Digest,
    pub healthy: bool,
}

impl AcceptanceFinalizedReceipt {
    pub fn new(
        operation_id: OperationId,
        baseline_id: BaselineId,
        baseline_vector_digest: Sha256Digest,
        mut finalized_locations: Vec<LocationId>,
        mut device_receipts: Vec<DeviceMaterializationReceipt>,
    ) -> Result<Self, ChangeSetError> {
        finalized_locations.sort();
        finalized_locations.dedup();
        device_receipts.sort();
        device_receipts.dedup();
        if finalized_locations.is_empty()
            || device_receipts.len() != finalized_locations.len()
            || finalized_locations.iter().any(|location| {
                !device_receipts.iter().any(|receipt| {
                    receipt.healthy
                        && receipt.location_id == *location
                        && receipt.baseline_id == baseline_id
                        && receipt.baseline_vector_digest == baseline_vector_digest
                })
            })
        {
            return Err(ChangeSetError::AcceptanceStateConflict);
        }
        let receipt_digest = finalization_digest(
            &operation_id,
            &baseline_id,
            baseline_vector_digest,
            &finalized_locations,
            &device_receipts,
        )?;
        Ok(Self {
            operation_id,
            baseline_id,
            baseline_vector_digest,
            finalized_locations,
            device_receipts,
            receipt_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    journal_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptanceJournal {
    current: BaselineRevision,
    preparations: BTreeMap<OperationId, PreparationState>,
}

impl AcceptanceService {
    pub fn new(current: BaselineRevision) -> Self {
        Self {
            current,
            preparations: BTreeMap::new(),
            journal_path: None,
        }
    }
    pub fn open(
        current: BaselineRevision,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self, ChangeSetError> {
        let path = journal_path.as_ref().to_path_buf();
        if path.exists() {
            if fs::metadata(&path)?.len() > 8 * 1024 * 1024 {
                return Err(ChangeSetError::JournalCorrupt);
            }
            let journal: AcceptanceJournal = serde_json::from_slice(&fs::read(&path)?)
                .map_err(|_| ChangeSetError::JournalCorrupt)?;
            verify_baseline(&journal.current)?;
            if journal.current.baseline_id != current.baseline_id
                || journal.current.revision < current.revision
            {
                return Err(ChangeSetError::BaselineConflict);
            }
            return Ok(Self {
                current: journal.current,
                preparations: journal.preparations,
                journal_path: Some(path),
            });
        }
        let service = Self {
            current,
            preparations: BTreeMap::new(),
            journal_path: Some(path),
        };
        service.persist()?;
        Ok(service)
    }

    fn persist(&self) -> Result<(), ChangeSetError> {
        let Some(path) = &self.journal_path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&AcceptanceJournal {
            current: self.current.clone(),
            preparations: self.preparations.clone(),
        })
        .map_err(|_| ChangeSetError::JournalCorrupt)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(ChangeSetError::JournalCorrupt);
        }
        let parent = path.parent().ok_or(ChangeSetError::JournalCorrupt)?;
        fs::create_dir_all(parent)?;
        static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let temporary = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn current(&self) -> &BaselineRevision {
        &self.current
    }

    pub fn prepare(
        &mut self,
        operation_id: OperationId,
        change_set: &ChangeSet,
        expected_digest: Sha256Digest,
        preparation_refs: BTreeMap<SourceId, String>,
        reviews: &[Review],
        require_approval: bool,
    ) -> Result<AcceptancePreparedReceipt, ChangeSetError> {
        if change_set.digest() != expected_digest {
            return Err(ChangeSetError::DigestMismatch);
        }
        verify_baseline(&self.current)?;
        if change_set.parent_baseline_id != self.current.baseline_id
            || change_set.parent_baseline_revision != self.current.revision
        {
            return Err(ChangeSetError::BaselineConflict);
        }
        change_set.verify_acceptance()?;
        let expected_sources = change_set
            .source_changes
            .iter()
            .map(|change| change.source_id().clone())
            .collect::<BTreeSet<_>>();
        if preparation_refs.keys().cloned().collect::<BTreeSet<_>>() != expected_sources
            || preparation_refs.values().any(|reference| {
                reference.is_empty()
                    || reference.len() > 1_024
                    || !reference.starts_with("refs/conduit/acceptance-prepares/")
            })
        {
            return Err(ChangeSetError::AcceptanceStateConflict);
        }
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
        let mut receipt = AcceptancePreparedReceipt {
            operation_id: operation_id.clone(),
            change_set_id: change_set.id().clone(),
            change_set_digest: change_set.digest(),
            expected_baseline_id: self.current.baseline_id.clone(),
            expected_revision: self.current.revision,
            preparation_refs,
            receipt_digest: Sha256Digest::from_bytes([0; 32]),
        };
        receipt.receipt_digest = prepared_receipt_digest(&receipt, change_set)?;
        self.preparations
            .insert(operation_id, PreparationState::Prepared(receipt.clone()));
        if let Err(error) = self.persist() {
            self.preparations.remove(&receipt.operation_id);
            return Err(error);
        }
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
        if prepared_receipt_digest(receipt, change_set)? != receipt.receipt_digest {
            return Err(ChangeSetError::DigestMismatch);
        }
        match self.preparations.get(&receipt.operation_id) {
            Some(PreparationState::Prepared(stored)) if stored == receipt => {}
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
            revision: self
                .current
                .revision
                .checked_add(1)
                .ok_or(ChangeSetError::BaselineConflict)?,
            predecessor: Some(self.current.baseline_id.clone()),
            entries,
            vector_digest,
            accepted_change_set: Some(change_set.id().clone()),
            acceptance_operation: Some(receipt.operation_id.clone()),
            accepting_principal: Some(accepting_principal),
            accepted_at: Some(accepted_at),
            materialization,
        };
        let previous = self.current.clone();
        self.current = next.clone();
        self.preparations.insert(
            receipt.operation_id.clone(),
            PreparationState::Committed(next_baseline_id),
        );
        if let Err(error) = self.persist() {
            self.current = previous;
            self.preparations.insert(
                receipt.operation_id.clone(),
                PreparationState::Prepared(receipt.clone()),
            );
            return Err(error);
        }
        Ok(next)
    }

    pub fn finalize(&mut self, receipt: &AcceptanceFinalizedReceipt) -> Result<(), ChangeSetError> {
        if finalization_digest(
            &receipt.operation_id,
            &receipt.baseline_id,
            receipt.baseline_vector_digest,
            &receipt.finalized_locations,
            &receipt.device_receipts,
        )? != receipt.receipt_digest
        {
            return Err(ChangeSetError::DigestMismatch);
        }
        let state = self
            .preparations
            .get(&receipt.operation_id)
            .cloned()
            .ok_or(ChangeSetError::AcceptanceStateConflict)?;
        match &state {
            PreparationState::Committed(baseline) | PreparationState::Finalized(baseline) => {
                if *baseline != receipt.baseline_id
                    || self.current.baseline_id != receipt.baseline_id
                    || self.current.vector_digest != receipt.baseline_vector_digest
                {
                    return Err(ChangeSetError::AcceptanceStateConflict);
                }
                if receipt.finalized_locations.iter().any(|location| {
                    !self.current.materialization.contains_key(location)
                        || !receipt.device_receipts.iter().any(|device_receipt| {
                            device_receipt.healthy
                                && device_receipt.location_id == *location
                                && device_receipt.baseline_id == receipt.baseline_id
                                && device_receipt.baseline_vector_digest
                                    == receipt.baseline_vector_digest
                        })
                }) {
                    return Err(ChangeSetError::AcceptanceStateConflict);
                }
                let previous = self.current.materialization.clone();
                for location in &receipt.finalized_locations {
                    let value = self
                        .current
                        .materialization
                        .get_mut(location)
                        .ok_or(ChangeSetError::AcceptanceStateConflict)?;
                    *value = MaterializationState::Finalized;
                }
                let fully_finalized = self
                    .current
                    .materialization
                    .values()
                    .all(|value| *value == MaterializationState::Finalized);
                self.preparations.insert(
                    receipt.operation_id.clone(),
                    if fully_finalized {
                        PreparationState::Finalized(baseline.clone())
                    } else {
                        PreparationState::Committed(baseline.clone())
                    },
                );
                if let Err(error) = self.persist() {
                    self.current.materialization = previous;
                    self.preparations
                        .insert(receipt.operation_id.clone(), state);
                    return Err(error);
                }
                Ok(())
            }
            _ => Err(ChangeSetError::AcceptanceStateConflict),
        }
    }

    pub fn abort(&mut self, operation_id: &OperationId) -> Result<(), ChangeSetError> {
        match self.preparations.get(operation_id).cloned() {
            Some(previous @ PreparationState::Prepared(_))
            | Some(previous @ PreparationState::Aborted) => {
                self.preparations
                    .insert(operation_id.clone(), PreparationState::Aborted);
                if let Err(error) = self.persist() {
                    self.preparations.insert(operation_id.clone(), previous);
                    return Err(error);
                }
                Ok(())
            }
            _ => Err(ChangeSetError::AcceptanceStateConflict),
        }
    }
}

fn verify_baseline(baseline: &BaselineRevision) -> Result<(), ChangeSetError> {
    let mut entries = baseline.entries.clone();
    normalize_entries(&mut entries)?;
    if entries != baseline.entries || canonical_sha256(&entries)? != baseline.vector_digest {
        return Err(ChangeSetError::JournalCorrupt);
    }
    Ok(())
}

fn finalization_digest(
    operation_id: &OperationId,
    baseline_id: &BaselineId,
    baseline_vector_digest: Sha256Digest,
    locations: &[LocationId],
    receipts: &[DeviceMaterializationReceipt],
) -> Result<Sha256Digest, ChangeSetError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Core<'a> {
        operation_id: &'a OperationId,
        baseline_id: &'a BaselineId,
        baseline_vector_digest: Sha256Digest,
        locations: &'a [LocationId],
        device_receipts: &'a [DeviceMaterializationReceipt],
    }
    canonical_sha256(&Core {
        operation_id,
        baseline_id,
        baseline_vector_digest,
        locations,
        device_receipts: receipts,
    })
    .map_err(Into::into)
}

fn prepared_receipt_digest(
    receipt: &AcceptancePreparedReceipt,
    change_set: &ChangeSet,
) -> Result<Sha256Digest, ChangeSetError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Core<'a> {
        operation_id: &'a OperationId,
        change_set_id: &'a ChangeSetId,
        change_set_digest: Sha256Digest,
        expected_baseline_id: &'a BaselineId,
        expected_revision: u64,
        preparation_refs: &'a BTreeMap<SourceId, String>,
        custody_receipts: Vec<&'a CustodyReceipt>,
    }
    let mut custody_receipts = change_set
        .source_changes
        .iter()
        .flat_map(SourceChange::receipts)
        .collect::<Vec<_>>();
    custody_receipts.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    canonical_sha256(&Core {
        operation_id: &receipt.operation_id,
        change_set_id: &receipt.change_set_id,
        change_set_digest: receipt.change_set_digest,
        expected_baseline_id: &receipt.expected_baseline_id,
        expected_revision: receipt.expected_revision,
        preparation_refs: &receipt.preparation_refs,
        custody_receipts,
    })
    .map_err(Into::into)
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
    #[error("acceptance journal is corrupt")]
    JournalCorrupt,
    #[error("acceptance journal filesystem operation failed: {0}")]
    Io(String),
}

impl From<conduit_crypto::CanonicalJsonError> for ChangeSetError {
    fn from(_: conduit_crypto::CanonicalJsonError) -> Self {
        Self::Digest
    }
}

impl From<std::io::Error> for ChangeSetError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

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

fn change_set_digest(input: &DigestInput<'_>) -> Result<Sha256Digest, ChangeSetError> {
    canonical_sha256(input).map_err(Into::into)
}

fn require_custody(
    source_id: &SourceId,
    state_digest: Sha256Digest,
    receipts: &[CustodyReceipt],
) -> Result<(), ChangeSetError> {
    let healthy_ref = receipts
        .iter()
        .filter(|receipt| {
            receipt.healthy
                && receipt.source_id == *source_id
                && receipt.state_digest == state_digest
                && receipt.class == CustodyClass::DeviceRef
        })
        .map(|receipt| &receipt.device_id)
        .collect::<BTreeSet<_>>();
    let healthy_archive = receipts
        .iter()
        .filter(|receipt| {
            receipt.healthy
                && receipt.source_id == *source_id
                && receipt.state_digest == state_digest
                && receipt.class == CustodyClass::DeviceArchive
        })
        .map(|receipt| &receipt.device_id)
        .collect::<BTreeSet<_>>();
    if healthy_ref
        .iter()
        .any(|device| healthy_archive.contains(device))
    {
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
    fn custody(source_id: SourceId, state: &BaselineSourceState) -> Vec<CustodyReceipt> {
        let state_digest = canonical_sha256(state).unwrap();
        [CustodyClass::DeviceRef, CustodyClass::DeviceArchive]
            .into_iter()
            .enumerate()
            .map(|(i, class)| CustodyReceipt {
                receipt_id: format!("receipt-{i}"),
                source_id: source_id.clone(),
                device_id: DeviceId::parse("dev_abcdefgh").unwrap(),
                class,
                state_digest,
                healthy: true,
            })
            .collect()
    }
    fn baseline() -> BaselineRevision {
        let state = BaselineSourceState::Git {
            repository_identity_digest: digest(1),
            commit: "a".repeat(40),
            tree_digest: digest(2),
        };
        BaselineRevision::initial(
            BaselineId::parse("bln_abcdefgh").unwrap(),
            vec![BaselineEntry {
                source_id: source("src_abcdefgh"),
                state: state.clone(),
                custody_receipts: custody(source("src_abcdefgh"), &state),
            }],
        )
        .unwrap()
    }
    fn proposed(id: &str) -> ChangeSet {
        let sid = source("src_abcdefgh");
        let result_state = BaselineSourceState::Git {
            repository_identity_digest: digest(1),
            commit: "b".repeat(40),
            tree_digest: digest(4),
        };
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
                custody_receipts: custody(sid.clone(), &result_state),
            }],
            unchanged_sources: vec![],
            application_order: vec![sid],
            required_checks: vec![],
            verification: vec![],
            artifact_commitments: vec![],
        })
        .unwrap()
    }

    fn prepared_refs(operation: &OperationId, change: &ChangeSet) -> BTreeMap<SourceId, String> {
        change
            .source_changes()
            .iter()
            .map(|source_change| {
                let source_id = source_change.source_id().clone();
                (
                    source_id.clone(),
                    format!(
                        "refs/conduit/acceptance-prepares/{}/{}",
                        operation.as_str(),
                        source_id.as_str()
                    ),
                )
            })
            .collect()
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
                    prepared_refs(&OperationId::parse("op_abcdefgh").unwrap(), &input),
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
            .prepare(
                op.clone(),
                &change,
                change.digest(),
                prepared_refs(&op, &change),
                &[],
                false,
            )
            .unwrap();
        service
            .commit(
                &receipt,
                &change,
                BaselineId::parse("bln_ijklmnop").unwrap(),
                PrincipalId::parse("prin_abcdefgh").unwrap(),
                UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap(),
                vec![LocationId::parse("loc_abcdefgh").unwrap()],
            )
            .unwrap();
        assert_eq!(
            service
                .prepare(
                    OperationId::parse("op_ijklmnop").unwrap(),
                    &competing,
                    competing.digest(),
                    prepared_refs(&OperationId::parse("op_ijklmnop").unwrap(), &competing),
                    &[],
                    false
                )
                .unwrap_err(),
            ChangeSetError::BaselineConflict
        );
        service
            .finalize(
                &AcceptanceFinalizedReceipt::new(
                    op,
                    BaselineId::parse("bln_ijklmnop").unwrap(),
                    service.current().vector_digest,
                    vec![LocationId::parse("loc_abcdefgh").unwrap()],
                    vec![DeviceMaterializationReceipt {
                        receipt_id: "device-receipt-1".into(),
                        location_id: LocationId::parse("loc_abcdefgh").unwrap(),
                        device_id: DeviceId::parse("dev_abcdefgh").unwrap(),
                        baseline_id: BaselineId::parse("bln_ijklmnop").unwrap(),
                        baseline_vector_digest: service.current().vector_digest,
                        healthy: true,
                    }],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            service.current().accepted_change_set.as_ref(),
            Some(change.id())
        );
    }

    #[test]
    fn acceptance_recomputes_deserialized_change_set_digest() {
        let mut change = proposed("chg_abcdefgh");
        if let SourceChange::Git { head_commit, .. } = &mut change.source_changes[0] {
            *head_commit = Some("c".repeat(40));
        }
        let mut service = AcceptanceService::new(baseline());
        assert_eq!(
            service
                .prepare(
                    OperationId::parse("op_abcdefgh").unwrap(),
                    &change,
                    change.digest(),
                    prepared_refs(&OperationId::parse("op_abcdefgh").unwrap(), &change),
                    &[],
                    false,
                )
                .unwrap_err(),
            ChangeSetError::DigestMismatch
        );
    }

    #[test]
    fn prepared_acceptance_survives_restart() {
        let root = std::env::temp_dir().join(format!(
            "conduit-acceptance-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let journal = root.join("acceptance.json");
        let change = proposed("chg_abcdefgh");
        let operation = OperationId::parse("op_abcdefgh").unwrap();
        let receipt = AcceptanceService::open(baseline(), &journal)
            .unwrap()
            .prepare(
                operation.clone(),
                &change,
                change.digest(),
                prepared_refs(&operation, &change),
                &[],
                false,
            )
            .unwrap();
        let mut reopened = AcceptanceService::open(baseline(), &journal).unwrap();
        assert_eq!(
            reopened
                .prepare(
                    operation.clone(),
                    &change,
                    change.digest(),
                    prepared_refs(&operation, &change),
                    &[],
                    false
                )
                .unwrap(),
            receipt
        );
        fs::remove_dir_all(root).unwrap();
    }
}
