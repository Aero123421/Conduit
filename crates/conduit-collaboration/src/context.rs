use std::{
    fs,
    io::{Read, Take},
    path::Path,
};

use conduit_crypto::{canonical_sha256, sha256_bytes};
use conduit_domain::{
    AssignmentId, CollaborationSessionId, ContextSnapshotId, Sha256Digest, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextOrigin {
    ProjectOverview,
    ProjectRule,
    Decision,
    Resource,
    SessionSummary,
    RecentMessage,
    UnreadImportantMessage,
    Assignment,
    SourceReference,
    ChangeSetReference,
    ArtifactReference,
    Instruction,
    SkillCatalog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InclusionState {
    Included,
    Summarized,
    Referenced,
    Omitted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCandidate {
    pub origin: ContextOrigin,
    pub source_record_id: String,
    pub revision: u64,
    pub priority: u16,
    pub content: String,
    pub sensitivity: String,
    pub important_unread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledContextItem {
    pub origin: ContextOrigin,
    pub source_record_id: String,
    pub revision: u64,
    pub priority: u16,
    pub content_digest: Sha256Digest,
    pub original_bytes: u64,
    pub retained_text: Option<String>,
    pub state: InclusionState,
    pub reason: Option<String>,
    pub sensitivity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextSnapshot {
    pub context_snapshot_id: ContextSnapshotId,
    pub run_or_assignment_input_id: String,
    pub assignment_id: AssignmentId,
    pub session_id: CollaborationSessionId,
    pub session_revision: u64,
    pub mode: ContextMode,
    pub compiler_version: String,
    pub ordered_items: Vec<CompiledContextItem>,
    pub instruction_catalog_digest: Sha256Digest,
    pub skill_catalog_digest: Sha256Digest,
    pub compiled_bytes: u64,
    pub compiled_content_digest: Sha256Digest,
    pub snapshot_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCompileRequest {
    pub context_snapshot_id: ContextSnapshotId,
    pub run_or_assignment_input_id: String,
    pub assignment_id: AssignmentId,
    pub session_id: CollaborationSessionId,
    pub session_revision: u64,
    pub mode: ContextMode,
    pub candidates: Vec<ContextCandidate>,
    pub instruction_catalog_digest: Sha256Digest,
    pub skill_catalog_digest: Sha256Digest,
    pub created_at: UtcTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCompiler {
    pub version: String,
    pub max_items: usize,
    pub max_compiled_bytes: usize,
    pub max_item_bytes: usize,
}

impl ContextCompiler {
    pub fn compile(
        &self,
        mut request: ContextCompileRequest,
    ) -> Result<ContextSnapshot, ContextError> {
        if self.max_items == 0 || self.max_compiled_bytes == 0 || self.max_item_bytes == 0 {
            return Err(ContextError::InvalidLimits);
        }
        if self.max_items > 16_384
            || self.max_compiled_bytes > 64 * 1024 * 1024
            || self.max_item_bytes > 8 * 1024 * 1024
            || request.candidates.len() > 16_384
        {
            return Err(ContextError::InputTooLarge);
        }
        let max_input_bytes = self.max_compiled_bytes.saturating_mul(16);
        let mut input_bytes = 0usize;
        for candidate in &request.candidates {
            input_bytes = input_bytes
                .checked_add(candidate.content.len())
                .ok_or(ContextError::InputTooLarge)?;
            if input_bytes > max_input_bytes
                || candidate.content.len() > self.max_item_bytes.saturating_mul(16)
            {
                return Err(ContextError::InputTooLarge);
            }
            if candidate.sensitivity == "secret" {
                return Err(ContextError::SensitiveContentForbidden);
            }
        }
        request.candidates.sort_by(|left, right| {
            (
                std::cmp::Reverse(left.important_unread),
                left.priority,
                left.origin as u8,
                &left.source_record_id,
            )
                .cmp(&(
                    std::cmp::Reverse(right.important_unread),
                    right.priority,
                    right.origin as u8,
                    &right.source_record_id,
                ))
        });
        let mut remaining = self.max_compiled_bytes;
        let mut items = Vec::with_capacity(request.candidates.len().min(self.max_items));
        let mut compiled = Vec::new();
        for (index, candidate) in request.candidates.into_iter().enumerate() {
            let digest = sha256_bytes(candidate.content.as_bytes());
            let original_bytes = candidate.content.len() as u64;
            let (state, retained_text, reason) = if index >= self.max_items {
                (
                    InclusionState::Referenced,
                    None,
                    Some("item_count_limit".into()),
                )
            } else if remaining == 0 {
                (
                    InclusionState::Referenced,
                    None,
                    Some("compiled_byte_limit".into()),
                )
            } else {
                let content_allowance = remaining.saturating_sub(1).min(self.max_item_bytes);
                if candidate.content.len() <= content_allowance {
                    remaining -= candidate.content.len() + 1;
                    compiled.extend_from_slice(candidate.content.as_bytes());
                    compiled.push(b'\n');
                    (InclusionState::Included, Some(candidate.content), None)
                } else if content_allowance >= 64 {
                    let retained = truncate_utf8(&candidate.content, content_allowance);
                    remaining -= retained.len() + 1;
                    compiled.extend_from_slice(retained.as_bytes());
                    compiled.push(b'\n');
                    (
                        InclusionState::Summarized,
                        Some(retained),
                        Some("item_byte_limit".into()),
                    )
                } else {
                    (
                        InclusionState::Referenced,
                        None,
                        Some("insufficient_byte_budget".into()),
                    )
                }
            };
            items.push(CompiledContextItem {
                origin: candidate.origin,
                source_record_id: bound(candidate.source_record_id, 256),
                revision: candidate.revision,
                priority: candidate.priority,
                content_digest: digest,
                original_bytes,
                retained_text,
                state,
                reason,
                sensitivity: bound(candidate.sensitivity, 64),
            });
        }
        let compiled_content_digest = sha256_bytes(&compiled);
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SnapshotCore<'a> {
            id: &'a ContextSnapshotId,
            input: &'a str,
            assignment: &'a AssignmentId,
            session: &'a CollaborationSessionId,
            session_revision: u64,
            mode: ContextMode,
            compiler: &'a str,
            items: &'a [CompiledContextItem],
            instruction_catalog: Sha256Digest,
            skill_catalog: Sha256Digest,
            compiled_content: Sha256Digest,
        }
        let snapshot_digest = canonical_sha256(&SnapshotCore {
            id: &request.context_snapshot_id,
            input: &request.run_or_assignment_input_id,
            assignment: &request.assignment_id,
            session: &request.session_id,
            session_revision: request.session_revision,
            mode: request.mode,
            compiler: &self.version,
            items: &items,
            instruction_catalog: request.instruction_catalog_digest,
            skill_catalog: request.skill_catalog_digest,
            compiled_content: compiled_content_digest,
        })
        .map_err(|_| ContextError::Digest)?;
        Ok(ContextSnapshot {
            context_snapshot_id: request.context_snapshot_id,
            run_or_assignment_input_id: request.run_or_assignment_input_id,
            assignment_id: request.assignment_id,
            session_id: request.session_id,
            session_revision: request.session_revision,
            mode: request.mode,
            compiler_version: self.version.clone(),
            ordered_items: items,
            instruction_catalog_digest: request.instruction_catalog_digest,
            skill_catalog_digest: request.skill_catalog_digest,
            compiled_bytes: compiled.len() as u64,
            compiled_content_digest,
            snapshot_digest,
            created_at: request.created_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Explicit,
    Observed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionState {
    Discovered,
    Loaded,
    Skipped,
    Truncated,
    Overridden,
    Ineligible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstructionEvidence {
    pub instruction_id: String,
    pub filename: String,
    pub display_path: String,
    pub opaque_path_ref: Sha256Digest,
    pub content_digest: Sha256Digest,
    pub byte_count: u64,
    pub precedence: u32,
    pub eligible_adapters: Vec<String>,
    pub state: InstructionState,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillCatalogEvidence {
    pub skill_id: String,
    pub name: String,
    pub package_digest: Sha256Digest,
    pub eligible: bool,
    pub triggered: bool,
    pub loaded: bool,
    pub resource_digests: Vec<Sha256Digest>,
    pub evidence_level: EvidenceLevel,
}

pub fn discover_instructions(
    source_root: impl AsRef<Path>,
    working_directory: impl AsRef<Path>,
    adapter_id: &str,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> Result<Vec<InstructionEvidence>, ContextError> {
    if max_file_bytes == 0
        || max_total_bytes == 0
        || max_file_bytes > 8 * 1024 * 1024
        || max_total_bytes > 64 * 1024 * 1024
    {
        return Err(ContextError::InvalidLimits);
    }
    let root = fs::canonicalize(source_root)?;
    let working = fs::canonicalize(working_directory)?;
    if !working.starts_with(&root) {
        return Err(ContextError::WorkingDirectoryOutsideSource);
    }
    let mut directories = Vec::new();
    let mut current = Some(working.as_path());
    while let Some(directory) = current {
        directories.push(directory.to_path_buf());
        if directory == root {
            break;
        }
        current = directory.parent();
    }
    directories.reverse();
    let mut total = 0usize;
    let mut evidence = Vec::new();
    for (depth, directory) in directories.iter().enumerate() {
        for filename in ["AGENTS.md", "AGENTS.override.md", "CLAUDE.md"] {
            let path = directory.join(filename);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(ContextError::Io(error)),
            };
            if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                continue;
            }
            let canonical = fs::canonicalize(&path)?;
            if !canonical.starts_with(&root) {
                return Err(ContextError::InstructionOutsideSource);
            }
            let eligible = match filename {
                "CLAUDE.md" => adapter_id == "claude-code",
                _ => adapter_id == "codex" || adapter_id == "opencode" || adapter_id == "pi",
            };
            let available = max_total_bytes.saturating_sub(total);
            let retained_limit =
                max_file_bytes.min(if eligible { available } else { max_file_bytes });
            let bytes = read_bounded(&canonical, retained_limit)?;
            let original_len = fs::metadata(&canonical)?.len();
            let retained = bytes.len();
            if eligible {
                total = total.saturating_add(retained);
            }
            let state = if !eligible {
                InstructionState::Ineligible
            } else if (retained as u64) < original_len {
                InstructionState::Truncated
            } else {
                InstructionState::Discovered
            };
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| ContextError::WorkingDirectoryOutsideSource)?;
            let opaque_path_ref = sha256_bytes(canonical.as_os_str().as_encoded_bytes());
            evidence.push(InstructionEvidence {
                instruction_id: format!("instruction-{}", &sha256_bytes(&bytes).to_string()[..20]),
                filename: filename.into(),
                display_path: relative.to_string_lossy().into_owned(),
                opaque_path_ref,
                content_digest: sha256_bytes(&bytes),
                byte_count: original_len,
                precedence: (depth * 2 + usize::from(filename == "AGENTS.override.md")) as u32,
                eligible_adapters: if eligible {
                    vec![adapter_id.to_owned()]
                } else {
                    vec![]
                },
                state,
                evidence_level: EvidenceLevel::Observed,
            });
        }
    }
    Ok(evidence)
}

pub fn instruction_catalog_digest(
    items: &[InstructionEvidence],
) -> Result<Sha256Digest, ContextError> {
    canonical_sha256(&items).map_err(|_| ContextError::Digest)
}

pub fn skill_catalog_digest(items: &[SkillCatalogEvidence]) -> Result<Sha256Digest, ContextError> {
    canonical_sha256(&items).map_err(|_| ContextError::Digest)
}

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("context compiler limits must be positive")]
    InvalidLimits,
    #[error("working directory is outside the Source root")]
    WorkingDirectoryOutsideSource,
    #[error("instruction path resolves outside the Source root")]
    InstructionOutsideSource,
    #[error("context input exceeds its configured hard bound")]
    InputTooLarge,
    #[error("secret content cannot be embedded in a Context Snapshot")]
    SensitiveContentForbidden,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("context digest failed")]
    Digest,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ContextError> {
    let file = fs::File::open(path)?;
    let mut reader: Take<fs::File> = file.take(limit as u64);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn bound(value: String, max: usize) -> String {
    truncate_utf8(&value, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    #[test]
    fn compiler_prioritizes_unread_and_never_dumps_unbounded_history() {
        let compiler = ContextCompiler {
            version: "context/1".into(),
            max_items: 2,
            max_compiled_bytes: 64,
            max_item_bytes: 48,
        };
        let snapshot = compiler
            .compile(ContextCompileRequest {
                context_snapshot_id: ContextSnapshotId::parse("ctxs_abcdefgh").unwrap(),
                run_or_assignment_input_id: "input-1".into(),
                assignment_id: AssignmentId::parse("asg_abcdefgh").unwrap(),
                session_id: CollaborationSessionId::parse("csess_abcdefgh").unwrap(),
                session_revision: 7,
                mode: ContextMode::Initial,
                candidates: vec![
                    ContextCandidate {
                        origin: ContextOrigin::RecentMessage,
                        source_record_id: "old".into(),
                        revision: 1,
                        priority: 100,
                        content: "old message".into(),
                        sensitivity: "project_content".into(),
                        important_unread: false,
                    },
                    ContextCandidate {
                        origin: ContextOrigin::UnreadImportantMessage,
                        source_record_id: "important".into(),
                        revision: 2,
                        priority: 1,
                        content: "must read".into(),
                        sensitivity: "project_content".into(),
                        important_unread: true,
                    },
                    ContextCandidate {
                        origin: ContextOrigin::RecentMessage,
                        source_record_id: "overflow".into(),
                        revision: 3,
                        priority: 200,
                        content: "overflow".into(),
                        sensitivity: "project_content".into(),
                        important_unread: false,
                    },
                ],
                instruction_catalog_digest: digest(1),
                skill_catalog_digest: digest(2),
                created_at: UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        assert_eq!(snapshot.ordered_items[0].source_record_id, "important");
        assert_eq!(
            snapshot
                .ordered_items
                .iter()
                .filter(|item| item.retained_text.is_some())
                .count(),
            2
        );
        assert!(snapshot.compiled_bytes <= 64);
    }

    #[test]
    fn instruction_discovery_records_hashes_not_canonical_paths() {
        let root = std::env::temp_dir().join(format!(
            "conduit-context-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("AGENTS.md"), "root rule").unwrap();
        fs::write(root.join("sub/AGENTS.override.md"), "local rule").unwrap();
        let evidence = discover_instructions(&root, root.join("sub"), "codex", 1024, 2048).unwrap();
        assert_eq!(evidence.len(), 2);
        assert!(
            evidence
                .iter()
                .all(|item| !item.display_path.starts_with('/'))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiler_counts_separators_inside_the_byte_budget() {
        let compiler = ContextCompiler {
            version: "context/1".into(),
            max_items: 2,
            max_compiled_bytes: 65,
            max_item_bytes: 64,
        };
        let candidates = ["a".repeat(32), "b".repeat(32)]
            .into_iter()
            .enumerate()
            .map(|(index, content)| ContextCandidate {
                origin: ContextOrigin::RecentMessage,
                source_record_id: format!("message-{index}"),
                revision: 1,
                priority: index as u16,
                content,
                sensitivity: "project_content".into(),
                important_unread: false,
            })
            .collect();
        let snapshot = compiler
            .compile(ContextCompileRequest {
                context_snapshot_id: ContextSnapshotId::parse("ctxs_abcdefgh").unwrap(),
                run_or_assignment_input_id: "input-1".into(),
                assignment_id: AssignmentId::parse("asg_abcdefgh").unwrap(),
                session_id: CollaborationSessionId::parse("csess_abcdefgh").unwrap(),
                session_revision: 1,
                mode: ContextMode::Initial,
                candidates,
                instruction_catalog_digest: digest(1),
                skill_catalog_digest: digest(2),
                created_at: UtcTimestamp::parse("2026-09-01T00:00:00Z").unwrap(),
            })
            .unwrap();
        assert!(snapshot.compiled_bytes <= 65);
    }

    #[test]
    fn instruction_symlink_cannot_escape_source() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("conduit-context-link-{}", std::process::id()));
        let outside = root.with_extension("outside");
        fs::create_dir_all(&root).unwrap();
        fs::write(&outside, "private").unwrap();
        symlink(&outside, root.join("AGENTS.md")).unwrap();
        assert!(matches!(
            discover_instructions(&root, &root, "codex", 1024, 4096),
            Err(ContextError::InstructionOutsideSource)
        ));
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(outside).unwrap();
    }
}
