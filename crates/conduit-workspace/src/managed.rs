use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Component, Path, PathBuf},
};

use conduit_crypto::{canonical_sha256, sha256_bytes};
use conduit_domain::{Sha256Digest, SourceId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    Preserve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotPolicy {
    pub max_files: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub excluded_prefixes: Vec<String>,
    pub symlink_policy: SymlinkPolicy,
    pub preserve_modes: bool,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_file_bytes: 256 * 1024 * 1024,
            excluded_prefixes: vec![".git".into()],
            symlink_policy: SymlinkPolicy::Preserve,
            preserve_modes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEntry {
    pub relative_path: String,
    pub kind: ManifestEntryKind,
    pub size: u64,
    pub content_digest: Option<Sha256Digest>,
    pub mode: u32,
    pub symlink_target: Option<String>,
    pub hardlink_group: Option<u64>,
    pub crosses_mount: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedSnapshot {
    pub snapshot_id: String,
    pub source_id: SourceId,
    pub manifest_digest: Sha256Digest,
    pub entries: Vec<ManifestEntry>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub excluded_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationKind {
    Created,
    Modified,
    Deleted,
    Renamed,
    TypeChanged,
    ModeChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileOperation {
    pub kind: FileOperationKind,
    pub path: String,
    pub previous_path: Option<String>,
    pub before_digest: Option<Sha256Digest>,
    pub after_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileOperationManifest {
    pub base_manifest_digest: Sha256Digest,
    pub result_manifest_digest: Sha256Digest,
    pub operations: Vec<FileOperation>,
    pub digest: Sha256Digest,
}

#[derive(Debug, Error)]
pub enum ManagedError {
    #[error("managed folder contains too many entries")]
    FileCountLimit,
    #[error("managed folder exceeds the total byte limit")]
    TotalByteLimit,
    #[error("file exceeds the per-file byte limit: {0}")]
    FileByteLimit(String),
    #[error("special filesystem object is unsupported: {0}")]
    SpecialFile(String),
    #[error("symlink is forbidden by snapshot policy: {0}")]
    SymlinkForbidden(String),
    #[error("path is not valid UTF-8 relative content")]
    InvalidPath,
    #[error("managed copy destination already exists")]
    DestinationExists,
    #[error("managed snapshots belong to different Sources")]
    SourceMismatch,
    #[error("symlink target escapes the managed Workspace")]
    SymlinkEscapesWorkspace,
    #[error("snapshot source changed during copy")]
    ExternalEdit,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest digest failed: {0}")]
    Digest(#[from] conduit_crypto::CanonicalJsonError),
}

pub fn snapshot_folder(
    source_id: SourceId,
    root: impl AsRef<Path>,
    policy: &SnapshotPolicy,
) -> Result<ManagedSnapshot, ManagedError> {
    let root = fs::canonicalize(root)?;
    let root_device = fs::metadata(&root)?.dev();
    let mut entries = Vec::new();
    let mut total_files = 0u64;
    let mut total_bytes = 0u64;
    let mut hardlinks: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    walk(
        &root,
        &root,
        root_device,
        policy,
        &mut entries,
        &mut total_files,
        &mut total_bytes,
        &mut hardlinks,
    )?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ManifestIdentity<'a> {
        source_id: &'a SourceId,
        policy: &'a SnapshotPolicy,
        entries: &'a [ManifestEntry],
    }
    let manifest_digest = canonical_sha256(&ManifestIdentity {
        source_id: &source_id,
        policy,
        entries: &entries,
    })?;
    let snapshot_id = format!("snap_{}", &manifest_digest.to_string()[..24]);
    Ok(ManagedSnapshot {
        snapshot_id,
        source_id,
        manifest_digest,
        entries,
        total_files,
        total_bytes,
        excluded_prefixes: policy.excluded_prefixes.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn walk(
    root: &Path,
    directory: &Path,
    root_device: u64,
    policy: &SnapshotPolicy,
    entries: &mut Vec<ManifestEntry>,
    total_files: &mut u64,
    total_bytes: &mut u64,
    hardlinks: &mut BTreeMap<(u64, u64), u64>,
) -> Result<(), ManagedError> {
    let mut children: Vec<_> = fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ManagedError::InvalidPath)?;
        let relative_text = relative
            .to_str()
            .ok_or(ManagedError::InvalidPath)?
            .replace('\\', "/");
        if excluded(&relative_text, &policy.excluded_prefixes) {
            continue;
        }
        if entries.len() as u64 >= policy.max_files {
            return Err(ManagedError::FileCountLimit);
        }
        let metadata = fs::symlink_metadata(&path)?;
        let mode = metadata.permissions().mode();
        let crosses_mount = metadata.dev() != root_device;
        if metadata.file_type().is_symlink() {
            if policy.symlink_policy == SymlinkPolicy::Reject {
                return Err(ManagedError::SymlinkForbidden(relative_text));
            }
            let target = fs::read_link(&path)?;
            let target_text = target.to_str().ok_or(ManagedError::InvalidPath)?.to_owned();
            entries.push(ManifestEntry {
                relative_path: relative_text,
                kind: ManifestEntryKind::Symlink,
                size: target_text.len() as u64,
                content_digest: Some(sha256_bytes(target_text.as_bytes())),
                mode,
                symlink_target: Some(target_text),
                hardlink_group: None,
                crosses_mount,
            });
        } else if metadata.is_dir() {
            entries.push(ManifestEntry {
                relative_path: relative_text,
                kind: ManifestEntryKind::Directory,
                size: 0,
                content_digest: None,
                mode,
                symlink_target: None,
                hardlink_group: None,
                crosses_mount,
            });
            walk(
                root,
                &path,
                root_device,
                policy,
                entries,
                total_files,
                total_bytes,
                hardlinks,
            )?;
        } else if metadata.is_file() {
            if metadata.len() > policy.max_file_bytes {
                return Err(ManagedError::FileByteLimit(relative_text));
            }
            *total_files += 1;
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or(ManagedError::TotalByteLimit)?;
            if *total_bytes > policy.max_total_bytes {
                return Err(ManagedError::TotalByteLimit);
            }
            let bytes = fs::read(&path)?;
            let after = fs::metadata(&path)?;
            if after.len() != metadata.len()
                || after.mtime_nsec() != metadata.mtime_nsec()
                || after.mtime() != metadata.mtime()
            {
                return Err(ManagedError::ExternalEdit);
            }
            let hardlink_group = if metadata.nlink() > 1 {
                let next = hardlinks.len() as u64 + 1;
                Some(
                    *hardlinks
                        .entry((metadata.dev(), metadata.ino()))
                        .or_insert(next),
                )
            } else {
                None
            };
            entries.push(ManifestEntry {
                relative_path: relative_text,
                kind: ManifestEntryKind::File,
                size: metadata.len(),
                content_digest: Some(sha256_bytes(&bytes)),
                mode,
                symlink_target: None,
                hardlink_group,
                crosses_mount,
            });
        } else {
            return Err(ManagedError::SpecialFile(relative_text));
        }
    }
    Ok(())
}

pub fn create_managed_copy(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    expected: &ManagedSnapshot,
    policy: &SnapshotPolicy,
) -> Result<ManagedSnapshot, ManagedError> {
    let source = fs::canonicalize(source)?;
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(ManagedError::DestinationExists);
    }
    let observed = snapshot_folder(expected.source_id.clone(), &source, policy)?;
    if observed.manifest_digest != expected.manifest_digest || observed.entries != expected.entries
    {
        return Err(ManagedError::ExternalEdit);
    }
    fs::create_dir_all(destination)?;
    let copy_result = (|| {
        let mut copied_hardlinks = BTreeMap::<u64, PathBuf>::new();
        for entry in &expected.entries {
            let relative = validated_relative_path(&entry.relative_path)?;
            let from = source.join(&relative);
            let to = destination.join(&relative);
            ensure_beneath(destination, &to)?;
            match entry.kind {
                ManifestEntryKind::Directory => fs::create_dir_all(&to)?,
                ManifestEntryKind::File => {
                    if let Some(parent) = to.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if let Some(group) = entry.hardlink_group {
                        if let Some(first) = copied_hardlinks.get(&group) {
                            fs::hard_link(first, &to)?;
                        } else {
                            fs::copy(&from, &to)?;
                            copied_hardlinks.insert(group, to.clone());
                        }
                    } else {
                        fs::copy(&from, &to)?;
                    }
                    if policy.preserve_modes {
                        fs::set_permissions(&to, fs::Permissions::from_mode(entry.mode))?;
                    }
                }
                ManifestEntryKind::Symlink => {
                    if let Some(parent) = to.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let target = entry
                        .symlink_target
                        .as_deref()
                        .ok_or(ManagedError::InvalidPath)?;
                    validate_contained_symlink(&relative, target)?;
                    symlink(target, &to)?;
                }
            }
        }
        let result = snapshot_folder(expected.source_id.clone(), destination, policy)?;
        if result.manifest_digest != expected.manifest_digest {
            return Err(ManagedError::ExternalEdit);
        }
        Ok(result)
    })();
    if copy_result.is_err() {
        // A failed copy is never exposed as a usable Run Workspace.
        let _ = fs::remove_dir_all(destination);
    }
    copy_result
}

pub fn diff_snapshots(
    base: &ManagedSnapshot,
    result: &ManagedSnapshot,
) -> Result<FileOperationManifest, ManagedError> {
    if base.source_id != result.source_id {
        return Err(ManagedError::SourceMismatch);
    }
    let old: BTreeMap<_, _> = base
        .entries
        .iter()
        .map(|entry| (&entry.relative_path, entry))
        .collect();
    let new: BTreeMap<_, _> = result
        .entries
        .iter()
        .map(|entry| (&entry.relative_path, entry))
        .collect();
    let paths: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
    let mut operations = Vec::new();
    for path in paths {
        match (old.get(path), new.get(path)) {
            (None, Some(after)) => operations.push(operation(
                FileOperationKind::Created,
                path,
                None,
                None,
                after.content_digest,
            )),
            (Some(before), None) => operations.push(operation(
                FileOperationKind::Deleted,
                path,
                None,
                before.content_digest,
                None,
            )),
            (Some(before), Some(after)) if before.kind != after.kind => operations.push(operation(
                FileOperationKind::TypeChanged,
                path,
                None,
                before.content_digest,
                after.content_digest,
            )),
            (Some(before), Some(after))
                if before.content_digest != after.content_digest
                    || before.symlink_target != after.symlink_target
                    || before.mode != after.mode =>
            {
                operations.push(operation(
                    FileOperationKind::Modified,
                    path,
                    None,
                    before.content_digest,
                    after.content_digest,
                ))
            }
            (Some(before), Some(after)) if before.mode != after.mode => operations.push(operation(
                FileOperationKind::ModeChanged,
                path,
                None,
                before.content_digest,
                after.content_digest,
            )),
            _ => {}
        }
    }
    // Convert an unambiguous delete/create content match into a rename.
    for index in 0..operations.len() {
        if operations[index].kind != FileOperationKind::Deleted {
            continue;
        }
        let digest = operations[index].before_digest;
        let matches: Vec<_> = operations
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                candidate.kind == FileOperationKind::Created
                    && digest.is_some()
                    && candidate.after_digest == digest
            })
            .map(|(i, _)| i)
            .collect();
        if matches.len() == 1 {
            let target = matches[0];
            let old_path = operations[index].path.clone();
            operations[target].kind = FileOperationKind::Renamed;
            operations[target].previous_path = Some(old_path);
            operations[index].kind = FileOperationKind::Renamed;
            operations[index].path.clear();
        }
    }
    operations.retain(|operation| !operation.path.is_empty());
    operations.sort_by(|left, right| left.path.cmp(&right.path));
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DigestInput<'a> {
        base: Sha256Digest,
        result: Sha256Digest,
        operations: &'a [FileOperation],
    }
    let digest = canonical_sha256(&DigestInput {
        base: base.manifest_digest,
        result: result.manifest_digest,
        operations: &operations,
    })?;
    Ok(FileOperationManifest {
        base_manifest_digest: base.manifest_digest,
        result_manifest_digest: result.manifest_digest,
        operations,
        digest,
    })
}

fn operation(
    kind: FileOperationKind,
    path: &str,
    previous_path: Option<String>,
    before_digest: Option<Sha256Digest>,
    after_digest: Option<Sha256Digest>,
) -> FileOperation {
    FileOperation {
        kind,
        path: path.to_owned(),
        previous_path,
        before_digest,
        after_digest,
    }
}

fn excluded(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn validated_relative_path(value: &str) -> Result<PathBuf, ManagedError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ManagedError::InvalidPath);
    }
    Ok(path.to_path_buf())
}

fn ensure_beneath(root: &Path, candidate: &Path) -> Result<(), ManagedError> {
    if candidate.starts_with(root) {
        Ok(())
    } else {
        Err(ManagedError::InvalidPath)
    }
}

fn validate_contained_symlink(link_path: &Path, target: &str) -> Result<(), ManagedError> {
    let target = Path::new(target);
    if target.is_absolute() {
        return Err(ManagedError::SymlinkEscapesWorkspace);
    }
    let mut depth = link_path.parent().map_or(0usize, |parent| {
        parent
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count()
    });
    for component in target.components() {
        match component {
            Component::Normal(_) => depth = depth.saturating_add(1),
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ManagedError::SymlinkEscapesWorkspace);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "conduit-managed-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn managed_copy_and_delta_are_content_addressed() {
        let root = temp();
        fs::write(root.join("a.txt"), "one").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/b.txt"), "two").unwrap();
        let source = SourceId::parse("src_abcdefgh").unwrap();
        let policy = SnapshotPolicy::default();
        let before = snapshot_folder(source.clone(), &root, &policy).unwrap();
        let copy = root.with_extension("copy");
        create_managed_copy(&root, &copy, &before, &policy).unwrap();
        fs::write(copy.join("a.txt"), "changed").unwrap();
        fs::rename(copy.join("sub/b.txt"), copy.join("sub/c.txt")).unwrap();
        let after = snapshot_folder(source, &copy, &policy).unwrap();
        let delta = diff_snapshots(&before, &after).unwrap();
        assert!(
            delta
                .operations
                .iter()
                .any(|op| op.kind == FileOperationKind::Modified)
        );
        assert!(
            delta
                .operations
                .iter()
                .any(|op| op.kind == FileOperationKind::Renamed)
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(copy).unwrap();
    }

    #[test]
    fn managed_copy_rejects_manifest_path_traversal_before_writing() {
        let root = temp();
        fs::write(root.join("a.txt"), "one").unwrap();
        let policy = SnapshotPolicy::default();
        let mut snapshot =
            snapshot_folder(SourceId::parse("src_abcdefgh").unwrap(), &root, &policy).unwrap();
        snapshot.entries[0].relative_path = "../../escape".into();
        let copy = root.with_extension("copy-traversal");
        assert!(matches!(
            create_managed_copy(&root, &copy, &snapshot, &policy),
            Err(ManagedError::ExternalEdit | ManagedError::InvalidPath)
        ));
        assert!(!copy.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
