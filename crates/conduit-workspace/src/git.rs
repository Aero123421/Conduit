use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use conduit_crypto::{canonical_sha256, sha256_bytes};
use conduit_domain::{RunId, Sha256Digest, SourceId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub digest: Sha256Digest,
    pub object_format: GitObjectFormat,
    pub repository_format_version: String,
    pub normalized_remotes: Vec<String>,
    pub initial_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitDiagnostics {
    pub git_version: String,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub upstream_ahead: Option<u64>,
    pub upstream_behind: Option<u64>,
    pub detached: bool,
    pub dirty: bool,
    pub conflicted: bool,
    pub status_digest: Sha256Digest,
    pub bounded_status: Vec<String>,
    pub shallow: bool,
    pub partial_clone_filter: Option<String>,
    pub sparse_checkout: bool,
    pub sparse_patterns_digest: Option<Sha256Digest>,
    pub submodules: Vec<SubmoduleDiagnostic>,
    pub lfs: LfsDiagnostic,
    pub missing_objects: Vec<String>,
    pub alternates_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmoduleDiagnostic {
    pub path: String,
    pub commit: String,
    pub initialized: bool,
    pub conflicted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LfsDiagnostic {
    pub tracked_paths_declared: bool,
    pub client_available: bool,
    pub objects_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitObservation {
    pub identity: RepositoryIdentity,
    pub diagnostics: GitDiagnostics,
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git executable is unavailable")]
    GitUnavailable,
    #[error("path is not a Git work tree")]
    NotRepository,
    #[error("git command {operation} failed: {summary}")]
    CommandFailed {
        operation: &'static str,
        summary: String,
    },
    #[error("git returned invalid UTF-8 for {0}")]
    InvalidOutput(&'static str),
    #[error("repository object format is unsupported: {0}")]
    UnsupportedObjectFormat(String),
    #[error("required repository object is missing: {0}")]
    RepositoryObjectMissing(String),
    #[error("generated worktree branch already exists")]
    WorktreeBranchInUse,
    #[error("managed worktree path already exists")]
    WorktreePathConflict,
    #[error("writer lease already exists")]
    LeaseConflict,
    #[error("writer lease was not found")]
    LeaseMissing,
    #[error("writer lease journal is corrupt")]
    LeaseJournalCorrupt,
    #[error("worktree is dirty")]
    WorkspaceDirty,
    #[error("direct Workspace diverged from its recorded preflight state")]
    WorkspaceDiverged,
    #[error("worktree directory is missing")]
    WorktreeMissing,
    #[error("cleanup requires a healthy custody receipt")]
    CustodyInsufficient,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity digest failed: {0}")]
    Digest(#[from] conduit_crypto::CanonicalJsonError),
}

pub struct GitRepository {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectWorkspacePreflight {
    pub repository_identity_digest: Sha256Digest,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub status_digest: Sha256Digest,
    pub dirty_at_start: bool,
}

impl GitRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GitError> {
        let path = fs::canonicalize(path)?;
        let repository = Self { path };
        let inside = repository.read_text("probe", &["rev-parse", "--is-inside-work-tree"])?;
        if inside.trim() != "true" {
            return Err(GitError::NotRepository);
        }
        Ok(repository)
    }

    pub fn observe(&self) -> Result<GitObservation, GitError> {
        let object_format_text =
            self.read_text("object-format", &["rev-parse", "--show-object-format"])?;
        let object_format = match object_format_text.trim() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => GitObjectFormat::Other(bound(other, 32)),
        };
        let repository_format_version = self
            .optional_text(&["config", "--get", "core.repositoryformatversion"])?
            .unwrap_or_else(|| "0".into());
        let mut normalized_remotes = self.remote_identities()?;
        normalized_remotes.sort();
        normalized_remotes.dedup();
        let initial_root = self
            .optional_text(&["rev-list", "--max-parents=0", "HEAD"])?
            .and_then(|text| text.lines().next().map(ToOwned::to_owned));
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IdentityInput<'a> {
            object_format: &'a GitObjectFormat,
            repository_format_version: &'a str,
            normalized_remotes: &'a [String],
            initial_root: &'a Option<String>,
        }
        let digest = canonical_sha256(&IdentityInput {
            object_format: &object_format,
            repository_format_version: &repository_format_version,
            normalized_remotes: &normalized_remotes,
            initial_root: &initial_root,
        })?;

        let status = self.read_bytes("status", &["status", "--porcelain=v2", "-z", "--branch"])?;
        let status_digest = sha256_bytes(&status);
        let fields: Vec<&[u8]> = status
            .split(|byte| *byte == 0)
            .filter(|v| !v.is_empty())
            .collect();
        let mut branch = None;
        let mut upstream = None;
        let mut upstream_ahead = None;
        let mut upstream_behind = None;
        let mut dirty = false;
        let mut conflicted = false;
        let mut bounded_status = Vec::new();
        for field in fields {
            let line = String::from_utf8_lossy(field);
            if let Some(value) = line.strip_prefix("# branch.head ") {
                if value != "(detached)" {
                    branch = Some(bound(value, 256));
                }
            } else if let Some(value) = line.strip_prefix("# branch.upstream ") {
                upstream = Some(bound(value, 256));
            } else if let Some(value) = line.strip_prefix("# branch.ab ") {
                let mut counts = value.split_whitespace();
                upstream_ahead = counts
                    .next()
                    .and_then(|text| text.strip_prefix('+'))
                    .and_then(|text| text.parse().ok());
                upstream_behind = counts
                    .next()
                    .and_then(|text| text.strip_prefix('-'))
                    .and_then(|text| text.parse().ok());
            } else if !line.starts_with('#') {
                dirty = true;
                conflicted |= line.starts_with("u ");
                if bounded_status.len() < 64 {
                    bounded_status.push(bound(&line, 512));
                }
            }
        }
        let head = self
            .optional_text(&["rev-parse", "--verify", "HEAD"])?
            .map(|value| value.trim().to_owned());
        let detached = branch.is_none() && head.is_some();
        let shallow = self
            .optional_text(&["rev-parse", "--is-shallow-repository"])?
            .is_some_and(|value| value.trim() == "true");
        let partial_clone_filter = self.partial_clone_filter()?;
        let sparse_checkout = self
            .optional_text(&["config", "--bool", "--get", "core.sparseCheckout"])?
            .is_some_and(|value| value.trim() == "true");
        let git_dir = self.read_text("git-dir", &["rev-parse", "--git-dir"])?;
        let git_dir = if Path::new(git_dir.trim()).is_absolute() {
            PathBuf::from(git_dir.trim())
        } else {
            self.path.join(git_dir.trim())
        };
        let sparse_patterns = [
            git_dir.join("info/sparse-checkout"),
            git_dir.join("info/sparse-checkout-cone"),
        ]
        .into_iter()
        .find_map(|path| fs::read(path).ok());
        let sparse_patterns_digest = sparse_patterns.as_deref().map(sha256_bytes);
        let alternates_present = git_dir.join("objects/info/alternates").exists();
        let submodules = self.submodules()?;
        let lfs = self.lfs_diagnostic()?;
        let missing_objects = self.missing_objects()?;
        Ok(GitObservation {
            identity: RepositoryIdentity {
                digest,
                object_format,
                repository_format_version: bound(repository_format_version.trim(), 32),
                normalized_remotes,
                initial_root,
            },
            diagnostics: GitDiagnostics {
                git_version: git_version()?,
                head,
                branch,
                upstream,
                upstream_ahead,
                upstream_behind,
                detached,
                dirty,
                conflicted,
                status_digest,
                bounded_status,
                shallow,
                partial_clone_filter,
                sparse_checkout,
                sparse_patterns_digest,
                submodules,
                lfs,
                missing_objects,
                alternates_present,
            },
        })
    }

    pub fn direct_preflight(&self) -> Result<DirectWorkspacePreflight, GitError> {
        let observation = self.observe()?;
        Ok(DirectWorkspacePreflight {
            repository_identity_digest: observation.identity.digest,
            head: observation.diagnostics.head,
            branch: observation.diagnostics.branch,
            upstream: observation.diagnostics.upstream,
            status_digest: observation.diagnostics.status_digest,
            dirty_at_start: observation.diagnostics.dirty,
        })
    }

    /// The caller supplies the status digest it attributes to the Run. Changes to
    /// HEAD, branch, identity, or any other working status are treated as external.
    pub fn verify_direct_attribution(
        &self,
        preflight: &DirectWorkspacePreflight,
        attributed_status_digest: Sha256Digest,
    ) -> Result<(), GitError> {
        let current = self.observe()?;
        if current.identity.digest != preflight.repository_identity_digest
            || current.diagnostics.head != preflight.head
            || current.diagnostics.branch != preflight.branch
            || current.diagnostics.status_digest != attributed_status_digest
        {
            Err(GitError::WorkspaceDiverged)
        } else {
            Ok(())
        }
    }

    pub fn verify_object(&self, object: &str) -> Result<(), GitError> {
        if !valid_object_expression(object) {
            return Err(GitError::RepositoryObjectMissing(bound(object, 128)));
        }
        if self.run(&["cat-file", "-e", object])?.status.success() {
            Ok(())
        } else {
            Err(GitError::RepositoryObjectMissing(bound(object, 128)))
        }
    }

    fn remote_identities(&self) -> Result<Vec<String>, GitError> {
        let Some(text) = self.optional_text(&["remote", "-v"])? else {
            return Ok(Vec::new());
        };
        Ok(text
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .map(normalize_remote)
            .collect())
    }

    fn partial_clone_filter(&self) -> Result<Option<String>, GitError> {
        let text = self.optional_text(&[
            "config",
            "--get-regexp",
            r"^remote\..*\.partialclonefilter$",
        ])?;
        Ok(text.and_then(|value| value.split_whitespace().nth(1).map(|v| bound(v, 128))))
    }

    fn submodules(&self) -> Result<Vec<SubmoduleDiagnostic>, GitError> {
        let output = self.run(&["submodule", "status", "--recursive"])?;
        if !output.status.success() {
            return Ok(Vec::new());
        }
        let text =
            String::from_utf8(output.stdout).map_err(|_| GitError::InvalidOutput("submodule"))?;
        Ok(text
            .lines()
            .take(128)
            .filter_map(|line| {
                let marker = line.as_bytes().first().copied()?;
                let mut parts = line[1..].split_whitespace();
                Some(SubmoduleDiagnostic {
                    commit: bound(parts.next()?, 128),
                    path: bound(parts.next()?, 512),
                    initialized: marker != b'-',
                    conflicted: marker == b'U',
                })
            })
            .collect())
    }

    fn lfs_diagnostic(&self) -> Result<LfsDiagnostic, GitError> {
        let attributes =
            self.optional_text(&["grep", "-Il", "filter=lfs", "--", ".gitattributes"])?;
        let tracked_paths_declared = attributes.is_some();
        let available = Command::new("git-lfs")
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success());
        let objects_available = if tracked_paths_declared && available {
            Some(self.run(&["lfs", "fsck", "--objects"])?.status.success())
        } else {
            None
        };
        Ok(LfsDiagnostic {
            tracked_paths_declared,
            client_available: available,
            objects_available,
        })
    }

    fn missing_objects(&self) -> Result<Vec<String>, GitError> {
        let output = self.run(&["rev-list", "--objects", "--missing=print", "HEAD"])?;
        if !output.status.success() {
            return Ok(vec!["head_or_history_unavailable".into()]);
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.starts_with('?'))
            .take(64)
            .map(|line| bound(line, 160))
            .collect())
    }

    fn read_text(&self, operation: &'static str, args: &[&str]) -> Result<String, GitError> {
        String::from_utf8(self.read_bytes(operation, args)?)
            .map_err(|_| GitError::InvalidOutput(operation))
    }

    fn read_bytes(&self, operation: &'static str, args: &[&str]) -> Result<Vec<u8>, GitError> {
        let output = self.run(args)?;
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                operation,
                summary: bound(&String::from_utf8_lossy(&output.stderr), 512),
            });
        }
        Ok(output.stdout)
    }

    fn optional_text(&self, args: &[&str]) -> Result<Option<String>, GitError> {
        let output = self.run(args)?;
        if output.status.success() {
            Ok(Some(
                String::from_utf8(output.stdout)
                    .map_err(|_| GitError::InvalidOutput("optional"))?,
            ))
        } else {
            Ok(None)
        }
    }

    fn run(&self, args: &[&str]) -> Result<Output, GitError> {
        Command::new("git")
            .arg("-c")
            .arg("color.ui=false")
            .arg("-c")
            .arg("core.quotePath=false")
            .arg("-C")
            .arg(&self.path)
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    GitError::GitUnavailable
                } else {
                    GitError::Io(error)
                }
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeLease {
    pub run_id: RunId,
    pub source_id: SourceId,
    pub branch: String,
    pub path: PathBuf,
    pub base_commit: String,
}

#[derive(Debug)]
pub struct WorktreeManager {
    root: PathBuf,
    leases: BTreeMap<(RunId, SourceId), WorktreeLease>,
}

impl WorktreeManager {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, GitError> {
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root)?;
        let mut leases = BTreeMap::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_name().to_string_lossy().ends_with(".lease.json") {
                continue;
            }
            let journal: LeaseJournal = serde_json::from_slice(&fs::read(entry.path())?)
                .map_err(|_| GitError::LeaseJournalCorrupt)?;
            leases.insert(
                (
                    journal.lease.run_id.clone(),
                    journal.lease.source_id.clone(),
                ),
                journal.lease,
            );
        }
        Ok(Self { root, leases })
    }

    pub fn create(
        &mut self,
        repository: &GitRepository,
        run_id: RunId,
        source_id: SourceId,
        source_slug: &str,
        base_commit: &str,
    ) -> Result<WorktreeLease, GitError> {
        repository.verify_object(&format!("{base_commit}^{{commit}}"))?;
        let key = (run_id.clone(), source_id.clone());
        if self.leases.contains_key(&key) {
            return Err(GitError::LeaseConflict);
        }
        let run_short = run_id
            .as_str()
            .trim_start_matches("run_")
            .chars()
            .take(12)
            .collect::<String>();
        let slug = sanitize_slug(source_slug);
        let branch = format!("conduit/run/{run_short}/{slug}");
        if repository
            .run(&[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch}"),
            ])?
            .status
            .success()
        {
            return Err(GitError::WorktreeBranchInUse);
        }
        let path = self.root.join(format!("{}-{}", run_short, slug));
        if path.exists() {
            return Err(GitError::WorktreePathConflict);
        }
        let lease = WorktreeLease {
            run_id,
            source_id,
            branch: branch.clone(),
            path: path.clone(),
            base_commit: base_commit.to_owned(),
        };
        self.persist_lease(&lease, LeaseJournalState::Reserved)?;
        let output = Command::new("git")
            .arg("-C")
            .arg(&repository.path)
            .args(["worktree", "add", "-b", &branch])
            .arg(&path)
            .arg(base_commit)
            .output()?;
        if !output.status.success() {
            let _ = fs::remove_file(self.lease_journal_path(&lease));
            return Err(GitError::CommandFailed {
                operation: "worktree-add",
                summary: bound(&String::from_utf8_lossy(&output.stderr), 512),
            });
        }
        let lock = Command::new("git")
            .arg("-C")
            .arg(&repository.path)
            .args(["worktree", "lock", "--reason", "Conduit active Run"])
            .arg(&path)
            .output()?;
        if !lock.status.success() {
            let _ = Command::new("git")
                .arg("-C")
                .arg(&repository.path)
                .args(["worktree", "remove", "--force"])
                .arg(&path)
                .output();
            let _ = fs::remove_file(self.lease_journal_path(&lease));
            return Err(GitError::CommandFailed {
                operation: "worktree-lock",
                summary: bound(&String::from_utf8_lossy(&lock.stderr), 512),
            });
        }
        self.persist_lease(&lease, LeaseJournalState::Active)?;
        self.leases.insert(key, lease.clone());
        Ok(lease)
    }

    pub fn cleanup(
        &mut self,
        repository: &GitRepository,
        run_id: &RunId,
        source_id: &SourceId,
        healthy_custody_receipt: bool,
    ) -> Result<(), GitError> {
        if !healthy_custody_receipt {
            return Err(GitError::CustodyInsufficient);
        }
        let key = (run_id.clone(), source_id.clone());
        let lease = self.leases.get(&key).ok_or(GitError::LeaseMissing)?;
        if !lease.path.exists() {
            return Err(GitError::WorktreeMissing);
        }
        let worktree = GitRepository::open(&lease.path)?;
        if worktree.observe()?.diagnostics.dirty {
            return Err(GitError::WorkspaceDirty);
        }
        let unlock = Command::new("git")
            .arg("-C")
            .arg(&repository.path)
            .args(["worktree", "unlock"])
            .arg(&lease.path)
            .output()?;
        if !unlock.status.success() {
            return Err(GitError::CommandFailed {
                operation: "worktree-unlock",
                summary: bound(&String::from_utf8_lossy(&unlock.stderr), 512),
            });
        }
        let remove = Command::new("git")
            .arg("-C")
            .arg(&repository.path)
            .args(["worktree", "remove"])
            .arg(&lease.path)
            .output()?;
        if !remove.status.success() {
            return Err(GitError::CommandFailed {
                operation: "worktree-remove",
                summary: bound(&String::from_utf8_lossy(&remove.stderr), 512),
            });
        }
        fs::remove_file(self.lease_journal_path(lease))?;
        self.leases.remove(&key);
        Ok(())
    }

    pub fn reconcile(&self, run_id: &RunId, source_id: &SourceId) -> Result<(), GitError> {
        let lease = self
            .leases
            .get(&(run_id.clone(), source_id.clone()))
            .ok_or(GitError::LeaseMissing)?;
        if lease.path.exists() {
            Ok(())
        } else {
            Err(GitError::WorktreeMissing)
        }
    }

    fn lease_journal_path(&self, lease: &WorktreeLease) -> PathBuf {
        self.root.join(format!(
            "{}-{}.lease.json",
            lease.run_id.as_str(),
            lease.source_id.as_str()
        ))
    }

    fn persist_lease(
        &self,
        lease: &WorktreeLease,
        state: LeaseJournalState,
    ) -> Result<(), GitError> {
        let path = self.lease_journal_path(lease);
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let bytes = serde_json::to_vec(&LeaseJournal {
            lease: lease.clone(),
            state,
        })
        .map_err(|_| GitError::LeaseJournalCorrupt)?;
        let mut file = fs::File::create(&temporary)?;
        use std::io::Write as _;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LeaseJournalState {
    Reserved,
    Active,
}

#[derive(Debug, Serialize, Deserialize)]
struct LeaseJournal {
    lease: WorktreeLease,
    state: LeaseJournalState,
}

fn git_version() -> Result<String, GitError> {
    let output = Command::new("git")
        .arg("--version")
        .output()
        .map_err(|_| GitError::GitUnavailable)?;
    if !output.status.success() {
        return Err(GitError::GitUnavailable);
    }
    Ok(bound(String::from_utf8_lossy(&output.stdout).trim(), 128))
}

fn normalize_remote(value: &str) -> String {
    let mut remote = value.trim().trim_end_matches('/').to_owned();
    if let Some(scheme) = remote.find("://") {
        let authority_start = scheme + 3;
        if let Some(at) = remote[authority_start..].find('@') {
            remote.replace_range(authority_start..authority_start + at + 1, "");
        }
    }
    if remote.ends_with(".git") {
        remote.truncate(remote.len() - 4);
    }
    bound(&remote.to_lowercase(), 512)
}

fn sanitize_slug(value: &str) -> String {
    let slug: String = value
        .chars()
        .filter_map(|ch| {
            if ch.is_ascii_alphanumeric() {
                Some(ch.to_ascii_lowercase())
            } else if matches!(ch, '-' | '_') {
                Some(ch)
            } else {
                None
            }
        })
        .take(48)
        .collect();
    if slug.is_empty() {
        "source".into()
    } else {
        slug
    }
}

fn valid_object_expression(value: &str) -> bool {
    let object = value.strip_suffix("^{commit}").unwrap_or(value);
    matches!(object.len(), 40 | 64) && object.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bound(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("conduit-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn git(path: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn repository() -> (PathBuf, GitRepository, String) {
        let path = temp_dir("git");
        git(&path, &["init", "-q"]);
        git(&path, &["config", "user.email", "test@example.invalid"]);
        git(&path, &["config", "user.name", "Conduit Test"]);
        fs::write(path.join("README"), "base\n").unwrap();
        git(&path, &["add", "README"]);
        git(&path, &["commit", "-qm", "base"]);
        let repo = GitRepository::open(&path).unwrap();
        let head = repo.observe().unwrap().diagnostics.head.unwrap();
        (path, repo, head)
    }

    #[test]
    fn observes_dirty_detached_and_repository_identity() {
        let (path, repo, _) = repository();
        fs::write(path.join("README"), "dirty\n").unwrap();
        let observation = repo.observe().unwrap();
        assert!(observation.diagnostics.dirty);
        assert!(matches!(
            observation.identity.object_format,
            GitObjectFormat::Sha1 | GitObjectFormat::Sha256
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn creates_unique_locked_worktree_without_touching_dirty_main_tree() {
        let (path, repo, head) = repository();
        fs::write(path.join("README"), "user edit\n").unwrap();
        let root = temp_dir("worktrees");
        let mut manager = WorktreeManager::new(&root).unwrap();
        let run = RunId::parse("run_abcdefgh").unwrap();
        let source = SourceId::parse("src_abcdefgh").unwrap();
        let lease = manager
            .create(&repo, run.clone(), source.clone(), "primary", &head)
            .unwrap();
        assert_eq!(
            fs::read_to_string(lease.path.join("README")).unwrap(),
            "base\n"
        );
        assert_eq!(
            fs::read_to_string(path.join("README")).unwrap(),
            "user edit\n"
        );
        assert!(matches!(
            manager.create(&repo, run.clone(), source.clone(), "primary", &head),
            Err(GitError::LeaseConflict)
        ));
        assert!(matches!(
            manager.cleanup(&repo, &run, &source, false),
            Err(GitError::CustodyInsufficient)
        ));
        fs::write(lease.path.join("uncollected"), "dirty").unwrap();
        assert!(matches!(
            manager.cleanup(&repo, &run, &source, true),
            Err(GitError::WorkspaceDirty)
        ));
        fs::remove_dir_all(path).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn direct_workspace_detects_external_head_movement() {
        let (path, repo, _) = repository();
        let preflight = repo.direct_preflight().unwrap();
        fs::write(path.join("external"), "edit").unwrap();
        git(&path, &["add", "external"]);
        git(&path, &["commit", "-qm", "external edit"]);
        let attributed = repo.observe().unwrap().diagnostics.status_digest;
        assert!(matches!(
            repo.verify_direct_attribution(&preflight, attributed),
            Err(GitError::WorkspaceDiverged)
        ));
        fs::remove_dir_all(path).unwrap();
    }
}
