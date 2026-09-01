//! Typed Linux Runtime Providers. Provider commands are assembled from typed
//! fields; no provider or shell command string is accepted from an Agent.

mod container;
mod incus;
mod native;
mod restricted;

pub use container::{ContainerBackend, ContainerProvider};
pub use incus::IncusProvider;
pub use native::{NativeProvider, ProcessSupervisor};
pub use restricted::RestrictedNativeProvider;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::{fs::FileTypeExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("capability unavailable: {0}")]
    CapabilityUnavailable(String),
    #[error("runtime identity mismatch")]
    IdentityMismatch,
    #[error("runtime not found")]
    NotFound,
    #[error("runtime state is uncertain: {0}")]
    Uncertain(String),
    #[error("invalid runtime request: {0}")]
    Invalid(String),
    #[error("provider command failed: {code}")]
    Provider { code: String },
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime record failed: {0}")]
    Record(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    Native,
    RestrictedNative,
    Container,
    Vm,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Planned,
    Preparing,
    Prepared,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
    Lost,
    Uncertain,
    RecoveryRequired,
    Destroying,
    Destroyed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Effective,
    Degraded,
    Unavailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub capability: String,
    pub state: CapabilityState,
    pub source: String,
    pub reason_code: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReceipt {
    pub provider_id: String,
    pub provider_version: Option<String>,
    pub capabilities: Vec<CapabilityEvidence>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Open,
    Restricted,
    Offline,
    LanExplicit,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub pid_limit: Option<u32>,
    pub storage_bytes: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceAttachment {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
    pub read_only: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRequest {
    pub runtime_id: String,
    pub run_id: String,
    pub kind: RuntimeKind,
    pub provider_selector: String,
    pub spec_digest: String,
    pub image: Option<String>,
    pub resources: ResourceLimits,
    pub network: NetworkMode,
    pub workspaces: Vec<WorkspaceAttachment>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRuntime {
    pub runtime_id: String,
    pub provider_id: String,
    pub spec_digest: String,
    pub object_id: String,
    pub state: RuntimeState,
    pub evidence: Vec<CapabilityEvidence>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IoMode {
    Pipes,
    Pty,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchPlan {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub io_mode: IoMode,
    pub timeout_ms: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHandle {
    pub runtime_id: String,
    pub provider_id: String,
    pub spec_digest: String,
    pub object_id: String,
    pub process_identity: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStateReceipt {
    pub handle: RuntimeHandle,
    pub state: RuntimeState,
    pub exit_code: Option<i32>,
    pub evidence: Vec<CapabilityEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotReceipt {
    pub runtime_id: String,
    pub snapshot_id: String,
    pub digest: String,
    pub bytes: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionReceipt {
    pub runtime_id: String,
    pub collection_id: String,
    pub custody_complete: bool,
    pub digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyRequest {
    pub discard_authorized: bool,
    pub custody_complete: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyReceipt {
    pub runtime_id: String,
    pub destroyed: bool,
    pub evidence: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedRuntime {
    pub handle: RuntimeHandle,
    pub expected_state: RuntimeState,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReceipt {
    pub runtime_id: String,
    pub state: RuntimeState,
    pub reason_code: String,
    pub observed_identity: Option<String>,
}

pub trait RuntimeProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError>;
    fn prepare(&self, request: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError>;
    fn start(
        &self,
        prepared: &PreparedRuntime,
        launch: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError>;
    fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError>;
    fn signal(
        &self,
        handle: &RuntimeHandle,
        signal: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError>;
    fn snapshot(&self, handle: &RuntimeHandle, name: &str)
    -> Result<SnapshotReceipt, RuntimeError>;
    fn collect(&self, handle: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError>;
    fn archive(
        &self,
        _handle: &RuntimeHandle,
        _target: &Path,
    ) -> Result<SnapshotReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "runtime archive".into(),
        ))
    }
    fn restore(
        &self,
        _archive: &Path,
        _request: &RuntimeRequest,
    ) -> Result<PreparedRuntime, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "runtime archive restore".into(),
        ))
    }
    fn destroy(
        &self,
        handle: &RuntimeHandle,
        request: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError>;
    fn reconcile(
        &self,
        records: &[ExpectedRuntime],
    ) -> Result<Vec<ReconciliationReceipt>, RuntimeError>;
}
#[derive(Debug, Clone, Copy)]
pub enum RuntimeSignal {
    GracefulStop,
    ForceStop,
    Pause,
    Resume,
}

pub(crate) fn validate_request(
    request: &RuntimeRequest,
    kind: RuntimeKind,
    provider_ids: &[&str],
) -> Result<(), RuntimeError> {
    if request.kind != kind {
        return Err(RuntimeError::Invalid(
            "runtime kind does not match provider".into(),
        ));
    }
    if !provider_ids.contains(&request.provider_selector.as_str()) {
        return Err(RuntimeError::Invalid(
            "runtime provider selector does not match provider".into(),
        ));
    }
    if !request.runtime_id.starts_with("rt_")
        || request.runtime_id.len() < 11
        || request.runtime_id.len() > 131
        || !request
            .runtime_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(RuntimeError::Invalid("invalid Runtime ID".into()));
    }
    if !(request.run_id.starts_with("run_") || request.run_id.starts_with("lrun_"))
        || request.run_id.len() < 12
        || request.run_id.len() > 132
        || !request
            .run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(RuntimeError::Invalid("invalid Run ID".into()));
    }
    if request.spec_digest.len() != 64
        || !request
            .spec_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(RuntimeError::Invalid("invalid spec digest".into()));
    }
    for w in &request.workspaces {
        if !w.host_path.is_absolute() || !w.guest_path.is_absolute() {
            return Err(RuntimeError::Invalid(
                "workspace paths must be absolute".into(),
            ));
        }
        let canonical = std::fs::canonicalize(&w.host_path)
            .map_err(|_| RuntimeError::Invalid("workspace host path cannot be resolved".into()))?;
        if canonical != w.host_path {
            return Err(RuntimeError::Invalid(
                "workspace host path must be canonical".into(),
            ));
        }
        let s = canonical.to_string_lossy();
        let guest = w.guest_path.to_string_lossy();
        let metadata = std::fs::metadata(&canonical)?;
        if !metadata.is_dir() || metadata.file_type().is_socket() {
            return Err(RuntimeError::Invalid(
                "workspace host path must be a directory".into(),
            ));
        }
        if s.contains([',', '\n', '\r', '\0']) || guest.contains([',', '\n', '\r', '\0']) {
            return Err(RuntimeError::Invalid(
                "workspace mount path contains a provider delimiter".into(),
            ));
        }
        let user_home = std::env::var_os("HOME").and_then(|path| std::fs::canonicalize(path).ok());
        if canonical == Path::new("/") || user_home.as_ref() == Some(&canonical) {
            return Err(RuntimeError::Invalid(
                "broad host mounts are forbidden".into(),
            ));
        }
        if s.contains("docker.sock")
            || s.contains("podman.sock")
            || s.contains("incus") && s.contains("socket")
        {
            return Err(RuntimeError::Invalid(
                "provider socket projection is forbidden".into(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn command_output(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::Output, RuntimeError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child.id() as i32;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| RuntimeError::Record("provider stdout unavailable".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| RuntimeError::Record("provider stderr unavailable".into()))?;
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            return Err(RuntimeError::Provider {
                code: "provider_timeout_killed".into(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out
        .join()
        .map_err(|_| RuntimeError::Record("provider stdout reader panicked".into()))??;
    let stderr = err
        .join()
        .map_err(|_| RuntimeError::Record("provider stderr reader panicked".into()))??;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}
pub(crate) fn version(program: &str) -> Option<String> {
    let mut c = Command::new(program);
    c.arg("--version");
    command_output(c, Duration::from_secs(3))
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .chars()
                .take(256)
                .collect()
        })
}
pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use tempfile::tempdir;

    fn request(path: PathBuf) -> RuntimeRequest {
        RuntimeRequest {
            runtime_id: "rt_contract_01".into(),
            run_id: "run_contract_01".into(),
            kind: RuntimeKind::Container,
            provider_selector: "docker".into(),
            spec_digest: "44".repeat(32),
            image: Some("example.invalid/image@sha256:00".into()),
            resources: ResourceLimits {
                cpu: None,
                memory_bytes: None,
                pid_limit: None,
                storage_bytes: None,
            },
            network: NetworkMode::Offline,
            workspaces: vec![WorkspaceAttachment {
                host_path: path,
                guest_path: "/workspace".into(),
                read_only: true,
            }],
        }
    }

    #[test]
    fn provider_timeout_kills_and_waits() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let started = Instant::now();
        assert!(matches!(
            command_output(command, Duration::from_millis(20)),
            Err(RuntimeError::Provider { code }) if code == "provider_timeout_killed"
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn mounts_require_canonical_custody_and_reject_delimiters_and_sockets() {
        let d = tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert!(validate_request(&request(alias), RuntimeKind::Container, &["docker"]).is_err());
        let delimited = d.path().join("comma,name");
        std::fs::create_dir(&delimited).unwrap();
        assert!(
            validate_request(&request(delimited), RuntimeKind::Container, &["docker"]).is_err()
        );
        let socket = d.path().join("docker.sock");
        std::fs::create_dir(&socket).unwrap();
        assert!(validate_request(&request(socket), RuntimeKind::Container, &["docker"]).is_err());
    }
}
