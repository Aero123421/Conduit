use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
static NEXT_RECORD_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupervisorRecord {
    runtime_id: String,
    #[serde(default = "native_provider")]
    provider_id: String,
    spec_digest: String,
    pid: Option<u32>,
    birth: Option<u64>,
    executable: PathBuf,
    state: RuntimeState,
    exit_code: Option<i32>,
    started_unix_ms: Option<u128>,
    timeout_ms: Option<u64>,
    pty: bool,
}
fn native_provider() -> String {
    "native".into()
}

#[derive(Clone)]
pub struct ProcessSupervisor {
    root: PathBuf,
    live: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<Child>>>>>,
    pty_masters: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<File>>>>>,
}
impl ProcessSupervisor {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            live: Arc::new(Mutex::new(Default::default())),
            pty_masters: Arc::new(Mutex::new(Default::default())),
        })
    }
    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
    fn load(&self, id: &str) -> Result<SupervisorRecord, RuntimeError> {
        let b = fs::read(self.path(id)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RuntimeError::NotFound
            } else {
                RuntimeError::Io(e)
            }
        })?;
        if b.len() > 64 * 1024 {
            return Err(RuntimeError::Record("supervisor record too large".into()));
        }
        serde_json::from_slice(&b).map_err(|e| RuntimeError::Record(e.to_string()))
    }
    fn save(&self, r: &SupervisorRecord) -> Result<(), RuntimeError> {
        let b = serde_json::to_vec(r).map_err(|e| RuntimeError::Record(e.to_string()))?;
        let p = self.path(&r.runtime_id);
        let tmp = p.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            NEXT_RECORD_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&b)?;
            f.sync_all()?;
        }
        fs::rename(tmp, p)?;
        Ok(())
    }
    pub fn reserve(
        &self,
        request: &RuntimeRequest,
        provider_id: &str,
        executable: PathBuf,
        pty: bool,
    ) -> Result<PreparedRuntime, RuntimeError> {
        if let Ok(existing) = self.load(&request.runtime_id) {
            if existing.spec_digest != request.spec_digest || existing.provider_id != provider_id {
                return Err(RuntimeError::IdentityMismatch);
            }
            return Ok(PreparedRuntime {
                runtime_id: request.runtime_id.clone(),
                provider_id: provider_id.into(),
                spec_digest: request.spec_digest.clone(),
                object_id: request.runtime_id.clone(),
                state: existing.state,
                evidence: vec![],
            });
        }
        let r = SupervisorRecord {
            runtime_id: request.runtime_id.clone(),
            provider_id: provider_id.into(),
            spec_digest: request.spec_digest.clone(),
            pid: None,
            birth: None,
            executable,
            state: RuntimeState::Prepared,
            exit_code: None,
            started_unix_ms: None,
            timeout_ms: None,
            pty,
        };
        self.save(&r)?;
        Ok(PreparedRuntime {
            runtime_id: request.runtime_id.clone(),
            provider_id: provider_id.into(),
            spec_digest: request.spec_digest.clone(),
            object_id: request.runtime_id.clone(),
            state: RuntimeState::Prepared,
            evidence: vec![],
        })
    }
    pub fn spawn(
        &self,
        prepared: &PreparedRuntime,
        launch: &LaunchPlan,
        wrapper: impl FnOnce(&mut Command) -> Result<(), RuntimeError>,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let mut record = self.load(&prepared.runtime_id)?;
        if record.spec_digest != prepared.spec_digest {
            return Err(RuntimeError::IdentityMismatch);
        }
        if record.provider_id != prepared.provider_id {
            return Err(RuntimeError::IdentityMismatch);
        }
        if let Some(pid) = record.pid
            && process_birth(pid) == record.birth
        {
            return self.receipt(record);
        }
        if record.state != RuntimeState::Prepared {
            return Err(RuntimeError::Uncertain(
                "a prior start did not leave a provably live process".into(),
            ));
        }
        if !launch.executable.is_absolute() {
            return Err(RuntimeError::Invalid(
                "executable identity must be absolute".into(),
            ));
        }
        let meta = fs::metadata(&launch.executable)?;
        if !meta.is_file() {
            return Err(RuntimeError::Invalid(
                "executable is not a regular file".into(),
            ));
        }
        let mut cmd = Command::new(&launch.executable);
        cmd.args(&launch.argv).current_dir(&launch.cwd).env_clear();
        for (k, v) in &launch.environment {
            if k.len() > 128
                || v.len() > 32 * 1024
                || k.as_bytes().contains(&0)
                || v.as_bytes().contains(&0)
            {
                return Err(RuntimeError::Invalid(
                    "environment projection exceeds bounds".into(),
                ));
            }
            cmd.env(k, v);
        }
        wrapper(&mut cmd)?;
        let spool = self.root.join(format!("{}.stream", prepared.runtime_id));
        let mut pty_master = None;
        match launch.io_mode {
            IoMode::Pipes => {
                let out = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&spool)?;
                let err = out.try_clone()?;
                cmd.stdin(Stdio::piped()).stdout(out).stderr(err);
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::setpgid(0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            IoMode::Pty => unsafe {
                let mut master = 0;
                let mut slave = 0;
                if libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                ) != 0
                {
                    return Err(RuntimeError::Io(std::io::Error::last_os_error()));
                }
                let master_file = File::from_raw_fd(master);
                let slave_file = File::from_raw_fd(slave);
                let s1 = slave_file.try_clone()?;
                let s2 = slave_file.try_clone()?;
                cmd.stdin(Stdio::from(slave_file))
                    .stdout(Stdio::from(s1))
                    .stderr(Stdio::from(s2));
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
                pty_master = Some(master_file);
            },
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        let birth = process_birth(pid).ok_or_else(|| {
            RuntimeError::Uncertain("spawned process birth identity unavailable".into())
        })?;
        record.pid = Some(pid);
        record.executable = launch.executable.clone();
        record.birth = Some(birth);
        record.state = RuntimeState::Running;
        record.started_unix_ms = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        );
        record.timeout_ms = launch.timeout_ms;
        self.save(&record)?;
        let child = Arc::new(Mutex::new(child));
        self.live
            .lock()
            .map_err(|_| RuntimeError::Record("live map poisoned".into()))?
            .insert(record.runtime_id.clone(), child.clone());
        if let Some(master) = pty_master {
            let mut reader = master.try_clone()?;
            let master = Arc::new(Mutex::new(master));
            self.pty_masters
                .lock()
                .map_err(|_| RuntimeError::Record("pty map poisoned".into()))?
                .insert(record.runtime_id.clone(), master.clone());
            let spool = spool.clone();
            std::thread::spawn(move || {
                let mut out = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(spool)
                    .ok();
                let mut buf = [0u8; 8192];
                loop {
                    let n = match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if let Some(ref mut f) = out {
                        let _ = f.write_all(&buf[..n]);
                    }
                }
            });
        }
        self.start_waiter(record.runtime_id.clone(), child, launch.timeout_ms);
        self.receipt(record)
    }

    /// Adopts a process group that was spawned with its protocol input still
    /// withheld. Persisting this receipt before initialization prevents an
    /// Agent process from becoming anonymous if the Node exits after spawn.
    pub fn adopt_external(
        &self,
        prepared: &PreparedRuntime,
        launch: &LaunchPlan,
        pid: u32,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let mut record = self.load(&prepared.runtime_id)?;
        if record.spec_digest != prepared.spec_digest
            || record.provider_id != prepared.provider_id
            || record.state != RuntimeState::Prepared
            || record.pid.is_some()
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        if !launch.executable.is_absolute() || !launch.executable.is_file() {
            return Err(RuntimeError::Invalid(
                "executable identity must be an absolute regular file".into(),
            ));
        }
        let birth = process_birth(pid).ok_or_else(|| {
            RuntimeError::Uncertain("spawned process birth identity unavailable".into())
        })?;
        record.pid = Some(pid);
        record.birth = Some(birth);
        record.executable = launch.executable.clone();
        record.state = RuntimeState::Running;
        record.started_unix_ms = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        );
        record.timeout_ms = launch.timeout_ms;
        self.save(&record)?;
        self.receipt(record)
    }

    pub fn mark_external_stopped(
        &self,
        runtime_id: &str,
        exit_code: Option<i32>,
    ) -> Result<(), RuntimeError> {
        let mut record = self.load(runtime_id)?;
        if let Some(pid) = record.pid
            && process_birth(pid) == record.birth
        {
            return Err(RuntimeError::Uncertain(
                "external process is still live while recording stop".into(),
            ));
        }
        record.state = RuntimeState::Stopped;
        record.exit_code = exit_code;
        self.save(&record)
    }
    fn start_waiter(&self, id: String, child: Arc<Mutex<Child>>, timeout: Option<u64>) {
        let this = self.clone();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            loop {
                let status = child
                    .lock()
                    .ok()
                    .and_then(|mut c| c.try_wait().ok())
                    .flatten();
                if let Some(status) = status {
                    if let Ok(mut r) = this.load(&id) {
                        r.state = RuntimeState::Stopped;
                        r.exit_code = status.code();
                        let _ = this.save(&r);
                    }
                    break;
                }
                if timeout.is_some_and(|ms| started.elapsed() >= Duration::from_millis(ms)) {
                    if let Ok(r) = this.load(&id)
                        && let Some(pid) = r.pid
                    {
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGTERM);
                        }
                        std::thread::sleep(Duration::from_millis(500));
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGKILL);
                        }
                    }
                    if let Ok(mut child) = child.lock() {
                        let _ = child.wait();
                    }
                    if let Ok(mut r) = this.load(&id) {
                        r.state = RuntimeState::Stopped;
                        r.exit_code = None;
                        let _ = this.save(&r);
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
    }
    pub fn write_pty(&self, id: &str, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > 64 * 1024 {
            return Err(RuntimeError::Invalid("PTY input exceeds bound".into()));
        }
        let map = self
            .pty_masters
            .lock()
            .map_err(|_| RuntimeError::Record("pty map poisoned".into()))?;
        let master = map.get(id).ok_or(RuntimeError::NotFound)?;
        master
            .lock()
            .map_err(|_| RuntimeError::Record("pty lock poisoned".into()))?
            .write_all(bytes)?;
        Ok(())
    }
    pub fn signal(
        &self,
        id: &str,
        signal: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let mut r = self.load(id)?;
        let pid = r.pid.ok_or(RuntimeError::NotFound)? as i32;
        let (sig, state) = match signal {
            RuntimeSignal::GracefulStop => (libc::SIGTERM, RuntimeState::Stopping),
            RuntimeSignal::ForceStop => (libc::SIGKILL, RuntimeState::Stopping),
            RuntimeSignal::Pause => (libc::SIGSTOP, RuntimeState::Paused),
            RuntimeSignal::Resume => (libc::SIGCONT, RuntimeState::Running),
        };
        if process_birth(pid as u32) != r.birth {
            return Err(RuntimeError::Uncertain("PID birth identity changed".into()));
        }
        if unsafe { libc::kill(-pid, sig) } != 0 {
            return Err(RuntimeError::Io(std::io::Error::last_os_error()));
        }
        r.state = state;
        self.save(&r)?;
        self.receipt(r)
    }
    pub fn inspect(&self, id: &str) -> Result<RuntimeStateReceipt, RuntimeError> {
        let mut r = self.load(id)?;
        if let Some(child) = self
            .live
            .lock()
            .map_err(|_| RuntimeError::Record("live map poisoned".into()))?
            .get(id)
            .cloned()
            && let Some(status) = child
                .lock()
                .map_err(|_| RuntimeError::Record("child lock poisoned".into()))?
                .try_wait()?
        {
            r.state = RuntimeState::Stopped;
            r.exit_code = status.code();
            self.save(&r)?;
            return self.receipt(r);
        }
        if let Some(pid) = r.pid {
            match process_birth(pid) {
                Some(b) if Some(b) == r.birth => {}
                None if matches!(r.state, RuntimeState::Stopped | RuntimeState::Failed) => {}
                None => {
                    r.state = RuntimeState::Lost;
                    self.save(&r)?
                }
                _ => {
                    r.state = RuntimeState::RecoveryRequired;
                    self.save(&r)?
                }
            }
        }
        self.receipt(r)
    }
    fn receipt(&self, r: SupervisorRecord) -> Result<RuntimeStateReceipt, RuntimeError> {
        let identity = match (r.pid, r.birth) {
            (Some(p), Some(b)) => Some(format!("pid:{p}:birth:{b}")),
            _ => None,
        };
        Ok(RuntimeStateReceipt {
            handle: RuntimeHandle {
                runtime_id: r.runtime_id,
                provider_id: r.provider_id,
                spec_digest: r.spec_digest,
                object_id: "native-supervisor".into(),
                process_identity: identity,
            },
            state: r.state,
            exit_code: r.exit_code,
            evidence: vec![CapabilityEvidence {
                capability: "process_tree_tracking".into(),
                state: CapabilityState::Effective,
                source: "linux_process_group_and_procfs".into(),
                reason_code: "process_group_birth_witness".into(),
                detail: "process group plus /proc starttime".into(),
            }],
        })
    }
}

fn process_birth(pid: u32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = s.rfind(')')?;
    s.get(close + 2..)?.split_whitespace().nth(19)?.parse().ok()
}

pub struct NativeProvider {
    supervisor: ProcessSupervisor,
}
impl NativeProvider {
    pub fn new(supervisor: ProcessSupervisor) -> Self {
        Self { supervisor }
    }
    pub fn supervisor(&self) -> &ProcessSupervisor {
        &self.supervisor
    }
}
impl RuntimeProvider for NativeProvider {
    fn provider_id(&self) -> &str {
        "native"
    }
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        Ok(CapabilityReceipt {
            provider_id: "native".into(),
            provider_version: Some(std::env::consts::OS.into()),
            capabilities: vec![
                CapabilityEvidence {
                    capability: "exact_argv".into(),
                    state: CapabilityState::Effective,
                    source: "std_process_command".into(),
                    reason_code: "direct_exec".into(),
                    detail: "shell reconstruction is not used".into(),
                },
                CapabilityEvidence {
                    capability: "pty".into(),
                    state: CapabilityState::Effective,
                    source: "openpty".into(),
                    reason_code: "linux_openpty".into(),
                    detail: "PTY master retained by supervisor".into(),
                },
            ],
        })
    }
    fn prepare(&self, r: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(r, RuntimeKind::Native, &["native", "native.linux"])?;
        if r.workspaces.iter().any(|workspace| workspace.read_only) {
            return Err(RuntimeError::CapabilityUnavailable(
                "native provider cannot enforce a read-only mount; select an effective restricted/container/VM provider".into(),
            ));
        }
        self.supervisor
            .reserve(r, self.provider_id(), PathBuf::new(), false)
    }
    fn start(
        &self,
        p: &PreparedRuntime,
        l: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        self.supervisor.spawn(p, l, |_| Ok(()))
    }
    fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        if h.provider_id != "native" || h.object_id != "native-supervisor" {
            return Err(RuntimeError::IdentityMismatch);
        }
        let r = self.supervisor.inspect(&h.runtime_id)?;
        if r.handle.spec_digest != h.spec_digest
            || h.process_identity
                .as_ref()
                .is_some_and(|expected| r.handle.process_identity.as_ref() != Some(expected))
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        Ok(r)
    }
    fn signal(
        &self,
        h: &RuntimeHandle,
        s: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != "native-supervisor" {
            return Err(RuntimeError::IdentityMismatch);
        }
        self.inspect(h)?;
        self.supervisor.signal(&h.runtime_id, s)
    }
    fn snapshot(&self, _: &RuntimeHandle, _: &str) -> Result<SnapshotReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "native process snapshot".into(),
        ))
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != "native-supervisor" {
            return Err(RuntimeError::IdentityMismatch);
        }
        let p = self
            .supervisor
            .root
            .join(format!("{}.stream", h.runtime_id));
        let mut file = File::open(&p)?;
        file.metadata()?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let digest = hex::encode(digest.finalize());
        Ok(CollectionReceipt {
            runtime_id: h.runtime_id.clone(),
            collection_id: format!("collect_{}", &digest[..16]),
            custody_complete: true,
            digest,
        })
    }
    fn destroy(
        &self,
        h: &RuntimeHandle,
        r: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != "native-supervisor" {
            return Err(RuntimeError::IdentityMismatch);
        }
        let state = self.inspect(h)?.state;
        if matches!(
            state,
            RuntimeState::Running | RuntimeState::Paused | RuntimeState::Stopping
        ) {
            return Err(RuntimeError::Invalid(
                "running Runtime cannot be destroyed".into(),
            ));
        }
        if !r.custody_complete && !r.discard_authorized {
            return Err(RuntimeError::Invalid("collection receipt required".into()));
        }
        let path = self.supervisor.path(&h.runtime_id);
        fs::remove_file(path)?;
        Ok(DestroyReceipt {
            runtime_id: h.runtime_id.clone(),
            destroyed: true,
            evidence: "supervisor record removed after custody gate".into(),
        })
    }
    fn reconcile(
        &self,
        records: &[ExpectedRuntime],
    ) -> Result<Vec<ReconciliationReceipt>, RuntimeError> {
        records
            .iter()
            .map(|e| match self.inspect(&e.handle) {
                Ok(r) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: r.state,
                    reason_code: if r.state == RuntimeState::Running {
                        "identity_and_liveness_proven"
                    } else {
                        "observed_state"
                    }
                    .into(),
                    observed_identity: r.handle.process_identity,
                }),
                Err(RuntimeError::NotFound) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: RuntimeState::Lost,
                    reason_code: "runtime_absent".into(),
                    observed_identity: None,
                }),
                Err(e) => Err(e),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    fn req() -> RuntimeRequest {
        RuntimeRequest {
            runtime_id: "rt_12345678".into(),
            run_id: "run_12345678".into(),
            kind: RuntimeKind::Native,
            provider_selector: "native".into(),
            spec_digest: "11".repeat(32),
            image: None,
            resources: ResourceLimits {
                cpu: None,
                memory_bytes: None,
                pid_limit: None,
                storage_bytes: None,
            },
            network: NetworkMode::Open,
            workspaces: vec![],
        }
    }
    fn launch(command: &str, mode: IoMode, timeout: u64, cwd: &Path) -> LaunchPlan {
        LaunchPlan {
            executable: "/bin/sh".into(),
            argv: vec!["-c".into(), command.into()],
            cwd: cwd.into(),
            environment: Default::default(),
            io_mode: mode,
            timeout_ms: Some(timeout),
        }
    }
    #[test]
    fn runs_exact_argv_and_reconciles() {
        let d = tempdir().unwrap();
        let p = NativeProvider::new(ProcessSupervisor::open(d.path()).unwrap());
        let prepared = p.prepare(&req()).unwrap();
        let r = p
            .start(
                &prepared,
                &launch("printf runtime-ok", IoMode::Pipes, 5000, d.path()),
            )
            .unwrap();
        assert_eq!(r.state, RuntimeState::Running);
        std::thread::sleep(Duration::from_millis(100));
        let r = p.inspect(&r.handle).unwrap();
        assert_eq!(r.state, RuntimeState::Stopped);
        let c = p.collect(&r.handle).unwrap();
        assert!(c.custody_complete);
        assert_eq!(
            fs::read_to_string(d.path().join("rt_12345678.stream")).unwrap(),
            "runtime-ok"
        );
    }
    #[test]
    fn timeout_terminates_process_group() {
        let d = tempdir().unwrap();
        let p = NativeProvider::new(ProcessSupervisor::open(d.path()).unwrap());
        let prepared = p.prepare(&req()).unwrap();
        let r = p
            .start(&prepared, &launch("sleep 30", IoMode::Pipes, 30, d.path()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(p.inspect(&r.handle).unwrap().state, RuntimeState::Stopped);
    }
    #[test]
    fn missing_runtime_reconciles_lost_without_restart() {
        let d = tempdir().unwrap();
        let s = ProcessSupervisor::open(d.path()).unwrap();
        s.save(&SupervisorRecord {
            runtime_id: "rt_12345678".into(),
            provider_id: "native".into(),
            spec_digest: "11".repeat(32),
            pid: Some(u32::MAX),
            birth: Some(1),
            executable: "/bin/true".into(),
            state: RuntimeState::Running,
            exit_code: None,
            started_unix_ms: Some(1),
            timeout_ms: None,
            pty: false,
        })
        .unwrap();
        let h = RuntimeHandle {
            runtime_id: "rt_12345678".into(),
            provider_id: "native".into(),
            spec_digest: "11".repeat(32),
            object_id: "native-supervisor".into(),
            process_identity: Some(format!("pid:{}:birth:1", u32::MAX)),
        };
        let p = NativeProvider::new(s);
        let r = p
            .reconcile(&[ExpectedRuntime {
                handle: h,
                expected_state: RuntimeState::Running,
            }])
            .unwrap();
        assert_eq!(r[0].state, RuntimeState::Lost);
    }

    #[test]
    fn rejects_read_only_workspace_when_mount_enforcement_is_unavailable() {
        let d = tempdir().unwrap();
        let p = NativeProvider::new(ProcessSupervisor::open(d.path()).unwrap());
        let mut request = req();
        request.workspaces.push(WorkspaceAttachment {
            host_path: d.path().into(),
            guest_path: PathBuf::from("/workspace/source"),
            read_only: true,
        });

        assert!(matches!(
            p.prepare(&request),
            Err(RuntimeError::CapabilityUnavailable(message))
                if message.contains("cannot enforce a read-only mount")
        ));
    }
}
