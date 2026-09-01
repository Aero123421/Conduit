use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_ENVIRONMENT_ENTRIES: usize = 1_024;
const MAX_ENVIRONMENT_BYTES: usize = 256 * 1024;
const MAX_ARGUMENTS: usize = 4_096;
const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
const MAX_SINGLE_VALUE_BYTES: usize = 32 * 1024;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_ARCHIVE_MANIFEST_BYTES: u64 = 1024 * 1024;
static NEXT_RECORD_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerBackend {
    Docker,
    Podman,
}

impl ContainerBackend {
    fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    fn log_driver(self) -> &'static str {
        match self {
            Self::Docker => "json-file",
            Self::Podman => "k8s-file",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContainerRecord {
    request: RuntimeRequest,
    state: RuntimeState,
    launch_digest: Option<String>,
    container_id: Option<String>,
    deadline_unix_ms: Option<u128>,
    collection_digest: Option<String>,
}

#[derive(Debug)]
struct ContainerInspection {
    container_id: String,
    runtime_id: String,
    spec_digest: String,
    launch_digest: String,
    state: RuntimeState,
    exit_code: Option<i32>,
}

#[derive(Clone)]
pub struct ContainerProvider {
    backend: ContainerBackend,
    program: PathBuf,
    state_root: PathBuf,
}

impl ContainerProvider {
    pub fn new(backend: ContainerBackend) -> Self {
        Self {
            backend,
            program: backend.program().into(),
            state_root: default_state_root().join(backend.program()),
        }
    }

    /// Uses an explicit Device-owned state directory. The directory stores only
    /// bounded provider records and collected output, never projected credentials.
    pub fn with_state_root(
        backend: ContainerBackend,
        state_root: impl AsRef<Path>,
    ) -> Result<Self, RuntimeError> {
        let provider = Self {
            backend,
            program: backend.program().into(),
            state_root: state_root.as_ref().to_path_buf(),
        };
        provider.ensure_state_root()?;
        Ok(provider)
    }

    #[cfg(test)]
    fn with_program(
        backend: ContainerBackend,
        state_root: impl AsRef<Path>,
        program: impl AsRef<Path>,
    ) -> Result<Self, RuntimeError> {
        let provider = Self {
            backend,
            program: program.as_ref().to_path_buf(),
            state_root: state_root.as_ref().to_path_buf(),
        };
        provider.ensure_state_root()?;
        Ok(provider)
    }

    fn ensure_state_root(&self) -> Result<(), RuntimeError> {
        fs::create_dir_all(&self.state_root)?;
        fs::set_permissions(&self.state_root, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn run(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, RuntimeError> {
        let mut command = Command::new(&self.program);
        command.args(args);
        command_output(command, timeout)
    }

    fn version(&self) -> Option<String> {
        let mut command = Command::new(&self.program);
        command.arg("--version");
        command_output(command, Duration::from_secs(3))
            .ok()
            .filter(|output| output.status.success())
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .chars()
                    .take(256)
                    .collect()
            })
    }

    fn name(id: &str) -> String {
        let readable = format!("conduit-{}", id.trim_start_matches("rt_"));
        if readable.len() <= 128 {
            readable
        } else {
            format!("conduit-{}", &digest_bytes(id.as_bytes())[..40])
        }
    }

    fn record_path(&self, runtime_id: &str) -> Result<PathBuf, RuntimeError> {
        validate_runtime_id(runtime_id)?;
        Ok(self.state_root.join(format!("{runtime_id}.json")))
    }

    fn collection_path(&self, runtime_id: &str) -> Result<PathBuf, RuntimeError> {
        validate_runtime_id(runtime_id)?;
        Ok(self.state_root.join(format!("{runtime_id}.collection")))
    }

    fn load_record(&self, runtime_id: &str) -> Result<ContainerRecord, RuntimeError> {
        let path = self.record_path(runtime_id)?;
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                RuntimeError::NotFound
            } else {
                RuntimeError::Io(error)
            }
        })?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RuntimeError::Record(
                "container provider record exceeds bound".into(),
            ));
        }
        serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Record(error.to_string()))
    }

    fn save_record(&self, record: &ContainerRecord) -> Result<(), RuntimeError> {
        self.ensure_state_root()?;
        let bytes =
            serde_json::to_vec(record).map_err(|error| RuntimeError::Record(error.to_string()))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RuntimeError::Record(
                "container provider record exceeds bound".into(),
            ));
        }
        let path = self.record_path(&record.request.runtime_id)?;
        let temporary = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            NEXT_RECORD_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn inspect_container(&self, name: &str) -> Result<ContainerInspection, RuntimeError> {
        const FORMAT: &str = "{{.Id}}|{{index .Config.Labels \"dev.conduit.runtime-id\"}}|{{index .Config.Labels \"dev.conduit.spec-digest\"}}|{{index .Config.Labels \"dev.conduit.launch-digest\"}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.Paused}}";
        let output = self.run(
            &[
                "inspect".into(),
                "--format".into(),
                FORMAT.into(),
                name.into(),
            ],
            Duration::from_secs(10),
        )?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if error.contains("no such")
                || error.contains("not found")
                || error.contains("does not exist")
            {
                return Err(RuntimeError::NotFound);
            }
            return Err(RuntimeError::Provider {
                code: "container_inspect_failed".into(),
            });
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|_| RuntimeError::Provider {
            code: "container_inspect_invalid_utf8".into(),
        })?;
        let fields = text.trim().split('|').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(RuntimeError::Provider {
                code: "container_inspect_invalid_output".into(),
            });
        }
        let exit_code = fields[5]
            .parse::<i32>()
            .map_err(|_| RuntimeError::Provider {
                code: "container_inspect_invalid_exit_code".into(),
            })?;
        let state = if fields[6] == "true" || fields[4].eq_ignore_ascii_case("paused") {
            RuntimeState::Paused
        } else {
            match fields[4] {
                "created" | "configured" => RuntimeState::Prepared,
                "running" => RuntimeState::Running,
                "exited" | "stopped" => RuntimeState::Stopped,
                "dead" => RuntimeState::Failed,
                _ => RuntimeState::Uncertain,
            }
        };
        let container_id = fields[0].trim_start_matches("sha256:").to_owned();
        if container_id.len() < 12
            || container_id.len() > 64
            || !container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RuntimeError::Provider {
                code: "container_inspect_invalid_identity".into(),
            });
        }
        Ok(ContainerInspection {
            container_id,
            runtime_id: fields[1].into(),
            spec_digest: fields[2].into(),
            launch_digest: fields[3].into(),
            state,
            exit_code: matches!(state, RuntimeState::Stopped | RuntimeState::Failed)
                .then_some(exit_code),
        })
    }

    fn verify_inspection(
        &self,
        runtime_id: &str,
        spec_digest: &str,
        launch_digest: Option<&str>,
        inspection: &ContainerInspection,
    ) -> Result<(), RuntimeError> {
        if inspection.runtime_id != runtime_id || inspection.spec_digest != spec_digest {
            return Err(RuntimeError::IdentityMismatch);
        }
        if let Some(expected) = launch_digest
            && inspection.launch_digest != expected
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        Ok(())
    }

    fn receipt(
        &self,
        runtime_id: &str,
        spec_digest: &str,
        inspection: ContainerInspection,
    ) -> RuntimeStateReceipt {
        RuntimeStateReceipt {
            handle: RuntimeHandle {
                runtime_id: runtime_id.into(),
                provider_id: self.provider_id().into(),
                spec_digest: spec_digest.into(),
                object_id: Self::name(runtime_id),
                process_identity: Some(format!(
                    "container:{}:launch:{}",
                    inspection.container_id, inspection.launch_digest
                )),
            },
            state: inspection.state,
            exit_code: inspection.exit_code,
            evidence: vec![CapabilityEvidence {
                capability: "tracked_launch_plan".into(),
                state: CapabilityState::Effective,
                source: "container_id_and_launch_digest_labels".into(),
                reason_code: "container_process_identity_verified".into(),
                detail: "provider container ID and committed LaunchPlan digest were inspected"
                    .into(),
            }],
        }
    }

    fn create_args(
        &self,
        record: &ContainerRecord,
        image: &str,
        launch: Option<&LaunchPlan>,
        launch_digest: &str,
    ) -> Result<Vec<String>, RuntimeError> {
        let request = &record.request;
        let mut args = vec![
            "create".into(),
            "--name".into(),
            Self::name(&request.runtime_id),
            "--label".into(),
            format!("dev.conduit.runtime-id={}", request.runtime_id),
            "--label".into(),
            format!("dev.conduit.spec-digest={}", request.spec_digest),
            "--label".into(),
            format!("dev.conduit.run-id={}", request.run_id),
            "--label".into(),
            format!("dev.conduit.launch-digest={launch_digest}"),
            "--network".into(),
            match request.network {
                NetworkMode::Open => "bridge",
                NetworkMode::Offline => "none",
                NetworkMode::Restricted => {
                    return Err(RuntimeError::CapabilityUnavailable(
                        "complete restricted egress enforcement".into(),
                    ));
                }
                NetworkMode::LanExplicit => {
                    return Err(RuntimeError::CapabilityUnavailable(
                        "explicit LAN destination enforcement".into(),
                    ));
                }
            }
            .into(),
            "--log-driver".into(),
            self.backend.log_driver().into(),
            "--log-opt".into(),
            "max-size=8m".into(),
        ];
        if self.backend == ContainerBackend::Docker {
            args.extend(["--log-opt".into(), "max-file=2".into()]);
        }
        if let Some(value) = request.resources.cpu {
            args.extend(["--cpus".into(), value.to_string()]);
        }
        if let Some(value) = request.resources.memory_bytes {
            args.extend(["--memory".into(), value.to_string()]);
        }
        if let Some(value) = request.resources.pid_limit {
            args.extend(["--pids-limit".into(), value.to_string()]);
        }
        for workspace in &request.workspaces {
            let mut mount = format!(
                "type=bind,src={},dst={}",
                workspace.host_path.display(),
                workspace.guest_path.display()
            );
            if workspace.read_only {
                mount.push_str(",readonly");
            }
            args.extend(["--mount".into(), mount]);
        }
        if let Some(launch) = launch {
            let executable = launch
                .executable
                .to_str()
                .ok_or_else(|| RuntimeError::Invalid("executable must be UTF-8".into()))?;
            let cwd = launch
                .cwd
                .to_str()
                .ok_or_else(|| RuntimeError::Invalid("working directory must be UTF-8".into()))?;
            args.extend(["--workdir".into(), cwd.into()]);
            for (key, value) in &launch.environment {
                args.extend(["--env".into(), format!("{key}={value}")]);
            }
            if launch.io_mode == IoMode::Pty {
                args.push("--tty".into());
            }
            args.extend(["--entrypoint".into(), executable.into()]);
        }
        args.push(image.into());
        if let Some(launch) = launch {
            args.extend(launch.argv.iter().cloned());
        }
        Ok(args)
    }

    fn update_record_from_inspection(
        &self,
        record: &mut ContainerRecord,
        inspection: &ContainerInspection,
    ) -> Result<(), RuntimeError> {
        record.container_id = Some(inspection.container_id.clone());
        if record.launch_digest.is_none() && !inspection.launch_digest.is_empty() {
            record.launch_digest = Some(inspection.launch_digest.clone());
        }
        record.state = inspection.state;
        if !matches!(
            inspection.state,
            RuntimeState::Running | RuntimeState::Paused
        ) {
            record.deadline_unix_ms = None;
        }
        self.save_record(record)
    }

    fn arm_timeout(&self, handle: RuntimeHandle, timeout_ms: u64) {
        let provider = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(timeout_ms));
            if provider.inspect(&handle).is_ok_and(|receipt| {
                matches!(receipt.state, RuntimeState::Running | RuntimeState::Paused)
            }) {
                let _ = provider.signal(&handle, RuntimeSignal::ForceStop);
            }
        });
    }

    fn commit_image(&self, handle: &RuntimeHandle, image: &str) -> Result<String, RuntimeError> {
        let output = self.run(
            &["commit".into(), handle.object_id.clone(), image.into()],
            Duration::from_secs(120),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_snapshot_failed".into(),
            });
        }
        let inspected = self.run(
            &[
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{.Id}}".into(),
                image.into(),
            ],
            Duration::from_secs(30),
        )?;
        if !inspected.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_snapshot_digest_unavailable".into(),
            });
        }
        parse_sha256(&inspected.stdout, "container_snapshot_digest_invalid")
    }
}

impl RuntimeProvider for ContainerProvider {
    fn provider_id(&self) -> &str {
        match self.backend {
            ContainerBackend::Docker => "docker",
            ContainerBackend::Podman => "podman",
        }
    }

    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        let mut command = Command::new(&self.program);
        command.arg("info");
        let effective = command_output(command, Duration::from_secs(5))
            .is_ok_and(|output| output.status.success());
        let state = if effective {
            CapabilityState::Effective
        } else {
            CapabilityState::Unavailable
        };
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: self.version(),
            capabilities: vec![
                CapabilityEvidence {
                    capability: "container_boundary".into(),
                    state,
                    source: "provider_info_live_probe".into(),
                    reason_code: if effective {
                        "daemon_reachable"
                    } else {
                        "daemon_unavailable"
                    }
                    .into(),
                    detail: "provider info completed; per-runtime controls are applied at create"
                        .into(),
                },
                CapabilityEvidence {
                    capability: "tracked_launch_plan".into(),
                    state,
                    source: "container_main_process_adapter".into(),
                    reason_code: if effective {
                        "exact_entrypoint_and_container_identity"
                    } else {
                        "daemon_unavailable"
                    }
                    .into(),
                    detail: "LaunchPlan executable and argv become the container main process"
                        .into(),
                },
                CapabilityEvidence {
                    capability: "bounded_output_custody".into(),
                    state,
                    source: "bounded_provider_log_driver_and_device_collection".into(),
                    reason_code: if effective {
                        "provider_logs_collectible"
                    } else {
                        "daemon_unavailable"
                    }
                    .into(),
                    detail: "provider logs are bounded before Device-owned collection".into(),
                },
                CapabilityEvidence {
                    capability: "archive_restore".into(),
                    state,
                    source: "provider_image_save_load_probe".into(),
                    reason_code: if effective {
                        "typed_image_archive_adapter"
                    } else {
                        "daemon_unavailable"
                    }
                    .into(),
                    detail: "archive identity is read from the bounded single-image manifest"
                        .into(),
                },
            ],
        })
    }

    fn prepare(&self, request: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(request, RuntimeKind::Container, &[self.provider_id()])?;
        validate_container_request(request, true)?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(format!(
                "{} service",
                self.provider_id()
            )));
        }
        let image = request
            .image
            .as_deref()
            .ok_or_else(|| RuntimeError::Invalid("container image required".into()))?;
        let output = self.run(
            &[
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{.Id}}".into(),
                image.into(),
            ],
            Duration::from_secs(30),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::CapabilityUnavailable(
                "container image is not available locally".into(),
            ));
        }
        let name = Self::name(&request.runtime_id);
        match self.inspect_container(&name) {
            Ok(inspection) => self.verify_inspection(
                &request.runtime_id,
                &request.spec_digest,
                None,
                &inspection,
            )?,
            Err(RuntimeError::NotFound) => {}
            Err(error) => return Err(error),
        }
        match self.load_record(&request.runtime_id) {
            Ok(existing)
                if existing.request.spec_digest != request.spec_digest
                    || existing.request.provider_selector != request.provider_selector =>
            {
                return Err(RuntimeError::IdentityMismatch);
            }
            Ok(_) => {}
            Err(RuntimeError::NotFound) => self.save_record(&ContainerRecord {
                request: request.clone(),
                state: RuntimeState::Prepared,
                launch_digest: None,
                container_id: None,
                deadline_unix_ms: None,
                collection_digest: None,
            })?,
            Err(error) => return Err(error),
        }
        Ok(PreparedRuntime {
            runtime_id: request.runtime_id.clone(),
            provider_id: self.provider_id().into(),
            spec_digest: request.spec_digest.clone(),
            object_id: name,
            state: RuntimeState::Prepared,
            evidence: vec![CapabilityEvidence {
                capability: "deterministic_runtime_reservation".into(),
                state: CapabilityState::Effective,
                source: "device_provider_record".into(),
                reason_code: "identity_and_spec_reserved_before_container_create".into(),
                detail: "the Device persisted Runtime identity and spec before start".into(),
            }],
        })
    }

    fn start(
        &self,
        prepared: &PreparedRuntime,
        launch: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if prepared.provider_id != self.provider_id()
            || prepared.object_id != Self::name(&prepared.runtime_id)
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        validate_launch_plan(launch)?;
        let launch_digest = launch_digest(launch)?;
        let mut record = self.load_record(&prepared.runtime_id)?;
        if record.request.spec_digest != prepared.spec_digest
            || record.request.provider_selector != prepared.provider_id
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        if record
            .launch_digest
            .as_deref()
            .is_some_and(|digest| digest != launch_digest)
        {
            return Err(RuntimeError::IdentityMismatch);
        }
        match self.inspect_container(&prepared.object_id) {
            Ok(inspection) => {
                self.verify_inspection(
                    &prepared.runtime_id,
                    &prepared.spec_digest,
                    Some(&launch_digest),
                    &inspection,
                )?;
                if inspection.state != RuntimeState::Prepared {
                    self.update_record_from_inspection(&mut record, &inspection)?;
                    return Ok(self.receipt(
                        &prepared.runtime_id,
                        &prepared.spec_digest,
                        inspection,
                    ));
                }
            }
            Err(RuntimeError::NotFound) => {
                if record.state != RuntimeState::Prepared {
                    return Err(RuntimeError::Uncertain(
                        "a prior container create has no provable outcome".into(),
                    ));
                }
                let image = record
                    .request
                    .image
                    .as_deref()
                    .ok_or_else(|| RuntimeError::Invalid("container image required".into()))?;
                let args = self.create_args(&record, image, Some(launch), &launch_digest)?;
                record.launch_digest = Some(launch_digest.clone());
                record.state = RuntimeState::Starting;
                self.save_record(&record)?;
                let output = self.run(&args, Duration::from_secs(120))?;
                if !output.status.success() {
                    return Err(RuntimeError::Provider {
                        code: "container_create_failed".into(),
                    });
                }
            }
            Err(error) => return Err(error),
        }
        let created = self.inspect_container(&prepared.object_id)?;
        self.verify_inspection(
            &prepared.runtime_id,
            &prepared.spec_digest,
            Some(&launch_digest),
            &created,
        )?;
        record.launch_digest = Some(launch_digest);
        record.container_id = Some(created.container_id);
        record.state = RuntimeState::Starting;
        self.save_record(&record)?;
        let output = self.run(
            &["start".into(), prepared.object_id.clone()],
            Duration::from_secs(60),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_start_failed".into(),
            });
        }
        let inspection = self.inspect_container(&prepared.object_id)?;
        self.verify_inspection(
            &prepared.runtime_id,
            &prepared.spec_digest,
            record.launch_digest.as_deref(),
            &inspection,
        )?;
        record.deadline_unix_ms = launch
            .timeout_ms
            .map(|timeout| unix_time_ms().saturating_add(u128::from(timeout)));
        self.update_record_from_inspection(&mut record, &inspection)?;
        let receipt = self.receipt(&prepared.runtime_id, &prepared.spec_digest, inspection);
        if receipt.state == RuntimeState::Running
            && let Some(timeout) = launch.timeout_ms
        {
            self.arm_timeout(receipt.handle.clone(), timeout);
        }
        Ok(receipt)
    }

    fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        validate_handle(self.provider_id(), handle)?;
        let mut inspection = self.inspect_container(&handle.object_id)?;
        let expected_launch = process_identity_launch(handle.process_identity.as_deref());
        self.verify_inspection(
            &handle.runtime_id,
            &handle.spec_digest,
            expected_launch,
            &inspection,
        )?;
        if let Some(identity) = handle.process_identity.as_deref() {
            let observed = format!(
                "container:{}:launch:{}",
                inspection.container_id, inspection.launch_digest
            );
            if identity != observed {
                return Err(RuntimeError::IdentityMismatch);
            }
        }
        if matches!(
            inspection.state,
            RuntimeState::Running | RuntimeState::Paused
        ) && self
            .load_record(&handle.runtime_id)
            .ok()
            .and_then(|record| record.deadline_unix_ms)
            .is_some_and(|deadline| unix_time_ms() >= deadline)
        {
            let output = self.run(
                &[
                    "kill".into(),
                    "--signal".into(),
                    "KILL".into(),
                    handle.object_id.clone(),
                ],
                Duration::from_secs(30),
            )?;
            if !output.status.success() {
                return Err(RuntimeError::Provider {
                    code: "container_timeout_kill_failed".into(),
                });
            }
            inspection = self.inspect_container(&handle.object_id)?;
        }
        if let Ok(mut record) = self.load_record(&handle.runtime_id) {
            self.update_record_from_inspection(&mut record, &inspection)?;
        }
        Ok(self.receipt(&handle.runtime_id, &handle.spec_digest, inspection))
    }

    fn signal(
        &self,
        handle: &RuntimeHandle,
        signal: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let current = self.inspect(handle)?;
        match (signal, current.state) {
            (RuntimeSignal::GracefulStop | RuntimeSignal::ForceStop, RuntimeState::Stopped)
            | (RuntimeSignal::Pause, RuntimeState::Paused)
            | (RuntimeSignal::Resume, RuntimeState::Running) => return Ok(current),
            _ => {}
        }
        let args = match signal {
            RuntimeSignal::GracefulStop => vec![
                "stop".into(),
                "--time".into(),
                "30".into(),
                handle.object_id.clone(),
            ],
            RuntimeSignal::ForceStop => vec![
                "kill".into(),
                "--signal".into(),
                "KILL".into(),
                handle.object_id.clone(),
            ],
            RuntimeSignal::Pause => vec!["pause".into(), handle.object_id.clone()],
            RuntimeSignal::Resume => vec!["unpause".into(), handle.object_id.clone()],
        };
        let output = self.run(&args, Duration::from_secs(45))?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_lifecycle_failed".into(),
            });
        }
        self.inspect(handle)
    }

    fn snapshot(
        &self,
        handle: &RuntimeHandle,
        name: &str,
    ) -> Result<SnapshotReceipt, RuntimeError> {
        self.inspect(handle)?;
        validate_snapshot_name(name)?;
        let image = format!(
            "conduit-snapshot:{}-{name}",
            &digest_bytes(handle.runtime_id.as_bytes())[..16]
        );
        let digest = self.commit_image(handle, &image)?;
        Ok(SnapshotReceipt {
            runtime_id: handle.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest[..16]),
            digest,
            bytes: None,
        })
    }

    fn collect(&self, handle: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        let state = self.inspect(handle)?.state;
        if matches!(state, RuntimeState::Running | RuntimeState::Paused) {
            return Err(RuntimeError::Invalid(
                "container must stop before complete output collection".into(),
            ));
        }
        let output = self.run(
            &[
                "logs".into(),
                "--timestamps=false".into(),
                handle.object_id.clone(),
            ],
            Duration::from_secs(120),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_log_collection_failed".into(),
            });
        }
        self.ensure_state_root()?;
        let path = self.collection_path(&handle.runtime_id)?;
        let temporary = path.with_extension(format!(
            "collection-tmp-{}-{}",
            std::process::id(),
            NEXT_RECORD_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut bytes = Vec::with_capacity(output.stdout.len() + output.stderr.len() + 64);
        bytes.extend_from_slice(b"CONDUIT-CONTAINER-OUTPUT-V1\n");
        bytes.extend_from_slice(format!("stdout:{}\n", output.stdout.len()).as_bytes());
        bytes.extend_from_slice(&output.stdout);
        bytes.extend_from_slice(format!("\nstderr:{}\n", output.stderr.len()).as_bytes());
        bytes.extend_from_slice(&output.stderr);
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(temporary, path)?;
        let digest = digest_bytes(&bytes);
        if let Ok(mut record) = self.load_record(&handle.runtime_id) {
            record.collection_digest = Some(digest.clone());
            self.save_record(&record)?;
        }
        Ok(CollectionReceipt {
            runtime_id: handle.runtime_id.clone(),
            collection_id: format!("collect_{}", &digest[..16]),
            custody_complete: true,
            digest,
        })
    }

    fn archive(
        &self,
        handle: &RuntimeHandle,
        target: &Path,
    ) -> Result<SnapshotReceipt, RuntimeError> {
        self.inspect(handle)?;
        validate_new_archive_target(target)?;
        let image = format!("conduit-archive:{}", handle.spec_digest);
        self.commit_image(handle, &image)?;
        let output = self.run(
            &[
                "image".into(),
                "save".into(),
                "--output".into(),
                target.to_string_lossy().into_owned(),
                image,
            ],
            Duration::from_secs(1800),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_archive_failed".into(),
            });
        }
        fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
        let bytes = fs::metadata(target)?.len();
        let digest = digest_file(target)?;
        Ok(SnapshotReceipt {
            runtime_id: handle.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest[..16]),
            digest,
            bytes: Some(bytes),
        })
    }

    fn restore(
        &self,
        archive: &Path,
        request: &RuntimeRequest,
    ) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(request, RuntimeKind::Container, &[self.provider_id()])?;
        validate_container_request(request, false)?;
        validate_existing_archive(archive)?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(format!(
                "{} service",
                self.provider_id()
            )));
        }
        let image_id = docker_archive_image_id(archive)?;
        let output = self.run(
            &[
                "image".into(),
                "load".into(),
                "--input".into(),
                archive.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(1800),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_restore_load_failed".into(),
            });
        }
        let image = format!("sha256:{image_id}");
        let output = self.run(&["image".into(), "inspect".into(), "--format".into(), "{{index .Config.Labels \"dev.conduit.spec-digest\"}}|{{index .Config.Labels \"dev.conduit.launch-digest\"}}".into(), image.clone()], Duration::from_secs(30))?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_restore_image_inspect_failed".into(),
            });
        }
        let labels = std::str::from_utf8(&output.stdout)
            .map_err(|_| RuntimeError::Provider {
                code: "container_restore_metadata_invalid".into(),
            })?
            .trim()
            .split('|')
            .collect::<Vec<_>>();
        if labels.len() != 2 || labels[0] != request.spec_digest || labels[1].len() != 64 {
            return Err(RuntimeError::IdentityMismatch);
        }
        let launch_digest = labels[1].to_owned();
        let name = Self::name(&request.runtime_id);
        match self.inspect_container(&name) {
            Ok(inspection) => {
                self.verify_inspection(
                    &request.runtime_id,
                    &request.spec_digest,
                    Some(&launch_digest),
                    &inspection,
                )?;
                self.save_record(&ContainerRecord {
                    request: request.clone(),
                    state: inspection.state,
                    launch_digest: Some(launch_digest.clone()),
                    container_id: Some(inspection.container_id.clone()),
                    deadline_unix_ms: None,
                    collection_digest: None,
                })?;
                return Ok(PreparedRuntime {
                    runtime_id: request.runtime_id.clone(),
                    provider_id: self.provider_id().into(),
                    spec_digest: request.spec_digest.clone(),
                    object_id: name,
                    state: inspection.state,
                    evidence: vec![archive_restore_evidence()],
                });
            }
            Err(RuntimeError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let mut record = ContainerRecord {
            request: request.clone(),
            state: RuntimeState::Preparing,
            launch_digest: Some(launch_digest.clone()),
            container_id: None,
            deadline_unix_ms: None,
            collection_digest: None,
        };
        self.save_record(&record)?;
        let args = self.create_args(&record, &image, None, &launch_digest)?;
        let output = self.run(&args, Duration::from_secs(120))?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_restore_create_failed".into(),
            });
        }
        let inspection = self.inspect_container(&name)?;
        self.verify_inspection(
            &request.runtime_id,
            &request.spec_digest,
            Some(&launch_digest),
            &inspection,
        )?;
        self.update_record_from_inspection(&mut record, &inspection)?;
        Ok(PreparedRuntime {
            runtime_id: request.runtime_id.clone(),
            provider_id: self.provider_id().into(),
            spec_digest: request.spec_digest.clone(),
            object_id: name,
            state: RuntimeState::Prepared,
            evidence: vec![archive_restore_evidence()],
        })
    }

    fn destroy(
        &self,
        handle: &RuntimeHandle,
        request: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        let state = match self.inspect(handle) {
            Ok(receipt) => receipt.state,
            Err(RuntimeError::NotFound) => {
                return Ok(DestroyReceipt {
                    runtime_id: handle.runtime_id.clone(),
                    destroyed: true,
                    evidence: "provider object was already absent".into(),
                });
            }
            Err(error) => return Err(error),
        };
        if matches!(state, RuntimeState::Running | RuntimeState::Paused) {
            return Err(RuntimeError::Invalid(
                "running container cannot be destroyed".into(),
            ));
        }
        if !request.custody_complete && !request.discard_authorized {
            return Err(RuntimeError::Invalid("collection receipt required".into()));
        }
        let output = self.run(
            &["rm".into(), handle.object_id.clone()],
            Duration::from_secs(30),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_destroy_failed".into(),
            });
        }
        let path = self.record_path(&handle.runtime_id)?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(RuntimeError::Io(error)),
        }
        Ok(DestroyReceipt {
            runtime_id: handle.runtime_id.clone(),
            destroyed: true,
            evidence: "provider confirmed object removal after custody gate".into(),
        })
    }

    fn reconcile(
        &self,
        records: &[ExpectedRuntime],
    ) -> Result<Vec<ReconciliationReceipt>, RuntimeError> {
        records
            .iter()
            .map(|expected| match self.inspect(&expected.handle) {
                Ok(receipt) => Ok(ReconciliationReceipt {
                    runtime_id: expected.handle.runtime_id.clone(),
                    state: receipt.state,
                    reason_code: if receipt.state == expected.expected_state {
                        "container_identity_and_expected_state_verified"
                    } else {
                        "container_identity_verified_state_diverged"
                    }
                    .into(),
                    observed_identity: receipt.handle.process_identity,
                }),
                Err(RuntimeError::NotFound) => Ok(ReconciliationReceipt {
                    runtime_id: expected.handle.runtime_id.clone(),
                    state: RuntimeState::Lost,
                    reason_code: "provider_object_absent_no_automatic_replay".into(),
                    observed_identity: None,
                }),
                Err(RuntimeError::IdentityMismatch) => Ok(ReconciliationReceipt {
                    runtime_id: expected.handle.runtime_id.clone(),
                    state: RuntimeState::RecoveryRequired,
                    reason_code: "provider_metadata_or_process_identity_conflict".into(),
                    observed_identity: Some(expected.handle.object_id.clone()),
                }),
                Err(error) => Err(error),
            })
            .collect()
    }
}

fn default_state_root() -> PathBuf {
    std::env::var_os("CONDUIT_RUNTIME_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_DATA_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|path| path.join("conduit/runtime"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|path| path.join(".local/share/conduit/runtime"))
        })
        .unwrap_or_else(|| PathBuf::from("/var/lib/conduit/runtime"))
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn validate_runtime_id(runtime_id: &str) -> Result<(), RuntimeError> {
    if !runtime_id.starts_with("rt_")
        || runtime_id.len() < 11
        || runtime_id.len() > 131
        || !runtime_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(RuntimeError::Invalid("invalid Runtime ID".into()));
    }
    Ok(())
}

fn validate_handle(provider_id: &str, handle: &RuntimeHandle) -> Result<(), RuntimeError> {
    validate_runtime_id(&handle.runtime_id)?;
    if handle.provider_id != provider_id
        || handle.object_id != ContainerProvider::name(&handle.runtime_id)
        || handle.spec_digest.len() != 64
        || !handle
            .spec_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RuntimeError::IdentityMismatch);
    }
    Ok(())
}

fn validate_container_request(
    request: &RuntimeRequest,
    image_required: bool,
) -> Result<(), RuntimeError> {
    if image_required && request.image.is_none() {
        return Err(RuntimeError::Invalid("container image required".into()));
    }
    if let Some(image) = request.image.as_deref()
        && (image.is_empty()
            || image.len() > 512
            || image.starts_with('-')
            || image
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r'))
    {
        return Err(RuntimeError::Invalid(
            "invalid container image reference".into(),
        ));
    }
    if request
        .resources
        .cpu
        .is_some_and(|cpu| !cpu.is_finite() || cpu <= 0.0)
        || request.resources.memory_bytes == Some(0)
        || request.resources.pid_limit == Some(0)
    {
        return Err(RuntimeError::Invalid(
            "invalid container resource limit".into(),
        ));
    }
    if request.resources.storage_bytes.is_some() {
        return Err(RuntimeError::CapabilityUnavailable(
            "portable writable-layer storage limit".into(),
        ));
    }
    match request.network {
        NetworkMode::Restricted => {
            return Err(RuntimeError::CapabilityUnavailable(
                "complete restricted egress enforcement".into(),
            ));
        }
        NetworkMode::LanExplicit => {
            return Err(RuntimeError::CapabilityUnavailable(
                "explicit LAN destination enforcement".into(),
            ));
        }
        NetworkMode::Open | NetworkMode::Offline => {}
    }
    for workspace in &request.workspaces {
        if workspace.host_path.to_str().is_none() || workspace.guest_path.to_str().is_none() {
            return Err(RuntimeError::Invalid(
                "container workspace paths must be UTF-8".into(),
            ));
        }
        if workspace.guest_path == Path::new("/") {
            return Err(RuntimeError::Invalid(
                "workspace cannot replace the container root".into(),
            ));
        }
    }
    Ok(())
}

fn validate_launch_plan(launch: &LaunchPlan) -> Result<(), RuntimeError> {
    let executable = launch
        .executable
        .to_str()
        .ok_or_else(|| RuntimeError::Invalid("executable must be UTF-8".into()))?;
    let cwd = launch
        .cwd
        .to_str()
        .ok_or_else(|| RuntimeError::Invalid("working directory must be UTF-8".into()))?;
    if !launch.executable.is_absolute()
        || executable.is_empty()
        || executable.len() > 4_096
        || executable.as_bytes().contains(&0)
    {
        return Err(RuntimeError::Invalid(
            "container executable must be a bounded absolute path".into(),
        ));
    }
    if !launch.cwd.is_absolute() || cwd.len() > 4_096 || cwd.as_bytes().contains(&0) {
        return Err(RuntimeError::Invalid(
            "container working directory must be a bounded absolute path".into(),
        ));
    }
    if launch.argv.len() > MAX_ARGUMENTS
        || launch
            .argv
            .iter()
            .any(|value| value.len() > MAX_SINGLE_VALUE_BYTES || value.as_bytes().contains(&0))
        || launch.argv.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_BYTES
    {
        return Err(RuntimeError::Invalid(
            "container argv exceeds bounds".into(),
        ));
    }
    if launch.environment.len() > MAX_ENVIRONMENT_ENTRIES
        || launch.environment.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || value.len() > MAX_SINGLE_VALUE_BYTES
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || key.as_bytes()[0].is_ascii_digit()
                || value.as_bytes().contains(&0)
        })
        || launch
            .environment
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_ENVIRONMENT_BYTES
    {
        return Err(RuntimeError::Invalid(
            "container environment exceeds bounds".into(),
        ));
    }
    if launch.timeout_ms == Some(0)
        || launch
            .timeout_ms
            .is_some_and(|timeout| timeout > 30 * 24 * 60 * 60 * 1_000)
    {
        return Err(RuntimeError::Invalid(
            "container timeout must be between 1 ms and 30 days".into(),
        ));
    }
    Ok(())
}

fn launch_digest(launch: &LaunchPlan) -> Result<String, RuntimeError> {
    let bytes =
        serde_json::to_vec(launch).map_err(|error| RuntimeError::Record(error.to_string()))?;
    Ok(digest_bytes(&bytes))
}
fn process_identity_launch(identity: Option<&str>) -> Option<&str> {
    identity.and_then(|value| value.rsplit_once(":launch:").map(|(_, digest)| digest))
}
fn archive_restore_evidence() -> CapabilityEvidence {
    CapabilityEvidence {
        capability: "archive_restore".into(),
        state: CapabilityState::Effective,
        source: "provider_image_load_and_config_digest".into(),
        reason_code: "archive_image_and_launch_identity_verified".into(),
        detail: "archive image config and LaunchPlan labels were verified before create".into(),
    }
}
fn validate_snapshot_name(name: &str) -> Result<(), RuntimeError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(RuntimeError::Invalid("invalid snapshot name".into()));
    }
    Ok(())
}
fn parse_sha256(bytes: &[u8], error_code: &str) -> Result<String, RuntimeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RuntimeError::Provider {
        code: error_code.into(),
    })?;
    let digest = text.trim().strip_prefix("sha256:").unwrap_or(text.trim());
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RuntimeError::Provider {
            code: error_code.into(),
        });
    }
    Ok(digest.to_ascii_lowercase())
}
fn validate_new_archive_target(target: &Path) -> Result<(), RuntimeError> {
    if !target.is_absolute()
        || target.exists()
        || target.to_str().is_none_or(|value| value.len() > 4_096)
    {
        return Err(RuntimeError::Invalid(
            "archive target must be a new absolute path".into(),
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| RuntimeError::Invalid("archive target has no parent".into()))?;
    if fs::canonicalize(parent).map_err(RuntimeError::Io)? != parent {
        return Err(RuntimeError::Invalid(
            "archive target parent must be canonical".into(),
        ));
    }
    Ok(())
}
fn validate_existing_archive(archive: &Path) -> Result<(), RuntimeError> {
    if !archive.is_absolute()
        || !archive.is_file()
        || archive.to_str().is_none_or(|value| value.len() > 4_096)
    {
        return Err(RuntimeError::Invalid(
            "archive must be an absolute regular file".into(),
        ));
    }
    if fs::canonicalize(archive).map_err(RuntimeError::Io)? != archive {
        return Err(RuntimeError::Invalid(
            "archive path must be canonical".into(),
        ));
    }
    Ok(())
}
fn digest_file(path: &Path) -> Result<String, RuntimeError> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn docker_archive_image_id(path: &Path) -> Result<String, RuntimeError> {
    let mut file = fs::File::open(path)?;
    loop {
        let mut header = [0_u8; 512];
        file.read_exact(&mut header)
            .map_err(|_| RuntimeError::Provider {
                code: "container_archive_invalid_tar".into(),
            })?;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let name =
            std::str::from_utf8(&header[..name_end]).map_err(|_| RuntimeError::Provider {
                code: "container_archive_invalid_tar".into(),
            })?;
        let size_text = std::str::from_utf8(&header[124..136])
            .map_err(|_| RuntimeError::Provider {
                code: "container_archive_invalid_tar".into(),
            })?
            .trim_matches(char::from(0))
            .trim();
        let size = u64::from_str_radix(size_text, 8).map_err(|_| RuntimeError::Provider {
            code: "container_archive_invalid_tar".into(),
        })?;
        if name == "manifest.json" {
            if size > MAX_ARCHIVE_MANIFEST_BYTES {
                return Err(RuntimeError::Provider {
                    code: "container_archive_manifest_too_large".into(),
                });
            }
            let mut bytes = vec![0_u8; size as usize];
            file.read_exact(&mut bytes)?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| RuntimeError::Provider {
                    code: "container_archive_manifest_invalid".into(),
                })?;
            let config = manifest
                .as_array()
                .filter(|entries| entries.len() == 1)
                .and_then(|entries| entries[0]["Config"].as_str())
                .ok_or_else(|| RuntimeError::Provider {
                    code: "container_archive_manifest_ambiguous".into(),
                })?;
            let image_id = config.strip_suffix(".json").unwrap_or(config);
            if image_id.len() != 64 || !image_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(RuntimeError::Provider {
                    code: "container_archive_image_identity_invalid".into(),
                });
            }
            return Ok(image_id.to_ascii_lowercase());
        }
        let padded = size.div_ceil(512) * 512;
        file.seek(SeekFrom::Current(i64::try_from(padded).map_err(|_| {
            RuntimeError::Provider {
                code: "container_archive_invalid_tar".into(),
            }
        })?))?;
    }
    Err(RuntimeError::Provider {
        code: "container_archive_manifest_missing".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn request(workspace: &Path) -> RuntimeRequest {
        RuntimeRequest {
            runtime_id: "rt_container_01".into(),
            run_id: "run_container_01".into(),
            kind: RuntimeKind::Container,
            provider_selector: "docker".into(),
            spec_digest: "44".repeat(32),
            image: Some("example.invalid/tool@sha256:00".into()),
            resources: ResourceLimits {
                cpu: Some(1.5),
                memory_bytes: Some(64 * 1024 * 1024),
                pid_limit: Some(64),
                storage_bytes: None,
            },
            network: NetworkMode::Offline,
            workspaces: vec![WorkspaceAttachment {
                host_path: workspace.into(),
                guest_path: "/workspace".into(),
                read_only: true,
            }],
        }
    }
    fn launch() -> LaunchPlan {
        LaunchPlan {
            executable: "/usr/bin/tool".into(),
            argv: vec!["literal ; $(touch nope)".into(), "--flag".into()],
            cwd: "/workspace".into(),
            environment: BTreeMap::from([("SAFE_VALUE".into(), "a b;c".into())]),
            io_mode: IoMode::Pipes,
            timeout_ms: None,
        }
    }
    fn fake_provider_for(root: &Path, backend: ContainerBackend) -> ContainerProvider {
        let script = root.join("docker-fake");
        fs::write(&script, r##"#!/bin/sh
set -eu
root=$(dirname "$0")
printf '%s\n' '---' >> "$root/argv"
printf '%s\n' "$@" >> "$root/argv"
case "${1:-}" in
  --version) printf '%s\n' 'Docker fake 1.0' ;;
  info) exit 0 ;;
  image)
    case "${2:-}" in
      inspect)
        case "$*" in *dev.conduit.spec-digest*) printf '%s|%s\n' "$(cat "$root/spec")" "$(cat "$root/launch")" ;; *) printf 'sha256:%064d\n' 1 ;; esac ;;
      save)
        while [ "$#" -gt 0 ]; do
          if [ "$1" = '--output' ]; then shift; : > "$1"; fi
          shift
        done ;;
      load) exit 0 ;;
    esac ;;
  inspect)
    if [ ! -f "$root/state" ]; then printf '%s\n' 'No such object' >&2; exit 1; fi
    printf '%064d|%s|%s|%s|%s|%s|%s\n' 2 "$(cat "$root/runtime")" "$(cat "$root/spec")" "$(cat "$root/launch")" "$(cat "$root/state")" "$(cat "$root/exit")" "$(cat "$root/paused")" ;;
  create)
    printf '%s' created > "$root/state"; printf '%s' false > "$root/paused"; printf '%s' 0 > "$root/exit"
    while [ "$#" -gt 0 ]; do if [ "$1" = '--label' ]; then shift; case "$1" in dev.conduit.runtime-id=*) printf '%s' "${1#*=}" > "$root/runtime" ;; dev.conduit.spec-digest=*) printf '%s' "${1#*=}" > "$root/spec" ;; dev.conduit.launch-digest=*) printf '%s' "${1#*=}" > "$root/launch" ;; esac; fi; shift; done ;;
  start) printf '%s' running > "$root/state" ;;
  stop|kill) printf '%s' exited > "$root/state" ;;
  pause) printf '%s' true > "$root/paused"; printf '%s' paused > "$root/state" ;;
  unpause) printf '%s' false > "$root/paused"; printf '%s' running > "$root/state" ;;
  logs) printf '%s' 'stdout bytes'; printf '%s' 'stderr bytes' >&2 ;;
  commit) printf 'sha256:%064d\n' 1 ;;
  rm) rm -f "$root/state" ;;
esac
"##).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        ContainerProvider::with_program(backend, root.join("records"), script).unwrap()
    }

    fn fake_provider(root: &Path) -> ContainerProvider {
        fake_provider_for(root, ContainerBackend::Docker)
    }

    #[test]
    fn exact_launch_is_main_process_and_lifecycle_is_tracked() {
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider = fake_provider(directory.path());
        let prepared = provider.prepare(&request(&workspace)).unwrap();
        assert!(!directory.path().join("state").exists());
        let started = provider.start(&prepared, &launch()).unwrap();
        assert_eq!(started.state, RuntimeState::Running);
        assert!(started.handle.process_identity.is_some());
        let argv = fs::read_to_string(directory.path().join("argv")).unwrap();
        assert!(argv.contains("--entrypoint\n/usr/bin/tool\n"));
        assert!(argv.contains("example.invalid/tool@sha256:00\nliteral ; $(touch nope)\n--flag"));
        assert!(argv.contains("type=bind,src="));
        assert!(argv.contains(",dst=/workspace,readonly"));
        assert!(!directory.path().join("nope").exists());
        assert_eq!(
            provider
                .signal(&started.handle, RuntimeSignal::Pause)
                .unwrap()
                .state,
            RuntimeState::Paused
        );
        assert_eq!(
            provider
                .signal(&started.handle, RuntimeSignal::Resume)
                .unwrap()
                .state,
            RuntimeState::Running
        );
        let stopped = provider
            .signal(&started.handle, RuntimeSignal::GracefulStop)
            .unwrap();
        assert_eq!(stopped.state, RuntimeState::Stopped);
        let archive = directory.path().join("runtime.tar");
        let archived = provider.archive(&stopped.handle, &archive).unwrap();
        assert_eq!(archived.bytes, Some(0));
        assert!(archive.exists());
        let collection = provider.collect(&stopped.handle).unwrap();
        assert!(collection.custody_complete);
        let collected =
            fs::read(directory.path().join("records/rt_container_01.collection")).unwrap();
        assert!(
            collected
                .windows(12)
                .any(|window| window == b"stdout bytes")
        );
        assert!(
            collected
                .windows(12)
                .any(|window| window == b"stderr bytes")
        );
        provider
            .destroy(
                &stopped.handle,
                &DestroyRequest {
                    custody_complete: true,
                    discard_authorized: false,
                },
            )
            .unwrap();
        assert!(
            directory
                .path()
                .join("records/rt_container_01.collection")
                .exists()
        );
    }

    #[test]
    fn launch_validation_is_bounded() {
        let mut plan = launch();
        plan.executable = "relative".into();
        assert!(matches!(
            validate_launch_plan(&plan),
            Err(RuntimeError::Invalid(_))
        ));
        let mut plan = launch();
        plan.argv = vec!["x".repeat(MAX_SINGLE_VALUE_BYTES + 1)];
        assert!(matches!(
            validate_launch_plan(&plan),
            Err(RuntimeError::Invalid(_))
        ));
        let mut plan = launch();
        plan.environment.insert("BAD=KEY".into(), "x".into());
        assert!(matches!(
            validate_launch_plan(&plan),
            Err(RuntimeError::Invalid(_))
        ));
    }

    #[test]
    fn podman_uses_its_supported_bounded_log_driver_options() {
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider = fake_provider_for(directory.path(), ContainerBackend::Podman);
        let mut request = request(&workspace);
        request.provider_selector = "podman".into();
        let prepared = provider.prepare(&request).unwrap();
        provider.start(&prepared, &launch()).unwrap();
        let argv = fs::read_to_string(directory.path().join("argv")).unwrap();
        assert!(argv.contains("--log-driver\nk8s-file\n"));
        assert!(argv.contains("--log-opt\nmax-size=8m\n"));
        assert!(!argv.contains("max-file=2"));
    }

    #[test]
    fn restore_uses_the_single_image_identity_from_the_archive() {
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider = fake_provider(directory.path());
        let mut request = request(&workspace);
        request.image = None;
        let launch_digest = "55".repeat(32);
        fs::write(directory.path().join("spec"), &request.spec_digest).unwrap();
        fs::write(directory.path().join("launch"), &launch_digest).unwrap();
        let archive = directory.path().join("saved-image.tar");
        write_test_archive(&archive, &"11".repeat(32));

        let prepared = provider.restore(&archive, &request).unwrap();
        assert_eq!(prepared.state, RuntimeState::Prepared);
        let argv = fs::read_to_string(directory.path().join("argv")).unwrap();
        assert!(argv.contains(&format!("sha256:{}", "11".repeat(32))));
        assert!(argv.contains(&format!("dev.conduit.launch-digest={launch_digest}")));
    }

    #[test]
    fn reconciliation_never_restarts_missing_container() {
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider = fake_provider(directory.path());
        let prepared = provider.prepare(&request(&workspace)).unwrap();
        let started = provider.start(&prepared, &launch()).unwrap();
        fs::remove_file(directory.path().join("state")).unwrap();
        let receipts = provider
            .reconcile(&[ExpectedRuntime {
                handle: started.handle,
                expected_state: RuntimeState::Running,
            }])
            .unwrap();
        assert_eq!(receipts[0].state, RuntimeState::Lost);
        assert_eq!(
            receipts[0].reason_code,
            "provider_object_absent_no_automatic_replay"
        );
    }

    #[test]
    #[ignore = "requires a locally available image and a live Docker or Podman service"]
    fn live_container_lifecycle_without_network_or_pull() {
        let backend = match std::env::var("CONDUIT_RUNTIME_LIVE_BACKEND").as_deref() {
            Ok("podman") => ContainerBackend::Podman,
            _ => ContainerBackend::Docker,
        };
        let Ok(image) = std::env::var("CONDUIT_RUNTIME_LIVE_IMAGE") else {
            return;
        };
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider =
            ContainerProvider::with_state_root(backend, directory.path().join("records")).unwrap();
        let mut request = request(&workspace);
        request.runtime_id = format!("rt_live_{}", std::process::id());
        request.run_id = format!("run_live_{}", std::process::id());
        request.provider_selector = provider.provider_id().into();
        request.image = Some(image);
        let prepared = provider.prepare(&request).unwrap();
        let plan = LaunchPlan {
            executable: "/bin/true".into(),
            argv: vec![],
            cwd: "/tmp".into(),
            environment: Default::default(),
            io_mode: IoMode::Pipes,
            timeout_ms: Some(5_000),
        };
        let started = provider.start(&prepared, &plan).unwrap();
        for _ in 0..100 {
            if provider.inspect(&started.handle).unwrap().state == RuntimeState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let stopped = provider.inspect(&started.handle).unwrap();
        assert_eq!(stopped.state, RuntimeState::Stopped);
        provider.collect(&stopped.handle).unwrap();
        provider
            .destroy(
                &stopped.handle,
                &DestroyRequest {
                    custody_complete: true,
                    discard_authorized: false,
                },
            )
            .unwrap();
    }

    fn write_test_archive(path: &Path, image_id: &str) {
        let manifest = format!(r#"[{{"Config":"{image_id}.json"}}]"#).into_bytes();
        let mut header = [0_u8; 512];
        header[.."manifest.json".len()].copy_from_slice(b"manifest.json");
        let size = format!("{:011o}\0", manifest.len());
        header[124..136].copy_from_slice(size.as_bytes());
        let mut archive = Vec::from(header);
        archive.extend_from_slice(&manifest);
        archive.resize(512 + manifest.len().div_ceil(512) * 512, 0);
        archive.extend_from_slice(&[0_u8; 1024]);
        fs::write(path, archive).unwrap();
    }
}
