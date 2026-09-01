use crate::container::{launch_digest, validate_launch_plan, validate_runtime_id};
use crate::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

/// Incus/KVM adapter. Every lifecycle call uses a fixed verb and typed fields.
/// Global networks, pools and host disks are intentionally outside this API.
pub struct IncusProvider {
    project: String,
    program: PathBuf,
    state_root: PathBuf,
    require_kvm: bool,
}
impl IncusProvider {
    pub fn new(project: impl Into<String>) -> Result<Self, RuntimeError> {
        let p = project.into();
        if p.is_empty()
            || p.len() > 64
            || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RuntimeError::Invalid("invalid Incus project".into()));
        }
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|path| path.join(".local/state"))
            })
            .ok_or_else(|| RuntimeError::Invalid("Device state root is unavailable".into()))?
            .join("conduit/incus");
        Self::with_configuration(p, "incus", state_root, true)
    }
    pub fn with_state_root(
        project: impl Into<String>,
        state_root: impl AsRef<Path>,
    ) -> Result<Self, RuntimeError> {
        let project = project.into();
        if project.is_empty()
            || project.len() > 64
            || !project
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(RuntimeError::Invalid("invalid Incus project".into()));
        }
        Self::with_configuration(project, "incus", state_root, true)
    }
    fn with_configuration(
        project: String,
        program: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        require_kvm: bool,
    ) -> Result<Self, RuntimeError> {
        let state_root = state_root.as_ref().to_path_buf();
        fs::create_dir_all(&state_root)?;
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            project,
            program: program.as_ref().to_path_buf(),
            state_root,
            require_kvm,
        })
    }
    fn run(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, RuntimeError> {
        let mut c = Command::new(&self.program);
        c.arg("--project").arg(&self.project).args(args);
        command_output(c, timeout)
    }
    fn name(id: &str) -> String {
        format!("conduit-{}", id.trim_start_matches("rt_"))
    }
    fn artifact_path(&self, runtime_id: &str, suffix: &str) -> Result<PathBuf, RuntimeError> {
        validate_runtime_id(runtime_id)?;
        Ok(self.state_root.join(format!("{runtime_id}.{suffix}")))
    }
    fn inspect_json(&self, name: &str) -> Result<Value, RuntimeError> {
        let o = self.run(
            &["list".into(), name.into(), "--format=json".into()],
            Duration::from_secs(10),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::NotFound);
        }
        let v: Value = serde_json::from_slice(&o.stdout).map_err(|_| RuntimeError::Provider {
            code: "incus_invalid_json".into(),
        })?;
        v.as_array()
            .and_then(|a| a.first())
            .cloned()
            .ok_or(RuntimeError::NotFound)
    }
    fn metadata(v: &Value) -> (Option<&str>, Option<&str>, Option<&str>) {
        let cfg = &v["config"];
        (
            cfg["user.conduit.runtime-id"].as_str(),
            cfg["user.conduit.spec-digest"].as_str(),
            v["status"].as_str(),
        )
    }

    fn ensure_guest_ready(&self, name: &str) -> Result<(), RuntimeError> {
        let inspected = self.inspect_json(name)?;
        let (_, _, status) = Self::metadata(&inspected);
        if status == Some("Stopped") {
            let output = self.run(&["start".into(), name.into()], Duration::from_secs(120))?;
            if !output.status.success() {
                return Err(RuntimeError::Provider {
                    code: "incus_vm_start_failed".into(),
                });
            }
        } else if status != Some("Running") {
            return Err(RuntimeError::Uncertain(
                "Incus VM is not in a startable state".into(),
            ));
        }
        for _ in 0..30 {
            let probe = self.run(
                &[
                    "exec".into(),
                    name.into(),
                    "-T".into(),
                    "--".into(),
                    "/bin/true".into(),
                ],
                Duration::from_secs(5),
            );
            if probe.is_ok_and(|output| output.status.success()) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(RuntimeError::CapabilityUnavailable(
            "Incus guest agent exec did not become ready".into(),
        ))
    }

    fn exec_args(&self, name: &str, launch: &LaunchPlan) -> Result<Vec<String>, RuntimeError> {
        validate_launch_plan(launch)?;
        let cwd = launch
            .cwd
            .to_str()
            .ok_or_else(|| RuntimeError::Invalid("guest cwd must be UTF-8".into()))?;
        let executable = launch
            .executable
            .to_str()
            .ok_or_else(|| RuntimeError::Invalid("guest executable must be UTF-8".into()))?;
        let mut args = vec![
            "exec".into(),
            name.into(),
            "--cwd".into(),
            cwd.into(),
            "-T".into(),
        ];
        for (key, value) in &launch.environment {
            args.extend(["--env".into(), format!("{key}={value}")]);
        }
        args.extend(["--".into(), executable.into()]);
        args.extend(launch.argv.iter().cloned());
        Ok(args)
    }

    fn attach_workspaces(
        &self,
        name: &str,
        workspaces: &[WorkspaceAttachment],
    ) -> Result<(), RuntimeError> {
        for (index, workspace) in workspaces.iter().enumerate() {
            let mut args = vec![
                "config".into(),
                "device".into(),
                "add".into(),
                name.into(),
                format!("conduit-workspace-{index}"),
                "disk".into(),
                format!("source={}", workspace.host_path.display()),
                format!("path={}", workspace.guest_path.display()),
            ];
            if workspace.read_only {
                args.push("readonly=true".into());
            }
            let output = self.run(&args, Duration::from_secs(30))?;
            if !output.status.success() {
                return Err(RuntimeError::Provider {
                    code: "incus_workspace_attach_failed".into(),
                });
            }
        }
        Ok(())
    }

    fn remove_archived_workspaces(&self, name: &str, value: &Value) -> Result<(), RuntimeError> {
        let Some(devices) = value["devices"].as_object() else {
            return Ok(());
        };
        for device_name in devices
            .keys()
            .filter(|device_name| device_name.starts_with("conduit-workspace-"))
        {
            let output = self.run(
                &[
                    "config".into(),
                    "device".into(),
                    "remove".into(),
                    name.into(),
                    device_name.clone(),
                ],
                Duration::from_secs(30),
            )?;
            if !output.status.success() {
                return Err(RuntimeError::Provider {
                    code: "incus_archived_workspace_detach_failed".into(),
                });
            }
        }
        Ok(())
    }
}
impl RuntimeProvider for IncusProvider {
    fn provider_id(&self) -> &str {
        "incus_kvm"
    }
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        let mut c = Command::new(&self.program);
        c.arg("--project")
            .arg(&self.project)
            .args(["info", "--resources"]);
        let live = command_output(c, Duration::from_secs(8)).is_ok_and(|o| o.status.success());
        let kvm = !self.require_kvm
            || std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok();
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: {
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
            },
            capabilities: vec![
                CapabilityEvidence {
                    capability: "vm_boundary".into(),
                    state: if live && kvm {
                        CapabilityState::Effective
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "incus_resources_and_kvm_open".into(),
                    reason_code: if !live {
                        "incus_unreachable"
                    } else if !kvm {
                        "kvm_unavailable"
                    } else {
                        "incus_kvm_ready"
                    }
                    .into(),
                    detail: "Incus service response plus Device-user /dev/kvm access".into(),
                },
                CapabilityEvidence {
                    capability: "guest_exec".into(),
                    state: if live && kvm {
                        CapabilityState::Supported
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "incus_exec_typed_adapter".into(),
                    reason_code: if live && kvm {
                        "guest_exec_requires_per_vm_agent_probe"
                    } else if !live {
                        "incus_unreachable"
                    } else {
                        "kvm_unavailable"
                    }
                    .into(),
                    detail: "Incus exec is admitted only after the VM starts and a non-interactive guest-agent probe succeeds".into(),
                },
                CapabilityEvidence {
                    capability: "archive_restore".into(),
                    state: if live && kvm {
                        CapabilityState::Effective
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "incus_export_import_adapter".into(),
                    reason_code: if !live {
                        "incus_unreachable"
                    } else if !kvm {
                        "kvm_unavailable"
                    } else {
                        "typed_vm_archive_adapter"
                    }
                    .into(),
                    detail: "stopped VM export and import use Device-selected absolute paths"
                        .into(),
                },
            ],
        })
    }
    fn prepare(&self, r: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(r, RuntimeKind::Vm, &["incus_kvm", "incus.kvm"])?;
        validate_vm_request(r, true)?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(
                "Incus KVM prerequisites".into(),
            ));
        }
        let image = r
            .image
            .as_deref()
            .ok_or_else(|| RuntimeError::Invalid("VM image required".into()))?;
        let name = Self::name(&r.runtime_id);
        if let Ok(v) = self.inspect_json(&name) {
            let (id, d, _) = Self::metadata(&v);
            if id == Some(r.runtime_id.as_str()) && d == Some(r.spec_digest.as_str()) {
                return Ok(PreparedRuntime {
                    runtime_id: r.runtime_id.clone(),
                    provider_id: self.provider_id().into(),
                    spec_digest: r.spec_digest.clone(),
                    object_id: name,
                    state: RuntimeState::Prepared,
                    evidence: vec![],
                });
            }
            return Err(RuntimeError::IdentityMismatch);
        }
        let mut a = vec![
            "init".into(),
            image.into(),
            name.clone(),
            "--vm".into(),
            "-c".into(),
            format!("user.conduit.runtime-id={}", r.runtime_id),
            "-c".into(),
            format!("user.conduit.spec-digest={}", r.spec_digest),
            "-c".into(),
            format!("user.conduit.run-id={}", r.run_id),
        ];
        if let Some(v) = r.resources.cpu {
            a.extend(["-c".into(), format!("limits.cpu={}", v.ceil() as u64)])
        }
        if let Some(v) = r.resources.memory_bytes {
            a.extend(["-c".into(), format!("limits.memory={v}")])
        }
        if r.network == NetworkMode::Offline {
            a.extend(["-c".into(), "security.secureboot=true".into()])
        }
        let o = self.run(&a, Duration::from_secs(180))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_vm_init_failed".into(),
            });
        }
        if r.network == NetworkMode::Offline {
            let removed = self.run(
                &[
                    "config".into(),
                    "device".into(),
                    "remove".into(),
                    name.clone(),
                    "eth0".into(),
                ],
                Duration::from_secs(30),
            )?;
            if !removed.status.success() {
                let _ = self.run(&["delete".into(), name.clone()], Duration::from_secs(30));
                return Err(RuntimeError::Provider {
                    code: "incus_offline_network_not_enforced".into(),
                });
            }
        }
        if let Err(error) = self.attach_workspaces(&name, &r.workspaces) {
            let _ = self.run(&["delete".into(), name.clone()], Duration::from_secs(30));
            return Err(error);
        }
        Ok(PreparedRuntime {
            runtime_id: r.runtime_id.clone(),
            provider_id: self.provider_id().into(),
            spec_digest: r.spec_digest.clone(),
            object_id: name,
            state: RuntimeState::Prepared,
            evidence: vec![CapabilityEvidence {
                capability: "vm_boundary".into(),
                state: CapabilityState::Effective,
                source: "incus_vm_object".into(),
                reason_code: "vm_created_with_metadata".into(),
                detail: "Incus VM object created; liveness is not yet claimed".into(),
            }],
        })
    }
    fn start(
        &self,
        p: &PreparedRuntime,
        launch: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if p.provider_id != self.provider_id() || p.object_id != Self::name(&p.runtime_id) {
            return Err(RuntimeError::IdentityMismatch);
        }
        validate_launch_plan(launch)?;
        if launch.io_mode != IoMode::Pipes {
            return Err(RuntimeError::CapabilityUnavailable(
                "Incus guest adapter PTY protocol".into(),
            ));
        }
        self.ensure_guest_ready(&p.object_id)?;
        let args = self.exec_args(&p.object_id, launch)?;
        let output = self.run(
            &args,
            Duration::from_millis(launch.timeout_ms.unwrap_or(24 * 60 * 60 * 1_000)),
        )?;
        let stream = self.artifact_path(&p.runtime_id, "stream")?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stream)?;
        file.write_all(&output.stdout)?;
        file.write_all(&output.stderr)?;
        file.sync_all()?;
        Ok(RuntimeStateReceipt {
            handle: RuntimeHandle {
                runtime_id: p.runtime_id.clone(),
                provider_id: self.provider_id().into(),
                spec_digest: p.spec_digest.clone(),
                object_id: p.object_id.clone(),
                process_identity: Some(format!(
                    "host-incus-cli:{}:launch:{}",
                    p.object_id,
                    &launch_digest(launch)?[..16]
                )),
            },
            state: RuntimeState::Stopped,
            exit_code: output.status.code(),
            evidence: vec![CapabilityEvidence {
                capability: "guest_exec".into(),
                state: CapabilityState::Effective,
                source: "incus_agent_exec_receipt".into(),
                reason_code: "typed_launch_completed".into(),
                detail: "Incus agent executed the exact LaunchPlan argv without an inbound guest listener".into(),
            }, CapabilityEvidence {
                capability: "guest_process_identity".into(),
                state: CapabilityState::Degraded,
                source: "incus_agent_exec_without_guest_pid_receipt".into(),
                reason_code: "guest_pid_not_exposed".into(),
                detail: "the identity names the host Incus CLI session and LaunchPlan digest; it is not presented as a guest PID".into(),
            }],
        })
    }
    fn start_interactive(
        &self,
        p: &PreparedRuntime,
        launch: &LaunchPlan,
    ) -> Result<InteractiveRuntime, RuntimeError> {
        if p.provider_id != self.provider_id() || p.object_id != Self::name(&p.runtime_id) {
            return Err(RuntimeError::IdentityMismatch);
        }
        if launch.io_mode != IoMode::Pipes {
            return Err(RuntimeError::CapabilityUnavailable(
                "structured adapter I/O requires non-PTY pipes".into(),
            ));
        }
        self.ensure_guest_ready(&p.object_id)?;
        let args = self.exec_args(&p.object_id, launch)?;
        let mut command = Command::new(&self.program);
        command
            .arg("--project")
            .arg(&self.project)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn()?;
        std::thread::sleep(Duration::from_millis(20));
        if let Some(status) = child.try_wait()? {
            return Err(RuntimeError::Provider {
                code: if status.success() {
                    "incus_guest_adapter_exited_before_initialization"
                } else {
                    "incus_guest_exec_failed"
                }
                .into(),
            });
        }
        let digest = launch_digest(launch)?;
        Ok(InteractiveRuntime {
            child,
            receipt: RuntimeStateReceipt {
                handle: RuntimeHandle {
                    runtime_id: p.runtime_id.clone(),
                    provider_id: self.provider_id().into(),
                    spec_digest: p.spec_digest.clone(),
                    object_id: p.object_id.clone(),
                    process_identity: Some(format!(
                        "host-incus-cli:{}:launch:{}",
                        p.object_id,
                        &digest[..16]
                    )),
                },
                state: RuntimeState::Running,
                exit_code: None,
                evidence: vec![CapabilityEvidence {
                    capability: "interactive_adapter_io".into(),
                    state: CapabilityState::Effective,
                    source: "incus_agent_attached_exec".into(),
                    reason_code: "guest_protocol_pipes_attached".into(),
                    detail: "protocol pipes traverse Incus agent exec; no Incus socket or inbound guest listener is exposed".into(),
                }, CapabilityEvidence {
                    capability: "guest_process_identity".into(),
                    state: CapabilityState::Degraded,
                    source: "incus_agent_exec_without_guest_pid_receipt".into(),
                    reason_code: "guest_pid_not_exposed".into(),
                    detail: "the identity names the host Incus CLI session and LaunchPlan digest; a Node restart therefore fails closed instead of claiming guest PID attachment".into(),
                }],
            },
        })
    }
    fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != Self::name(&h.runtime_id) {
            return Err(RuntimeError::IdentityMismatch);
        }
        let v = self.inspect_json(&h.object_id)?;
        let (id, d, status) = Self::metadata(&v);
        if id != Some(h.runtime_id.as_str()) || d != Some(h.spec_digest.as_str()) {
            return Err(RuntimeError::IdentityMismatch);
        }
        let state = match status.unwrap_or("") {
            "Running" => RuntimeState::Running,
            "Stopped" => RuntimeState::Stopped,
            "Frozen" => RuntimeState::Paused,
            _ => RuntimeState::Uncertain,
        };
        Ok(RuntimeStateReceipt {
            handle: h.clone(),
            state,
            exit_code: None,
            evidence: vec![],
        })
    }
    fn signal(
        &self,
        h: &RuntimeHandle,
        s: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let current = self.inspect(h)?;
        match (s, current.state) {
            (RuntimeSignal::GracefulStop | RuntimeSignal::ForceStop, RuntimeState::Stopped)
            | (RuntimeSignal::Pause, RuntimeState::Paused)
            | (RuntimeSignal::Resume, RuntimeState::Running) => return Ok(current),
            _ => {}
        }
        let args = match s {
            RuntimeSignal::GracefulStop => {
                vec!["stop".into(), h.object_id.clone(), "--timeout=30".into()]
            }
            RuntimeSignal::ForceStop => vec!["stop".into(), h.object_id.clone(), "--force".into()],
            RuntimeSignal::Pause => vec!["pause".into(), h.object_id.clone()],
            RuntimeSignal::Resume => vec!["resume".into(), h.object_id.clone()],
        };
        let o = self.run(&args, Duration::from_secs(60))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_lifecycle_failed".into(),
            });
        }
        self.inspect(h)
    }
    fn snapshot(&self, h: &RuntimeHandle, name: &str) -> Result<SnapshotReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RuntimeError::Invalid("invalid snapshot name".into()));
        }
        self.inspect(h)?;
        let output = self.run(
            &[
                "snapshot".into(),
                "create".into(),
                h.object_id.clone(),
                name.into(),
            ],
            Duration::from_secs(300),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_snapshot_failed".into(),
            });
        }
        let target = self.artifact_path(&h.runtime_id, &format!("snapshot-{name}.tar.gz"))?;
        if target.exists() {
            return Err(RuntimeError::IdentityMismatch);
        }
        let export = self.run(
            &[
                "export".into(),
                format!("{}/{}", h.object_id, name),
                target.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(1800),
        )?;
        if !export.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_snapshot_export_failed".into(),
            });
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let bytes = fs::metadata(&target)?.len();
        let digest = digest_file(&target)?;
        Ok(SnapshotReceipt {
            runtime_id: h.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest[..16]),
            digest,
            bytes: Some(bytes),
        })
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        let state = self.inspect(h)?.state;
        if matches!(state, RuntimeState::Running | RuntimeState::Paused) {
            return Err(RuntimeError::Invalid(
                "Incus VM must stop before complete collection".into(),
            ));
        }
        let target = self.artifact_path(&h.runtime_id, "collection.tar.gz")?;
        if !target.exists() {
            let output = self.run(
                &[
                    "export".into(),
                    h.object_id.clone(),
                    target.to_string_lossy().into_owned(),
                ],
                Duration::from_secs(1800),
            )?;
            if !output.status.success() {
                return Err(RuntimeError::Provider {
                    code: "incus_collection_export_failed".into(),
                });
            }
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        let digest = digest_file(&target)?;
        Ok(CollectionReceipt {
            runtime_id: h.runtime_id.clone(),
            collection_id: format!("collect_{}", &digest[..16]),
            custody_complete: true,
            digest,
        })
    }
    fn archive(&self, h: &RuntimeHandle, target: &Path) -> Result<SnapshotReceipt, RuntimeError> {
        let state = self.inspect(h)?.state;
        if !matches!(state, RuntimeState::Stopped | RuntimeState::Prepared) {
            return Err(RuntimeError::Invalid(
                "Incus VM must stop before a consistent archive".into(),
            ));
        }
        validate_new_archive_target(target)?;
        let output = self.run(
            &[
                "export".into(),
                h.object_id.clone(),
                target.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(1800),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_archive_failed".into(),
            });
        }
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))?;
        let bytes = std::fs::metadata(target)?.len();
        let digest = digest_file(target)?;
        Ok(SnapshotReceipt {
            runtime_id: h.runtime_id.clone(),
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
        validate_request(request, RuntimeKind::Vm, &["incus_kvm", "incus.kvm"])?;
        validate_vm_request(request, false)?;
        validate_existing_archive(archive)?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(
                "Incus KVM prerequisites".into(),
            ));
        }
        let name = Self::name(&request.runtime_id);
        match self.inspect_json(&name) {
            Ok(existing) => {
                let (runtime_id, spec_digest, status) = Self::metadata(&existing);
                if runtime_id != Some(request.runtime_id.as_str())
                    || spec_digest != Some(request.spec_digest.as_str())
                {
                    return Err(RuntimeError::IdentityMismatch);
                }
                if has_forbidden_host_device(&existing, &request.workspaces)
                    || request.network == NetworkMode::Offline && has_network_device(&existing)
                {
                    return Err(RuntimeError::IdentityMismatch);
                }
                return Ok(PreparedRuntime {
                    runtime_id: request.runtime_id.clone(),
                    provider_id: self.provider_id().into(),
                    spec_digest: request.spec_digest.clone(),
                    object_id: name,
                    state: match status {
                        Some("Running") => RuntimeState::Running,
                        Some("Frozen") => RuntimeState::Paused,
                        Some("Stopped") => RuntimeState::Prepared,
                        _ => RuntimeState::Uncertain,
                    },
                    evidence: vec![archive_restore_evidence()],
                });
            }
            Err(RuntimeError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let output = self.run(
            &[
                "import".into(),
                archive.to_string_lossy().into_owned(),
                name.clone(),
            ],
            Duration::from_secs(1800),
        )?;
        if !output.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_restore_failed".into(),
            });
        }
        let imported = self.inspect_json(&name)?;
        self.remove_archived_workspaces(&name, &imported)?;
        let imported = self.inspect_json(&name)?;
        if has_forbidden_host_device(&imported, &[]) {
            let _ = self.run(
                &["delete".into(), name.clone(), "--force".into()],
                Duration::from_secs(120),
            );
            return Err(RuntimeError::Invalid(
                "restored VM contains a forbidden host device projection".into(),
            ));
        }
        let configure = (|| {
            let mut settings = vec![
                (
                    "user.conduit.runtime-id".to_owned(),
                    request.runtime_id.clone(),
                ),
                (
                    "user.conduit.spec-digest".to_owned(),
                    request.spec_digest.clone(),
                ),
                ("user.conduit.run-id".to_owned(), request.run_id.clone()),
            ];
            if let Some(cpu) = request.resources.cpu {
                settings.push(("limits.cpu".into(), (cpu.ceil() as u64).to_string()));
            }
            if let Some(memory) = request.resources.memory_bytes {
                settings.push(("limits.memory".into(), memory.to_string()));
            }
            for (key, value) in settings {
                let output = self.run(
                    &["config".into(), "set".into(), name.clone(), key, value],
                    Duration::from_secs(30),
                )?;
                if !output.status.success() {
                    return Err(RuntimeError::Provider {
                        code: "incus_restore_metadata_failed".into(),
                    });
                }
            }
            if request.network == NetworkMode::Offline {
                let removed = self.run(
                    &[
                        "config".into(),
                        "device".into(),
                        "remove".into(),
                        name.clone(),
                        "eth0".into(),
                    ],
                    Duration::from_secs(30),
                )?;
                if !removed.status.success() {
                    let inspected = self.inspect_json(&name)?;
                    if has_network_device(&inspected) {
                        return Err(RuntimeError::Provider {
                            code: "incus_restore_offline_network_not_enforced".into(),
                        });
                    }
                }
            }
            self.attach_workspaces(&name, &request.workspaces)?;
            Ok(())
        })();
        if let Err(error) = configure {
            let _ = self.run(
                &["delete".into(), name.clone(), "--force".into()],
                Duration::from_secs(120),
            );
            return Err(error);
        }
        let restored = self.inspect_json(&name)?;
        let (runtime_id, spec_digest, status) = Self::metadata(&restored);
        if runtime_id != Some(request.runtime_id.as_str())
            || spec_digest != Some(request.spec_digest.as_str())
            || !matches!(status, Some("Stopped"))
        {
            return Err(RuntimeError::IdentityMismatch);
        }
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
        h: &RuntimeHandle,
        r: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        let state = match self.inspect(h) {
            Ok(receipt) => receipt.state,
            Err(RuntimeError::NotFound) => {
                return Ok(DestroyReceipt {
                    runtime_id: h.runtime_id.clone(),
                    destroyed: true,
                    evidence: "Incus VM was already absent".into(),
                });
            }
            Err(error) => return Err(error),
        };
        if matches!(state, RuntimeState::Running | RuntimeState::Paused) {
            return Err(RuntimeError::Invalid(
                "running Incus VM cannot be destroyed".into(),
            ));
        }
        if !r.custody_complete && !r.discard_authorized {
            return Err(RuntimeError::Invalid("collection receipt required".into()));
        }
        let o = self.run(
            &["delete".into(), h.object_id.clone()],
            Duration::from_secs(120),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_destroy_failed".into(),
            });
        }
        Ok(DestroyReceipt {
            runtime_id: h.runtime_id.clone(),
            destroyed: true,
            evidence: "Incus confirmed VM deletion after custody gate".into(),
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
                    reason_code: "incus_metadata_verified".into(),
                    observed_identity: Some(e.handle.object_id.clone()),
                }),
                Err(RuntimeError::NotFound) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: RuntimeState::Lost,
                    reason_code: "vm_absent".into(),
                    observed_identity: None,
                }),
                Err(RuntimeError::IdentityMismatch) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: RuntimeState::RecoveryRequired,
                    reason_code: "vm_metadata_conflict".into(),
                    observed_identity: Some(e.handle.object_id.clone()),
                }),
                Err(e) => Err(e),
            })
            .collect()
    }
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
    if std::fs::canonicalize(parent)? != parent {
        return Err(RuntimeError::Invalid(
            "archive target parent must be canonical".into(),
        ));
    }
    Ok(())
}

fn archive_restore_evidence() -> CapabilityEvidence {
    CapabilityEvidence {
        capability: "archive_restore".into(),
        state: CapabilityState::Effective,
        source: "incus_import_and_metadata_inspection".into(),
        reason_code: "restored_vm_identity_verified".into(),
        detail: "Incus imported a stopped VM and the Device verified rewritten identity".into(),
    }
}

fn validate_vm_request(request: &RuntimeRequest, image_required: bool) -> Result<(), RuntimeError> {
    if image_required && request.image.is_none() {
        return Err(RuntimeError::Invalid("VM image required".into()));
    }
    if let Some(image) = request.image.as_deref()
        && (image.is_empty()
            || image.len() > 512
            || image.starts_with('-')
            || image
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r'))
    {
        return Err(RuntimeError::Invalid("invalid VM image reference".into()));
    }
    if request
        .resources
        .cpu
        .is_some_and(|cpu| !cpu.is_finite() || cpu <= 0.0)
        || request.resources.memory_bytes == Some(0)
    {
        return Err(RuntimeError::Invalid("invalid VM resource limit".into()));
    }
    if request.resources.pid_limit.is_some() {
        return Err(RuntimeError::CapabilityUnavailable(
            "verified VM guest PID limit".into(),
        ));
    }
    if request.resources.storage_bytes.is_some() {
        return Err(RuntimeError::CapabilityUnavailable(
            "verified restored VM storage resize".into(),
        ));
    }
    match request.network {
        NetworkMode::Open | NetworkMode::Offline => {}
        NetworkMode::Restricted => {
            return Err(RuntimeError::CapabilityUnavailable(
                "complete restricted VM egress enforcement".into(),
            ));
        }
        NetworkMode::LanExplicit => {
            return Err(RuntimeError::CapabilityUnavailable(
                "explicit VM LAN destination enforcement".into(),
            ));
        }
    }
    Ok(())
}

fn has_network_device(value: &Value) -> bool {
    ["devices", "expanded_devices"].iter().any(|field| {
        value[*field].as_object().is_some_and(|devices| {
            devices.values().any(|device| {
                matches!(
                    device["type"].as_str(),
                    Some("nic") | Some("proxy") | Some("infiniband")
                )
            })
        })
    })
}

fn has_forbidden_host_device(value: &Value, expected_workspaces: &[WorkspaceAttachment]) -> bool {
    ["devices", "expanded_devices"].iter().any(|field| {
        value[*field].as_object().is_some_and(|devices| {
            devices.iter().any(|(name, device)| {
                let device_type = device["type"].as_str().unwrap_or_default();
                let source = device["source"].as_str().unwrap_or_default();
                let declared_workspace = name
                    .strip_prefix("conduit-workspace-")
                    .and_then(|index| index.parse::<usize>().ok())
                    .and_then(|index| expected_workspaces.get(index))
                    .is_some_and(|workspace| {
                        device["source"].as_str()
                            == Some(workspace.host_path.to_string_lossy().as_ref())
                            && device["path"].as_str()
                                == Some(workspace.guest_path.to_string_lossy().as_ref())
                            && (!workspace.read_only
                                || matches!(device["readonly"].as_str(), Some("true") | Some("1")))
                    });
                matches!(
                    device_type,
                    "proxy" | "unix-char" | "unix-block" | "gpu" | "usb" | "pci"
                ) || (device_type == "disk" && source.starts_with('/') && !declared_workspace)
                    || source.contains("docker.sock")
                    || source.contains("podman.sock")
                    || source.contains("incus") && source.contains("socket")
            })
        })
    })
}

fn validate_existing_archive(archive: &Path) -> Result<(), RuntimeError> {
    if !archive.is_absolute()
        || !archive.is_file()
        || archive.to_str().is_none_or(|value| value.len() > 4_096)
        || std::fs::canonicalize(archive)? != archive
    {
        return Err(RuntimeError::Invalid(
            "archive must be a canonical absolute regular file".into(),
        ));
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, RuntimeError> {
    let mut file = std::fs::File::open(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use tempfile::tempdir;

    fn provider(root: &Path) -> IncusProvider {
        let program = root.join("incus-fake");
        fs::write(
            &program,
            r##"#!/bin/sh
set -eu
root=$(dirname "$0")
printf '%s\n' '---' >> "$root/argv"
printf '%s\n' "$@" >> "$root/argv"
if [ "${1:-}" = "--version" ]; then printf '%s\n' '6.18-fake'; exit 0; fi
if [ "${1:-}" = "--project" ]; then shift 2; fi
case "${1:-}" in
  info) exit 0 ;;
  list)
    if [ ! -f "$root/status" ]; then exit 1; fi
    printf '[{"status":"%s","config":{"user.conduit.runtime-id":"%s","user.conduit.spec-digest":"%s"}}]\n' "$(cat "$root/status")" "$(cat "$root/runtime")" "$(cat "$root/spec")" ;;
  init)
    printf '%s' Stopped > "$root/status"
    while [ "$#" -gt 0 ]; do
      if [ "$1" = '-c' ]; then
        shift
        case "$1" in
          user.conduit.runtime-id=*) printf '%s' "${1#*=}" > "$root/runtime" ;;
          user.conduit.spec-digest=*) printf '%s' "${1#*=}" > "$root/spec" ;;
        esac
      fi
      shift
    done ;;
  config) exit 0 ;;
  start) printf '%s' Running > "$root/status" ;;
  exec)
    case "$*" in
      *'/bin/true'*) exit 0 ;;
      *) IFS= read -r line; printf '%s\n' "$line" ;;
    esac ;;
  stop) printf '%s' Stopped > "$root/status" ;;
  snapshot) exit 0 ;;
  export)
    for last do :; done
    printf '%s' 'bounded-vm-custody' > "$last" ;;
  delete) rm -f "$root/status" ;;
esac
"##,
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        IncusProvider::with_configuration("conduit".into(), program, root.join("records"), false)
            .unwrap()
    }

    fn request(workspace: &Path) -> RuntimeRequest {
        RuntimeRequest {
            runtime_id: "rt_incus_agent_01".into(),
            run_id: "run_incus_agent_01".into(),
            kind: RuntimeKind::Vm,
            provider_selector: "incus_kvm".into(),
            spec_digest: "55".repeat(32),
            image: Some("images:ubuntu/24.04".into()),
            resources: ResourceLimits {
                cpu: Some(2.0),
                memory_bytes: Some(512 * 1024 * 1024),
                pid_limit: None,
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
            executable: "/usr/local/bin/agy".into(),
            argv: vec![
                "--input-format".into(),
                "stream-json".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            cwd: "/workspace".into(),
            environment: BTreeMap::new(),
            io_mode: IoMode::Pipes,
            timeout_ms: None,
        }
    }

    #[test]
    fn vm_agent_uses_guest_exec_and_keeps_read_only_workspace_and_custody() {
        let directory = tempdir().unwrap();
        let workspace = directory.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let provider = provider(directory.path());
        let prepared = provider.prepare(&request(&workspace)).unwrap();
        let mut interactive = provider.start_interactive(&prepared, &launch()).unwrap();
        let mut stdin = interactive.child.stdin.take().unwrap();
        stdin
            .write_all(b"{\"event\":\"user\",\"message\":{\"content\":\"review\"}}\n")
            .unwrap();
        drop(stdin);
        let mut output = String::new();
        BufReader::new(interactive.child.stdout.take().unwrap())
            .read_line(&mut output)
            .unwrap();
        assert!(output.contains("\"event\":\"user\""));
        assert!(interactive.child.wait().unwrap().success());
        let stopped = provider
            .signal(&interactive.receipt.handle, RuntimeSignal::GracefulStop)
            .unwrap();
        let snapshot = provider.snapshot(&stopped.handle, "reviewed").unwrap();
        assert_eq!(snapshot.bytes, Some(18));
        let collection = provider.collect(&stopped.handle).unwrap();
        assert!(collection.custody_complete);
        let argv = fs::read_to_string(directory.path().join("argv")).unwrap();
        assert!(argv.contains("conduit-workspace-0\ndisk\n"));
        assert!(argv.contains("path=/workspace\nreadonly=true\n"));
        assert!(argv.contains("exec\nconduit-incus_agent_01\n--cwd\n/workspace\n-T\n"));
        assert!(!argv.contains("incus.sock"));
    }
}
