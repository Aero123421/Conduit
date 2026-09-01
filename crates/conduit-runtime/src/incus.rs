use crate::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

/// Incus/KVM adapter. Every lifecycle call uses a fixed verb and typed fields.
/// Global networks, pools and host disks are intentionally outside this API.
pub struct IncusProvider {
    project: String,
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
        Ok(Self { project: p })
    }
    fn run(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, RuntimeError> {
        let mut c = Command::new("incus");
        c.arg("--project").arg(&self.project).args(args);
        command_output(c, timeout)
    }
    fn name(id: &str) -> String {
        format!("conduit-{}", id.trim_start_matches("rt_"))
    }
    fn tracked_guest_launch_available(&self) -> bool {
        false
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
}
impl RuntimeProvider for IncusProvider {
    fn provider_id(&self) -> &str {
        "incus_kvm"
    }
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        let mut c = Command::new("incus");
        c.args(["info", "--resources"]);
        let live = command_output(c, Duration::from_secs(8)).is_ok_and(|o| o.status.success());
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: version("incus"),
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
                    state: CapabilityState::Unavailable,
                    source: "incus_service_probe".into(),
                    reason_code: "versioned_guest_agent_unavailable".into(),
                    detail: "no tracked guest-agent execution contract is installed".into(),
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
        if !self.tracked_guest_launch_available() {
            return Err(RuntimeError::CapabilityUnavailable(
                "tracked VM LaunchPlan execution through a versioned guest agent".into(),
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
        _launch: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if p.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        Err(RuntimeError::CapabilityUnavailable(
            "tracked VM LaunchPlan execution requires a versioned guest-agent identity".into(),
        ))
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
        let _ = (h, name);
        Err(RuntimeError::CapabilityUnavailable(
            "Incus snapshot digest custody requires archive export".into(),
        ))
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        Err(RuntimeError::CapabilityUnavailable(format!(
            "VM collection target is not configured for {}",
            h.runtime_id
        )))
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
                if has_forbidden_host_device(&existing)
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
        if has_forbidden_host_device(&imported) {
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
    if !request.workspaces.is_empty() {
        return Err(RuntimeError::CapabilityUnavailable(
            "verified VM workspace attachment mechanism".into(),
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

fn has_forbidden_host_device(value: &Value) -> bool {
    ["devices", "expanded_devices"].iter().any(|field| {
        value[*field].as_object().is_some_and(|devices| {
            devices.values().any(|device| {
                let device_type = device["type"].as_str().unwrap_or_default();
                let source = device["source"].as_str().unwrap_or_default();
                matches!(
                    device_type,
                    "proxy" | "unix-char" | "unix-block" | "gpu" | "usb" | "pci"
                ) || (device_type == "disk" && source.starts_with('/'))
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
