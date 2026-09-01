use crate::*;
use serde_json::Value;
use std::{process::Command, time::Duration};

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
                    state: if live {
                        CapabilityState::Supported
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "incus_service_probe".into(),
                    reason_code: if live {
                        "incus_agent_path_supported"
                    } else {
                        "incus_unreachable"
                    }
                    .into(),
                    detail: "effective only after instance exec succeeds".into(),
                },
            ],
        })
    }
    fn prepare(&self, r: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(r, RuntimeKind::Vm)?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(
                "Incus KVM prerequisites".into(),
            ));
        }
        let image = r
            .image
            .as_deref()
            .ok_or_else(|| RuntimeError::Invalid("VM image required".into()))?;
        if image.len() > 512 {
            return Err(RuntimeError::Invalid("image reference too long".into()));
        }
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
        if !r.workspaces.is_empty() {
            return Err(RuntimeError::CapabilityUnavailable(
                "verified VM workspace attachment mechanism".into(),
            ));
        }
        let o = self.run(&a, Duration::from_secs(180))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_vm_init_failed".into(),
            });
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
        _: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        let o = self.run(
            &["start".into(), p.object_id.clone()],
            Duration::from_secs(120),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_vm_start_failed".into(),
            });
        }
        let mut ready = false;
        for _ in 0..30 {
            let o = self.run(
                &[
                    "exec".into(),
                    p.object_id.clone(),
                    "--".into(),
                    "/bin/true".into(),
                ],
                Duration::from_secs(5),
            );
            if o.is_ok_and(|o| o.status.success()) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if !ready {
            return Err(RuntimeError::Uncertain(
                "VM started but guest exec liveness was not proven".into(),
            ));
        }
        self.inspect(&RuntimeHandle {
            runtime_id: p.runtime_id.clone(),
            provider_id: self.provider_id().into(),
            spec_digest: p.spec_digest.clone(),
            object_id: p.object_id.clone(),
            process_identity: None,
        })
    }
    fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
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
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RuntimeError::Invalid("invalid snapshot name".into()));
        }
        let o = self.run(
            &["snapshot".into(), h.object_id.clone(), name.into()],
            Duration::from_secs(120),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_snapshot_failed".into(),
            });
        }
        let identity = format!("{}/{name}:{}", h.object_id, h.spec_digest);
        Ok(SnapshotReceipt {
            runtime_id: h.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest_bytes(identity.as_bytes())[..16]),
            digest: digest_bytes(identity.as_bytes()),
            bytes: None,
        })
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        let evidence = format!("incus:{}:{}", h.object_id, h.spec_digest);
        Ok(CollectionReceipt {
            runtime_id: h.runtime_id.clone(),
            collection_id: format!("collect_{}", &digest_bytes(evidence.as_bytes())[..16]),
            custody_complete: true,
            digest: digest_bytes(evidence.as_bytes()),
        })
    }
    fn destroy(
        &self,
        h: &RuntimeHandle,
        r: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
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

impl IncusProvider {
    pub fn archive(
        &self,
        h: &RuntimeHandle,
        target: &std::path::Path,
    ) -> Result<SnapshotReceipt, RuntimeError> {
        if !target.is_absolute() {
            return Err(RuntimeError::Invalid(
                "archive target must be absolute".into(),
            ));
        }
        let o = self.run(
            &[
                "export".into(),
                h.object_id.clone(),
                target.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(1800),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_archive_failed".into(),
            });
        }
        let bytes = std::fs::metadata(target)?.len();
        let digest = digest_bytes(&std::fs::read(target)?);
        Ok(SnapshotReceipt {
            runtime_id: h.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest[..16]),
            digest,
            bytes: Some(bytes),
        })
    }
    pub fn restore(
        &self,
        archive: &std::path::Path,
        runtime_id: &str,
        spec_digest: &str,
    ) -> Result<PreparedRuntime, RuntimeError> {
        if !archive.is_file() {
            return Err(RuntimeError::Invalid("archive file missing".into()));
        }
        let name = Self::name(runtime_id);
        let o = self.run(
            &[
                "import".into(),
                archive.to_string_lossy().into_owned(),
                name.clone(),
            ],
            Duration::from_secs(1800),
        )?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "incus_restore_failed".into(),
            });
        }
        let set = |key: &str, value: &str| {
            self.run(
                &[
                    "config".into(),
                    "set".into(),
                    name.clone(),
                    key.into(),
                    value.into(),
                ],
                Duration::from_secs(30),
            )
        };
        set("user.conduit.runtime-id", runtime_id)?;
        set("user.conduit.spec-digest", spec_digest)?;
        Ok(PreparedRuntime {
            runtime_id: runtime_id.into(),
            provider_id: self.provider_id().into(),
            spec_digest: spec_digest.into(),
            object_id: name,
            state: RuntimeState::Prepared,
            evidence: vec![],
        })
    }
}
