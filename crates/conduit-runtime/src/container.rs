use crate::*;
use std::{process::Command, time::Duration};

#[derive(Debug, Clone, Copy)]
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
}
pub struct ContainerProvider {
    backend: ContainerBackend,
}
impl ContainerProvider {
    pub fn new(backend: ContainerBackend) -> Self {
        Self { backend }
    }
    fn run(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, RuntimeError> {
        let mut c = Command::new(self.backend.program());
        c.args(args);
        command_output(c, timeout)
    }
    fn name(id: &str) -> String {
        format!("conduit-{}", id.trim_start_matches("rt_"))
    }
    fn tracked_launch_available(&self) -> bool {
        false
    }
    fn inspect_labels(&self, name: &str) -> Result<(String, String, bool), RuntimeError> {
        let args=vec!["inspect".into(),"--format".into(),"{{index .Config.Labels \"dev.conduit.runtime-id\"}}|{{index .Config.Labels \"dev.conduit.spec-digest\"}}|{{.State.Running}}".into(),name.into()];
        let o = self.run(&args, Duration::from_secs(10))?;
        if !o.status.success() {
            return Err(RuntimeError::NotFound);
        }
        let s = String::from_utf8_lossy(&o.stdout);
        let mut p = s.trim().split('|');
        Ok((
            p.next().unwrap_or_default().into(),
            p.next().unwrap_or_default().into(),
            p.next() == Some("true"),
        ))
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
        let mut c = Command::new(self.backend.program());
        c.arg("info");
        let effective = command_output(c, Duration::from_secs(5)).is_ok_and(|o| o.status.success());
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: version(self.backend.program()),
            capabilities: vec![
                CapabilityEvidence {
                    capability: "container_boundary".into(),
                    state: if effective {
                        CapabilityState::Effective
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "provider_info_live_probe".into(),
                    reason_code: if effective {
                        "daemon_reachable"
                    } else {
                        "daemon_unavailable"
                    }
                    .into(),
                    detail: "provider info completed; per-runtime limits are verified separately"
                        .into(),
                },
                CapabilityEvidence {
                    capability: "tracked_launch_plan".into(),
                    state: CapabilityState::Unavailable,
                    source: "container_exec_adapter".into(),
                    reason_code: "exec_identity_backend_unavailable".into(),
                    detail: "Running is not reported without tracked LaunchPlan completion".into(),
                },
            ],
        })
    }
    fn prepare(&self, r: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(r, RuntimeKind::Container, &[self.provider_id()])?;
        if self.probe()?.capabilities[0].state != CapabilityState::Effective {
            return Err(RuntimeError::CapabilityUnavailable(format!(
                "{} service",
                self.provider_id()
            )));
        }
        if !self.tracked_launch_available() {
            return Err(RuntimeError::CapabilityUnavailable(
                "tracked container LaunchPlan execution".into(),
            ));
        }
        let image = r
            .image
            .as_deref()
            .ok_or_else(|| RuntimeError::Invalid("container image required".into()))?;
        if image.len() > 512 {
            return Err(RuntimeError::Invalid("image reference too long".into()));
        }
        let name = Self::name(&r.runtime_id);
        if let Ok((id, digest, _)) = self.inspect_labels(&name) {
            if id == r.runtime_id && digest == r.spec_digest {
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
            "create".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("dev.conduit.runtime-id={}", r.runtime_id),
            "--label".into(),
            format!("dev.conduit.spec-digest={}", r.spec_digest),
            "--label".into(),
            format!("dev.conduit.run-id={}", r.run_id),
            "--network".into(),
            match r.network {
                NetworkMode::Open | NetworkMode::LanExplicit => "bridge",
                NetworkMode::Offline => "none",
                NetworkMode::Restricted => {
                    return Err(RuntimeError::CapabilityUnavailable(
                        "complete restricted egress enforcement".into(),
                    ));
                }
            }
            .into(),
        ];
        if let Some(v) = r.resources.cpu {
            a.extend(["--cpus".into(), v.to_string()])
        }
        if let Some(v) = r.resources.memory_bytes {
            a.extend(["--memory".into(), v.to_string()])
        }
        if let Some(v) = r.resources.pid_limit {
            a.extend(["--pids-limit".into(), v.to_string()])
        }
        for w in &r.workspaces {
            a.extend([
                "--mount".into(),
                format!(
                    "type=bind,src={},dst={},readonly={}",
                    w.host_path.display(),
                    w.guest_path.display(),
                    w.read_only
                ),
            ])
        }
        a.push(image.into());
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push("trap : TERM INT; sleep infinity & wait".into());
        let o = self.run(&a, Duration::from_secs(60))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_create_failed".into(),
            });
        }
        Ok(PreparedRuntime {
            runtime_id: r.runtime_id.clone(),
            provider_id: self.provider_id().into(),
            spec_digest: r.spec_digest.clone(),
            object_id: name,
            state: RuntimeState::Prepared,
            evidence: vec![CapabilityEvidence {
                capability: "host_management_socket_absent".into(),
                state: CapabilityState::Effective,
                source: "typed_mount_allowlist".into(),
                reason_code: "no_socket_projection".into(),
                detail: "only declared workspace mounts were constructed".into(),
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
            "tracked container LaunchPlan execution requires an exec identity backend".into(),
        ))
    }
    fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != Self::name(&h.runtime_id) {
            return Err(RuntimeError::IdentityMismatch);
        }
        let (id, digest, running) = self.inspect_labels(&h.object_id)?;
        if id != h.runtime_id || digest != h.spec_digest {
            return Err(RuntimeError::IdentityMismatch);
        }
        Ok(RuntimeStateReceipt {
            handle: h.clone(),
            state: if running {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            exit_code: None,
            evidence: vec![],
        })
    }
    fn signal(
        &self,
        h: &RuntimeHandle,
        s: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        self.inspect(h)?;
        let op = match s {
            RuntimeSignal::GracefulStop => "stop",
            RuntimeSignal::ForceStop => "kill",
            RuntimeSignal::Pause => "pause",
            RuntimeSignal::Resume => "unpause",
        };
        let o = self.run(&[op.into(), h.object_id.clone()], Duration::from_secs(30))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: format!("container_{op}_failed"),
            });
        }
        self.inspect(h)
    }
    fn snapshot(&self, h: &RuntimeHandle, name: &str) -> Result<SnapshotReceipt, RuntimeError> {
        self.inspect(h)?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(RuntimeError::Invalid("invalid snapshot name".into()));
        }
        let image = format!(
            "conduit-snapshot:{}-{}",
            h.runtime_id.trim_start_matches("rt_"),
            name
        );
        let o = self.run(
            &["commit".into(), h.object_id.clone(), image.clone()],
            Duration::from_secs(120),
        )?;
        if !o.status.success() {
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
                image,
            ],
            Duration::from_secs(30),
        )?;
        if !inspected.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_snapshot_digest_unavailable".into(),
            });
        }
        let raw = String::from_utf8_lossy(&inspected.stdout);
        let digest = raw
            .trim()
            .strip_prefix("sha256:")
            .ok_or_else(|| RuntimeError::Provider {
                code: "container_snapshot_digest_invalid".into(),
            })?
            .to_owned();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RuntimeError::Provider {
                code: "container_snapshot_digest_invalid".into(),
            });
        }
        Ok(SnapshotReceipt {
            runtime_id: h.runtime_id.clone(),
            snapshot_id: format!("snap_{}", &digest[..16]),
            digest,
            bytes: None,
        })
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        Err(RuntimeError::CapabilityUnavailable(format!(
            "container collection target is not configured for {}",
            h.runtime_id
        )))
    }
    fn destroy(
        &self,
        h: &RuntimeHandle,
        r: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        self.inspect(h)?;
        if !r.custody_complete && !r.discard_authorized {
            return Err(RuntimeError::Invalid("collection receipt required".into()));
        }
        let o = self.run(&["rm".into(), h.object_id.clone()], Duration::from_secs(30))?;
        if !o.status.success() {
            return Err(RuntimeError::Provider {
                code: "container_destroy_failed".into(),
            });
        }
        Ok(DestroyReceipt {
            runtime_id: h.runtime_id.clone(),
            destroyed: true,
            evidence: "provider confirmed object removal".into(),
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
                    reason_code: "labels_and_state_verified".into(),
                    observed_identity: Some(e.handle.object_id.clone()),
                }),
                Err(RuntimeError::NotFound) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: RuntimeState::Lost,
                    reason_code: "provider_object_absent".into(),
                    observed_identity: None,
                }),
                Err(RuntimeError::IdentityMismatch) => Ok(ReconciliationReceipt {
                    runtime_id: e.handle.runtime_id.clone(),
                    state: RuntimeState::RecoveryRequired,
                    reason_code: "provider_metadata_conflict".into(),
                    observed_identity: Some(e.handle.object_id.clone()),
                }),
                Err(e) => Err(e),
            })
            .collect()
    }
}
