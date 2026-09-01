use crate::*;
use std::{path::PathBuf, process::Command, time::Duration};

pub struct RestrictedNativeProvider {
    supervisor: ProcessSupervisor,
    require_filesystem: bool,
    require_cgroup: bool,
}
impl RestrictedNativeProvider {
    pub fn new(
        supervisor: ProcessSupervisor,
        require_filesystem: bool,
        require_cgroup: bool,
    ) -> Self {
        Self {
            supervisor,
            require_filesystem,
            require_cgroup,
        }
    }
    fn bwrap_effective() -> bool {
        let mut c = Command::new("bwrap");
        c.args([
            "--unshare-user",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ]);
        command_output(c, Duration::from_secs(5)).is_ok_and(|o| o.status.success())
    }
    fn systemd_effective() -> bool {
        let mut c = Command::new("systemd-run");
        c.args(["--user", "--scope", "--quiet", "/bin/true"]);
        command_output(c, Duration::from_secs(5)).is_ok_and(|o| o.status.success())
    }
}
impl RuntimeProvider for RestrictedNativeProvider {
    fn provider_id(&self) -> &str {
        "restricted_native"
    }
    fn probe(&self) -> Result<CapabilityReceipt, RuntimeError> {
        let b = Self::bwrap_effective();
        let s = Self::systemd_effective();
        let landlock = std::fs::read_to_string("/sys/kernel/security/lsm")
            .ok()
            .is_some_and(|v| v.contains("landlock"));
        Ok(CapabilityReceipt {
            provider_id: self.provider_id().into(),
            provider_version: version("bwrap"),
            capabilities: vec![
                CapabilityEvidence {
                    capability: "filesystem_restriction".into(),
                    state: if b {
                        CapabilityState::Effective
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "bubblewrap_live_probe".into(),
                    reason_code: if b {
                        "bwrap_namespaces_applied"
                    } else {
                        "bwrap_probe_failed"
                    }
                    .into(),
                    detail: "live user+PID namespace and read-only root probe".into(),
                },
                CapabilityEvidence {
                    capability: "cgroup_scope".into(),
                    state: if s {
                        CapabilityState::Effective
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "systemd_user_scope_live_probe".into(),
                    reason_code: if s {
                        "user_scope_applied"
                    } else {
                        "user_scope_probe_failed"
                    }
                    .into(),
                    detail: "transient user scope executed and waited".into(),
                },
                CapabilityEvidence {
                    capability: "landlock".into(),
                    state: if landlock {
                        CapabilityState::Supported
                    } else {
                        CapabilityState::Unavailable
                    },
                    source: "kernel_lsm_list".into(),
                    reason_code: if landlock {
                        "kernel_reports_landlock"
                    } else {
                        "landlock_not_reported"
                    }
                    .into(),
                    detail: "support only; no effective claim until a ruleset is applied".into(),
                },
            ],
        })
    }
    fn prepare(&self, r: &RuntimeRequest) -> Result<PreparedRuntime, RuntimeError> {
        validate_request(
            r,
            RuntimeKind::RestrictedNative,
            &["restricted_native", "restricted-native.linux"],
        )?;
        let p = self.probe()?;
        let b = p
            .capabilities
            .iter()
            .find(|c| c.capability == "filesystem_restriction")
            .is_some_and(|c| c.state == CapabilityState::Effective);
        let s = p
            .capabilities
            .iter()
            .find(|c| c.capability == "cgroup_scope")
            .is_some_and(|c| c.state == CapabilityState::Effective);
        if self.require_filesystem && !b {
            return Err(RuntimeError::CapabilityUnavailable(
                "required filesystem restriction".into(),
            ));
        }
        if self.require_cgroup && !s {
            return Err(RuntimeError::CapabilityUnavailable(
                "required systemd scope".into(),
            ));
        }
        let mut out = self
            .supervisor
            .reserve(r, self.provider_id(), PathBuf::new(), false)?;
        out.evidence = p.capabilities;
        Ok(out)
    }
    fn start(
        &self,
        p: &PreparedRuntime,
        l: &LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError> {
        if p.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        let b = Self::bwrap_effective();
        let s = Self::systemd_effective();
        if self.require_filesystem && !b {
            return Err(RuntimeError::CapabilityUnavailable(
                "bubblewrap is no longer effective".into(),
            ));
        }
        if self.require_cgroup && !s {
            return Err(RuntimeError::CapabilityUnavailable(
                "systemd user scope is no longer effective".into(),
            ));
        }
        let mut wrapped = l.clone();
        if b {
            let mut args = vec![
                "--die-with-parent".into(),
                "--unshare-user".into(),
                "--unshare-pid".into(),
                "--proc".into(),
                "/proc".into(),
                "--dev".into(),
                "/dev".into(),
                "--ro-bind".into(),
                "/".into(),
                "/".into(),
                "--chdir".into(),
                l.cwd.to_string_lossy().into_owned(),
                "--".into(),
                l.executable.to_string_lossy().into_owned(),
            ];
            args.extend(l.argv.clone());
            wrapped.executable = "/usr/bin/bwrap".into();
            if !wrapped.executable.exists() {
                wrapped.executable = "/bin/bwrap".into()
            }
            wrapped.argv = args;
        }
        if s {
            let mut args = vec![
                "--user".into(),
                "--scope".into(),
                "--quiet".into(),
                "--collect".into(),
                "--unit".into(),
                format!("conduit-{}.scope", p.runtime_id),
                "--".into(),
                wrapped.executable.to_string_lossy().into_owned(),
            ];
            args.extend(wrapped.argv.clone());
            wrapped.executable = "/usr/bin/systemd-run".into();
            if !wrapped.executable.exists() {
                wrapped.executable = "/bin/systemd-run".into()
            }
            wrapped.argv = args;
        }
        let mut r = self.supervisor.spawn(p, &wrapped, |_| Ok(()))?;
        r.handle.provider_id = self.provider_id().into();
        r.evidence.extend(p.evidence.clone());
        Ok(r)
    }
    fn inspect(&self, h: &RuntimeHandle) -> Result<RuntimeStateReceipt, RuntimeError> {
        if h.provider_id != self.provider_id() || h.object_id != "native-supervisor" {
            return Err(RuntimeError::IdentityMismatch);
        }
        let mut r = self.supervisor.inspect(&h.runtime_id)?;
        if r.handle.spec_digest != h.spec_digest || r.handle.provider_id != self.provider_id() {
            return Err(RuntimeError::IdentityMismatch);
        }
        r.handle.provider_id = self.provider_id().into();
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
        let mut r = self.supervisor.signal(&h.runtime_id, s)?;
        r.handle.provider_id = self.provider_id().into();
        Ok(r)
    }
    fn snapshot(&self, _: &RuntimeHandle, _: &str) -> Result<SnapshotReceipt, RuntimeError> {
        Err(RuntimeError::CapabilityUnavailable(
            "restricted native snapshot".into(),
        ))
    }
    fn collect(&self, h: &RuntimeHandle) -> Result<CollectionReceipt, RuntimeError> {
        self.inspect(h)?;
        let native = NativeProvider::new(self.supervisor.clone());
        native.collect(&RuntimeHandle {
            provider_id: "native".into(),
            ..h.clone()
        })
    }
    fn destroy(
        &self,
        h: &RuntimeHandle,
        r: &DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError> {
        self.inspect(h)?;
        let native = NativeProvider::new(self.supervisor.clone());
        native.destroy(
            &RuntimeHandle {
                provider_id: "native".into(),
                ..h.clone()
            },
            r,
        )
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
                    reason_code: "restricted_identity_observed".into(),
                    observed_identity: receipt.handle.process_identity,
                }),
                Err(RuntimeError::NotFound) => Ok(ReconciliationReceipt {
                    runtime_id: expected.handle.runtime_id.clone(),
                    state: RuntimeState::Lost,
                    reason_code: "runtime_absent".into(),
                    observed_identity: None,
                }),
                Err(error) => Err(error),
            })
            .collect()
    }
}
