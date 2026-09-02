use crate::{HelperError, Result};
use conduit_privileged_protocol::ResourceCeilings;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    pub unit_name: String,
    pub worker_path: String,
    pub execution_record_path: String,
    pub receipt_public_key_path: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub resources: ResourceCeilings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitObservation {
    pub unit_name: String,
    pub invocation_id: Option<String>,
    pub main_pid: Option<u32>,
    pub active_state: String,
    pub cgroup: Option<String>,
    pub effective_uid: Option<u32>,
    pub effective_gid: Option<u32>,
    pub process_birth: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

pub trait SystemdManager: Send + Sync + 'static {
    fn available(&self) -> Result<bool>;
    fn start_transient(&self, spec: &UnitSpec) -> Result<UnitObservation>;
    fn inspect(&self, unit_name: &str) -> Result<UnitObservation>;
    fn inspect_optional(&self, unit_name: &str) -> Result<Option<UnitObservation>> {
        self.inspect(unit_name).map(Some)
    }
    fn pause(&self, unit_name: &str) -> Result<()>;
    fn resume(&self, unit_name: &str) -> Result<()>;
    fn graceful_stop(&self, unit_name: &str) -> Result<()>;
    fn force_stop(&self, unit_name: &str) -> Result<()>;
}

/// Production backend. All mutations use the system manager's typed D-Bus
/// interface; no shell, `systemctl`, or `systemd-run` process is involved.
pub struct SystemdBackend {
    connection: Connection,
}

impl SystemdBackend {
    pub fn connect_system() -> Result<Self> {
        Ok(Self {
            connection: Connection::system().map_err(bus_error)?,
        })
    }

    fn manager(&self) -> Result<Proxy<'_>> {
        Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .map_err(bus_error)
    }

    fn unit_path(&self, unit_name: &str) -> Result<OwnedObjectPath> {
        self.manager()?
            .call("GetUnit", &(unit_name,))
            .map_err(bus_error)
    }

    fn optional_unit_path(&self, unit_name: &str) -> Result<Option<OwnedObjectPath>> {
        match self.manager()?.call("GetUnit", &(unit_name,)) {
            Ok(path) => Ok(Some(path)),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                Ok(None)
            }
            Err(error) => Err(bus_error(error)),
        }
    }

    fn inspect_path(&self, unit_name: &str, path: OwnedObjectPath) -> Result<UnitObservation> {
        let active_state = String::try_from(self.property(
            &path,
            "org.freedesktop.systemd1.Unit",
            "ActiveState",
        )?)
        .map_err(bus_error)?;
        let cgroup = String::try_from(self.property(
            &path,
            "org.freedesktop.systemd1.Service",
            "ControlGroup",
        )?)
        .ok()
        .filter(|v| !v.is_empty());
        let main_pid =
            u32::try_from(self.property(&path, "org.freedesktop.systemd1.Service", "MainPID")?)
                .ok()
                .filter(|v| *v != 0);
        let invocation = Vec::<u8>::try_from(self.property(
            &path,
            "org.freedesktop.systemd1.Unit",
            "InvocationID",
        )?)
        .ok()
        .filter(|v| v.len() == 16)
        .map(hex::encode);
        let (effective_uid, effective_gid, process_birth) = main_pid
            .and_then(proc_identity)
            .map(|v| (Some(v.0), Some(v.1), Some(v.2)))
            .unwrap_or((None, None, None));
        let main_code = i32::try_from(self.property(
            &path,
            "org.freedesktop.systemd1.Service",
            "ExecMainCode",
        )?)
        .ok();
        let main_status = i32::try_from(self.property(
            &path,
            "org.freedesktop.systemd1.Service",
            "ExecMainStatus",
        )?)
        .ok();
        let (exit_code, signal) = match (main_code, main_status) {
            (Some(libc::CLD_EXITED), value) => (value, None),
            (Some(_), value) => (None, value),
            _ => (None, None),
        };
        Ok(UnitObservation {
            unit_name: unit_name.into(),
            invocation_id: invocation,
            main_pid,
            active_state,
            cgroup,
            effective_uid,
            effective_gid,
            process_birth,
            exit_code,
            signal,
        })
    }

    fn property(&self, path: &OwnedObjectPath, interface: &str, name: &str) -> Result<OwnedValue> {
        let proxy = Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            path.as_str(),
            "org.freedesktop.DBus.Properties",
        )
        .map_err(bus_error)?;
        proxy.call("Get", &(interface, name)).map_err(bus_error)
    }
}

impl SystemdManager for SystemdBackend {
    fn available(&self) -> Result<bool> {
        let _: String = self.manager()?.get_property("Version").map_err(bus_error)?;
        Ok(true)
    }

    fn start_transient(&self, spec: &UnitSpec) -> Result<UnitObservation> {
        validate_unit_spec(spec)?;
        let argv = vec![
            spec.worker_path.clone(),
            "exec-worker".into(),
            "--record".into(),
            spec.execution_record_path.clone(),
            "--receipt-public-key".into(),
            spec.receipt_public_key_path.clone(),
        ];
        let exec = vec![(spec.worker_path.clone(), argv, false)];
        let mut properties: Vec<(&str, Value<'_>)> = vec![
            (
                "Description",
                Value::new(format!("Conduit elevated runtime {}", spec.unit_name)),
            ),
            ("Type", Value::new("exec")),
            ("User", Value::new("root")),
            ("Group", Value::new("root")),
            ("ExecStart", Value::new(exec)),
            ("KillMode", Value::new("control-group")),
            ("Restart", Value::new("no")),
            ("StandardOutput", Value::new("null")),
            ("StandardError", Value::new("null")),
        ];
        if let Some(value) = spec.resources.cpu_quota_per_sec_usec {
            properties.push(("CPUQuotaPerSecUSec", Value::new(value)));
        }
        if let Some(value) = spec.resources.memory_max_bytes {
            properties.push(("MemoryMax", Value::new(value)));
        }
        if let Some(value) = spec.resources.tasks_max {
            properties.push(("TasksMax", Value::new(value as u64)));
        }
        if let Some(value) = spec.resources.io_weight {
            properties.push(("IOWeight", Value::new(value as u64)));
        }
        if let Some(value) = spec.resources.runtime_max_usec {
            properties.push(("RuntimeMaxUSec", Value::new(value)));
        }
        let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
        let _: OwnedObjectPath = self
            .manager()?
            .call(
                "StartTransientUnit",
                &(&spec.unit_name, "fail", properties, auxiliary),
            )
            .map_err(bus_error)?;
        self.inspect(&spec.unit_name)
    }

    fn inspect(&self, unit_name: &str) -> Result<UnitObservation> {
        validate_unit_name(unit_name)?;
        let path = self.unit_path(unit_name)?;
        self.inspect_path(unit_name, path)
    }

    fn inspect_optional(&self, unit_name: &str) -> Result<Option<UnitObservation>> {
        validate_unit_name(unit_name)?;
        self.optional_unit_path(unit_name)?
            .map(|path| self.inspect_path(unit_name, path))
            .transpose()
    }

    fn pause(&self, unit_name: &str) -> Result<()> {
        validate_unit_name(unit_name)?;
        self.manager()?
            .call::<_, _, ()>("FreezeUnit", &(unit_name,))
            .map_err(bus_error)
    }
    fn resume(&self, unit_name: &str) -> Result<()> {
        validate_unit_name(unit_name)?;
        self.manager()?
            .call::<_, _, ()>("ThawUnit", &(unit_name,))
            .map_err(bus_error)
    }
    fn graceful_stop(&self, unit_name: &str) -> Result<()> {
        validate_unit_name(unit_name)?;
        let _: OwnedObjectPath = self
            .manager()?
            .call("StopUnit", &(unit_name, "replace"))
            .map_err(bus_error)?;
        Ok(())
    }
    fn force_stop(&self, unit_name: &str) -> Result<()> {
        validate_unit_name(unit_name)?;
        self.manager()?
            .call::<_, _, ()>("KillUnit", &(unit_name, "all", libc::SIGKILL))
            .map_err(bus_error)
    }
}

#[derive(Clone, Default)]
pub struct FakeSystemd {
    inner: Arc<Mutex<FakeState>>,
}

#[derive(Default)]
struct FakeState {
    units: BTreeMap<String, UnitObservation>,
    calls: Vec<String>,
    fail_next: Option<String>,
}

impl FakeSystemd {
    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }
    pub fn fail_next(&self, reason: impl Into<String>) {
        self.inner.lock().unwrap().fail_next = Some(reason.into());
    }
    #[cfg(test)]
    pub fn forget_unit(&self, unit_name: &str) {
        self.inner.lock().unwrap().units.remove(unit_name);
    }
    fn mutation(&self, call: String) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| HelperError::Systemd("fake lock poisoned".into()))?;
        state.calls.push(call);
        if let Some(reason) = state.fail_next.take() {
            return Err(HelperError::Systemd(reason));
        }
        Ok(())
    }
}

impl SystemdManager for FakeSystemd {
    fn available(&self) -> Result<bool> {
        Ok(true)
    }
    fn start_transient(&self, spec: &UnitSpec) -> Result<UnitObservation> {
        validate_unit_spec(spec)?;
        self.mutation(format!("start:{}", spec.unit_name))?;
        let observation = UnitObservation {
            unit_name: spec.unit_name.clone(),
            invocation_id: Some(format!("inv-{}", spec.unit_name)),
            main_pid: Some(4242),
            active_state: "active".into(),
            cgroup: Some(format!("/system.slice/{}", spec.unit_name)),
            effective_uid: Some(0),
            effective_gid: Some(0),
            process_birth: Some("fake:4242".into()),
            exit_code: None,
            signal: None,
        };
        self.inner
            .lock()
            .unwrap()
            .units
            .insert(spec.unit_name.clone(), observation.clone());
        Ok(observation)
    }
    fn inspect(&self, unit_name: &str) -> Result<UnitObservation> {
        self.inner
            .lock()
            .unwrap()
            .units
            .get(unit_name)
            .cloned()
            .ok_or_else(|| HelperError::Systemd("unit_not_found".into()))
    }
    fn inspect_optional(&self, unit_name: &str) -> Result<Option<UnitObservation>> {
        Ok(self.inner.lock().unwrap().units.get(unit_name).cloned())
    }
    fn pause(&self, unit_name: &str) -> Result<()> {
        self.mutation(format!("pause:{unit_name}"))?;
        self.inner
            .lock()
            .unwrap()
            .units
            .get_mut(unit_name)
            .ok_or_else(|| HelperError::Systemd("unit_not_found".into()))?
            .active_state = "frozen".into();
        Ok(())
    }
    fn resume(&self, unit_name: &str) -> Result<()> {
        self.mutation(format!("resume:{unit_name}"))?;
        self.inner
            .lock()
            .unwrap()
            .units
            .get_mut(unit_name)
            .ok_or_else(|| HelperError::Systemd("unit_not_found".into()))?
            .active_state = "active".into();
        Ok(())
    }
    fn graceful_stop(&self, unit_name: &str) -> Result<()> {
        self.mutation(format!("stop:{unit_name}"))?;
        self.inner
            .lock()
            .unwrap()
            .units
            .get_mut(unit_name)
            .ok_or_else(|| HelperError::Systemd("unit_not_found".into()))?
            .active_state = "inactive".into();
        Ok(())
    }
    fn force_stop(&self, unit_name: &str) -> Result<()> {
        self.mutation(format!("kill:{unit_name}"))?;
        self.inner
            .lock()
            .unwrap()
            .units
            .get_mut(unit_name)
            .ok_or_else(|| HelperError::Systemd("unit_not_found".into()))?
            .active_state = "failed".into();
        Ok(())
    }
}

fn validate_unit_spec(spec: &UnitSpec) -> Result<()> {
    validate_unit_name(&spec.unit_name)?;
    for path in [
        &spec.worker_path,
        &spec.execution_record_path,
        &spec.receipt_public_key_path,
        &spec.stdout_path,
        &spec.stderr_path,
    ] {
        if !path.starts_with('/') || path.as_bytes().contains(&0) {
            return Err(HelperError::Denied("invalid_absolute_path".into()));
        }
    }
    Ok(())
}

fn validate_unit_name(name: &str) -> Result<()> {
    if !name.starts_with("conduit-elevated-")
        || !name.ends_with(".service")
        || name.len() > 200
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(HelperError::Denied("invalid_systemd_unit".into()));
    }
    Ok(())
}

fn bus_error(error: impl std::fmt::Display) -> HelperError {
    HelperError::Systemd(error.to_string())
}
fn proc_identity(pid: u32) -> Option<(u32, u32, String)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status
        .lines()
        .find(|v| v.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let gid = status
        .lines()
        .find(|v| v.starts_with("Gid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let start = stat[end + 2..].split_whitespace().nth(19)?;
    Some((uid, gid, format!("{pid}:{start}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fake_uses_exact_unit_and_supports_control() {
        let backend = FakeSystemd::default();
        let spec = UnitSpec {
            unit_name: "conduit-elevated-test.service".into(),
            worker_path: "/usr/lib/conduit/helper".into(),
            execution_record_path: "/run/conduit/r.json".into(),
            receipt_public_key_path: "/var/lib/conduit/receipt.public".into(),
            stdout_path: "/var/lib/conduit/out".into(),
            stderr_path: "/var/lib/conduit/err".into(),
            resources: ResourceCeilings {
                cpu_quota_per_sec_usec: None,
                memory_max_bytes: None,
                tasks_max: None,
                io_weight: None,
                runtime_max_usec: None,
            },
        };
        backend.start_transient(&spec).unwrap();
        backend.pause(&spec.unit_name).unwrap();
        backend.resume(&spec.unit_name).unwrap();
        backend.force_stop(&spec.unit_name).unwrap();
        assert_eq!(
            backend.calls(),
            vec![
                "start:conduit-elevated-test.service",
                "pause:conduit-elevated-test.service",
                "resume:conduit-elevated-test.service",
                "kill:conduit-elevated-test.service"
            ]
        );
    }
}
