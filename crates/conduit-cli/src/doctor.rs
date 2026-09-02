use std::{
    env,
    path::PathBuf,
    process::{Command, Stdio},
};

use conduit_adapters::AdapterCatalog;
use conduit_core::{CONFIG_SCHEMA_VERSION, FEATURE_REGISTRY_VERSION};
use serde_json::{Value, json};

use crate::{CliError, privileged};

const MAX_PROBE_OUTPUT_BYTES: usize = 16 * 1024;

pub(crate) fn collect() -> Result<Value, CliError> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let node_socket = runtime.as_ref().map(|path| path.join("conduit/node.sock"));
    let providers = [
        ("git", &["--version"][..]),
        ("bwrap", &["--version"][..]),
        ("systemd-run", &["--version"][..]),
        ("docker", &["--version"][..]),
        ("podman", &["--version"][..]),
        ("incus", &["version"][..]),
    ]
    .into_iter()
    .map(|(name, args)| probe(name, args))
    .collect::<Vec<_>>();

    Ok(json!({
        "platform": {
            "os": env::consts::OS,
            "architecture": env::consts::ARCH,
            "linuxSupported": env::consts::OS == "linux"
        },
        "registry": {
            "featureVersion": FEATURE_REGISTRY_VERSION,
            "configVersion": CONFIG_SCHEMA_VERSION
        },
        "node": {
            "runtimeDirectoryConfigured": runtime.as_ref().is_some_and(|path| path.is_absolute()),
            "socketPresent": node_socket.as_ref().is_some_and(|path| path.exists())
        },
        "hostPrerequisites": providers,
        "agentAdapters": AdapterCatalog::discover_all(),
        "privilegedHelper": privileged::doctor_probe(),
        "liveVerification": {
            "performed": false,
            "reason": "doctor probes binaries and versions only; provider lifecycle and paid Agent inference are opt-in"
        }
    }))
}

fn probe(name: &str, args: &[&str]) -> Value {
    let executable = find_in_path(name);
    let Some(path) = executable else {
        return json!({
            "name": name,
            "binaryState": "unavailable",
            "reasonCode": "executable_not_found"
        });
    };
    let output = Command::new(&path).args(args).stdin(Stdio::null()).output();
    match output {
        Ok(output) if output.status.success() => {
            let bytes = if output.stdout.is_empty() {
                &output.stderr
            } else {
                &output.stdout
            };
            if bytes.len() > MAX_PROBE_OUTPUT_BYTES {
                return json!({
                    "name": name,
                    "binaryState": "degraded",
                    "reasonCode": "version_output_too_large"
                });
            }
            let version = String::from_utf8_lossy(bytes);
            json!({
                "name": name,
                "binaryState": "observed",
                "mechanism": "bounded_version_probe",
                "version": version.lines().next().unwrap_or("").trim(),
                "providerLifecycleVerified": false
            })
        }
        Ok(output) => json!({
            "name": name,
            "binaryState": "degraded",
            "reasonCode": "version_probe_failed",
            "exitCode": output.status.code()
        }),
        Err(error) => json!({
            "name": name,
            "binaryState": "degraded",
            "reasonCode": "version_probe_io_error",
            "errorKind": format!("{:?}", error.kind())
        }),
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_reports_truthful_live_boundary() {
        let value = collect().unwrap();
        assert_eq!(
            value.pointer("/liveVerification/performed"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            value
                .pointer("/agentAdapters")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            5
        );
    }
}
