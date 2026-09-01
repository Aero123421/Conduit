use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use conduit_core::CapabilityState;

use crate::{
    driver::ProtocolDriver,
    types::{
        AdapterCapability, AdapterError, AdapterKind, AdapterOperation, AdapterProbe,
        AdapterProtocol, AuthenticationState, LaunchRequest, LaunchSpec, MAX_VERSION_OUTPUT_BYTES,
        SupportLevel, bound_utf8, validate_launch_request,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct AdapterProfile {
    pub kind: AdapterKind,
    pub executable: &'static str,
    pub protocol: AdapterProtocol,
    pub version_args: &'static [&'static str],
}

impl AdapterProfile {
    pub fn capabilities(self) -> Vec<AdapterCapability> {
        use AdapterOperation as Operation;
        let supported = |operation, evidence: &'static str| AdapterCapability {
            operation,
            support: SupportLevel::Supported,
            evidence: evidence.to_owned(),
        };
        let degraded = |operation, evidence: &'static str| AdapterCapability {
            operation,
            support: SupportLevel::Degraded,
            evidence: evidence.to_owned(),
        };
        let mut values = vec![
            supported(Operation::Discover, "PATH executable identity"),
            supported(Operation::Probe, "bounded --version invocation"),
            supported(Operation::Capability, "versioned adapter profile"),
            supported(
                Operation::AuthenticationStatus,
                "structured login errors and local probe state",
            ),
            supported(Operation::Open, "structured child protocol"),
            supported(Operation::Send, "correlated prompt admission"),
            supported(
                Operation::Cancel,
                "typed protocol cancellation or process termination",
            ),
            supported(Operation::State, "correlated state and terminal events"),
            supported(Operation::Replay, "bounded normalized event journal"),
            supported(Operation::Close, "child stdin close and process lifecycle"),
        ];
        match self.kind {
            AdapterKind::Codex => values.extend([
                supported(Operation::ModelDiscovery, "model/list"),
                supported(Operation::Steer, "turn/steer with expectedTurnId"),
                supported(Operation::FollowUp, "turn/start after terminal turn"),
                supported(Operation::Resume, "thread/resume"),
            ]),
            AdapterKind::OpenCode => values.extend([
                degraded(
                    Operation::ModelDiscovery,
                    "ACP model capabilities are server-negotiated",
                ),
                degraded(
                    Operation::Steer,
                    "ACP cancel plus a new prompt; no silent mid-turn rewrite",
                ),
                supported(Operation::FollowUp, "session/prompt"),
                supported(Operation::Resume, "session/load when negotiated"),
            ]),
            AdapterKind::Pi => values.extend([
                supported(Operation::ModelDiscovery, "get_available_models"),
                supported(Operation::Steer, "steer RPC"),
                supported(Operation::FollowUp, "follow_up RPC"),
                supported(Operation::Resume, "--session-id or managed session path"),
            ]),
            AdapterKind::ClaudeCode => values.extend([
                degraded(
                    Operation::ModelDiscovery,
                    "model is selected explicitly; CLI has no bounded list protocol",
                ),
                degraded(
                    Operation::Steer,
                    "stream-json supports input during a live print session only",
                ),
                supported(Operation::FollowUp, "stream-json input or --resume"),
                supported(Operation::Resume, "--resume native session ID"),
            ]),
            AdapterKind::Agy => values.extend([
                degraded(
                    Operation::ModelDiscovery,
                    "no installed/verified model-list protocol",
                ),
                degraded(Operation::Steer, "no verified structured steer operation"),
                degraded(
                    Operation::FollowUp,
                    "new one-shot process only; native resume not verified",
                ),
                degraded(
                    Operation::Resume,
                    "native resume not verified by installed CLI",
                ),
            ]),
        }
        values.sort_by_key(|capability| capability.operation as u8);
        values
    }
}

pub struct AdapterCatalog;

impl AdapterCatalog {
    pub const fn profile(kind: AdapterKind) -> AdapterProfile {
        match kind {
            AdapterKind::Codex => AdapterProfile {
                kind,
                executable: "codex",
                protocol: AdapterProtocol::CodexAppServerV2,
                version_args: &["--version"],
            },
            AdapterKind::ClaudeCode => AdapterProfile {
                kind,
                executable: "claude",
                protocol: AdapterProtocol::ClaudeStreamJson,
                version_args: &["--version"],
            },
            AdapterKind::OpenCode => AdapterProfile {
                kind,
                executable: "opencode",
                protocol: AdapterProtocol::AgentClientProtocolV1,
                version_args: &["--version"],
            },
            AdapterKind::Pi => AdapterProfile {
                kind,
                executable: "pi",
                protocol: AdapterProtocol::PiRpcJsonl,
                version_args: &["--version"],
            },
            AdapterKind::Agy => AdapterProfile {
                kind,
                executable: "agy",
                protocol: AdapterProtocol::AgyStreamJson,
                version_args: &["--version"],
            },
        }
    }

    pub fn discover(kind: AdapterKind) -> AdapterProbe {
        let profile = Self::profile(kind);
        let executable = find_executable(profile.executable);
        let (version, state, reason_code) = match executable.as_ref() {
            Some(path) => match bounded_version(path, profile.version_args) {
                Ok(version) => (Some(version), CapabilityState::Effective, None),
                Err(_) => (
                    None,
                    CapabilityState::Degraded,
                    Some("version_probe_failed".to_owned()),
                ),
            },
            None => (
                None,
                CapabilityState::Unavailable,
                Some("executable_not_found".to_owned()),
            ),
        };
        AdapterProbe {
            adapter: kind,
            executable,
            version,
            protocol: profile.protocol,
            state,
            reason_code,
            authentication: AuthenticationState::Unknown,
            capabilities: profile.capabilities(),
        }
    }

    pub fn discover_all() -> Vec<AdapterProbe> {
        AdapterKind::ALL.into_iter().map(Self::discover).collect()
    }

    pub fn launch(
        kind: AdapterKind,
        request: &LaunchRequest,
    ) -> Result<(LaunchSpec, ProtocolDriver), AdapterError> {
        validate_launch_request(request)?;
        let profile = Self::profile(kind);
        let executable = find_executable(profile.executable)
            .ok_or(AdapterError::ExecutableUnavailable(profile.executable))?;
        let mut driver = ProtocolDriver::new(kind, request)?;
        let args = launch_args(kind, request)?;
        let initial_frames = driver.start()?;
        Ok((
            LaunchSpec {
                executable,
                args,
                cwd: request.cwd.clone(),
                protocol: profile.protocol,
                initial_frames,
            },
            driver,
        ))
    }
}

fn launch_args(kind: AdapterKind, request: &LaunchRequest) -> Result<Vec<String>, AdapterError> {
    let prompt = request.prompt.as_deref();
    let args = match kind {
        AdapterKind::Codex => vec![
            "app-server".to_owned(),
            "--listen".to_owned(),
            "stdio://".to_owned(),
        ],
        AdapterKind::ClaudeCode => {
            let mut args = vec![
                "-p".to_owned(),
                prompt.unwrap_or_default().to_owned(),
                "--input-format".to_owned(),
                "stream-json".to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
                "--verbose".to_owned(),
            ];
            if let Some(session_id) = request.native_session_id.as_deref() {
                args.extend(["--resume".to_owned(), session_id.to_owned()]);
            }
            if let Some(model) = request.model.as_deref() {
                args.extend(["--model".to_owned(), model.to_owned()]);
            }
            if let Some(effort) = request.effort.as_deref() {
                args.extend(["--effort".to_owned(), effort.to_owned()]);
            }
            args
        }
        AdapterKind::OpenCode => vec![
            "acp".to_owned(),
            "--cwd".to_owned(),
            request.cwd.to_string_lossy().into_owned(),
        ],
        AdapterKind::Pi => {
            let mut args = vec!["--mode".to_owned(), "rpc".to_owned()];
            if let Some(session_id) = request.native_session_id.as_deref() {
                args.extend(["--session-id".to_owned(), session_id.to_owned()]);
            }
            if let Some(path) = request.session_data_dir.as_ref() {
                args.extend([
                    "--session-dir".to_owned(),
                    path.to_string_lossy().into_owned(),
                ]);
            }
            if let Some(model) = request.model.as_deref() {
                args.extend(["--model".to_owned(), model.to_owned()]);
            }
            if let Some(effort) = request.effort.as_deref() {
                args.extend(["--thinking".to_owned(), effort.to_owned()]);
            }
            args
        }
        AdapterKind::Agy => {
            if request.native_session_id.is_some() {
                return Err(AdapterError::UnsupportedOperation {
                    adapter: kind,
                    operation: AdapterOperation::Resume,
                    reason: "Agy native resume was not verified",
                });
            }
            vec![
                "--print".to_owned(),
                prompt.unwrap_or_default().to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
            ]
        }
    };
    Ok(args)
}

fn find_executable(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        return executable_file(Path::new(name)).then(|| PathBuf::from(name));
    }
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| executable_file(candidate))
    })
}

fn executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn bounded_version(path: &Path, args: &[&str]) -> Result<String, AdapterError> {
    let output = Command::new(path).args(args).output()?;
    if !output.status.success() {
        return Err(AdapterError::InvalidExecutable);
    }
    let bytes = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    if bytes.len() > MAX_VERSION_OUTPUT_BYTES {
        return Err(AdapterError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_VERSION_OUTPUT_BYTES,
        });
    }
    let version = std::str::from_utf8(bytes).map_err(|_| AdapterError::InvalidExecutable)?;
    let version = bound_utf8(version.trim(), MAX_VERSION_OUTPUT_BYTES);
    if version.is_empty() || version.chars().any(|character| character == '\0') {
        return Err(AdapterError::InvalidExecutable);
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_required_adapter_has_a_structured_profile() {
        for kind in AdapterKind::ALL {
            let profile = AdapterCatalog::profile(kind);
            assert!(!profile.executable.is_empty());
            assert!(profile.capabilities().iter().any(|capability| {
                capability.operation == AdapterOperation::Open
                    && capability.support == SupportLevel::Supported
            }));
        }
    }

    #[test]
    fn agy_does_not_claim_unverified_resume() {
        let capability = AdapterCatalog::profile(AdapterKind::Agy)
            .capabilities()
            .into_iter()
            .find(|value| value.operation == AdapterOperation::Resume)
            .unwrap();
        assert_eq!(capability.support, SupportLevel::Degraded);
    }
}
