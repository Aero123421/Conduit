use std::{
    env, fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use conduit_core::CapabilityState;

use crate::{
    driver::ProtocolDriver,
    types::{
        AdapterCapability, AdapterError, AdapterKind, AdapterOperation, AdapterProbe,
        AdapterProtocol, ApprovalContext, AuthenticationState, LaunchRequest, LaunchSpec,
        MAX_VERSION_OUTPUT_BYTES, SupportLevel, bound_utf8, validate_launch_request,
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
                supported(Operation::ModelDiscovery, "agy models"),
                degraded(
                    Operation::Steer,
                    "official stream-json input accepts complete user turns, not mid-turn rewrites",
                ),
                supported(
                    Operation::FollowUp,
                    "stream-json user event in a new supervised turn",
                ),
                supported(
                    Operation::Resume,
                    "--conversation with the emitted conversation_id",
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
                Ok(version) => (
                    Some(version),
                    CapabilityState::Degraded,
                    Some("version_verified_live_protocol_not_probed".to_owned()),
                ),
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
        Self::launch_with_approval_context(kind, request, ApprovalContext::default())
    }

    pub fn launch_with_approval_context(
        kind: AdapterKind,
        request: &LaunchRequest,
        approval_context: ApprovalContext,
    ) -> Result<(LaunchSpec, ProtocolDriver), AdapterError> {
        validate_launch_request(request)?;
        let profile = Self::profile(kind);
        let executable = find_executable(profile.executable)
            .ok_or(AdapterError::ExecutableUnavailable(profile.executable))?;
        Self::launch_resolved(kind, request, executable, approval_context)
    }

    /// Builds the fixed Device-owned guest image contract without claiming
    /// that a host executable proves guest availability. Provider start/exec
    /// remains the effective per-Runtime probe.
    pub fn launch_in_guest(
        kind: AdapterKind,
        request: &LaunchRequest,
    ) -> Result<(LaunchSpec, ProtocolDriver), AdapterError> {
        Self::launch_in_guest_with_approval_context(kind, request, ApprovalContext::default())
    }

    pub fn launch_in_guest_with_approval_context(
        kind: AdapterKind,
        request: &LaunchRequest,
        approval_context: ApprovalContext,
    ) -> Result<(LaunchSpec, ProtocolDriver), AdapterError> {
        validate_launch_request(request)?;
        let executable = PathBuf::from("/usr/local/bin").join(Self::profile(kind).executable);
        Self::launch_resolved(kind, request, executable, approval_context)
    }

    fn launch_resolved(
        kind: AdapterKind,
        request: &LaunchRequest,
        executable: PathBuf,
        approval_context: ApprovalContext,
    ) -> Result<(LaunchSpec, ProtocolDriver), AdapterError> {
        let profile = Self::profile(kind);
        let mut driver =
            ProtocolDriver::new_with_approval_context(kind, request, approval_context)?;
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
    let args = match kind {
        AdapterKind::Codex => vec![
            "app-server".to_owned(),
            "--listen".to_owned(),
            "stdio://".to_owned(),
        ],
        AdapterKind::ClaudeCode => {
            let mut args = vec![
                "-p".to_owned(),
                "--input-format".to_owned(),
                "stream-json".to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
                "--replay-user-messages".to_owned(),
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
            let mut args = vec![
                "--input-format".to_owned(),
                "stream-json".to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
            ];
            if let Some(session_id) = request.native_session_id.as_deref() {
                args.extend(["--conversation".to_owned(), session_id.to_owned()]);
            }
            if let Some(model) = request.model.as_deref() {
                args.extend(["--model".to_owned(), model.to_owned()]);
            }
            if let Some(effort) = request.effort.as_deref() {
                args.extend(["--effort".to_owned(), effort.to_owned()]);
            }
            args
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
    let mut command = Command::new(path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or(AdapterError::InvalidExecutable)?;
    let stderr = child.stderr.take().ok_or(AdapterError::InvalidExecutable)?;
    let read_bounded = |stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::with_capacity(MAX_VERSION_OUTPUT_BYTES.min(4096));
            stream
                .take((MAX_VERSION_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
    };
    let stdout_reader = read_bounded(Box::new(stdout));
    let stderr_reader = read_bounded(Box::new(stderr));
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(AdapterError::VersionProbeTimeout);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| AdapterError::InvalidExecutable)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| AdapterError::InvalidExecutable)??;
    if !status.success() {
        return Err(AdapterError::InvalidExecutable);
    }
    let bytes = if stdout.is_empty() { &stderr } else { &stdout };
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

fn terminate_process_group(child: &mut std::process::Child) {
    let process_group = -(child.id() as i32);
    // SAFETY: the child was created as the leader of its own process group.
    unsafe {
        libc::kill(process_group, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_required_adapter_has_a_structured_profile() {
        for kind in AdapterKind::ALL {
            let profile = AdapterCatalog::profile(kind);
            assert!(!profile.executable.is_empty());
            let open = profile
                .capabilities()
                .into_iter()
                .find(|capability| capability.operation == AdapterOperation::Open)
                .unwrap();
            assert_eq!(open.support, SupportLevel::Supported);
        }
    }

    #[test]
    fn agy_uses_the_official_stream_json_contract() {
        let capability = AdapterCatalog::profile(AdapterKind::Agy)
            .capabilities()
            .into_iter()
            .find(|value| value.operation == AdapterOperation::Resume)
            .unwrap();
        assert_eq!(capability.support, SupportLevel::Supported);
    }

    #[test]
    fn claude_prompt_is_never_exposed_in_process_arguments() {
        let request = LaunchRequest {
            cwd: PathBuf::from("/tmp"),
            prompt: Some("private prompt".to_owned()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: None,
        };
        let args = launch_args(AdapterKind::ClaudeCode, &request).unwrap();
        assert!(!args.iter().any(|argument| argument == "private prompt"));
        let mut driver = ProtocolDriver::new(AdapterKind::ClaudeCode, &request).unwrap();
        let frames = driver.start().unwrap();
        assert_eq!(frames.len(), 1);
        assert!(String::from_utf8_lossy(&frames[0].0).contains("private prompt"));
    }

    #[test]
    fn agy_prompt_is_sent_over_the_official_stream_json_input() {
        let request = LaunchRequest {
            cwd: PathBuf::from("/tmp"),
            prompt: Some("hello".to_owned()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: None,
        };
        let args = launch_args(AdapterKind::Agy, &request).unwrap();
        assert!(!args.iter().any(|argument| argument == "hello"));
        assert_eq!(
            args,
            [
                "--input-format",
                "stream-json",
                "--output-format",
                "stream-json"
            ]
        );
        let mut driver = ProtocolDriver::new(AdapterKind::Agy, &request).unwrap();
        let frames = driver.start().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&frames[0].0).unwrap(),
            serde_json::json!({"event":"user","message":{"content":"hello"}})
        );
    }

    #[test]
    fn guest_launch_uses_the_fixed_image_contract_without_host_discovery() {
        let request = LaunchRequest {
            cwd: PathBuf::from("/workspace"),
            prompt: Some("review".to_owned()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: None,
        };
        let (spec, _) = AdapterCatalog::launch_in_guest(AdapterKind::Agy, &request).unwrap();
        assert_eq!(spec.executable, PathBuf::from("/usr/local/bin/agy"));
        assert_eq!(spec.cwd, PathBuf::from("/workspace"));
    }
}
