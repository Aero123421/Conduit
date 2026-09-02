use std::path::PathBuf;

use conduit_core::CapabilityState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const MAX_PROTOCOL_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;
pub const MAX_EVENT_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_VERSION_OUTPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Codex,
    ClaudeCode,
    OpenCode,
    Pi,
    Agy,
}

impl AdapterKind {
    pub const ALL: [Self; 5] = [
        Self::Codex,
        Self::ClaudeCode,
        Self::OpenCode,
        Self::Pi,
        Self::Agy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
            Self::OpenCode => "opencode",
            Self::Pi => "pi",
            Self::Agy => "agy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterProtocol {
    CodexAppServerV2,
    ClaudeStreamJson,
    AgentClientProtocolV1,
    PiRpcJsonl,
    AgyStreamJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveApprovalPolicy {
    Always,
    OutsideScope,
    RiskClasses,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApprovalRiskClassSet(u16);

impl ApprovalRiskClassSet {
    pub const EMPTY: Self = Self(0);
    pub const EXTERNAL_PUBLISH: Self = Self(1 << 0);
    pub const SECRET_ACCESS: Self = Self(1 << 1);
    pub const DESTRUCTIVE_DELETE: Self = Self(1 << 2);
    pub const ELEVATION: Self = Self(1 << 3);
    pub const PRODUCTION_DEPLOY: Self = Self(1 << 4);
    pub const DEVICE_ADMIN: Self = Self(1 << 5);
    pub const RAW_LOG_EXPORT: Self = Self(1 << 6);
    pub const LAN_ACCESS: Self = Self(1 << 7);
    pub const CREDENTIAL_EXPORT: Self = Self(1 << 8);
    pub const RUNTIME_MANAGEMENT: Self = Self(1 << 9);
    pub const ALL: Self = Self((1 << 10) - 1);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "external_publish" => Some(Self::EXTERNAL_PUBLISH),
            "secret_access" => Some(Self::SECRET_ACCESS),
            "destructive_delete" => Some(Self::DESTRUCTIVE_DELETE),
            "elevation" => Some(Self::ELEVATION),
            "production_deploy" => Some(Self::PRODUCTION_DEPLOY),
            "device_admin" => Some(Self::DEVICE_ADMIN),
            "raw_log_export" => Some(Self::RAW_LOG_EXPORT),
            "lan_access" => Some(Self::LAN_ACCESS),
            "credential_export" => Some(Self::CREDENTIAL_EXPORT),
            "runtime_management" => Some(Self::RUNTIME_MANAGEMENT),
            _ => None,
        }
    }
}

impl Default for ApprovalRiskClassSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveAccessScope {
    ReadOnly,
    SelectedSources,
    ProjectFull,
    FullUser,
    FullDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveSandboxPolicy {
    ReadOnly,
    External,
    WorkspaceWrite,
    DangerFullAccess,
}

impl TryFrom<&str> for EffectiveAccessScope {
    type Error = AdapterError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "read_only" => Ok(Self::ReadOnly),
            "selected_sources" => Ok(Self::SelectedSources),
            "project_full" | "full_project" => Ok(Self::ProjectFull),
            "full_user" => Ok(Self::FullUser),
            "full_device" => Ok(Self::FullDevice),
            _ => Err(AdapterError::InvalidAccessScope),
        }
    }
}

impl TryFrom<&str> for EffectiveApprovalPolicy {
    type Error = AdapterError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "always" => Ok(Self::Always),
            "outside_scope" => Ok(Self::OutsideScope),
            "risk_based" | "risk_classes" => Ok(Self::RiskClasses),
            "never" => Ok(Self::Never),
            _ => Err(AdapterError::InvalidApprovalPolicy),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalBridgeOwnership {
    Unavailable,
    Typed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalContext {
    pub effective_policy: EffectiveApprovalPolicy,
    pub bridge: ApprovalBridgeOwnership,
    #[serde(default)]
    pub required_risk_classes: ApprovalRiskClassSet,
}

impl Default for ApprovalContext {
    fn default() -> Self {
        Self {
            effective_policy: EffectiveApprovalPolicy::Always,
            bridge: ApprovalBridgeOwnership::Unavailable,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    Supported,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOperation {
    Discover,
    Probe,
    Capability,
    AuthenticationStatus,
    ModelDiscovery,
    Open,
    Send,
    Steer,
    FollowUp,
    Resume,
    Cancel,
    State,
    Replay,
    Close,
}

impl AdapterOperation {
    pub const ALL: [Self; 14] = [
        Self::Discover,
        Self::Probe,
        Self::Capability,
        Self::AuthenticationStatus,
        Self::ModelDiscovery,
        Self::Open,
        Self::Send,
        Self::Steer,
        Self::FollowUp,
        Self::Resume,
        Self::Cancel,
        Self::State,
        Self::Replay,
        Self::Close,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterCapability {
    pub operation: AdapterOperation,
    pub support: SupportLevel,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    Ready,
    LoginRequired,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProbe {
    pub adapter: AdapterKind,
    pub executable: Option<PathBuf>,
    pub version: Option<String>,
    pub protocol: AdapterProtocol,
    pub state: CapabilityState,
    pub reason_code: Option<String>,
    pub authentication: AuthenticationState,
    pub capabilities: Vec<AdapterCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub cwd: PathBuf,
    pub prompt: Option<String>,
    pub native_session_id: Option<String>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub session_data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub protocol: AdapterProtocol,
    pub initial_frames: Vec<ProtocolFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrame(pub Vec<u8>);

impl ProtocolFrame {
    pub fn json(value: &Value) -> Result<Self, AdapterError> {
        let mut encoded = serde_json::to_vec(value)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_PROTOCOL_FRAME_BYTES {
            return Err(AdapterError::FrameTooLarge {
                actual: encoded.len(),
                maximum: MAX_PROTOCOL_FRAME_BYTES,
            });
        }
        Ok(Self(encoded))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterState {
    Starting,
    Ready,
    Working,
    WaitingApproval,
    Completed,
    Cancelled,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterEventKind {
    PromptAccepted,
    Session,
    State,
    AssistantMessage,
    AssistantMessageDelta,
    ToolCall,
    ToolResult,
    Command,
    FileEffect,
    ApprovalRequest,
    Usage,
    Subagent,
    Completed,
    Error,
    AdapterError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterEvent {
    pub kind: AdapterEventKind,
    pub vendor_type: String,
    pub native_session_id: Option<String>,
    pub correlation_id: Option<String>,
    pub text: Option<String>,
    pub data: Option<Value>,
}

impl AdapterEvent {
    pub(crate) fn bounded(
        kind: AdapterEventKind,
        vendor_type: &str,
        native_session_id: Option<&str>,
        correlation_id: Option<&str>,
        text: Option<&str>,
        data: Option<Value>,
    ) -> Self {
        Self {
            kind,
            vendor_type: bound_utf8(vendor_type, 128),
            native_session_id: native_session_id.map(|value| bound_utf8(value, 512)),
            correlation_id: correlation_id.map(|value| bound_utf8(value, 512)),
            text: text.map(|value| bound_utf8(value, MAX_EVENT_TEXT_BYTES)),
            data,
        }
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("adapter executable is unavailable: {0}")]
    ExecutableUnavailable(&'static str),
    #[error("adapter path is not an executable file")]
    InvalidExecutable,
    #[error("adapter version probe exceeded its 3 second deadline")]
    VersionProbeTimeout,
    #[error("working directory must be absolute")]
    RelativeWorkingDirectory,
    #[error("effective access scope is invalid")]
    InvalidAccessScope,
    #[error("session data directory must be absolute")]
    RelativeSessionDirectory,
    #[error("prompt exceeds the {maximum} byte adapter limit")]
    PromptTooLarge { maximum: usize },
    #[error("adapter input contains a NUL byte")]
    NulInput,
    #[error("invalid native session identifier")]
    InvalidNativeSessionId,
    #[error("invalid effective approval policy")]
    InvalidApprovalPolicy,
    #[error("protocol frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("protocol frame is not LF-terminated UTF-8 JSON")]
    InvalidFrame,
    #[error("unexpected protocol response in phase {phase}: {reason}")]
    UnexpectedResponse {
        phase: &'static str,
        reason: &'static str,
    },
    #[error("operation {operation:?} is unavailable for {adapter:?}: {reason}")]
    UnsupportedOperation {
        adapter: AdapterKind,
        operation: AdapterOperation,
        reason: &'static str,
    },
    #[error("adapter process failed: {0}")]
    Process(#[from] std::io::Error),
    #[error("adapter protocol JSON failed validation: {0}")]
    Json(#[from] serde_json::Error),
}

pub(crate) fn validate_launch_request(request: &LaunchRequest) -> Result<(), AdapterError> {
    if !request.cwd.is_absolute() {
        return Err(AdapterError::RelativeWorkingDirectory);
    }
    if request
        .session_data_dir
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err(AdapterError::RelativeSessionDirectory);
    }
    if request
        .prompt
        .as_ref()
        .is_some_and(|value| value.as_bytes().contains(&0) || value.len() > MAX_PROMPT_BYTES)
    {
        return if request
            .prompt
            .as_ref()
            .is_some_and(|value| value.as_bytes().contains(&0))
        {
            Err(AdapterError::NulInput)
        } else {
            Err(AdapterError::PromptTooLarge {
                maximum: MAX_PROMPT_BYTES,
            })
        };
    }
    if request.native_session_id.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_control)
            || value.contains('/')
            || value.contains('\\')
    }) {
        return Err(AdapterError::InvalidNativeSessionId);
    }
    Ok(())
}

pub(crate) fn bound_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
