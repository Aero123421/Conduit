//! Process-independent Linux configuration, capability, and public-error contracts.

use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FEATURE_REGISTRY_VERSION: u16 = 1;
pub const CONFIG_SCHEMA_VERSION: u16 = 1;
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductFeature {
    ControlPlane,
    NodeTransport,
    NativeRuntime,
    RestrictedNativeRuntime,
    ContainerRuntime,
    IncusVmRuntime,
    WorkspaceChangeSet,
    AgentAdapters,
    CollaborationContext,
    McpGateway,
    ObservabilityEvaluation,
    CliOperations,
}

pub const PRODUCT_FEATURES_V1: [ProductFeature; 12] = [
    ProductFeature::ControlPlane,
    ProductFeature::NodeTransport,
    ProductFeature::NativeRuntime,
    ProductFeature::RestrictedNativeRuntime,
    ProductFeature::ContainerRuntime,
    ProductFeature::IncusVmRuntime,
    ProductFeature::WorkspaceChangeSet,
    ProductFeature::AgentAdapters,
    ProductFeature::CollaborationContext,
    ProductFeature::McpGateway,
    ProductFeature::ObservabilityEvaluation,
    ProductFeature::CliOperations,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDefaultDecision {
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub display_name: String,
    pub frame_max_bytes: usize,
    pub reconnect_min_ms: u64,
    pub reconnect_max_ms: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            display_name: "linux-device".to_owned(),
            frame_max_bytes: 65_536,
            reconnect_min_ms: 500,
            reconnect_max_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalPolicyConfig {
    pub default: LocalDefaultDecision,
}

impl Default for LocalPolicyConfig {
    fn default() -> Self {
        Self {
            default: LocalDefaultDecision::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u16,
    pub control_plane_url: String,
    pub log_level: LogLevel,
    pub node: NodeConfig,
    pub local_policy: LocalPolicyConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            control_plane_url: "http://127.0.0.1:8787".to_owned(),
            log_level: LogLevel::Info,
            node: NodeConfig::default(),
            local_policy: LocalPolicyConfig::default(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("configuration is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("configuration is not valid TOML: {0}")]
    InvalidToml(String),
    #[error("unsupported configuration schema version {0}")]
    UnsupportedVersion(u16),
    #[error("control_plane_url must be HTTPS, or HTTP on loopback for development")]
    InsecureControlPlane,
    #[error("node display_name must be 1 to 128 visible bytes")]
    InvalidDisplayName,
    #[error("node frame_max_bytes must be between 4,096 and 65,536")]
    InvalidFrameLimit,
    #[error("node reconnect bounds are invalid")]
    InvalidReconnectBounds,
}

impl AppConfig {
    pub fn from_toml(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                actual: bytes.len(),
                maximum: MAX_CONFIG_BYTES,
            });
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|error| ConfigError::InvalidToml(error.to_string()))?;
        let config: Self =
            toml::from_str(text).map_err(|error| ConfigError::InvalidToml(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.schema_version));
        }
        if !valid_control_plane_url(&self.control_plane_url) {
            return Err(ConfigError::InsecureControlPlane);
        }
        if self.node.display_name.is_empty()
            || self.node.display_name.len() > 128
            || self.node.display_name.chars().any(char::is_control)
        {
            return Err(ConfigError::InvalidDisplayName);
        }
        if !(4_096..=65_536).contains(&self.node.frame_max_bytes) {
            return Err(ConfigError::InvalidFrameLimit);
        }
        if self.node.reconnect_min_ms == 0
            || self.node.reconnect_max_ms < self.node.reconnect_min_ms
            || self.node.reconnect_max_ms > 300_000
        {
            return Err(ConfigError::InvalidReconnectBounds);
        }
        Ok(())
    }
}

fn valid_control_plane_url(value: &str) -> bool {
    if value.starts_with("https://") {
        return value.len() > "https://".len()
            && !value.contains('@')
            && !value.chars().any(char::is_control);
    }
    ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|origin| value == *origin || value.starts_with(&format!("{origin}:")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Effective,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityEvidence {
    pub capability: String,
    pub state: CapabilityState,
    pub mechanism: Option<String>,
    pub reason_code: Option<String>,
}

impl CapabilityEvidence {
    pub fn effective(capability: impl Into<String>, mechanism: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            state: CapabilityState::Effective,
            mechanism: Some(mechanism.into()),
            reason_code: None,
        }
    }

    pub fn unavailable(capability: impl Into<String>, reason_code: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            state: CapabilityState::Unavailable,
            mechanism: None,
            reason_code: Some(reason_code.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RevisionMismatch,
    RateLimited,
    ResourceExhausted,
    PrerequisiteUnavailable,
    RecoveryRequired,
    Uncertain,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code:?}: {message}")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicError {
    pub code: PublicErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl PublicError {
    pub const MAX_MESSAGE_BYTES: usize = 512;

    pub fn new(code: PublicErrorCode, message: impl AsRef<str>, retryable: bool) -> Self {
        Self {
            code,
            message: bound_utf8(message.as_ref(), Self::MAX_MESSAGE_BYTES),
            retryable,
        }
    }

    pub const fn http_status(&self) -> u16 {
        match self.code {
            PublicErrorCode::InvalidArgument => 400,
            PublicErrorCode::Unauthenticated => 401,
            PublicErrorCode::PermissionDenied => 403,
            PublicErrorCode::NotFound => 404,
            PublicErrorCode::Conflict | PublicErrorCode::RevisionMismatch => 409,
            PublicErrorCode::RateLimited => 429,
            PublicErrorCode::ResourceExhausted => 507,
            PublicErrorCode::PrerequisiteUnavailable => 503,
            PublicErrorCode::RecoveryRequired | PublicErrorCode::Uncertain => 409,
            PublicErrorCode::Internal => 500,
        }
    }

    pub const fn mcp_code(&self) -> i32 {
        match self.code {
            PublicErrorCode::InvalidArgument => -32_602,
            PublicErrorCode::NotFound => -32_601,
            PublicErrorCode::Internal => -32_603,
            _ => -32_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdgPaths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub runtime: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathConfigError {
    #[error("HOME is required when an XDG base directory is unset")]
    MissingHome,
    #[error("XDG_RUNTIME_DIR is required for authenticated local IPC")]
    MissingRuntimeDirectory,
    #[error("{variable} must be an absolute path")]
    RelativePath { variable: &'static str },
}

impl XdgPaths {
    pub fn from_environment() -> Result<Self, PathConfigError> {
        let home = env::var_os("HOME").map(PathBuf::from);
        let config = xdg_or_home("XDG_CONFIG_HOME", home.as_ref(), ".config")?.join("conduit");
        let data = xdg_or_home("XDG_DATA_HOME", home.as_ref(), ".local/share")?.join("conduit");
        let state = xdg_or_home("XDG_STATE_HOME", home.as_ref(), ".local/state")?.join("conduit");
        let cache = xdg_or_home("XDG_CACHE_HOME", home.as_ref(), ".cache")?.join("conduit");
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or(PathConfigError::MissingRuntimeDirectory)?;
        require_absolute("XDG_RUNTIME_DIR", &runtime)?;
        Ok(Self {
            config,
            data,
            state,
            cache,
            runtime: runtime.join("conduit"),
        })
    }
}

fn xdg_or_home(
    variable: &'static str,
    home: Option<&PathBuf>,
    fallback: &str,
) -> Result<PathBuf, PathConfigError> {
    let path = env::var_os(variable).map(PathBuf::from).map_or_else(
        || {
            home.map(|path| path.join(fallback))
                .ok_or(PathConfigError::MissingHome)
        },
        Ok,
    )?;
    require_absolute(variable, &path)?;
    Ok(path)
}

fn require_absolute(variable: &'static str, path: &Path) -> Result<(), PathConfigError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(PathConfigError::RelativePath { variable })
    }
}

fn bound_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_errors_map_without_exposing_unbounded_text() {
        let error = PublicError::new(PublicErrorCode::RateLimited, "x".repeat(700), true);
        assert_eq!(error.http_status(), 429);
        assert_eq!(error.mcp_code(), -32_000);
        assert_eq!(error.message.len(), PublicError::MAX_MESSAGE_BYTES);
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains(&"x".repeat(513))
        );
    }

    #[test]
    fn capability_receipts_never_imply_effective_without_a_mechanism() {
        let receipt = CapabilityEvidence::unavailable("runtime.vm", "incus_not_installed");
        assert_eq!(receipt.state, CapabilityState::Unavailable);
        assert!(receipt.mechanism.is_none());
        assert_eq!(receipt.reason_code.as_deref(), Some("incus_not_installed"));
    }

    #[test]
    fn xdg_paths_reject_relative_overrides() {
        assert_eq!(
            require_absolute("XDG_STATE_HOME", &PathBuf::from("relative")),
            Err(PathConfigError::RelativePath {
                variable: "XDG_STATE_HOME"
            })
        );
    }

    #[test]
    fn config_defaults_are_explicit_and_fail_closed() {
        let config = AppConfig::from_toml(b"").unwrap();
        assert_eq!(config.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(config.node.frame_max_bytes, 65_536);
        assert_eq!(config.local_policy.default, LocalDefaultDecision::Deny);
    }

    #[test]
    fn config_rejects_unknown_fields_and_insecure_remote_origins() {
        assert!(matches!(
            AppConfig::from_toml(b"unknown = true"),
            Err(ConfigError::InvalidToml(_))
        ));
        assert_eq!(
            AppConfig::from_toml(b"control_plane_url = 'http://example.com'"),
            Err(ConfigError::InsecureControlPlane)
        );
    }

    #[test]
    fn feature_registry_is_versioned_and_unique() {
        assert_eq!(FEATURE_REGISTRY_VERSION, 1);
        let mut names = PRODUCT_FEATURES_V1
            .iter()
            .map(|feature| format!("{feature:?}"))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), PRODUCT_FEATURES_V1.len());
    }
}
