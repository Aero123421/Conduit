//! Process-independent Linux configuration, capability, and public-error contracts.

use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FEATURE_REGISTRY_VERSION: u16 = 1;
pub const CONFIG_SCHEMA_VERSION: u16 = 1;

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
}
