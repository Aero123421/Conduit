use std::{fmt, str::FromStr};

use conduit_domain::OperationId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use thiserror::Error;

macro_rules! protocol_error_codes {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        /// A validated, forward-compatible protocol error code not known by this build.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct ProtocolErrorExtension(String);

        impl ProtocolErrorExtension {
            pub fn parse(value: impl Into<String>) -> Result<Self, ErrorCodeParseError> {
                let value = value.into();
                validate_code_syntax(&value)?;
                match value.as_str() {
                    $($wire => Err(ErrorCodeParseError::KnownCode),)+
                    _ => Ok(Self(value)),
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for ProtocolErrorExtension {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for ProtocolErrorExtension {
            type Err = ErrorCodeParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for ProtocolErrorExtension {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for ProtocolErrorExtension {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(de::Error::custom)
            }
        }

        /// A stable public error code.
        ///
        /// Codes documented by the authorization, node transport, Runtime, and
        /// session-baseline/Change Set contracts have dedicated variants. A
        /// syntactically valid future code is retained as `Extension`, so an older
        /// peer can relay it without changing or discarding it.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ProtocolErrorCode {
            $($variant,)+
            Extension(ProtocolErrorExtension),
        }

        impl ProtocolErrorCode {
            pub fn parse(value: impl Into<String>) -> Result<Self, ErrorCodeParseError> {
                let value = value.into();
                validate_code_syntax(&value)?;
                Ok(match value.as_str() {
                    $($wire => Self::$variant,)+
                    _ => Self::Extension(ProtocolErrorExtension(value)),
                })
            }

            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Extension(value) => value.as_str(),
                }
            }

            pub const fn is_known(&self) -> bool {
                !matches!(self, Self::Extension(_))
            }
        }
    };
}

protocol_error_codes! {
    AuthenticationRequired => "authentication_required",
    FreshAuthenticationRequired => "fresh_authentication_required",
    CsrfFailed => "csrf_failed",
    ClientNotRegistered => "client_not_registered",
    ClientMetadataChanged => "client_metadata_changed",
    GrantRequired => "grant_required",
    GrantPaused => "grant_paused",
    GrantRevoked => "grant_revoked",
    GrantReauthorizationRequired => "grant_reauthorization_required",
    ScopeInsufficient => "scope_insufficient",
    ConnectorCeilingExceeded => "connector_ceiling_exceeded",
    ProjectNotAllowed => "project_not_allowed",
    DeviceNotAllowed => "device_not_allowed",
    DeviceOffline => "device_offline",
    DeviceNotEnrolled => "device_not_enrolled",
    DeviceRevoked => "device_revoked",
    DeviceKeyInvalid => "device_key_invalid",
    RuntimeNotAllowed => "runtime_not_allowed",
    OperationNotAllowed => "operation_not_allowed",
    ApprovalRequired => "approval_required",
    ApprovalExpired => "approval_expired",
    ApprovalDigestMismatch => "approval_digest_mismatch",
    RateLimited => "rate_limited",
    ResourceLimit => "resource_limit",
    PlatformCapabilityUnavailable => "platform_capability_unavailable",
    ProtocolVersionUnsupported => "protocol_version_unsupported",
    ConnectionEpochStale => "connection_epoch_stale",
    ConnectionFenced => "connection_fenced",
    FrameTooLarge => "frame_too_large",
    FrameMalformed => "frame_malformed",
    PayloadDigestMismatch => "payload_digest_mismatch",
    SequenceConflict => "sequence_conflict",
    SequenceGap => "sequence_gap",
    ReplayRangeUnavailable => "replay_range_unavailable",
    OperationExpired => "operation_expired",
    OperationNotAuthorized => "operation_not_authorized",
    OperationRejectedLocalPolicy => "operation_rejected_local_policy",
    IdempotencyConflict => "idempotency_conflict",
    RuntimeIdentityMismatch => "runtime_identity_mismatch",
    JournalUnavailable => "journal_unavailable",
    JournalCorrupt => "journal_corrupt",
    StorageExhausted => "storage_exhausted",
    ObservabilityIncomplete => "observability_incomplete",
    ReconciliationRequired => "reconciliation_required",
    IngestionBackpressure => "ingestion_backpressure",
    ProviderUnavailable => "provider_unavailable",
    ProviderVersionUnsupported => "provider_version_unsupported",
    ProviderCapabilityMissing => "provider_capability_missing",
    RuntimeObjectExternal => "runtime_object_external",
    RuntimeStateConflict => "runtime_state_conflict",
    RuntimeLost => "runtime_lost",
    RuntimeUncertain => "runtime_uncertain",
    RuntimeRecoveryRequired => "runtime_recovery_required",
    WorkspaceAttachmentFailed => "workspace_attachment_failed",
    WorkspaceModeUnsupported => "workspace_mode_unsupported",
    CredentialProjectionFailed => "credential_projection_failed",
    CredentialProjectionNotAllowed => "credential_projection_not_allowed",
    NetworkModeUnsupported => "network_mode_unsupported",
    ResourceLimitUnsupported => "resource_limit_unsupported",
    ResourceExhausted => "resource_exhausted",
    HotStorageInsufficient => "hot_storage_insufficient",
    ArchiveStorageUnavailable => "archive_storage_unavailable",
    LaunchPlanMismatch => "launch_plan_mismatch",
    ProcessIdentityMismatch => "process_identity_mismatch",
    GuestAgentUnavailable => "guest_agent_unavailable",
    GuestExecUnavailable => "guest_exec_unavailable",
    PauseUnsupported => "pause_unsupported",
    SnapshotUnsupported => "snapshot_unsupported",
    CollectionRequired => "collection_required",
    DestroyBlocked => "destroy_blocked",
    PrivilegedHelperUnavailable => "privileged_helper_unavailable",
    FullDeviceCapabilityUnavailable => "full_device_capability_unavailable",
    PrivilegedHelperNotInstalled => "privileged_helper_not_installed",
    PrivilegedHelperDisabled => "privileged_helper_disabled",
    PrivilegedHelperRegistrationMissing => "privileged_helper_registration_missing",
    PrivilegedHelperPolicyMismatch => "privileged_helper_policy_mismatch",
    PrivilegedHelperProtocolUnsupported => "privileged_helper_protocol_unsupported",
    PrivilegeTicketRequired => "privilege_ticket_required",
    PrivilegeTicketInvalid => "privilege_ticket_invalid",
    PrivilegeTicketExpired => "privilege_ticket_expired",
    PrivilegeTicketReplayed => "privilege_ticket_replayed",
    PrivilegeTicketConflict => "privilege_ticket_conflict",
    FullDeviceNeverLocalOptInRequired => "full_device_never_local_opt_in_required",
    FullDeviceApprovalEnforcementUnavailable => "full_device_approval_enforcement_unavailable",
    PrivilegedRuntimeRecoveryRequired => "privileged_runtime_recovery_required",
    PrivilegedOperationNotAllowed => "privileged_operation_not_allowed",
    RepositoryIdentityMismatch => "repository_identity_mismatch",
    RepositoryObjectMissing => "repository_object_missing",
    RepositoryShallowBoundary => "repository_shallow_boundary",
    RepositoryPartialObjectMissing => "repository_partial_object_missing",
    WorktreeBranchInUse => "worktree_branch_in_use",
    WorktreePathConflict => "worktree_path_conflict",
    WorktreeAdminStale => "worktree_admin_stale",
    WorktreeMissing => "worktree_missing",
    WorkspaceDirty => "workspace_dirty",
    WorkspaceDiverged => "workspace_diverged",
    WorkspaceConflicted => "workspace_conflicted",
    WorkspaceReadOnlyUnavailable => "workspace_read_only_unavailable",
    SourceLocationStale => "source_location_stale",
    SubmoduleObjectMissing => "submodule_object_missing",
    LfsObjectMissing => "lfs_object_missing",
    ChangeSetDraft => "changeset_draft",
    ChangeSetStale => "changeset_stale",
    ChangeSetConflicted => "changeset_conflicted",
    ChangeSetDigestMismatch => "changeset_digest_mismatch",
    ReviewStale => "review_stale",
    VerificationRequired => "verification_required",
    CustodyInsufficient => "custody_insufficient",
    BaselineRevisionConflict => "baseline_revision_conflict",
    AcceptancePrepareFailed => "acceptance_prepare_failed",
    AcceptanceFinalizePending => "acceptance_finalize_pending",
    ApplicationTargetChanged => "application_target_changed",
    PushRemoteChanged => "push_remote_changed",
    CleanupBlocked => "cleanup_blocked",
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ErrorCodeParseError {
    #[error("protocol error code must contain 1 to 128 ASCII bytes")]
    InvalidLength,
    #[error("protocol error code must match ^[a-z][a-z0-9_.-]*$")]
    InvalidCharacters,
    #[error("known protocol error code cannot be constructed as an extension")]
    KnownCode,
}

fn validate_code_syntax(value: &str) -> Result<(), ErrorCodeParseError> {
    if value.is_empty() || value.len() > ErrorEnvelope::MAX_CODE_BYTES {
        return Err(ErrorCodeParseError::InvalidLength);
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(ErrorCodeParseError::InvalidCharacters);
    }
    Ok(())
}

impl fmt::Display for ProtocolErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProtocolErrorCode {
    type Err = ErrorCodeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for ProtocolErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorDetailValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetail {
    pub key: String,
    pub value: ErrorDetailValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub code: ProtocolErrorCode,
    pub message: String,
    pub retryable: bool,
    pub operation_id: Option<OperationId>,
    pub details: Vec<ErrorDetail>,
}

impl Serialize for ErrorEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate_bounds().map_err(ser::Error::custom)?;

        #[derive(Serialize)]
        struct WireEnvelope<'a> {
            code: &'a ProtocolErrorCode,
            message: &'a str,
            retryable: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            operation_id: Option<&'a OperationId>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            details: &'a Vec<ErrorDetail>,
        }

        WireEnvelope {
            code: &self.code,
            message: &self.message,
            retryable: self.retryable,
            operation_id: self.operation_id.as_ref(),
            details: &self.details,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ErrorEnvelopeBoundsError {
    #[error("error message exceeds 2048 UTF-8 bytes")]
    Message,
    #[error("error envelope exceeds 32 details")]
    Details,
    #[error("error detail key must contain 1 to 128 UTF-8 bytes")]
    DetailKey,
    #[error("string error detail exceeds 2048 UTF-8 bytes")]
    DetailString,
}

impl ErrorEnvelope {
    pub const MAX_CODE_BYTES: usize = 128;
    pub const MAX_MESSAGE_BYTES: usize = 2048;
    pub const MAX_DETAILS: usize = 32;
    pub const MAX_DETAIL_KEY_BYTES: usize = 128;
    pub const MAX_DETAIL_STRING_BYTES: usize = 2048;

    pub fn validate_bounds(&self) -> Result<(), ErrorEnvelopeBoundsError> {
        if self.message.len() > Self::MAX_MESSAGE_BYTES {
            return Err(ErrorEnvelopeBoundsError::Message);
        }
        if self.details.len() > Self::MAX_DETAILS {
            return Err(ErrorEnvelopeBoundsError::Details);
        }
        for detail in &self.details {
            if detail.key.is_empty() || detail.key.len() > Self::MAX_DETAIL_KEY_BYTES {
                return Err(ErrorEnvelopeBoundsError::DetailKey);
            }
            if let ErrorDetailValue::String(value) = &detail.value
                && value.len() > Self::MAX_DETAIL_STRING_BYTES
            {
                return Err(ErrorEnvelopeBoundsError::DetailString);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ErrorEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireEnvelope {
            code: ProtocolErrorCode,
            message: String,
            retryable: bool,
            operation_id: Option<OperationId>,
            #[serde(default)]
            details: Vec<ErrorDetail>,
        }

        let wire = WireEnvelope::deserialize(deserializer)?;
        let envelope = Self {
            code: wire.code,
            message: wire.message,
            retryable: wire.retryable,
            operation_id: wire.operation_id,
            details: wire.details,
        };
        envelope.validate_bounds().map_err(de::Error::custom)?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_have_stable_serde_text() {
        let code = ProtocolErrorCode::RuntimeIdentityMismatch;
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            r#""runtime_identity_mismatch""#
        );
        assert_eq!(
            serde_json::from_str::<ProtocolErrorCode>(r#""runtime_identity_mismatch""#).unwrap(),
            code
        );
        assert!(code.is_known());
    }

    #[test]
    fn preserves_valid_future_codes() {
        let code: ProtocolErrorCode = serde_json::from_str(r#""future.vendor_error""#).unwrap();
        assert_eq!(code.as_str(), "future.vendor_error");
        assert!(!code.is_known());
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            r#""future.vendor_error""#
        );
        let ProtocolErrorCode::Extension(extension) = code else {
            panic!("future code was not retained as an extension");
        };
        assert_eq!(extension.as_str(), "future.vendor_error");
    }

    #[test]
    fn rejects_codes_outside_wire_syntax() {
        assert!(ProtocolErrorCode::parse("").is_err());
        assert!(ProtocolErrorCode::parse("UPPER_CASE").is_err());
        assert!(ProtocolErrorCode::parse("x".repeat(129)).is_err());
        assert!(ProtocolErrorExtension::parse("UPPER_CASE").is_err());
        assert_eq!(
            ProtocolErrorExtension::parse("frame_malformed").unwrap_err(),
            ErrorCodeParseError::KnownCode
        );
    }

    #[test]
    fn rejects_unbounded_envelopes_during_deserialization() {
        let json = serde_json::json!({
            "code": "frame_malformed",
            "message": "x".repeat(ErrorEnvelope::MAX_MESSAGE_BYTES + 1),
            "retryable": false
        });
        assert!(serde_json::from_value::<ErrorEnvelope>(json).is_err());
    }

    #[test]
    fn rejects_unbounded_envelopes_during_serialization() {
        let envelope = |message: String, details: Vec<ErrorDetail>| ErrorEnvelope {
            code: ProtocolErrorCode::FrameMalformed,
            message,
            retryable: false,
            operation_id: None,
            details,
        };

        assert!(
            serde_json::to_value(envelope(
                "x".repeat(ErrorEnvelope::MAX_MESSAGE_BYTES + 1),
                Vec::new(),
            ))
            .is_err()
        );
        assert!(
            serde_json::to_value(envelope(
                String::new(),
                (0..=ErrorEnvelope::MAX_DETAILS)
                    .map(|index| ErrorDetail {
                        key: format!("key_{index}"),
                        value: ErrorDetailValue::Boolean(false),
                    })
                    .collect(),
            ))
            .is_err()
        );
        assert!(
            serde_json::to_value(envelope(
                String::new(),
                vec![ErrorDetail {
                    key: "detail".to_owned(),
                    value: ErrorDetailValue::String(
                        "x".repeat(ErrorEnvelope::MAX_DETAIL_STRING_BYTES + 1),
                    ),
                }],
            ))
            .is_err()
        );
    }
}
