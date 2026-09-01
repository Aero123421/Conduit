//! Shared Conduit domain primitives.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainValueError {
    #[error("{kind} must start with {prefix}")]
    WrongPrefix {
        kind: &'static str,
        prefix: &'static str,
    },
    #[error("{kind} suffix must contain 8 to 128 ASCII characters")]
    InvalidLength { kind: &'static str },
    #[error("{kind} suffix contains unsupported characters")]
    InvalidCharacters { kind: &'static str },
    #[error("u64 decimal must use canonical unsigned decimal text")]
    InvalidU64Decimal,
    #[error("SHA-256 digest must be 64 lowercase hexadecimal characters")]
    InvalidSha256Digest,
    #[error("timestamp must be a UTC RFC 3339 value ending in 'Z'")]
    InvalidUtcTimestamp,
}

fn validate_prefixed_id(
    value: &str,
    prefix: &'static str,
    kind: &'static str,
) -> Result<(), DomainValueError> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(DomainValueError::WrongPrefix { kind, prefix })?;

    if !(8..=128).contains(&suffix.len()) {
        return Err(DomainValueError::InvalidLength { kind });
    }

    let mut bytes = suffix.bytes();
    let first = bytes
        .next()
        .ok_or(DomainValueError::InvalidLength { kind })?;
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(DomainValueError::InvalidCharacters { kind });
    }

    Ok(())
}

macro_rules! define_id {
    ($name:ident, $prefix:literal, $kind:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn parse(value: impl Into<String>) -> Result<Self, DomainValueError> {
                let value = value.into();
                validate_prefixed_id(&value, Self::PREFIX, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(de::Error::custom)
            }
        }
    };
}

define_id!(ProjectId, "prj_", "Project ID");
define_id!(CollaborationSessionId, "csess_", "Collaboration Session ID");
define_id!(AssignmentId, "asg_", "Assignment ID");
define_id!(RunId, "run_", "Run ID");
define_id!(DeviceId, "dev_", "Device ID");
define_id!(SourceId, "src_", "Source ID");
define_id!(LocationId, "loc_", "Location ID");
define_id!(RuntimeId, "rt_", "Runtime ID");
define_id!(BaselineId, "bln_", "Baseline ID");
define_id!(ChangeSetId, "chg_", "Change Set ID");
define_id!(OperationId, "op_", "Operation ID");
define_id!(PrincipalId, "prin_", "Principal ID");
define_id!(ProjectAgentId, "pagent_", "Project Agent ID");
define_id!(ArtifactId, "art_", "Artifact ID");
define_id!(MessageId, "msg_", "Message ID");
define_id!(ManifestId, "rman_", "Run Manifest ID");
define_id!(ContextSnapshotId, "ctxs_", "Context Snapshot ID");
define_id!(EventId, "evt_", "Event ID");
define_id!(ContentObjectId, "obj_", "Content Object ID");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyRunId {
    Shared(RunId),
    Local(String),
}

impl AnyRunId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainValueError> {
        let value = value.into();
        if value.starts_with(RunId::PREFIX) {
            return RunId::parse(value).map(Self::Shared);
        }
        validate_prefixed_id(&value, "lrun_", "Local Run ID")?;
        Ok(Self::Local(value))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Shared(value) => value.as_str(),
            Self::Local(value) => value,
        }
    }
}

impl fmt::Debug for AnyRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AnyRunId")
            .field(&self.as_str())
            .finish()
    }
}

impl Serialize for AnyRunId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AnyRunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64Decimal(u64);

impl U64Decimal {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn parse(value: &str) -> Result<Self, DomainValueError> {
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DomainValueError::InvalidU64Decimal);
        }
        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| DomainValueError::InvalidU64Decimal)
    }
}

impl fmt::Display for U64Decimal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Serialize for U64Decimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for U64Decimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn parse(value: &str) -> Result<Self, DomainValueError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DomainValueError::InvalidSha256Digest);
        }
        let bytes = hex::decode(value).map_err(|_| DomainValueError::InvalidSha256Digest)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DomainValueError::InvalidSha256Digest)?;
        Ok(Self(array))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp(String);

impl UtcTimestamp {
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainValueError> {
        let value = value.into();
        if !value.ends_with('Z') {
            return Err(DomainValueError::InvalidUtcTimestamp);
        }
        let parsed = OffsetDateTime::parse(&value, &Rfc3339)
            .map_err(|_| DomainValueError::InvalidUtcTimestamp)?;
        if parsed.offset() != time::UtcOffset::UTC {
            return Err(DomainValueError::InvalidUtcTimestamp);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UtcTimestamp")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TimestampFixture {
        fixture_version: u8,
        contract: String,
        cases: Vec<TimestampCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TimestampCase {
        name: String,
        input: String,
        expected_wire_text: String,
    }

    #[test]
    fn validates_prefixed_ids() {
        assert!(ProjectId::parse("prj_abcdefgh").is_ok());
        assert!(ProjectId::parse("project_abcdefgh").is_err());
        assert!(ProjectId::parse("prj_short").is_err());
        assert!(ProjectId::parse("prj_abc defgh").is_err());
    }

    #[test]
    fn accepts_shared_and_local_run_ids() {
        assert!(matches!(
            AnyRunId::parse("run_abcdefgh").unwrap(),
            AnyRunId::Shared(_)
        ));
        assert!(matches!(
            AnyRunId::parse("lrun_abcdefgh").unwrap(),
            AnyRunId::Local(_)
        ));
    }

    #[test]
    fn rejects_noncanonical_u64_text() {
        assert_eq!(U64Decimal::parse("0").unwrap().get(), 0);
        assert_eq!(
            U64Decimal::parse("18446744073709551615").unwrap().get(),
            u64::MAX
        );
        assert!(U64Decimal::parse("01").is_err());
        assert!(U64Decimal::parse("18446744073709551616").is_err());
    }

    #[test]
    fn requires_lowercase_sha256() {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Sha256Digest::parse(digest).unwrap().to_string(), digest);
        assert!(Sha256Digest::parse(&digest.to_uppercase()).is_err());
    }

    #[test]
    fn requires_utc_z_timestamp() {
        assert_eq!(
            UtcTimestamp::parse("2026-09-01T12:00:00Z")
                .unwrap()
                .as_str(),
            "2026-09-01T12:00:00Z"
        );
        assert!(UtcTimestamp::parse("2026-09-01T21:00:00+09:00").is_err());
    }

    #[test]
    fn preserves_shared_utc_timestamp_wire_text_fixture() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let path = workspace_root.join("spec/fixtures/utc-timestamp-v1.json");
        let fixture: TimestampFixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();

        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(fixture.contract, "preserve_valid_utc_rfc3339_wire_text");
        assert!(!fixture.cases.is_empty());
        for case in fixture.cases {
            let timestamp = UtcTimestamp::parse(&case.input)
                .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            assert_eq!(timestamp.as_str(), case.expected_wire_text, "{}", case.name);
            assert_eq!(
                serde_json::to_string(&timestamp).unwrap(),
                serde_json::to_string(&case.expected_wire_text).unwrap(),
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn serializes_contract_representations() {
        assert_eq!(
            serde_json::to_string(&U64Decimal::new(42)).unwrap(),
            "\"42\""
        );
        let project: ProjectId = serde_json::from_str("\"prj_abcdefgh\"").unwrap();
        assert_eq!(project.as_str(), "prj_abcdefgh");
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new("do-not-print");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
    }
}
