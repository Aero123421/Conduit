//! Versioned wire-schema boundaries and bounded protocol errors.

mod error;
mod wire;

pub use error::{
    ErrorCodeParseError, ErrorDetail, ErrorDetailValue, ErrorEnvelope, ErrorEnvelopeBoundsError,
    ProtocolErrorCode, ProtocolErrorExtension,
};
pub use wire::{
    AuthV1, ChangeSetV1, DomainValidationIssue, NodeProtocolV1, PrivilegedHelperV1, RuntimeV1,
    SchemaValidationIssue, TraceV1, ValidatedDocument, WireSchema, WireValidationError,
};

pub const AUTH_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/auth-v1.schema.json";
pub const NODE_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/node-protocol-v1.schema.json";
pub const PRIVILEGED_SCHEMA_V1: &str =
    "https://conduit.dev/spec/schemas/privileged-helper-v1.schema.json";
pub const TRACE_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/trace-v1.schema.json";
pub const RUNTIME_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/runtime-v1.schema.json";
pub const CHANGESET_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/changeset-v1.schema.json";

pub const NODE_PROTOCOL_V1: &str = "conduit.node/1";
pub const PRIVILEGED_PROTOCOL_V1: &str = "conduit.privileged/1";
pub const TRACE_PROTOCOL_V1: &str = "conduit.trace/1";
