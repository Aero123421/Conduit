//! Shared schema identifiers and bounded protocol error envelopes.

use conduit_domain::OperationId;
use serde::{Deserialize, Serialize};

pub const AUTH_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/auth-v1.schema.json";
pub const NODE_SCHEMA_V1: &str =
    "https://conduit.dev/spec/schemas/node-protocol-v1.schema.json";
pub const TRACE_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/trace-v1.schema.json";
pub const RUNTIME_SCHEMA_V1: &str = "https://conduit.dev/spec/schemas/runtime-v1.schema.json";
pub const CHANGESET_SCHEMA_V1: &str =
    "https://conduit.dev/spec/schemas/changeset-v1.schema.json";

pub const NODE_PROTOCOL_V1: &str = "conduit.node/1";
pub const TRACE_PROTOCOL_V1: &str = "conduit.trace/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorDetailValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub key: String,
    pub value: ErrorDetailValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetail>,
}

impl ErrorEnvelope {
    pub const MAX_CODE_BYTES: usize = 128;
    pub const MAX_MESSAGE_BYTES: usize = 2048;
    pub const MAX_DETAILS: usize = 32;

    pub fn validate_bounds(&self) -> Result<(), &'static str> {
        if self.code.is_empty() || self.code.len() > Self::MAX_CODE_BYTES {
            return Err("error code is outside bounds");
        }
        if self.message.len() > Self::MAX_MESSAGE_BYTES {
            return Err("error message is outside bounds");
        }
        if self.details.len() > Self::MAX_DETAILS {
            return Err("too many error details");
        }
        if self
            .details
            .iter()
            .any(|detail| detail.key.is_empty() || detail.key.len() > 128)
        {
            return Err("error detail key is outside bounds");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_errors() {
        let envelope = ErrorEnvelope {
            code: "x".repeat(ErrorEnvelope::MAX_CODE_BYTES + 1),
            message: String::new(),
            retryable: false,
            operation_id: None,
            details: Vec::new(),
        };
        assert!(envelope.validate_bounds().is_err());
    }
}
