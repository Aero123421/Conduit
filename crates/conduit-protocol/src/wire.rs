use std::{fmt, marker::PhantomData, sync::OnceLock};

use conduit_domain::{
    AnyRunId, AssignmentId, BaselineId, ChangeSetId, CollaborationSessionId, DeviceId,
    DomainValueError, LocationId, OperationId, ProjectId, RuntimeId, Sha256Digest, SourceId,
    U64Decimal, UtcTimestamp,
};
use jsonschema::error::ValidationErrorKind;
use jsonschema::{Draft, Retrieve, Uri, ValidationError, Validator};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    AUTH_SCHEMA_V1, CHANGESET_SCHEMA_V1, NODE_SCHEMA_V1, RUNTIME_SCHEMA_V1, TRACE_SCHEMA_V1,
};

const MAX_REPORTED_ISSUES: usize = 16;
const TRACE_SCHEMA_SOURCE: &str = include_str!("../../../spec/schemas/trace-v1.schema.json");

mod private {
    pub trait Sealed {}
}

/// Marker for one checked-in, versioned JSON Schema wire contract.
///
/// Implementations are sealed so callers cannot associate arbitrary schema text
/// with one of Conduit's trusted wire-family types.
pub trait WireSchema: private::Sealed + fmt::Debug + Send + Sync + 'static {
    const ID: &'static str;
    const MAX_DOCUMENT_BYTES: Option<usize> = None;
    fn compiled() -> &'static Result<CompiledSchema, String>;
}

macro_rules! define_wire_schema {
    ($marker:ident, $id:ident, $path:literal, $max_document_bytes:expr) => {
        #[derive(Debug)]
        pub struct $marker;

        impl private::Sealed for $marker {}

        impl WireSchema for $marker {
            const ID: &'static str = $id;
            const MAX_DOCUMENT_BYTES: Option<usize> = $max_document_bytes;

            fn compiled() -> &'static Result<CompiledSchema, String> {
                static COMPILED: OnceLock<Result<CompiledSchema, String>> = OnceLock::new();
                COMPILED.get_or_init(|| compile_schema(include_str!($path)))
            }
        }
    };
}

define_wire_schema!(
    AuthV1,
    AUTH_SCHEMA_V1,
    "../../../spec/schemas/auth-v1.schema.json",
    None
);
define_wire_schema!(
    NodeProtocolV1,
    NODE_SCHEMA_V1,
    "../../../spec/schemas/node-protocol-v1.schema.json",
    Some(65_536)
);
define_wire_schema!(
    TraceV1,
    TRACE_SCHEMA_V1,
    "../../../spec/schemas/trace-v1.schema.json",
    None
);
define_wire_schema!(
    RuntimeV1,
    RUNTIME_SCHEMA_V1,
    "../../../spec/schemas/runtime-v1.schema.json",
    None
);
define_wire_schema!(
    ChangeSetV1,
    CHANGESET_SCHEMA_V1,
    "../../../spec/schemas/changeset-v1.schema.json",
    None
);

pub struct CompiledSchema {
    schema: Value,
    trace_schema: Value,
    validator: Validator,
}

fn compile_schema(source: &str) -> Result<CompiledSchema, String> {
    let schema: Value = serde_json::from_str(source).map_err(|error| error.to_string())?;
    let trace_schema: Value =
        serde_json::from_str(TRACE_SCHEMA_SOURCE).map_err(|error| error.to_string())?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_retriever(CheckedInSchemaRetriever)
        .build(&schema)
        .map_err(|error| error.to_string())?;
    Ok(CompiledSchema {
        schema,
        trace_schema,
        validator,
    })
}

struct CheckedInSchemaRetriever;

impl Retrieve for CheckedInSchemaRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        match uri.as_str() {
            TRACE_SCHEMA_V1 => Ok(serde_json::from_str(TRACE_SCHEMA_SOURCE)?),
            _ => Err(format!("external schema is not checked in: {uri}").into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaValidationIssue {
    pub instance_path: String,
    pub schema_path: String,
    pub keyword: String,
    pub message: String,
}

impl SchemaValidationIssue {
    pub const MAX_INSTANCE_PATH_BYTES: usize = 512;
    pub const MAX_SCHEMA_PATH_BYTES: usize = 512;
    pub const MAX_KEYWORD_BYTES: usize = 64;
    pub const MAX_MESSAGE_BYTES: usize = 160;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainValidationIssue {
    pub instance_path: String,
    pub validator: &'static str,
    pub reason: &'static str,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum WireValidationError {
    #[error("wire document is not valid JSON: {0}")]
    MalformedJson(#[from] serde_json::Error),
    #[error("wire document for {schema_id} is {actual_bytes} bytes; maximum is {max_bytes}")]
    DocumentTooLarge {
        schema_id: &'static str,
        max_bytes: usize,
        actual_bytes: usize,
    },
    #[error("checked-in schema {schema_id} could not be compiled: {message}")]
    SchemaUnavailable {
        schema_id: &'static str,
        message: String,
    },
    #[error("document does not satisfy {schema_id}")]
    Schema {
        schema_id: &'static str,
        issues: Vec<SchemaValidationIssue>,
    },
    #[error("document violates domain primitives after satisfying {schema_id}")]
    Domain {
        schema_id: &'static str,
        issues: Vec<DomainValidationIssue>,
    },
}

/// JSON retained only after both the versioned wire schema and shared domain
/// primitive checks have passed.
///
/// The marker type is the schema-family boundary. The JSON value remains the
/// canonical wire representation; semantic IDs and values are not redeclared as
/// a second set of generated Rust domain types.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValidatedDocument<S: WireSchema> {
    value: Value,
    #[serde(skip)]
    marker: PhantomData<S>,
}

impl<S: WireSchema> ValidatedDocument<S> {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireValidationError> {
        if let Some(max_bytes) = S::MAX_DOCUMENT_BYTES
            && bytes.len() > max_bytes
        {
            return Err(WireValidationError::DocumentTooLarge {
                schema_id: S::ID,
                max_bytes,
                actual_bytes: bytes.len(),
            });
        }
        Self::from_value(serde_json::from_slice(bytes)?)
    }

    pub fn from_value(value: Value) -> Result<Self, WireValidationError> {
        Self::validate_schema(&value)?;
        Self::validate_domain(&value)?;
        Ok(Self {
            value,
            marker: PhantomData,
        })
    }

    pub fn validate_schema(value: &Value) -> Result<(), WireValidationError> {
        let compiled = compiled::<S>()?;
        let mut issues = Vec::new();
        for error in compiled.validator.iter_errors(value) {
            collect_schema_issues(&error, &mut issues);
            if issues.len() >= MAX_REPORTED_ISSUES {
                break;
            }
        }
        issues.truncate(MAX_REPORTED_ISSUES);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(WireValidationError::Schema {
                schema_id: S::ID,
                issues,
            })
        }
    }

    pub fn validate_domain(value: &Value) -> Result<(), WireValidationError> {
        let compiled = compiled::<S>()?;
        let mut issues = Vec::new();
        validate_domain_node(
            value,
            &compiled.schema,
            &compiled.schema,
            &compiled.trace_schema,
            "",
            &mut issues,
            0,
        );
        issues.truncate(MAX_REPORTED_ISSUES);
        issues.sort_by(|left, right| {
            (
                &left.instance_path,
                left.validator,
                left.reason,
                &left.message,
            )
                .cmp(&(
                    &right.instance_path,
                    right.validator,
                    right.reason,
                    &right.message,
                ))
        });
        issues.dedup();
        if issues.is_empty() {
            Ok(())
        } else {
            Err(WireValidationError::Domain {
                schema_id: S::ID,
                issues,
            })
        }
    }

    pub const fn as_value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }
}

fn collect_schema_issues(error: &ValidationError<'_>, issues: &mut Vec<SchemaValidationIssue>) {
    if issues.len() >= MAX_REPORTED_ISSUES {
        return;
    }
    match error.kind() {
        ValidationErrorKind::AnyOf { context } | ValidationErrorKind::OneOfNotValid { context } => {
            for branch in context {
                for nested in branch {
                    collect_schema_issues(nested, issues);
                }
            }
        }
        ValidationErrorKind::PropertyNames { error } => collect_schema_issues(error, issues),
        _ => {
            let keyword = bounded_utf8(
                error.kind().keyword(),
                SchemaValidationIssue::MAX_KEYWORD_BYTES,
            );
            let message = bounded_utf8(
                &format!("schema keyword `{keyword}` rejected the value"),
                SchemaValidationIssue::MAX_MESSAGE_BYTES,
            );
            issues.push(SchemaValidationIssue {
                instance_path: bounded_utf8(
                    error.instance_path().as_str(),
                    SchemaValidationIssue::MAX_INSTANCE_PATH_BYTES,
                ),
                schema_path: bounded_utf8(
                    error.schema_path().as_str(),
                    SchemaValidationIssue::MAX_SCHEMA_PATH_BYTES,
                ),
                keyword,
                message,
            });
        }
    }
}

fn bounded_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn compiled<S: WireSchema>() -> Result<&'static CompiledSchema, WireValidationError> {
    S::compiled()
        .as_ref()
        .map_err(|message| WireValidationError::SchemaUnavailable {
            schema_id: S::ID,
            message: message.clone(),
        })
}

fn validate_domain_node(
    instance: &Value,
    schema: &Value,
    current_root: &Value,
    trace_schema: &Value,
    instance_path: &str,
    issues: &mut Vec<DomainValidationIssue>,
    depth: usize,
) {
    if depth > 128 || issues.len() >= MAX_REPORTED_ISSUES {
        return;
    }
    let Some(schema_object) = schema.as_object() else {
        return;
    };
    if !simple_constraints_match(instance, schema_object) {
        return;
    }

    if let Some(reference) = schema_object.get("$ref").and_then(Value::as_str)
        && let Some((target_root, target)) =
            resolve_reference(current_root, trace_schema, reference)
    {
        validate_domain_reference(instance, reference, instance_path, issues);
        validate_domain_node(
            instance,
            target,
            target_root,
            trace_schema,
            instance_path,
            issues,
            depth + 1,
        );
    }

    if let (Some(properties), Some(instance_object)) = (
        schema_object.get("properties").and_then(Value::as_object),
        instance.as_object(),
    ) {
        for (key, property_schema) in properties {
            if let Some(property) = instance_object.get(key) {
                let path = append_pointer(instance_path, key);
                validate_domain_node(
                    property,
                    property_schema,
                    current_root,
                    trace_schema,
                    &path,
                    issues,
                    depth + 1,
                );
            }
        }
    }

    if let (Some(item_schema), Some(items)) = (schema_object.get("items"), instance.as_array()) {
        for (index, item) in items.iter().enumerate() {
            let path = append_pointer(instance_path, &index.to_string());
            validate_domain_node(
                item,
                item_schema,
                current_root,
                trace_schema,
                &path,
                issues,
                depth + 1,
            );
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema_object.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                validate_domain_node(
                    instance,
                    branch,
                    current_root,
                    trace_schema,
                    instance_path,
                    issues,
                    depth + 1,
                );
            }
        }
    }
    if let Some(condition) = schema_object.get("if") {
        let branch = if simple_schema_matches(instance, condition) {
            schema_object.get("then")
        } else {
            schema_object.get("else")
        };
        if let Some(branch) = branch {
            validate_domain_node(
                instance,
                branch,
                current_root,
                trace_schema,
                instance_path,
                issues,
                depth + 1,
            );
        }
    }
}

fn simple_schema_matches(instance: &Value, schema: &Value) -> bool {
    schema
        .as_object()
        .is_none_or(|schema_object| simple_constraints_match(instance, schema_object))
}

fn simple_constraints_match(
    instance: &Value,
    schema_object: &serde_json::Map<String, Value>,
) -> bool {
    if let Some(expected) = schema_object.get("const")
        && instance != expected
    {
        return false;
    }
    let Some(instance_object) = instance.as_object() else {
        return true;
    };
    if let Some(required) = schema_object.get("required").and_then(Value::as_array)
        && required.iter().any(|key| {
            key.as_str()
                .is_some_and(|key| !instance_object.contains_key(key))
        })
    {
        return false;
    }
    if let Some(properties) = schema_object.get("properties").and_then(Value::as_object) {
        for (key, property_schema) in properties {
            if let (Some(actual), Some(expected)) =
                (instance_object.get(key), property_schema.get("const"))
                && actual != expected
            {
                return false;
            }
        }
    }
    true
}

fn validate_domain_reference(
    instance: &Value,
    reference: &str,
    instance_path: &str,
    issues: &mut Vec<DomainValidationIssue>,
) {
    let Some(value) = instance.as_str() else {
        return;
    };
    let definition = reference.rsplit('/').next();
    let result = match definition {
        Some("AssignmentId") => AssignmentId::parse(value)
            .map(|_| ())
            .map_err(|error| ("assignment_id", error)),
        Some("BaselineId") => BaselineId::parse(value)
            .map(|_| ())
            .map_err(|error| ("baseline_id", error)),
        Some("ChangeSetId") => ChangeSetId::parse(value)
            .map(|_| ())
            .map_err(|error| ("change_set_id", error)),
        Some("DeviceId") => DeviceId::parse(value)
            .map(|_| ())
            .map_err(|error| ("device_id", error)),
        Some("LocationId") => LocationId::parse(value)
            .map(|_| ())
            .map_err(|error| ("location_id", error)),
        Some("OperationId") => OperationId::parse(value)
            .map(|_| ())
            .map_err(|error| ("operation_id", error)),
        Some("ProjectId") => ProjectId::parse(value)
            .map(|_| ())
            .map_err(|error| ("project_id", error)),
        Some("RunId") => AnyRunId::parse(value)
            .map(|_| ())
            .map_err(|error| ("run_id", error)),
        Some("RuntimeId") => RuntimeId::parse(value)
            .map(|_| ())
            .map_err(|error| ("runtime_id", error)),
        Some("SessionId") => CollaborationSessionId::parse(value)
            .map(|_| ())
            .map_err(|error| ("collaboration_session_id", error)),
        Some("U64Decimal") => U64Decimal::parse(value)
            .map(|_| ())
            .map_err(|error| ("u64_decimal", error)),
        Some("Timestamp") => UtcTimestamp::parse(value)
            .map(|_| ())
            .map_err(|error| ("utc_timestamp", error)),
        Some("Sha256Hex") => Sha256Digest::parse(value)
            .map(|_| ())
            .map_err(|error| ("sha256_digest", error)),
        Some("SourceId") => SourceId::parse(value)
            .map(|_| ())
            .map_err(|error| ("source_id", error)),
        _ => return,
    };
    if let Err((validator, error)) = result {
        issues.push(DomainValidationIssue {
            instance_path: instance_path.to_owned(),
            validator,
            reason: domain_invalid_reason(definition, value, &error),
            message: error.to_string(),
        });
    }
}

fn domain_invalid_reason(
    definition: Option<&str>,
    value: &str,
    error: &DomainValueError,
) -> &'static str {
    match (definition, error) {
        (Some("U64Decimal"), DomainValueError::InvalidU64Decimal) => {
            let canonical_digits = !(value.is_empty() || value.len() > 1 && value.starts_with('0'))
                && value.bytes().all(|byte| byte.is_ascii_digit());
            if canonical_digits {
                "u64_overflow"
            } else {
                "invalid_u64_decimal"
            }
        }
        (Some("Timestamp"), DomainValueError::InvalidUtcTimestamp) => {
            if value.ends_with('Z') {
                "invalid_utc_timestamp"
            } else {
                "utc_offset_not_z"
            }
        }
        (Some("Sha256Hex"), DomainValueError::InvalidSha256Digest) => "invalid_digest",
        (
            _,
            DomainValueError::WrongPrefix { .. }
            | DomainValueError::InvalidLength { .. }
            | DomainValueError::InvalidCharacters { .. },
        ) => "malformed_id",
        _ => "invalid_domain_value",
    }
}

fn resolve_reference<'a>(
    current_root: &'a Value,
    trace_schema: &'a Value,
    reference: &str,
) -> Option<(&'a Value, &'a Value)> {
    if let Some(pointer) = reference.strip_prefix('#') {
        return current_root
            .pointer(pointer)
            .map(|target| (current_root, target));
    }
    for prefix in [
        "trace-v1.schema.json#",
        "https://conduit.dev/spec/schemas/trace-v1.schema.json#",
    ] {
        if let Some(pointer) = reference.strip_prefix(prefix) {
            return trace_schema
                .pointer(pointer)
                .map(|target| (trace_schema, target));
        }
    }
    None
}

fn append_pointer(parent: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde::Deserialize;

    use super::*;

    fn workspace_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
    }

    fn validate_example_directory<S: WireSchema>(directory: &str) -> usize {
        let path = workspace_root().join("spec/examples").join(directory);
        let mut count = 0;
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(entry.path()).unwrap();
            ValidatedDocument::<S>::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("{}: {error:#?}", entry.path().display()));
            count += 1;
        }
        count
    }

    #[test]
    fn validates_every_checked_in_wire_example() {
        assert_eq!(validate_example_directory::<AuthV1>("auth"), 5);
        assert_eq!(
            validate_example_directory::<NodeProtocolV1>("node-protocol"),
            4
        );
        assert_eq!(validate_example_directory::<TraceV1>("trace"), 5);
        assert_eq!(validate_example_directory::<RuntimeV1>("runtime"), 4);
        assert_eq!(validate_example_directory::<ChangeSetV1>("changeset"), 6);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let path = workspace_root().join("spec/examples/auth/connector-policy-read-only.json");
        let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value["schemaVersion"] = Value::from(2);
        assert!(matches!(
            ValidatedDocument::<AuthV1>::from_value(value),
            Err(WireValidationError::Schema { .. })
        ));
    }

    #[test]
    fn rejects_oversized_node_document_before_json_decoding() {
        let max_bytes = NodeProtocolV1::MAX_DOCUMENT_BYTES.unwrap();
        let bytes = vec![b'x'; max_bytes + 1];
        assert!(matches!(
            ValidatedDocument::<NodeProtocolV1>::from_slice(&bytes),
            Err(WireValidationError::DocumentTooLarge {
                max_bytes: 65_536,
                actual_bytes: 65_537,
                ..
            })
        ));
    }

    #[test]
    fn schema_issues_are_bounded_and_do_not_copy_instance_values() {
        let path = workspace_root().join("spec/examples/auth/connector-policy-read-only.json");
        let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let secret_marker = "PRIVATE_SECRET_MARKER".repeat(8_000);
        value["id"] = Value::String(secret_marker.clone());

        let error = ValidatedDocument::<AuthV1>::validate_schema(&value).unwrap_err();
        let WireValidationError::Schema { issues, .. } = &error else {
            panic!("unexpected validation error: {error:#?}");
        };
        assert!(!issues.is_empty());
        for issue in issues {
            assert!(issue.instance_path.len() <= SchemaValidationIssue::MAX_INSTANCE_PATH_BYTES);
            assert!(issue.schema_path.len() <= SchemaValidationIssue::MAX_SCHEMA_PATH_BYTES);
            assert!(issue.keyword.len() <= SchemaValidationIssue::MAX_KEYWORD_BYTES);
            assert!(issue.message.len() <= SchemaValidationIssue::MAX_MESSAGE_BYTES);
            assert!(!issue.message.contains("PRIVATE_SECRET_MARKER"));
            assert!(!issue.keyword.contains("PRIVATE_SECRET_MARKER"));
        }
        assert!(!format!("{error:?}").contains("PRIVATE_SECRET_MARKER"));
        assert!(!format!("{error}").contains("PRIVATE_SECRET_MARKER"));
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InvalidFixture {
        fixture_version: u8,
        schema_id: String,
        validation_layer: String,
        validator_kind: String,
        instance_path: String,
        expected_invalid_reason: String,
        instance: Value,
    }

    fn assert_invalid<S: WireSchema>(fixture: &InvalidFixture, path: &Path) {
        assert_eq!(fixture.fixture_version, 1, "{}", path.display());
        assert_eq!(fixture.schema_id, S::ID, "{}", path.display());
        assert!(
            !fixture.expected_invalid_reason.is_empty(),
            "{}",
            path.display()
        );

        match fixture.validation_layer.as_str() {
            "schema" => {
                assert_eq!(fixture.validator_kind, "json_schema", "{}", path.display());
                let expected_keyword = match fixture.expected_invalid_reason.as_str() {
                    "invalid_digest" | "malformed_id" => "pattern",
                    "unknown_schema_version" => "const",
                    reason => panic!(
                        "unknown schema expectedInvalidReason {reason:?} in {}",
                        path.display()
                    ),
                };
                let error = ValidatedDocument::<S>::validate_schema(&fixture.instance)
                    .expect_err("schema fixture unexpectedly passed");
                let WireValidationError::Schema { issues, .. } = error else {
                    panic!(
                        "unexpected validation layer in {}: {error:#?}",
                        path.display()
                    );
                };
                assert!(
                    issues
                        .iter()
                        .any(|issue| issue.instance_path == fixture.instance_path
                            && issue.keyword == expected_keyword),
                    "expected schema issue {} at {} in {} but got {issues:#?}",
                    expected_keyword,
                    fixture.instance_path,
                    path.display()
                );
            }
            "domain" => {
                ValidatedDocument::<S>::validate_schema(&fixture.instance).unwrap_or_else(
                    |error| {
                        panic!(
                            "domain fixture must first satisfy JSON Schema ({}): {error:#?}",
                            path.display()
                        )
                    },
                );
                let error = ValidatedDocument::<S>::validate_domain(&fixture.instance)
                    .expect_err("domain fixture unexpectedly passed");
                let WireValidationError::Domain { issues, .. } = error else {
                    panic!("unexpected validation layer in {}", path.display());
                };
                assert!(
                    issues.iter().any(|issue| {
                        issue.instance_path == fixture.instance_path
                            && issue.validator == fixture.validator_kind
                            && issue.reason == fixture.expected_invalid_reason
                    }),
                    "expected {} ({}) at {} in {} but got {issues:#?}",
                    fixture.validator_kind,
                    fixture.expected_invalid_reason,
                    fixture.instance_path,
                    path.display()
                );
            }
            layer => panic!("unknown validationLayer {layer:?} in {}", path.display()),
        }
    }

    #[test]
    fn validates_every_invalid_fixture_at_its_declared_layer() {
        let directory = workspace_root().join("spec/fixtures/invalid");
        let mut count = 0;
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let fixture: InvalidFixture =
                serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
            match fixture.schema_id.as_str() {
                AUTH_SCHEMA_V1 => assert_invalid::<AuthV1>(&fixture, &entry.path()),
                NODE_SCHEMA_V1 => assert_invalid::<NodeProtocolV1>(&fixture, &entry.path()),
                TRACE_SCHEMA_V1 => assert_invalid::<TraceV1>(&fixture, &entry.path()),
                RUNTIME_SCHEMA_V1 => assert_invalid::<RuntimeV1>(&fixture, &entry.path()),
                CHANGESET_SCHEMA_V1 => assert_invalid::<ChangeSetV1>(&fixture, &entry.path()),
                id => panic!("unknown schemaId {id:?} in {}", entry.path().display()),
            }
            count += 1;
        }
        assert_eq!(count, 5, "invalid fixture set changed");
    }
}
