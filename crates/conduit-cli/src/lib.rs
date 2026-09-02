mod command;
mod doctor;
mod transport;

use std::{fs, path::Path};

use clap::Parser;
use serde_json::Value;
use thiserror::Error;

pub use command::{Cli, Commands, OutputFormat};
use command::{InputDestination, Target};
use transport::{ControlPlaneClient, NodeIpcClient};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON input: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control-plane request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("operation was denied: {0}")]
    Denied(String),
    #[error("required service or capability is unavailable: {0}")]
    Unavailable(String),
    #[error("control-plane API error {status} {code}: {message}{request_suffix}")]
    Api {
        status: u16,
        code: String,
        message: String,
        request_suffix: String,
    },
}

impl CliError {
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Configuration(_) | Self::Json(_) => 2,
            Self::Denied(_) => 3,
            Self::Unavailable(_) => 4,
            Self::Io(_) | Self::Http(_) => 1,
            Self::Api { status, .. } => match status {
                400 | 404 | 405 | 411 | 413 | 422 => 2,
                401 | 403 | 409 | 428 | 429 => 3,
                _ => 4,
            },
        }
    }
}

pub fn run() -> Result<(), CliError> {
    run_cli(Cli::parse())
}

pub fn run_cli(cli: Cli) -> Result<(), CliError> {
    if matches!(cli.command, Commands::Doctor) {
        return print_value(cli.output, &doctor::collect()?);
    }
    let mut invocation = cli.command.into_invocation()?;
    if let Some(input) = invocation.input.take() {
        let input = read_json_input(input.inline.as_deref(), input.file.as_deref())?;
        match invocation.input_destination {
            InputDestination::Body => {
                invocation.body = Some(merge_input(invocation.body.take(), input)?);
            }
            InputDestination::Query => {
                invocation.route = append_query(&invocation.route, input)?;
            }
        }
    }
    finalize_effect(&mut invocation)?;
    let value = match invocation.target {
        Target::ControlPlane => {
            let client = ControlPlaneClient::new(&cli.control_plane, cli.timeout_seconds)?;
            client.execute(&invocation)?
        }
        Target::Node => {
            let client = NodeIpcClient::from_environment(cli.timeout_seconds)?;
            client.execute(&invocation)?
        }
    };
    print_value(cli.output, &value)
}

fn finalize_effect(invocation: &mut command::Invocation) -> Result<(), CliError> {
    if !invocation.effectful {
        return Ok(());
    }
    if invocation.mirror_idempotency_in_body {
        let body = invocation
            .body
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                CliError::Usage("typed operation payload must be a JSON object".to_owned())
            })?;
        let body_key = body.get("idempotencyKey").and_then(Value::as_str);
        match (invocation.idempotency_key.as_deref(), body_key) {
            (Some(header), Some(body)) if header != body => {
                return Err(CliError::Usage(
                    "operation idempotencyKey differs from --idempotency-key".to_owned(),
                ));
            }
            (None, Some(body)) => invocation.idempotency_key = Some(body.to_owned()),
            _ => {}
        }
    }
    if invocation.idempotency_key.is_none() {
        invocation.idempotency_key = Some(format!("cli-{}", uuid::Uuid::now_v7()));
    }
    let key = invocation.idempotency_key.as_deref().expect("key was set");
    if key.len() < 16 || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(CliError::Usage(
            "idempotency key must be 16-256 non-control characters".to_owned(),
        ));
    }
    if invocation.mirror_idempotency_in_body {
        invocation
            .body
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("operation body was checked")
            .insert("idempotencyKey".to_owned(), Value::String(key.to_owned()));
        validate_operation_payload(invocation.body.as_ref().expect("operation body exists"))?;
    }
    if invocation.route.ends_with("/controls") {
        let body = invocation
            .body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| CliError::Usage("control payload must be a JSON object".to_owned()))?;
        if body
            .get("expectedState")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(CliError::Usage(
                "existing-target control requires expectedState in --data/--file".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_operation_payload(value: &Value) -> Result<(), CliError> {
    let body = value.as_object().ok_or_else(|| {
        CliError::Usage("typed operation payload must be a JSON object".to_owned())
    })?;
    const ALLOWED_OPERATION_FIELDS: &[&str] = &[
        "idempotencyKey",
        "deviceId",
        "capability",
        "projectId",
        "sessionId",
        "assignmentId",
        "runId",
        "runtime",
        "accessScope",
        "approvalMode",
        "sourceRevisions",
        "arguments",
        "expiresInSeconds",
    ];
    if let Some(field) = body
        .keys()
        .find(|field| !ALLOWED_OPERATION_FIELDS.contains(&field.as_str()))
    {
        return Err(CliError::Usage(format!(
            "typed operation payload contains unsupported field {field}"
        )));
    }
    for field in [
        "idempotencyKey",
        "deviceId",
        "capability",
        "accessScope",
        "approvalMode",
    ] {
        if body
            .get(field)
            .is_none_or(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err(CliError::Usage(format!(
                "typed operation payload requires non-empty {field}"
            )));
        }
    }
    if !body
        .get("capability")
        .and_then(Value::as_str)
        .is_some_and(valid_capability_name)
    {
        return Err(CliError::Usage(
            "typed operation capability is invalid".to_owned(),
        ));
    }
    for (field, prefix) in [
        ("projectId", "prj_"),
        ("sessionId", "csess_"),
        ("assignmentId", "asg_"),
        ("runId", "run_"),
    ] {
        if body.get(field).is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(|id| valid_prefixed_id(id, prefix))
        }) {
            return Err(CliError::Usage(format!(
                "typed operation {field} is invalid"
            )));
        }
    }
    if !body
        .get("deviceId")
        .and_then(Value::as_str)
        .is_some_and(|id| valid_prefixed_id(id, "dev_"))
    {
        return Err(CliError::Usage(
            "typed operation deviceId is invalid".to_owned(),
        ));
    }
    let runtime = body
        .get("runtime")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Usage("typed operation payload requires runtime object".to_owned())
        })?;
    const ALLOWED_RUNTIME_FIELDS: &[&str] = &[
        "kind",
        "providerId",
        "configurationRevision",
        "cpuLimit",
        "memoryBytes",
        "storageBytes",
        "gpuCount",
        "networkMode",
    ];
    if runtime
        .keys()
        .any(|field| !ALLOWED_RUNTIME_FIELDS.contains(&field.as_str()))
    {
        return Err(CliError::Usage(
            "typed operation runtime contains unsupported fields".to_owned(),
        ));
    }
    if !runtime
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "native" | "container" | "vm"))
    {
        return Err(CliError::Usage(
            "typed operation runtime.kind must be native, container, or vm".to_owned(),
        ));
    }
    if !runtime
        .get("providerId")
        .and_then(Value::as_str)
        .is_some_and(valid_capability_name)
    {
        return Err(CliError::Usage(
            "typed operation runtime.providerId is invalid".to_owned(),
        ));
    }
    if runtime
        .get("configurationRevision")
        .and_then(Value::as_u64)
        .is_none_or(|revision| revision < 1)
    {
        return Err(CliError::Usage(
            "typed operation runtime.configurationRevision must be a positive integer".to_owned(),
        ));
    }
    if !body
        .get("accessScope")
        .and_then(Value::as_str)
        .is_some_and(|scope| {
            matches!(
                scope,
                "read_only"
                    | "selected_sources"
                    | "project_full"
                    | "full_user"
                    | "full_device"
                    | "custom"
            )
        })
    {
        return Err(CliError::Usage(
            "typed operation accessScope is invalid".to_owned(),
        ));
    }
    if !body
        .get("approvalMode")
        .and_then(Value::as_str)
        .is_some_and(|mode| matches!(mode, "always" | "outside_scope" | "risk_classes" | "never"))
    {
        return Err(CliError::Usage(
            "typed operation approvalMode is invalid".to_owned(),
        ));
    }
    let source_revisions = body
        .get("sourceRevisions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Usage("typed operation payload requires sourceRevisions array".to_owned())
        })?;
    if source_revisions.len() > 128 {
        return Err(CliError::Usage(
            "typed operation sourceRevisions exceeds 128 entries".to_owned(),
        ));
    }
    for revision in source_revisions {
        let revision = revision.as_object().ok_or_else(|| {
            CliError::Usage("each sourceRevisions entry must be an object".to_owned())
        })?;
        const ALLOWED_SOURCE_REVISION_FIELDS: &[&str] = &[
            "sourceId",
            "locationId",
            "locationRevision",
            "mode",
            "baseCommit",
            "dirtyDigest",
        ];
        if revision
            .keys()
            .any(|field| !ALLOWED_SOURCE_REVISION_FIELDS.contains(&field.as_str()))
        {
            return Err(CliError::Usage(
                "sourceRevisions entry contains unsupported fields".to_owned(),
            ));
        }
        for field in ["sourceId", "locationId", "mode"] {
            if !revision.get(field).is_some_and(Value::is_string) {
                return Err(CliError::Usage(format!(
                    "sourceRevisions entry requires {field}"
                )));
            }
        }
        if !revision
            .get("sourceId")
            .and_then(Value::as_str)
            .is_some_and(|id| valid_prefixed_id(id, "src_"))
            || !revision
                .get("locationId")
                .and_then(Value::as_str)
                .is_some_and(|id| valid_prefixed_id(id, "loc_"))
            || !revision
                .get("mode")
                .and_then(Value::as_str)
                .is_some_and(|mode| {
                    matches!(mode, "read_only" | "direct" | "worktree" | "managed_copy")
                })
        {
            return Err(CliError::Usage(
                "sourceRevisions entry contains an invalid sourceId, locationId, or mode"
                    .to_owned(),
            ));
        }
        if revision
            .get("locationRevision")
            .and_then(Value::as_u64)
            .is_none_or(|revision| revision < 1)
        {
            return Err(CliError::Usage(
                "sourceRevisions locationRevision must be a positive integer".to_owned(),
            ));
        }
    }
    let arguments = body
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Usage("typed operation payload requires arguments object".to_owned())
        })?;
    if arguments.len() > 128 {
        return Err(CliError::Usage(
            "typed operation arguments exceeds 128 properties".to_owned(),
        ));
    }
    Ok(())
}

fn valid_capability_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    let suffix = value.strip_prefix(prefix);
    value.len() >= prefix.len() + 8
        && value.len() <= 128
        && suffix.is_some_and(|suffix| {
            suffix
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
        })
        && suffix
            .expect("suffix was checked")
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn append_query(route: &str, input: Value) -> Result<String, CliError> {
    let input = input
        .as_object()
        .ok_or_else(|| CliError::Usage("query input must be a JSON object".to_owned()))?;
    if input.keys().any(|key| key != "limit" && key != "cursor") {
        return Err(CliError::Usage(
            "canonical list queries accept only limit and cursor".to_owned(),
        ));
    }
    let mut pairs = Vec::new();
    if let Some(limit) = input.get("limit") {
        let limit = limit
            .as_u64()
            .filter(|limit| (1..=200).contains(limit))
            .ok_or_else(|| {
                CliError::Usage("query limit must be an integer from 1 through 200".to_owned())
            })?;
        pairs.push(format!("limit={limit}"));
    }
    if let Some(cursor) = input.get("cursor") {
        let cursor = cursor
            .as_str()
            .filter(|cursor| !cursor.is_empty() && cursor.len() <= 256)
            .ok_or_else(|| {
                CliError::Usage("query cursor must be a bounded non-empty string".to_owned())
            })?;
        pairs.push(format!("cursor={}", percent_encode(cursor)));
    }
    if pairs.is_empty() {
        Ok(route.to_owned())
    } else {
        Ok(format!("{route}?{}", pairs.join("&")))
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn merge_input(existing: Option<Value>, input: Value) -> Result<Value, CliError> {
    let Some(Value::Object(mut protected)) = existing else {
        return Ok(input);
    };
    let Value::Object(input) = input else {
        return Err(CliError::Usage(
            "mutation input must be a JSON object".to_owned(),
        ));
    };
    for (key, value) in input {
        if protected.contains_key(&key) {
            return Err(CliError::Usage(format!(
                "JSON input cannot override CLI-bound field {key}"
            )));
        }
        protected.insert(key, value);
    }
    Ok(Value::Object(protected))
}

fn read_json_input(inline: Option<&str>, file: Option<&Path>) -> Result<Value, CliError> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(CliError::Usage(
            "--data and --file are mutually exclusive".to_owned(),
        )),
        (Some(value), None) => {
            if value.len() > MAX_INPUT_BYTES {
                return Err(CliError::Usage(format!(
                    "--data exceeds {MAX_INPUT_BYTES} bytes"
                )));
            }
            serde_json::from_str(value).map_err(CliError::from)
        }
        (None, Some(path)) => {
            let metadata = fs::metadata(path)?;
            if metadata.len() > MAX_INPUT_BYTES as u64 {
                return Err(CliError::Usage(format!(
                    "JSON input exceeds {MAX_INPUT_BYTES} bytes"
                )));
            }
            serde_json::from_slice(&fs::read(path)?).map_err(CliError::from)
        }
        (None, None) => Ok(Value::Object(serde_json::Map::new())),
    }
}

fn print_value(format: OutputFormat, value: &Value) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(value)?),
        OutputFormat::Text => {
            if let Some(message) = value.get("message").and_then(Value::as_str) {
                println!("{message}");
            } else {
                println!("{}", serde_json::to_string_pretty(value)?);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde_json::json;

    use super::*;

    fn prepare(args: &[&str]) -> Result<command::Invocation, CliError> {
        let cli = Cli::try_parse_from(args).unwrap();
        let mut invocation = cli.command.into_invocation()?;
        if let Some(input) = invocation.input.take() {
            let input = read_json_input(input.inline.as_deref(), input.file.as_deref())?;
            match invocation.input_destination {
                InputDestination::Body => {
                    invocation.body = Some(merge_input(invocation.body.take(), input)?);
                }
                InputDestination::Query => {
                    invocation.route = append_query(&invocation.route, input)?;
                }
            }
        }
        finalize_effect(&mut invocation)?;
        Ok(invocation)
    }

    #[test]
    fn typed_operation_payload_and_header_key_are_exactly_identical() {
        let data = json!({
            "deviceId": "dev_contract01",
            "runtime": { "kind": "native", "providerId": "native", "configurationRevision": 1 },
            "accessScope": "read_only",
            "approvalMode": "always",
            "sourceRevisions": [],
            "arguments": { "argv": ["true"] }
        })
        .to_string();
        let invocation = prepare(&[
            "conduit",
            "quick",
            "command",
            "--data",
            &data,
            "--idempotency-key",
            "operation-key-0001",
        ])
        .unwrap();
        assert_eq!(invocation.route, "/api/v1/operations");
        assert_eq!(
            invocation.idempotency_key.as_deref(),
            Some("operation-key-0001")
        );
        assert_eq!(
            invocation.body,
            Some(json!({
                "idempotencyKey": "operation-key-0001",
                "deviceId": "dev_contract01",
                "capability": "command.start",
                "runtime": { "kind": "native", "providerId": "native", "configurationRevision": 1 },
                "accessScope": "read_only",
                "approvalMode": "always",
                "sourceRevisions": [],
                "arguments": { "argv": ["true"] }
            }))
        );
    }

    #[test]
    fn operation_payload_fails_closed_on_missing_or_overridden_contract_fields() {
        assert!(matches!(
            prepare(&["conduit", "quick", "command"]),
            Err(CliError::Usage(message)) if message.contains("deviceId")
        ));
        assert!(matches!(
            prepare(&[
                "conduit",
                "quick",
                "command",
                "--data",
                r#"{"capability":"runtime.destroy"}"#,
            ]),
            Err(CliError::Usage(message)) if message.contains("cannot override")
        ));
    }

    #[test]
    fn existing_target_control_requires_and_preserves_exact_state_and_revision() {
        assert!(matches!(
            prepare(&[
                "conduit",
                "run",
                "pause",
                "run_contract01",
                "--revision",
                "3",
            ]),
            Err(CliError::Usage(message)) if message.contains("expectedState")
        ));

        let invocation = prepare(&[
            "conduit",
            "run",
            "pause",
            "run_contract01",
            "--revision",
            "3",
            "--data",
            r#"{"expectedState":"running"}"#,
            "--idempotency-key",
            "control-key-0001",
        ])
        .unwrap();
        assert_eq!(invocation.route, "/api/v1/runs/run_contract01/controls");
        assert_eq!(invocation.revision, None);
        assert_eq!(
            invocation.idempotency_key.as_deref(),
            Some("control-key-0001")
        );
        assert_eq!(
            invocation.body,
            Some(json!({
                "command": "pause",
                "expectedState": "running",
                "expectedRevision": 3
            }))
        );
    }

    #[test]
    fn canonical_list_query_is_encoded_in_url_and_never_sent_as_json_body() {
        let invocation = prepare(&[
            "conduit",
            "board",
            "search",
            "--data",
            r#"{"limit":25,"cursor":"msg_a/b"}"#,
        ])
        .unwrap();
        assert_eq!(
            invocation.route,
            "/api/v1/messages?limit=25&cursor=msg_a%2Fb"
        );
        assert_eq!(invocation.body, None);
        assert!(matches!(
            prepare(&[
                "conduit",
                "board",
                "search",
                "--data",
                r#"{"q":"legacy full-text body"}"#,
            ]),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn caller_cannot_diverge_operation_header_and_body_idempotency() {
        let data = json!({
            "idempotencyKey": "operation-key-body",
            "deviceId": "dev_contract01",
            "runtime": { "kind": "native", "providerId": "native", "configurationRevision": 1 },
            "accessScope": "read_only",
            "approvalMode": "always",
            "sourceRevisions": [],
            "arguments": {}
        })
        .to_string();
        assert!(matches!(
            prepare(&[
                "conduit",
                "quick",
                "command",
                "--data",
                &data,
                "--idempotency-key",
                "different-key-0001",
            ]),
            Err(CliError::Usage(message)) if message.contains("differs")
        ));
    }
}
