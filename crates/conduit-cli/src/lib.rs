mod command;
mod doctor;
mod transport;

use std::{fs, path::Path};

use clap::Parser;
use serde_json::Value;
use thiserror::Error;

use command::Target;
pub use command::{Cli, Commands, OutputFormat};
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
}

impl CliError {
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Configuration(_) | Self::Json(_) => 2,
            Self::Denied(_) => 3,
            Self::Unavailable(_) => 4,
            Self::Io(_) | Self::Http(_) => 1,
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
        invocation.body = Some(merge_input(invocation.body.take(), input)?);
    }
    if invocation.effectful && invocation.idempotency_key.is_none() {
        invocation.idempotency_key = Some(format!("cli-{}", uuid::Uuid::now_v7()));
    }
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
