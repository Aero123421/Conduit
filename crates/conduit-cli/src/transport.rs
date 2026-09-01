use std::{
    env, fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
    time::Duration,
};

use reqwest::{
    Method as HttpMethod, StatusCode, Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde_json::{Value, json};

use crate::{
    CliError,
    command::{Invocation, Method},
};

const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;

pub(crate) struct ControlPlaneClient {
    base: Url,
    client: Client,
    token: Option<String>,
}

impl ControlPlaneClient {
    pub fn new(base: &str, timeout_seconds: u64) -> Result<Self, CliError> {
        let base = validate_base_url(base)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(Policy::none())
            .build()?;
        Ok(Self {
            base,
            client,
            token: load_access_token()?,
        })
    }

    pub fn execute(&self, invocation: &Invocation) -> Result<Value, CliError> {
        let url = self
            .base
            .join(invocation.route.trim_start_matches('/'))
            .map_err(|error| CliError::Configuration(error.to_string()))?;
        if url.origin() != self.base.origin() {
            return Err(CliError::Configuration(
                "request escaped the configured control-plane origin".to_owned(),
            ));
        }
        let method = match invocation.method {
            Method::Get => HttpMethod::GET,
            Method::Post => HttpMethod::POST,
            Method::Patch => HttpMethod::PATCH,
            Method::Delete => HttpMethod::DELETE,
        };
        let mut request = self
            .client
            .request(method, url)
            .header("Accept", "application/json")
            .header(
                "X-Conduit-Client",
                concat!("conduit-cli/", env!("CARGO_PKG_VERSION")),
            );
        if invocation.auth_required {
            let token = self.token.as_deref().ok_or_else(|| {
                CliError::Unavailable(
                    "no CLI access token; set CONDUIT_ACCESS_TOKEN or complete `conduit auth login`"
                        .to_owned(),
                )
            })?;
            request = request.bearer_auth(token);
        }
        if let Some(key) = invocation.idempotency_key.as_deref() {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(revision) = invocation.revision {
            request = request.header("If-Match", format!("\"{revision}\""));
        }
        if let Some(body) = invocation.body.as_ref() {
            request = request.json(body);
        }
        decode_http_response(request.send()?)
    }
}

pub(crate) struct NodeIpcClient {
    socket: PathBuf,
    timeout: Duration,
}

impl NodeIpcClient {
    pub fn from_environment(timeout_seconds: u64) -> Result<Self, CliError> {
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| CliError::Configuration("XDG_RUNTIME_DIR is unset".to_owned()))?;
        if !runtime.is_absolute() {
            return Err(CliError::Configuration(
                "XDG_RUNTIME_DIR must be absolute".to_owned(),
            ));
        }
        Ok(Self {
            socket: runtime.join("conduit/node.sock"),
            timeout: Duration::from_secs(timeout_seconds),
        })
    }

    pub fn execute(&self, invocation: &Invocation) -> Result<Value, CliError> {
        validate_socket_custody(&self.socket)?;
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|error| CliError::Unavailable(format!("node IPC is unavailable: {error}")))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let value = json!({
            "version": 1,
            "requestId": request_id,
            "method": invocation.route,
            "params": invocation.body.clone().unwrap_or_else(|| json!({})),
            "revision": invocation.revision,
            "idempotencyKey": invocation.idempotency_key,
        });
        let mut frame = serde_json::to_vec(&value)?;
        frame.push(b'\n');
        if frame.len() > MAX_IPC_FRAME_BYTES {
            return Err(CliError::Usage(format!(
                "local IPC request exceeds {MAX_IPC_FRAME_BYTES} bytes"
            )));
        }
        stream.write_all(&frame)?;
        stream.flush()?;

        let mut response = Vec::new();
        stream
            .take((MAX_IPC_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut response)?;
        if response.len() > MAX_IPC_FRAME_BYTES {
            return Err(CliError::Unavailable(
                "node IPC response exceeded the bounded frame limit".to_owned(),
            ));
        }
        let value: Value = serde_json::from_slice(&response)?;
        if value.get("requestId").and_then(Value::as_str) != Some(&request_id) {
            return Err(CliError::Unavailable(
                "node IPC response correlation mismatch".to_owned(),
            ));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let code = value
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or("node_error");
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("node rejected the operation");
            return Err(CliError::Denied(format!("{code}: {}", bound(message, 512))));
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn validate_base_url(value: &str) -> Result<Url, CliError> {
    let mut url = Url::parse(value).map_err(|error| CliError::Configuration(error.to_string()))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::Configuration(
            "control-plane URL cannot contain credentials, query, or fragment".to_owned(),
        ));
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CliError::Configuration(
            "control-plane URL must use HTTPS except for loopback development".to_owned(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn load_access_token() -> Result<Option<String>, CliError> {
    if let Ok(value) = env::var("CONDUIT_ACCESS_TOKEN") {
        return validate_token(value).map(Some);
    }
    let config_root = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    let Some(path) = config_root.map(|root| root.join("conduit/access-token")) else {
        return Ok(None);
    };
    let Ok(metadata) = fs::metadata(&path) else {
        return Ok(None);
    };
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_TOKEN_BYTES as u64
    {
        return Err(CliError::Configuration(
            "CLI token file must be owner-only, regular, and bounded".to_owned(),
        ));
    }
    validate_token(fs::read_to_string(path)?).map(Some)
}

fn validate_token(value: String) -> Result<String, CliError> {
    let value = value.trim().to_owned();
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(CliError::Configuration(
            "CLI access token has an invalid bounded representation".to_owned(),
        ));
    }
    Ok(value)
}

fn validate_socket_custody(path: &PathBuf) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CliError::Unavailable(format!("node IPC socket is unavailable: {error}"))
    })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CliError::Denied(
            "node IPC socket failed owner/type/mode custody checks".to_owned(),
        ));
    }
    Ok(())
}

fn decode_http_response(response: Response) -> Result<Value, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_RESPONSE_BYTES as u64)
    {
        return Err(CliError::Unavailable(
            "control-plane response exceeded the bounded response limit".to_owned(),
        ));
    }
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(CliError::Unavailable(
            "control-plane response exceeded the bounded response limit".to_owned(),
        ));
    }
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    if status.is_success() {
        return Ok(value);
    }
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("http_error");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("request failed"));
    let rendered = format!("{code}: {}", bound(message, 512));
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        Err(CliError::Denied(rendered))
    } else {
        Err(CliError::Unavailable(rendered))
    }
}

fn bound(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_tls_remote_control_plane() {
        assert!(validate_base_url("http://example.com").is_err());
        assert!(validate_base_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_base_url("https://control.example.com").is_ok());
    }

    #[test]
    fn token_validation_never_accepts_header_injection() {
        assert!(validate_token("secret\r\nInjected: yes".to_owned()).is_err());
        assert!(validate_token("bounded-token".to_owned()).is_ok());
    }
}
