use std::{
    env, fs,
    fs::File,
    io::{Read, Seek, Write},
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
use sha2::{Digest, Sha256};

use crate::{
    CliError,
    command::{AuthRequirement, Invocation, Method},
};

const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_IPC_FRAME_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

struct BrowserCredentials {
    session: String,
    csrf: String,
}

pub(crate) struct ControlPlaneClient {
    base: Url,
    client: Client,
    token: Option<String>,
    browser: Option<BrowserCredentials>,
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
            browser: load_browser_credentials()?,
        })
    }

    pub fn execute(&self, invocation: &Invocation) -> Result<Value, CliError> {
        let request = self.build_request(invocation)?;
        decode_http_response(self.client.execute(request)?)
    }

    fn build_request(
        &self,
        invocation: &Invocation,
    ) -> Result<reqwest::blocking::Request, CliError> {
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
            Method::Put => HttpMethod::PUT,
        };
        let mut request = self
            .client
            .request(method, url)
            .header("Accept", "application/json")
            .header(
                "X-Conduit-Client",
                concat!("conduit-cli/", env!("CARGO_PKG_VERSION")),
            );
        match invocation.auth {
            AuthRequirement::None => {
                if invocation.method != Method::Get {
                    request = request.header("Origin", self.base.origin().ascii_serialization());
                }
            }
            AuthRequirement::Bearer => {
                let token = self.token.as_deref().ok_or_else(|| {
                    CliError::Unavailable(
                        "no CLI access token; set CONDUIT_ACCESS_TOKEN or complete `conduit auth login`"
                            .to_owned(),
                    )
                })?;
                request = request.bearer_auth(token);
            }
            AuthRequirement::OwnerBearer => {
                let token = self
                    .token
                    .as_deref()
                    .filter(|token| token.starts_with("conduit_owner_"))
                    .ok_or_else(|| {
                        CliError::Unavailable(
                            "this owner-only API requires a conduit_owner_ CLI bearer token"
                                .to_owned(),
                        )
                    })?;
                request = request.bearer_auth(token);
            }
            AuthRequirement::BrowserSession => {
                let browser = self.browser.as_ref().ok_or_else(|| {
                    CliError::Unavailable(
                        "browser-session API requires CONDUIT_SESSION_TOKEN and CONDUIT_CSRF_TOKEN"
                            .to_owned(),
                    )
                })?;
                request = request
                    .header(
                        "Cookie",
                        format!("__Host-conduit_session={}", browser.session),
                    )
                    .header("X-CSRF-Token", &browser.csrf)
                    .header("Origin", self.base.origin().ascii_serialization());
            }
        }
        if let Some(key) = invocation.idempotency_key.as_deref() {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(revision) = invocation.revision {
            request = request.header("If-Match", format!("\"{revision}\""));
        }
        if let Some(upload) = invocation.artifact_upload.as_ref() {
            let mut file = File::open(&upload.file)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
                return Err(CliError::Usage(format!(
                    "artifact must be a regular file no larger than {MAX_ARTIFACT_BYTES} bytes"
                )));
            }
            let mut hasher = Sha256::new();
            let mut chunk = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                hasher.update(&chunk[..read]);
            }
            let digest = hex::encode(hasher.finalize());
            if digest != upload.sha256 {
                return Err(CliError::Usage(
                    "artifact file digest does not match --sha256".to_owned(),
                ));
            }
            request = request
                .header("Content-Length", metadata.len())
                .header("X-Conduit-Content-SHA256", &upload.sha256)
                .header("Content-Type", &upload.content_type)
                .body({
                    file.rewind()?;
                    file
                });
        } else if let Some(body) = invocation.body.as_ref() {
            request = request.json(body);
        }
        request.build().map_err(CliError::from)
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
            "request_id": request_id,
            "method": invocation.route,
            "params": invocation.body.clone().unwrap_or_else(|| json!({})),
            "revision": invocation.revision,
            "idempotency_key": invocation.idempotency_key,
        });
        write_ipc_frame(&mut stream, &value)?;
        let value = read_ipc_frame(&mut stream)?;
        if value.get("request_id").and_then(Value::as_str) != Some(&request_id) {
            return Err(CliError::Unavailable(
                "node IPC response correlation mismatch".to_owned(),
            ));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let error = value.get("error");
            let code = error
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str)
                .unwrap_or("node_error");
            let message = error
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
                .or_else(|| error.and_then(Value::as_str))
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

fn load_browser_credentials() -> Result<Option<BrowserCredentials>, CliError> {
    let session = env::var("CONDUIT_SESSION_TOKEN").ok();
    let csrf = env::var("CONDUIT_CSRF_TOKEN").ok();
    match (session, csrf) {
        (None, None) => Ok(None),
        (Some(session), Some(csrf)) => Ok(Some(BrowserCredentials {
            session: validate_credential(session, MAX_TOKEN_BYTES, "browser session token")?,
            csrf: validate_credential(csrf, 128, "CSRF token")?,
        })),
        _ => Err(CliError::Configuration(
            "CONDUIT_SESSION_TOKEN and CONDUIT_CSRF_TOKEN must be set together".to_owned(),
        )),
    }
}

fn validate_credential(value: String, maximum: usize, name: &str) -> Result<String, CliError> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(CliError::Configuration(format!(
            "{name} has an invalid bounded representation"
        )));
    }
    Ok(value)
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
    let parent = path.parent().ok_or_else(|| {
        CliError::Denied("node IPC socket has no parent custody directory".to_owned())
    })?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CliError::Denied(
            "node IPC parent directory must be owner-only and non-symlinked".to_owned(),
        ));
    }
    Ok(())
}

fn write_ipc_frame(stream: &mut impl Write, value: &Value) -> Result<(), CliError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_IPC_FRAME_BYTES {
        return Err(CliError::Usage(format!(
            "local IPC request exceeds {MAX_IPC_FRAME_BYTES} bytes"
        )));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn read_ipc_frame(stream: &mut impl Read) -> Result<Value, CliError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_IPC_FRAME_BYTES {
        return Err(CliError::Unavailable(
            "node IPC response exceeded the bounded frame limit".to_owned(),
        ));
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(CliError::from)
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
    decode_http_value(status, value)
}

fn decode_http_value(status: StatusCode, value: Value) -> Result<Value, CliError> {
    if status.is_success() {
        return Ok(value);
    }
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .or_else(|| value.get("error").and_then(Value::as_str))
        .unwrap_or("http_error");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| value.get("error_description").and_then(Value::as_str))
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("request failed"));
    let request_suffix = value
        .pointer("/error/requestId")
        .and_then(Value::as_str)
        .map(|request_id| format!(" (request {request_id})"))
        .unwrap_or_default();
    Err(CliError::Api {
        status: status.as_u16(),
        code: bound(code, 128).to_owned(),
        message: bound(message, 512).to_owned(),
        request_suffix,
    })
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
    use clap::Parser;

    use super::*;
    use crate::command::Cli;

    fn test_client(token: Option<&str>, browser: Option<(&str, &str)>) -> ControlPlaneClient {
        ControlPlaneClient {
            base: Url::parse("https://conduit.example.com/").unwrap(),
            client: Client::builder().redirect(Policy::none()).build().unwrap(),
            token: token.map(str::to_owned),
            browser: browser.map(|(session, csrf)| BrowserCredentials {
                session: session.to_owned(),
                csrf: csrf.to_owned(),
            }),
        }
    }

    fn invocation(args: &[&str]) -> Invocation {
        Cli::try_parse_from(args)
            .unwrap()
            .command
            .into_invocation()
            .unwrap()
    }

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

    #[test]
    fn ipc_uses_one_bounded_big_endian_length_frame() {
        let value = json!({"request_id":"req_12345678","ok":true});
        let mut bytes = Vec::new();
        write_ipc_frame(&mut bytes, &value).unwrap();
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        assert_eq!(read_ipc_frame(&mut bytes.as_slice()).unwrap(), value);
    }

    #[test]
    fn ipc_rejects_oversized_response_before_allocating_body() {
        let bytes = ((MAX_IPC_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert!(matches!(
            read_ipc_frame(&mut bytes.as_slice()),
            Err(CliError::Unavailable(_))
        ));
    }

    #[test]
    fn bearer_request_has_exact_canonical_url_and_auth_headers() {
        let request = test_client(Some("conduit_owner_contract_token"), None)
            .build_request(&invocation(&["conduit", "project", "list"]))
            .unwrap();
        assert_eq!(request.method(), HttpMethod::GET);
        assert_eq!(
            request.url().as_str(),
            "https://conduit.example.com/api/v1/projects"
        );
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer conduit_owner_contract_token"
        );
        assert_eq!(request.headers().get("accept").unwrap(), "application/json");
        assert!(request.headers().get("cookie").is_none());
    }

    #[test]
    fn browser_session_request_has_cookie_csrf_origin_and_no_bearer() {
        let mut invocation = invocation(&[
            "conduit",
            "connector",
            "policy",
            "cpol_contract01",
            "--revision",
            "9",
        ]);
        invocation.idempotency_key = Some("policy-update-0001".to_owned());
        let request = test_client(None, Some(("session_contract", "csrf_contract")))
            .build_request(&invocation)
            .unwrap();
        assert_eq!(request.method(), HttpMethod::PATCH);
        assert_eq!(
            request.url().as_str(),
            "https://conduit.example.com/api/v1/connector-policies/cpol_contract01"
        );
        assert_eq!(request.headers().get("if-match").unwrap(), "\"9\"");
        assert_eq!(
            request.headers().get("idempotency-key").unwrap(),
            "policy-update-0001"
        );
        assert_eq!(
            request.headers().get("cookie").unwrap(),
            "__Host-conduit_session=session_contract"
        );
        assert_eq!(
            request.headers().get("x-csrf-token").unwrap(),
            "csrf_contract"
        );
        assert_eq!(
            request.headers().get("origin").unwrap(),
            "https://conduit.example.com"
        );
        assert!(request.headers().get("authorization").is_none());
    }

    #[test]
    fn owner_only_transition_rejects_connector_bearer_before_transport() {
        let invocation = invocation(&[
            "conduit",
            "assignment",
            "cancel",
            "asg_contract01",
            "--revision",
            "2",
        ]);
        assert!(matches!(
            test_client(Some("oauth-connector-token"), None).build_request(&invocation),
            Err(CliError::Unavailable(message)) if message.contains("owner-only")
        ));
        let request = test_client(Some("conduit_owner_contract_token"), None)
            .build_request(&invocation)
            .unwrap();
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer conduit_owner_contract_token"
        );
    }

    #[test]
    fn artifact_upload_commits_exact_digest_length_and_media_type() {
        let path = std::env::temp_dir().join(format!("conduit-artifact-{}", uuid::Uuid::now_v7()));
        fs::write(&path, b"contract artifact").unwrap();
        let digest = hex::encode(Sha256::digest(b"contract artifact"));
        let mut invocation = invocation(&[
            "conduit",
            "artifact",
            "upload",
            "art_contract01",
            "--file",
            path.to_str().unwrap(),
            "--sha256",
            &digest,
            "--content-type",
            "text/plain",
        ]);
        invocation.idempotency_key = Some("artifact-upload-0001".to_owned());
        let request = test_client(Some("connector-token"), None)
            .build_request(&invocation)
            .unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(request.method(), HttpMethod::PUT);
        assert_eq!(
            request.url().as_str(),
            "https://conduit.example.com/api/v1/artifacts/art_contract01/content"
        );
        assert_eq!(request.headers().get("content-length").unwrap(), "17");
        assert_eq!(
            request.headers().get("x-conduit-content-sha256").unwrap(),
            digest.as_str()
        );
        assert_eq!(request.headers().get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn api_error_envelopes_preserve_status_code_message_and_request_id() {
        let error = decode_http_value(
            StatusCode::CONFLICT,
            json!({ "error": { "code": "revision_conflict", "message": "stale target", "requestId": "req_contract01" } }),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::Api { status: 409, code, message, request_suffix }
                if code == "revision_conflict"
                    && message == "stale target"
                    && request_suffix == " (request req_contract01)"
        ));
        let oauth = decode_http_value(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_grant", "error_description": "grant expired" }),
        )
        .unwrap_err();
        assert!(matches!(
            oauth,
            CliError::Api { status: 400, code, message, .. }
                if code == "invalid_grant" && message == "grant expired"
        ));
    }
}
