use std::{
    collections::{BTreeMap, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::types::{
    AdapterError, AdapterEvent, AdapterEventKind, AdapterKind, AdapterOperation, AdapterState,
    ApprovalBridgeOwnership, ApprovalContext, ApprovalRiskClassSet, EffectiveAccessScope,
    EffectiveApprovalPolicy, EffectiveSandboxPolicy, LaunchRequest, MAX_PROTOCOL_FRAME_BYTES,
    ProtocolFrame, validate_launch_request,
};

const MAX_REPLAY_EVENTS: usize = 4_096;
const MAX_PENDING_CODEX_REQUESTS: usize = 64;
const MAX_PENDING_CODEX_APPROVALS: usize = 1;
// Provider request IDs are process-scoped. Settled IDs are retained without eviction so a reused
// ID can never receive a different terminal response. Once the bound is reached, new IDs fail
// closed without a response for the remainder of the adapter process lifetime.
const MAX_PROVIDER_REQUEST_TERMINALS: usize = 256;
const CODEX_APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;
const ACP_PERMISSION_TTL_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexResponseKind {
    Initialize,
    ThreadStart,
    ThreadResume,
    TurnStart,
    TurnSteer,
    TurnInterrupt,
    ThreadRead,
    ModelList,
    ThreadArchive,
}

#[derive(Debug, Clone)]
struct PendingCodexRequest {
    method: &'static str,
    response: CodexResponseKind,
    completed_turn_id: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingCodexApproval {
    request_id: Value,
    method: &'static str,
    params_digest: String,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    CodexInitialize,
    CodexThread,
    CodexTurn,
    AcpInitialize,
    AcpSession,
    AcpPrompt,
    Ready,
    Active,
    OneShot,
    Terminal,
}

#[derive(Debug)]
struct PendingAcpPermission {
    request_id: Value,
    method: &'static str,
    session_id: String,
    tool_call_id: String,
    params_digest: String,
    allow_once_option_id: Option<String>,
    expires_at_unix_ms: u64,
}

#[derive(Debug)]
struct PendingPiDialog {
    request_id: Value,
    method: String,
    params_digest: String,
}

#[derive(Debug, Clone)]
struct ProviderRequestTerminal {
    method: String,
    params_digest: String,
    response: ProtocolFrame,
}

#[derive(Debug)]
pub struct ProtocolDriver {
    kind: AdapterKind,
    phase: Phase,
    state: AdapterState,
    prompt: Option<String>,
    cwd: String,
    model: Option<String>,
    effort: Option<String>,
    requested_session_id: Option<String>,
    native_session_id: Option<String>,
    active_turn_id: Option<String>,
    next_request_id: u64,
    pending_codex: BTreeMap<u64, PendingCodexRequest>,
    pending_codex_approvals: BTreeMap<String, PendingCodexApproval>,
    effective_access_scope: EffectiveAccessScope,
    effective_sandbox_policy: EffectiveSandboxPolicy,
    approval_context: ApprovalContext,
    pending_acp_permission: Option<PendingAcpPermission>,
    pending_acp_prompt_id: Option<u64>,
    pending_pi_dialog: Option<PendingPiDialog>,
    provider_request_terminals: BTreeMap<String, ProviderRequestTerminal>,
    replay: VecDeque<AdapterEvent>,
}

impl ProtocolDriver {
    pub fn new(kind: AdapterKind, request: &LaunchRequest) -> Result<Self, AdapterError> {
        Self::new_with_approval_context(kind, request, ApprovalContext::default())
    }

    pub fn new_with_approval_context(
        kind: AdapterKind,
        request: &LaunchRequest,
        approval_context: ApprovalContext,
    ) -> Result<Self, AdapterError> {
        Self::new_with_authority_context(
            kind,
            request,
            EffectiveAccessScope::ReadOnly,
            EffectiveSandboxPolicy::ReadOnly,
            approval_context,
        )
    }

    pub fn new_with_authority_context(
        kind: AdapterKind,
        request: &LaunchRequest,
        effective_access_scope: EffectiveAccessScope,
        effective_sandbox_policy: EffectiveSandboxPolicy,
        approval_context: ApprovalContext,
    ) -> Result<Self, AdapterError> {
        validate_launch_request(request)?;
        let phase = match kind {
            AdapterKind::Codex => Phase::CodexInitialize,
            AdapterKind::OpenCode => Phase::AcpInitialize,
            AdapterKind::Pi => Phase::Ready,
            AdapterKind::ClaudeCode | AdapterKind::Agy => Phase::OneShot,
        };
        Ok(Self {
            kind,
            phase,
            state: AdapterState::Starting,
            prompt: request.prompt.clone(),
            cwd: request.cwd.to_string_lossy().into_owned(),
            model: request.model.clone(),
            effort: request.effort.clone(),
            requested_session_id: request.native_session_id.clone(),
            native_session_id: None,
            active_turn_id: None,
            next_request_id: 1,
            pending_codex: BTreeMap::new(),
            pending_codex_approvals: BTreeMap::new(),
            effective_access_scope,
            effective_sandbox_policy,
            approval_context,
            pending_acp_permission: None,
            pending_acp_prompt_id: None,
            pending_pi_dialog: None,
            provider_request_terminals: BTreeMap::new(),
            replay: VecDeque::new(),
        })
    }

    pub fn start(&mut self) -> Result<Vec<ProtocolFrame>, AdapterError> {
        match self.phase {
            Phase::CodexInitialize => Ok(vec![self.codex_request(
                "initialize",
                json!({
                    "clientInfo": {"name": "conduit", "title": "Conduit", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"experimentalApi": true}
                }),
                CodexResponseKind::Initialize,
            )?]),
            Phase::AcpInitialize => Ok(vec![self.json_rpc_request(
                "initialize",
                json!({
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {"readTextFile": false, "writeTextFile": false},
                        "terminal": false
                    },
                    "clientInfo": {"name": "conduit", "version": env!("CARGO_PKG_VERSION")}
                }),
            )?]),
            Phase::Ready if self.kind == AdapterKind::Pi => {
                self.state = AdapterState::Ready;
                if let Some(prompt) = self.prompt.clone() {
                    let frame = self.pi_command("prompt", Some(prompt.as_str()))?;
                    Ok(vec![frame])
                } else {
                    Ok(Vec::new())
                }
            }
            Phase::OneShot => {
                self.state = if self.prompt.is_some() {
                    AdapterState::Working
                } else {
                    AdapterState::Ready
                };
                match (self.kind, self.prompt.as_deref()) {
                    (AdapterKind::ClaudeCode, Some(prompt)) => {
                        Ok(vec![ProtocolFrame::json(&json!({
                            "type": "user",
                            "message": {"role": "user", "content": prompt},
                            "parent_tool_use_id": null,
                            "session_id": self.requested_session_id
                        }))?])
                    }
                    (AdapterKind::Agy, Some(prompt)) => Ok(vec![ProtocolFrame::json(&json!({
                        "event": "user",
                        "message": {"content": prompt}
                    }))?]),
                    _ => Ok(Vec::new()),
                }
            }
            _ => Err(AdapterError::UnexpectedResponse {
                phase: self.phase_name(),
                reason: "driver was already started",
            }),
        }
    }

    pub const fn state(&self) -> AdapterState {
        self.state
    }

    pub const fn approval_context(&self) -> ApprovalContext {
        self.approval_context
    }

    pub const fn effective_access_scope(&self) -> EffectiveAccessScope {
        self.effective_access_scope
    }

    pub const fn effective_sandbox_policy(&self) -> EffectiveSandboxPolicy {
        self.effective_sandbox_policy
    }

    pub fn native_session_id(&self) -> Option<&str> {
        self.native_session_id
            .as_deref()
            .or(self.requested_session_id.as_deref())
    }

    pub fn replay(&self) -> Vec<AdapterEvent> {
        self.replay.iter().cloned().collect()
    }

    pub fn on_record(
        &mut self,
        record: &[u8],
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        let value = parse_frame(record)?;
        let (frames, events) = match self.kind {
            AdapterKind::Codex => self.on_codex(&value)?,
            AdapterKind::OpenCode => self.on_acp(&value)?,
            AdapterKind::Pi => self.on_pi(&value)?,
            AdapterKind::ClaudeCode => (Vec::new(), self.normalize_claude(&value)),
            AdapterKind::Agy => (Vec::new(), self.normalize_agy(&value)),
        };
        for event in &events {
            self.push_event(event.clone());
        }
        Ok((frames, events))
    }

    pub fn command(
        &mut self,
        operation: AdapterOperation,
        text: Option<&str>,
    ) -> Result<Vec<ProtocolFrame>, AdapterError> {
        if text.is_some_and(|value| value.len() > crate::types::MAX_PROMPT_BYTES) {
            return Err(AdapterError::PromptTooLarge {
                maximum: crate::types::MAX_PROMPT_BYTES,
            });
        }
        match self.kind {
            AdapterKind::Codex => self.codex_command(operation, text),
            AdapterKind::OpenCode => self.acp_command(operation, text),
            AdapterKind::Pi => self.pi_operation(operation, text),
            AdapterKind::ClaudeCode | AdapterKind::Agy => Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation,
                reason: "one-shot structured adapter requires a new supervised process",
            }),
        }
    }

    pub fn approval_response(
        &mut self,
        request_id: &Value,
        allow: bool,
    ) -> Result<ProtocolFrame, AdapterError> {
        match self.kind {
            AdapterKind::Codex => Err(AdapterError::UnexpectedResponse {
                phase: "codex_server_request",
                reason: "Codex approval requires method, parameters digest, and expiry commitment",
            }),
            AdapterKind::OpenCode => {
                let pending = self.pending_acp_permission.as_ref().ok_or(
                    AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "no typed ACP permission request is pending",
                    },
                )?;
                if pending.request_id != *request_id
                    || self.native_session_id() != Some(pending.session_id.as_str())
                {
                    return Err(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "approval response did not match the pending ACP request binding",
                    });
                }
                if pending.expires_at_unix_ms <= unix_ms() {
                    let pending = self.pending_acp_permission.take().expect("checked");
                    self.mark_provider_request_settled();
                    let key = server_request_key(&pending.request_id).expect("admitted id");
                    let frame = acp_permission_cancelled(&pending.request_id)?;
                    return self.record_provider_request_terminal(
                        key,
                        pending.method,
                        pending.params_digest,
                        frame,
                    );
                }
                let pending = self.pending_acp_permission.take().expect("checked");
                self.mark_provider_request_settled();
                let key = server_request_key(&pending.request_id).expect("admitted id");
                let frame = if allow {
                    match pending.allow_once_option_id.as_deref() {
                        Some(option_id) => acp_permission_selected(request_id, option_id),
                        None => acp_permission_cancelled(request_id),
                    }
                } else {
                    acp_permission_cancelled(request_id)
                }?;
                self.record_provider_request_terminal(
                    key,
                    pending.method,
                    pending.params_digest,
                    frame,
                )
            }
            AdapterKind::Pi => {
                let pending =
                    self.pending_pi_dialog
                        .take()
                        .ok_or(AdapterError::UnexpectedResponse {
                            phase: self.phase_name(),
                            reason: "no typed Pi dialog request is pending",
                        })?;
                if pending.request_id != *request_id {
                    self.pending_pi_dialog = Some(pending);
                    return Err(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "approval response did not match the pending Pi dialog request",
                    });
                }
                self.mark_provider_request_settled();
                let _ = allow;
                let key = server_request_key(&pending.request_id).expect("admitted id");
                let frame = pi_dialog_cancelled(request_id)?;
                self.record_provider_request_terminal(
                    key,
                    &pending.method,
                    pending.params_digest,
                    frame,
                )
            }
            _ => Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation: AdapterOperation::Send,
                reason: "adapter has no typed correlated approval response protocol",
            }),
        }
    }

    pub fn resolve_codex_approval(
        &mut self,
        request_id: &Value,
        method: &str,
        params_digest: &str,
        allow: bool,
        now_unix_ms: u64,
    ) -> Result<ProtocolFrame, AdapterError> {
        if self.kind != AdapterKind::Codex {
            return Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation: AdapterOperation::Send,
                reason: "commitment-bound Codex approval used for a different adapter",
            });
        }
        let key = server_request_key(request_id).ok_or(AdapterError::UnexpectedResponse {
            phase: "codex_server_request",
            reason: "approval response id has an unsupported JSON-RPC type",
        })?;
        let pending =
            self.pending_codex_approvals
                .get(&key)
                .ok_or(AdapterError::UnexpectedResponse {
                    phase: "codex_server_request",
                    reason: "approval response id is not outstanding",
                })?;
        if pending.method != method || pending.params_digest != params_digest {
            return Err(AdapterError::UnexpectedResponse {
                phase: "codex_server_request",
                reason: "approval response commitment does not match the pending request",
            });
        }
        if pending.expires_at_unix_ms <= now_unix_ms {
            let pending = self.pending_codex_approvals.remove(&key).expect("checked");
            self.mark_provider_request_settled();
            let frame = codex_approval_response(pending.method, &pending.request_id, false)?;
            return self.record_provider_request_terminal(
                key,
                pending.method,
                pending.params_digest,
                frame,
            );
        }
        let pending = self.pending_codex_approvals.remove(&key).expect("checked");
        self.mark_provider_request_settled();
        let frame = codex_approval_response(pending.method, &pending.request_id, allow)?;
        self.record_provider_request_terminal(key, pending.method, pending.params_digest, frame)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_acp_permission(
        &mut self,
        request_id: &Value,
        method: &str,
        session_id: &str,
        tool_call_id: &str,
        params_digest: &str,
        allow: bool,
        now_unix_ms: u64,
    ) -> Result<ProtocolFrame, AdapterError> {
        if self.kind != AdapterKind::OpenCode {
            return Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation: AdapterOperation::Send,
                reason: "commitment-bound ACP approval used for a different adapter",
            });
        }
        let pending =
            self.pending_acp_permission
                .as_ref()
                .ok_or(AdapterError::UnexpectedResponse {
                    phase: "acp_permission_request",
                    reason: "no typed ACP permission request is pending",
                })?;
        if pending.request_id != *request_id
            || pending.method != method
            || pending.session_id != session_id
            || pending.tool_call_id != tool_call_id
            || pending.params_digest != params_digest
            || self.native_session_id() != Some(pending.session_id.as_str())
        {
            return Err(AdapterError::UnexpectedResponse {
                phase: "acp_permission_request",
                reason: "approval response commitment does not match the pending ACP request",
            });
        }
        if pending.expires_at_unix_ms <= now_unix_ms {
            let pending = self.pending_acp_permission.take().expect("checked");
            self.mark_provider_request_settled();
            let key = server_request_key(&pending.request_id).expect("admitted id");
            let frame = acp_permission_cancelled(&pending.request_id)?;
            return self.record_provider_request_terminal(
                key,
                pending.method,
                pending.params_digest,
                frame,
            );
        }
        let pending = self.pending_acp_permission.take().expect("checked");
        self.mark_provider_request_settled();
        let key = server_request_key(&pending.request_id).expect("admitted id");
        let frame = if allow {
            match pending.allow_once_option_id.as_deref() {
                Some(option_id) => acp_permission_selected(&pending.request_id, option_id),
                None => acp_permission_cancelled(&pending.request_id),
            }
        } else {
            acp_permission_cancelled(&pending.request_id)
        }?;
        self.record_provider_request_terminal(key, pending.method, pending.params_digest, frame)
    }

    pub fn expire_codex_approvals(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        if self.kind != AdapterKind::Codex {
            return Ok((Vec::new(), Vec::new()));
        }
        let expired = self
            .pending_codex_approvals
            .iter()
            .filter(|(_, pending)| pending.expires_at_unix_ms <= now_unix_ms)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut frames = Vec::with_capacity(expired.len());
        let mut events = Vec::with_capacity(expired.len());
        for key in expired {
            let pending = self.pending_codex_approvals.remove(&key).expect("selected");
            let frame = codex_approval_response(pending.method, &pending.request_id, false)?;
            frames.push(self.record_provider_request_terminal(
                key,
                pending.method,
                pending.params_digest.clone(),
                frame,
            )?);
            events.push(AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                pending.method,
                self.native_session_id(),
                Some(&request_id_text(&pending.request_id)),
                Some("commitment-bound approval expired and was denied"),
                Some(json!({
                    "providerRequestId": pending.request_id,
                    "method": pending.method,
                    "parametersDigest": pending.params_digest,
                    "approvalExpired": true
                })),
            ));
        }
        if self.pending_codex_approvals.is_empty() && !frames.is_empty() {
            self.mark_provider_request_settled();
        }
        Ok((frames, events))
    }

    fn on_codex(
        &mut self,
        value: &Value,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        if let Some(method) = value.get("method").and_then(Value::as_str) {
            if let Some(request_id) = value.get("id") {
                let correlation_id = request_id_text(request_id);
                let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
                let params_digest = canonical_digest(&params)?;
                let Some(key) = server_request_key(request_id) else {
                    return Ok(self.provider_request_admission_error(
                        method,
                        &correlation_id,
                        "provider request id had an unsupported type; no response was emitted",
                    ));
                };
                if let Some(outcome) = self.terminal_provider_request_outcome(
                    &key,
                    method,
                    &params_digest,
                    &correlation_id,
                ) {
                    return Ok(outcome);
                }
                if let Some(existing) = self.pending_codex_approvals.get(&key) {
                    return Ok((
                        Vec::new(),
                        vec![AdapterEvent::bounded(
                            AdapterEventKind::AdapterError,
                            method,
                            self.native_session_id(),
                            Some(&correlation_id),
                            Some(
                                "duplicate outstanding server request id was ignored; original request remains pending",
                            ),
                            Some(json!({
                                "existingMethod": existing.method,
                                "existingParametersDigest": existing.params_digest,
                                "duplicateParametersDigest": params_digest,
                                "sameCommitment": existing.method == method
                                    && existing.params_digest == params_digest
                            })),
                        )],
                    ));
                }
                if self.provider_request_slots_used() >= MAX_PROVIDER_REQUEST_TERMINALS {
                    return Ok(self.provider_request_capacity_error(method, &correlation_id));
                }
                if is_codex_approval_method(method) {
                    if !self.codex_approval_requires_bridge(method) {
                        let frame = codex_approval_response(method, request_id, true)?;
                        let event = AdapterEvent::bounded(
                            AdapterEventKind::ApprovalRequest,
                            method,
                            self.native_session_id(),
                            Some(&correlation_id),
                            Some("pre-authorized by the effective Conduit Approval Policy"),
                            Some(json!({
                                "providerRequestId": request_id,
                                "method": method,
                                "parametersDigest": params_digest,
                                "decision": "approved",
                                "preAuthorized": true
                            })),
                        );
                        let frame = self.record_provider_request_terminal(
                            key,
                            method,
                            params_digest.clone(),
                            frame,
                        )?;
                        return Ok((vec![frame], vec![event]));
                    }
                    if self.approval_context.bridge == ApprovalBridgeOwnership::Typed {
                        if self.pending_codex_approvals.len() >= MAX_PENDING_CODEX_APPROVALS {
                            let frame = codex_approval_response(method, request_id, false)?;
                            let frame = self.record_provider_request_terminal(
                                key,
                                method,
                                params_digest,
                                frame,
                            )?;
                            return Ok((
                                vec![frame],
                                vec![AdapterEvent::bounded(
                                    AdapterEventKind::AdapterError,
                                    method,
                                    self.native_session_id(),
                                    Some(&correlation_id),
                                    Some("bounded approval map is full; request was denied"),
                                    None,
                                )],
                            ));
                        }
                        let expires_at_unix_ms = unix_ms().saturating_add(CODEX_APPROVAL_TTL_MS);
                        self.pending_codex_approvals.insert(
                            key,
                            PendingCodexApproval {
                                request_id: request_id.clone(),
                                method: codex_approval_method(method).expect("matched"),
                                params_digest: params_digest.clone(),
                                expires_at_unix_ms,
                            },
                        );
                        self.state = AdapterState::WaitingApproval;
                        let event = AdapterEvent::bounded(
                            AdapterEventKind::ApprovalRequest,
                            method,
                            self.native_session_id(),
                            Some(&correlation_id),
                            Some("waiting for a commitment-bound Conduit Approval"),
                            Some(json!({
                                "providerRequestId": request_id,
                                "method": method,
                                "parametersDigest": params_digest,
                                "argumentsSummary": codex_approval_summary(method, &params, &params_digest),
                                "expiresAtUnixMs": expires_at_unix_ms,
                                "preAuthorized": false
                            })),
                        );
                        return Ok((Vec::new(), vec![event]));
                    }
                    let frame = codex_approval_response(method, request_id, false)?;
                    let event = AdapterEvent::bounded(
                        AdapterEventKind::ApprovalRequest,
                        method,
                        self.native_session_id(),
                        Some(&correlation_id),
                        Some("declined because the typed Conduit approval bridge is unavailable"),
                        Some(json!({
                            "providerRequestId": request_id,
                            "method": method,
                            "parametersDigest": params_digest,
                            "decision": "denied",
                            "preAuthorized": false
                        })),
                    );
                    let frame =
                        self.record_provider_request_terminal(key, method, params_digest, frame)?;
                    return Ok((vec![frame], vec![event]));
                }

                let known = is_codex_server_request(method);
                let frame = codex_fail_closed_response(method, request_id, known)?;
                let event = AdapterEvent::bounded(
                    AdapterEventKind::AdapterError,
                    method,
                    self.native_session_id(),
                    Some(&correlation_id),
                    Some(if known {
                        "Codex server request capability was not advertised and was denied"
                    } else {
                        "unknown Codex server request was denied"
                    }),
                    Some(params),
                );
                let frame =
                    self.record_provider_request_terminal(key, method, params_digest, frame)?;
                return Ok((vec![frame], vec![event]));
            }
            return Ok((Vec::new(), self.normalize_codex_notification(method, value)));
        }
        self.on_codex_response(value)
    }

    fn on_codex_response(
        &mut self,
        value: &Value,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        let id = value.get("id").and_then(Value::as_u64);
        let correlation = value.get("id").map(request_id_text);
        let Some(id) = id else {
            return Ok((
                Vec::new(),
                vec![self.codex_response_error(
                    correlation.as_deref(),
                    "response id was absent or was not the numeric client request id type",
                )],
            ));
        };
        let Some(pending) = self.pending_codex.remove(&id) else {
            return Ok((
                Vec::new(),
                vec![self.codex_response_error(
                    correlation.as_deref(),
                    "response id is not outstanding (wrong id or duplicate response)",
                )],
            ));
        };

        if value.get("error").is_some() {
            if matches!(
                pending.response,
                CodexResponseKind::Initialize
                    | CodexResponseKind::ThreadStart
                    | CodexResponseKind::ThreadResume
                    | CodexResponseKind::TurnStart
            ) {
                self.state = AdapterState::Failed;
            }
            return Ok((
                Vec::new(),
                vec![AdapterEvent::bounded(
                    AdapterEventKind::Error,
                    pending.method,
                    self.native_session_id(),
                    correlation.as_deref(),
                    value.pointer("/error/message").and_then(Value::as_str),
                    value.get("error").cloned(),
                )],
            ));
        }
        let result = match value.get("result") {
            Some(result) => result,
            None => {
                return Ok((
                    Vec::new(),
                    vec![self.codex_correlated_response_error(
                        correlation.as_deref(),
                        "correlated response omitted result",
                    )],
                ));
            }
        };

        match pending.response {
            CodexResponseKind::Initialize => {
                if !result.is_object() {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "initialize result was not an object",
                        )],
                    ));
                }
                self.phase = Phase::CodexThread;
                let (method, response, mut params) = self.requested_session_id.as_ref().map_or_else(
                    || {
                        (
                            "thread/start",
                            CodexResponseKind::ThreadStart,
                            json!({"cwd": self.cwd}),
                        )
                    },
                    |session_id| {
                        (
                            "thread/resume",
                            CodexResponseKind::ThreadResume,
                            json!({"threadId": session_id, "cwd": self.cwd, "excludeTurns": true}),
                        )
                    },
                );
                params["approvalPolicy"] = Value::String(self.codex_approval_policy().to_owned());
                params["sandbox"] = Value::String(self.codex_sandbox_mode().to_owned());
                params["approvalsReviewer"] = Value::String("user".to_owned());
                if let Some(model) = &self.model {
                    params["model"] = Value::String(model.clone());
                }
                Ok((
                    vec![
                        ProtocolFrame::json(&json!({"method": "initialized"}))?,
                        self.codex_request(method, params, response)?,
                    ],
                    Vec::new(),
                ))
            }
            CodexResponseKind::ThreadStart | CodexResponseKind::ThreadResume => {
                let Some(session_id) = result.pointer("/thread/id").and_then(Value::as_str) else {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "thread response omitted result.thread.id",
                        )],
                    ));
                };
                if matches!(pending.response, CodexResponseKind::ThreadResume)
                    && self.requested_session_id.as_deref() != Some(session_id)
                {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "thread/resume returned a different thread id",
                        )],
                    ));
                }
                let session_id = session_id.to_owned();
                self.native_session_id = Some(session_id.clone());
                self.state = AdapterState::Ready;
                let event = AdapterEvent::bounded(
                    AdapterEventKind::Session,
                    pending.method,
                    Some(&session_id),
                    correlation.as_deref(),
                    None,
                    None,
                );
                if let Some(prompt) = self.prompt.take() {
                    self.phase = Phase::CodexTurn;
                    self.state = AdapterState::Starting;
                    Ok((vec![self.codex_turn(&prompt)?], vec![event]))
                } else {
                    self.phase = Phase::Ready;
                    Ok((Vec::new(), vec![event]))
                }
            }
            CodexResponseKind::TurnStart => {
                let Some(turn_id) = result.pointer("/turn/id").and_then(Value::as_str) else {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "turn response omitted result.turn.id",
                        )],
                    ));
                };
                if let Some(completed_turn_id) = pending.completed_turn_id.as_deref() {
                    if completed_turn_id != turn_id {
                        return Ok((
                            Vec::new(),
                            vec![self.codex_correlated_response_error(
                                correlation.as_deref(),
                                "delayed turn/start response did not match the completed turn notification",
                            )],
                        ));
                    }
                    return Ok((
                        Vec::new(),
                        vec![AdapterEvent::bounded(
                            AdapterEventKind::State,
                            pending.method,
                            self.native_session_id(),
                            Some(turn_id),
                            Some(
                                "delayed correlated turn/start response consumed after turn completion",
                            ),
                            Some(json!({"requestId": id, "turnAlreadyCompleted": true})),
                        )],
                    ));
                }
                if self
                    .active_turn_id
                    .as_deref()
                    .is_some_and(|active| active != turn_id)
                {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "turn/start response conflicts with the correlated turn/started notification",
                        )],
                    ));
                }
                let turn_id = turn_id.to_owned();
                self.active_turn_id = Some(turn_id.clone());
                self.phase = Phase::Active;
                self.state = AdapterState::Working;
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::PromptAccepted,
                        pending.method,
                        self.native_session_id(),
                        Some(&turn_id),
                        None,
                        Some(json!({"requestId": id})),
                    )],
                ))
            }
            CodexResponseKind::TurnSteer => {
                let Some(turn_id) = result.get("turnId").and_then(Value::as_str) else {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "turn/steer response omitted result.turnId",
                        )],
                    ));
                };
                if self.active_turn_id.as_deref() != Some(turn_id) {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "turn/steer response did not match the active turn",
                        )],
                    ));
                }
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::PromptAccepted,
                        pending.method,
                        self.native_session_id(),
                        Some(turn_id),
                        None,
                        Some(json!({"requestId": id})),
                    )],
                ))
            }
            CodexResponseKind::TurnInterrupt => {
                if !result.is_object() {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "turn/interrupt result was not an object",
                        )],
                    ));
                }
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::State,
                        pending.method,
                        self.native_session_id(),
                        self.active_turn_id.as_deref(),
                        Some("interrupt accepted; terminal state awaits turn/completed"),
                        Some(json!({"requestId": id})),
                    )],
                ))
            }
            CodexResponseKind::ThreadRead => {
                let Some(thread_id) = result.pointer("/thread/id").and_then(Value::as_str) else {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "thread/read response omitted result.thread.id",
                        )],
                    ));
                };
                if self.native_session_id() != Some(thread_id) {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "thread/read response was for a different thread",
                        )],
                    ));
                }
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::State,
                        pending.method,
                        Some(thread_id),
                        correlation.as_deref(),
                        None,
                        Some(json!({"threadId": thread_id})),
                    )],
                ))
            }
            CodexResponseKind::ModelList => {
                let Some(models) = result.get("data").and_then(Value::as_array) else {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "model/list response omitted result.data",
                        )],
                    ));
                };
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::State,
                        pending.method,
                        self.native_session_id(),
                        correlation.as_deref(),
                        Some("model list received"),
                        Some(
                            json!({"count": models.len(), "nextCursor": result.get("nextCursor")}),
                        ),
                    )],
                ))
            }
            CodexResponseKind::ThreadArchive => {
                if !result.is_object() {
                    return Ok((
                        Vec::new(),
                        vec![self.codex_correlated_response_error(
                            correlation.as_deref(),
                            "thread/archive result was not an object",
                        )],
                    ));
                }
                self.phase = Phase::Terminal;
                self.state = AdapterState::Completed;
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::Completed,
                        pending.method,
                        self.native_session_id(),
                        correlation.as_deref(),
                        Some("thread archived"),
                        None,
                    )],
                ))
            }
        }
    }

    fn codex_response_error(&self, correlation_id: Option<&str>, reason: &str) -> AdapterEvent {
        AdapterEvent::bounded(
            AdapterEventKind::AdapterError,
            "unexpected_response",
            self.native_session_id(),
            correlation_id,
            Some(reason),
            None,
        )
    }

    fn codex_correlated_response_error(
        &mut self,
        correlation_id: Option<&str>,
        reason: &str,
    ) -> AdapterEvent {
        self.phase = Phase::Terminal;
        self.state = AdapterState::Failed;
        self.codex_response_error(correlation_id, reason)
    }

    fn normalize_codex_notification(&mut self, method: &str, value: &Value) -> Vec<AdapterEvent> {
        let params = value.get("params");
        let event = match method {
            "turn/started" => {
                let turn_id = params
                    .and_then(|params| params.pointer("/turn/id"))
                    .and_then(Value::as_str);
                let has_pending_turn_start = self
                    .pending_codex
                    .values()
                    .any(|pending| pending.response == CodexResponseKind::TurnStart);
                if self.active_turn_id.is_none() && !has_pending_turn_start {
                    return vec![self.codex_response_error(
                        turn_id,
                        "stale turn/started notification had no active turn/start request",
                    )];
                }
                if self
                    .active_turn_id
                    .as_deref()
                    .zip(turn_id)
                    .is_some_and(|(active, observed)| active != observed)
                {
                    return vec![self.codex_response_error(
                        turn_id,
                        "stale turn/started notification did not match the active turn",
                    )];
                }
                if let Some(turn_id) = turn_id {
                    self.active_turn_id
                        .get_or_insert_with(|| turn_id.to_owned());
                }
                self.state = AdapterState::Working;
                AdapterEvent::bounded(
                    AdapterEventKind::State,
                    method,
                    self.native_session_id(),
                    turn_id,
                    Some("working"),
                    None,
                )
            }
            "turn/completed" => {
                let turn_id = params
                    .and_then(|params| params.pointer("/turn/id"))
                    .and_then(Value::as_str);
                if self.active_turn_id.as_deref() != turn_id || turn_id.is_none() {
                    return vec![self.codex_response_error(
                        turn_id,
                        "stale or duplicate turn/completed notification did not match the active turn",
                    )];
                }
                self.active_turn_id = None;
                for pending in self
                    .pending_codex
                    .values_mut()
                    .filter(|pending| pending.response == CodexResponseKind::TurnStart)
                {
                    pending.completed_turn_id = Some(turn_id.expect("validated").to_owned());
                }
                self.phase = Phase::Ready;
                self.state = AdapterState::Completed;
                AdapterEvent::bounded(
                    AdapterEventKind::Completed,
                    method,
                    self.native_session_id(),
                    turn_id,
                    params
                        .and_then(|params| params.pointer("/turn/status/type"))
                        .and_then(Value::as_str),
                    None,
                )
            }
            "item/completed" | "item/started" => {
                let item = params.and_then(|params| params.get("item"));
                let item_type = item
                    .and_then(|item| item.get("type"))
                    .and_then(Value::as_str);
                let kind = match item_type {
                    Some("agentMessage") => AdapterEventKind::AssistantMessage,
                    Some("commandExecution") => AdapterEventKind::Command,
                    Some("fileChange") => AdapterEventKind::FileEffect,
                    Some("mcpToolCall" | "dynamicToolCall") => AdapterEventKind::ToolCall,
                    Some("collabAgentToolCall") => AdapterEventKind::Subagent,
                    Some("reasoning") => return Vec::new(),
                    _ => AdapterEventKind::AdapterError,
                };
                let text = item
                    .and_then(|item| item.get("text"))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        item.and_then(|item| item.get("command"))
                            .and_then(Value::as_str)
                    });
                AdapterEvent::bounded(
                    kind,
                    method,
                    self.native_session_id(),
                    item.and_then(|item| item.get("id")).and_then(Value::as_str),
                    text,
                    item_type.map(|item_type| json!({"itemType": item_type})),
                )
            }
            "thread/tokenUsage/updated" => AdapterEvent::bounded(
                AdapterEventKind::Usage,
                method,
                self.native_session_id(),
                None,
                None,
                params.cloned(),
            ),
            "error" => {
                self.state = AdapterState::Failed;
                AdapterEvent::bounded(
                    AdapterEventKind::Error,
                    method,
                    self.native_session_id(),
                    None,
                    params
                        .and_then(|params| params.get("message"))
                        .and_then(Value::as_str),
                    None,
                )
            }
            _ if method.contains("reasoning") || method.contains("rawResponse") => {
                return Vec::new();
            }
            _ => AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                method,
                self.native_session_id(),
                None,
                Some("unrecognized bounded Codex notification"),
                None,
            ),
        };
        vec![event]
    }

    fn on_acp(
        &mut self,
        value: &Value,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        if let Some(method) = value.get("method").and_then(Value::as_str) {
            if let Some(request_id) = value.get("id") {
                let correlation_id = request_id_text(request_id);
                let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
                let params_digest = canonical_digest(&params)?;
                let Some(key) = server_request_key(request_id) else {
                    return Ok(self.provider_request_admission_error(
                        method,
                        &correlation_id,
                        "provider request id had an unsupported type; no response was emitted",
                    ));
                };
                if let Some(outcome) = self.terminal_provider_request_outcome(
                    &key,
                    method,
                    &params_digest,
                    &correlation_id,
                ) {
                    return Ok(outcome);
                }
                if let Some(pending) = self.pending_acp_permission.as_ref()
                    && server_request_key(&pending.request_id).as_deref() == Some(key.as_str())
                {
                    return Ok((
                        Vec::new(),
                        vec![AdapterEvent::bounded(
                            AdapterEventKind::AdapterError,
                            method,
                            self.native_session_id(),
                            Some(&correlation_id),
                            Some(
                                "duplicate outstanding ACP permission id was ignored; original request remains pending",
                            ),
                            Some(json!({
                                "existingMethod": pending.method,
                                "existingParametersDigest": pending.params_digest,
                                "duplicateParametersDigest": params_digest,
                                "sameCommitment": pending.method == method
                                    && pending.params_digest == params_digest
                            })),
                        )],
                    ));
                }
                if self.provider_request_slots_used() >= MAX_PROVIDER_REQUEST_TERMINALS {
                    return Ok(self.provider_request_capacity_error(method, &correlation_id));
                }
                if method == "session/request_permission" {
                    let allow_once_option_id = acp_allow_once_option(value);
                    let requested_session_id = params
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let tool_call_id = params
                        .pointer("/toolCall/toolCallId")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if requested_session_id.is_none()
                        || requested_session_id.as_deref() != self.native_session_id()
                        || tool_call_id.is_none()
                    {
                        let frame = acp_permission_cancelled(request_id)?;
                        let frame = self.record_provider_request_terminal(
                            key,
                            method,
                            params_digest.clone(),
                            frame,
                        )?;
                        return Ok((
                            vec![frame],
                            vec![AdapterEvent::bounded(
                                AdapterEventKind::AdapterError,
                                method,
                                self.native_session_id(),
                                Some(&correlation_id),
                                Some(
                                    "ACP permission request did not match the active session and tool call binding; request was cancelled",
                                ),
                                Some(json!({"parametersDigest": params_digest})),
                            )],
                        ));
                    }
                    let expires_at_unix_ms = unix_ms().saturating_add(ACP_PERMISSION_TTL_MS);
                    let event = AdapterEvent::bounded(
                        AdapterEventKind::ApprovalRequest,
                        method,
                        self.native_session_id(),
                        Some(&correlation_id),
                        None,
                        Some(json!({
                            "providerRequestId": request_id,
                            "method": method,
                            "sessionId": requested_session_id.clone(),
                            "toolCallId": tool_call_id.clone(),
                            "parametersDigest": params_digest.clone(),
                            "expiresAtUnixMs": expires_at_unix_ms,
                            "request": params
                        })),
                    );
                    if self.approval_context.effective_policy == EffectiveApprovalPolicy::Never
                        && self.approval_context.required_risk_classes.is_empty()
                    {
                        let frame = match allow_once_option_id {
                            Some(option_id) => acp_permission_selected(request_id, &option_id)?,
                            None => acp_permission_cancelled(request_id)?,
                        };
                        let frame = self.record_provider_request_terminal(
                            key,
                            method,
                            params_digest,
                            frame,
                        )?;
                        return Ok((vec![frame], vec![event]));
                    }
                    if self.approval_context.bridge == ApprovalBridgeOwnership::Typed
                        && self.pending_acp_permission.is_none()
                    {
                        self.state = AdapterState::WaitingApproval;
                        self.pending_acp_permission = Some(PendingAcpPermission {
                            request_id: request_id.clone(),
                            method: "session/request_permission",
                            session_id: requested_session_id.expect("validated"),
                            tool_call_id: tool_call_id.expect("validated"),
                            params_digest,
                            allow_once_option_id,
                            expires_at_unix_ms,
                        });
                        return Ok((Vec::new(), vec![event]));
                    }
                    let frame = acp_permission_cancelled(request_id)?;
                    let frame =
                        self.record_provider_request_terminal(key, method, params_digest, frame)?;
                    return Ok((vec![frame], vec![event]));
                }
                let frame = acp_fail_closed_response(method, request_id)?;
                let frame =
                    self.record_provider_request_terminal(key, method, params_digest, frame)?;
                return Ok((
                    vec![frame],
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::AdapterError,
                        method,
                        self.native_session_id(),
                        Some(&correlation_id),
                        Some("ACP client request was not advertised and was denied"),
                        Some(params),
                    )],
                ));
            }
            return Ok((Vec::new(), self.normalize_acp_notification(method, value)));
        }
        if value.get("error").is_some() {
            self.state = AdapterState::Failed;
            return Ok((
                Vec::new(),
                vec![AdapterEvent::bounded(
                    AdapterEventKind::Error,
                    "acp_error",
                    self.native_session_id(),
                    value.get("id").map(request_id_text).as_deref(),
                    value.pointer("/error/message").and_then(Value::as_str),
                    None,
                )],
            ));
        }
        let id = value.get("id").map(request_id_text);
        let numeric_id = value.get("id").and_then(Value::as_u64);
        match self.phase {
            Phase::AcpInitialize if id.as_deref() == Some("1") => {
                let result = require_result(value, self.phase_name())?;
                if result.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
                    return Err(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "ACP protocolVersion 1 was not negotiated",
                    });
                }
                let can_load = result
                    .pointer("/agentCapabilities/loadSession")
                    .and_then(Value::as_bool)
                    == Some(true);
                let (method, params) = match self.requested_session_id.as_ref() {
                    Some(session_id) if can_load => (
                        "session/load",
                        json!({"sessionId": session_id, "cwd": self.cwd, "mcpServers": []}),
                    ),
                    Some(_) => {
                        return Err(AdapterError::UnsupportedOperation {
                            adapter: self.kind,
                            operation: AdapterOperation::Resume,
                            reason: "ACP peer did not negotiate loadSession",
                        });
                    }
                    None => ("session/new", json!({"cwd": self.cwd, "mcpServers": []})),
                };
                self.phase = Phase::AcpSession;
                Ok((vec![self.json_rpc_request(method, params)?], Vec::new()))
            }
            Phase::AcpSession if id.as_deref() == Some("2") => {
                let result = require_result(value, self.phase_name())?;
                let session_id = result
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .or(self.requested_session_id.as_deref())
                    .ok_or(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "ACP session response omitted sessionId",
                    })?
                    .to_owned();
                self.native_session_id = Some(session_id.clone());
                self.state = AdapterState::Ready;
                let event = AdapterEvent::bounded(
                    AdapterEventKind::Session,
                    "session/ready",
                    Some(&session_id),
                    None,
                    None,
                    None,
                );
                if let Some(prompt) = self.prompt.clone() {
                    self.phase = Phase::AcpPrompt;
                    let frame = self.acp_prompt(&prompt)?;
                    Ok((vec![frame], vec![event]))
                } else {
                    self.phase = Phase::Ready;
                    Ok((Vec::new(), vec![event]))
                }
            }
            Phase::AcpPrompt
                if numeric_id.is_some() && numeric_id == self.pending_acp_prompt_id =>
            {
                require_result(value, self.phase_name())?;
                self.pending_acp_prompt_id = None;
                self.phase = Phase::Ready;
                self.state = AdapterState::Completed;
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::Completed,
                        "session/prompt",
                        self.native_session_id(),
                        None,
                        value.pointer("/result/stopReason").and_then(Value::as_str),
                        None,
                    )],
                ))
            }
            _ => Ok((
                Vec::new(),
                vec![AdapterEvent::bounded(
                    AdapterEventKind::AdapterError,
                    "unexpected_acp_response",
                    self.native_session_id(),
                    id.as_deref(),
                    Some("response did not match the active ACP request"),
                    None,
                )],
            )),
        }
    }

    fn normalize_acp_notification(&mut self, method: &str, value: &Value) -> Vec<AdapterEvent> {
        if method != "session/update" {
            return vec![AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                method,
                self.native_session_id(),
                None,
                Some("unrecognized bounded ACP notification"),
                None,
            )];
        }
        let update = value.pointer("/params/update");
        let update_type = update
            .and_then(|update| update.get("sessionUpdate"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let kind = match update_type {
            "agent_message_chunk" => AdapterEventKind::AssistantMessageDelta,
            "tool_call" => AdapterEventKind::ToolCall,
            "tool_call_update" => AdapterEventKind::ToolResult,
            "plan" => AdapterEventKind::State,
            "usage_update" => AdapterEventKind::Usage,
            "available_commands_update" | "current_mode_update" => AdapterEventKind::State,
            _ => AdapterEventKind::AdapterError,
        };
        let text = update
            .and_then(|update| update.pointer("/content/text"))
            .and_then(Value::as_str)
            .or_else(|| {
                update
                    .and_then(|update| update.get("title"))
                    .and_then(Value::as_str)
            });
        vec![AdapterEvent::bounded(
            kind,
            update_type,
            self.native_session_id(),
            update
                .and_then(|update| update.get("toolCallId"))
                .and_then(Value::as_str),
            text,
            None,
        )]
    }

    fn on_pi(
        &mut self,
        value: &Value,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        if value.get("type").and_then(Value::as_str) == Some("extension_ui_request") {
            let method = value
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let request_id = value.get("id");
            let correlation_id = request_id.map(request_id_text);
            let dialog = matches!(method, "select" | "confirm" | "input" | "editor");
            let fire_and_forget = matches!(
                method,
                "notify" | "setStatus" | "setWidget" | "setTitle" | "set_editor_text"
            );
            let kind = if dialog {
                AdapterEventKind::ApprovalRequest
            } else if fire_and_forget {
                AdapterEventKind::State
            } else {
                AdapterEventKind::AdapterError
            };
            let params_digest = pi_ui_params_digest(value)?;
            let key = request_id.and_then(server_request_key);
            if let (Some(key), Some(correlation_id)) = (key.as_deref(), correlation_id.as_deref()) {
                if let Some(outcome) = self.terminal_provider_request_outcome(
                    key,
                    method,
                    &params_digest,
                    correlation_id,
                ) {
                    return Ok(outcome);
                }
                if let Some(pending) = self.pending_pi_dialog.as_ref()
                    && server_request_key(&pending.request_id).as_deref() == Some(key)
                {
                    return Ok((
                        Vec::new(),
                        vec![AdapterEvent::bounded(
                            AdapterEventKind::AdapterError,
                            &format!("extension_ui_request.{method}"),
                            self.native_session_id(),
                            Some(correlation_id),
                            Some(
                                "duplicate outstanding Pi UI request id was ignored; original dialog remains pending",
                            ),
                            Some(json!({
                                "existingMethod": pending.method,
                                "existingParametersDigest": pending.params_digest,
                                "duplicateParametersDigest": params_digest,
                                "sameCommitment": pending.method == method
                                    && pending.params_digest == params_digest
                            })),
                        )],
                    ));
                }
            }
            let event = AdapterEvent::bounded(
                kind,
                &format!("extension_ui_request.{method}"),
                self.native_session_id(),
                correlation_id.as_deref(),
                None,
                Some(value.clone()),
            );
            if fire_and_forget {
                return Ok((Vec::new(), vec![event]));
            }
            let Some(request_id) = request_id else {
                return Ok((Vec::new(), vec![event]));
            };
            let Some(key) = key else {
                return Ok(self.provider_request_admission_error(
                    &format!("extension_ui_request.{method}"),
                    &request_id_text(request_id),
                    "provider request id had an unsupported type; no response was emitted",
                ));
            };
            if self.provider_request_slots_used() >= MAX_PROVIDER_REQUEST_TERMINALS {
                return Ok(self.provider_request_capacity_error(
                    &format!("extension_ui_request.{method}"),
                    &request_id_text(request_id),
                ));
            }
            if dialog
                && self.approval_context.bridge == ApprovalBridgeOwnership::Typed
                && self.pending_pi_dialog.is_none()
            {
                self.state = AdapterState::WaitingApproval;
                self.pending_pi_dialog = Some(PendingPiDialog {
                    request_id: request_id.clone(),
                    method: method.to_owned(),
                    params_digest,
                });
                return Ok((Vec::new(), vec![event]));
            }
            let frame = pi_dialog_cancelled(request_id)?;
            let frame = self.record_provider_request_terminal(key, method, params_digest, frame)?;
            return Ok((vec![frame], vec![event]));
        }
        Ok((Vec::new(), self.normalize_pi_event(value)))
    }

    fn normalize_pi_event(&mut self, value: &Value) -> Vec<AdapterEvent> {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if event_type == "response" {
            let command = value
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let success = value.get("success").and_then(Value::as_bool) == Some(true);
            if command == "prompt" && success {
                self.state = AdapterState::Working;
                return vec![AdapterEvent::bounded(
                    AdapterEventKind::PromptAccepted,
                    "response.prompt",
                    self.native_session_id(),
                    value.get("id").and_then(Value::as_str),
                    None,
                    None,
                )];
            }
            if command == "get_state"
                && let Some(session_id) = value.pointer("/data/sessionId").and_then(Value::as_str)
            {
                self.native_session_id = Some(session_id.to_owned());
            }
            return vec![AdapterEvent::bounded(
                if success {
                    AdapterEventKind::State
                } else {
                    AdapterEventKind::Error
                },
                &format!("response.{command}"),
                self.native_session_id(),
                value.get("id").and_then(Value::as_str),
                value.get("error").and_then(Value::as_str),
                None,
            )];
        }
        let (kind, text, correlation) = match event_type {
            "agent_start" => {
                self.state = AdapterState::Working;
                (AdapterEventKind::State, Some("working"), None)
            }
            "agent_end" => {
                if value.get("willRetry").and_then(Value::as_bool).is_none() {
                    self.state = AdapterState::Failed;
                    return vec![AdapterEvent::bounded(
                        AdapterEventKind::AdapterError,
                        event_type,
                        self.native_session_id(),
                        None,
                        Some(
                            "Pi stream ended without settlement capability; completion is protocol-incomplete",
                        ),
                        Some(json!({"protocolIncomplete": true, "missingEvent": "agent_settled"})),
                    )];
                }
                self.state = AdapterState::Working;
                (
                    AdapterEventKind::State,
                    Some(
                        if value.get("willRetry").and_then(Value::as_bool) == Some(true) {
                            "low_level_run_ended_retry_pending"
                        } else {
                            "low_level_run_ended_settlement_pending"
                        },
                    ),
                    None,
                )
            }
            "agent_settled" => {
                self.state = AdapterState::Completed;
                (AdapterEventKind::Completed, Some("completed"), None)
            }
            "message_update" => {
                let update_type = value
                    .pointer("/assistantMessageEvent/type")
                    .and_then(Value::as_str);
                if update_type.is_some_and(|kind| kind.starts_with("thinking_")) {
                    return Vec::new();
                }
                (
                    AdapterEventKind::AssistantMessageDelta,
                    value
                        .pointer("/assistantMessageEvent/delta")
                        .and_then(Value::as_str),
                    None,
                )
            }
            "message_end" => (AdapterEventKind::AssistantMessage, None, None),
            "tool_execution_start" => (
                AdapterEventKind::ToolCall,
                value.get("toolName").and_then(Value::as_str),
                value.get("toolCallId").and_then(Value::as_str),
            ),
            "tool_execution_end" => (
                AdapterEventKind::ToolResult,
                pi_tool_result_text(value),
                value.get("toolCallId").and_then(Value::as_str),
            ),
            "queue_update"
            | "compaction_start"
            | "compaction_end"
            | "auto_compaction_start"
            | "auto_compaction_end"
            | "auto_retry_start"
            | "auto_retry_end"
            | "summarization_retry_scheduled"
            | "summarization_retry_attempt_start"
            | "summarization_retry_finished" => (AdapterEventKind::State, None, None),
            "extension_error" => (
                AdapterEventKind::Error,
                value.get("error").and_then(Value::as_str),
                None,
            ),
            _ => (AdapterEventKind::AdapterError, None, None),
        };
        vec![AdapterEvent::bounded(
            kind,
            event_type,
            self.native_session_id(),
            correlation,
            text,
            matches!(
                event_type,
                "agent_end"
                    | "queue_update"
                    | "compaction_end"
                    | "auto_retry_start"
                    | "auto_retry_end"
                    | "tool_execution_end"
            )
            .then(|| value.clone()),
        )]
    }

    fn normalize_claude(&mut self, value: &Value) -> Vec<AdapterEvent> {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if event_type == "system" && value.get("subtype").and_then(Value::as_str) == Some("init") {
            if let Some(session_id) = value.get("session_id").and_then(Value::as_str) {
                self.native_session_id = Some(session_id.to_owned());
            }
            self.state = AdapterState::Working;
            return vec![AdapterEvent::bounded(
                AdapterEventKind::Session,
                "system.init",
                self.native_session_id(),
                None,
                None,
                None,
            )];
        }
        if event_type == "result" {
            self.state = if value.get("is_error").and_then(Value::as_bool) == Some(true) {
                AdapterState::Failed
            } else {
                AdapterState::Completed
            };
            return vec![AdapterEvent::bounded(
                if self.state == AdapterState::Completed {
                    AdapterEventKind::Completed
                } else {
                    AdapterEventKind::Error
                },
                event_type,
                self.native_session_id(),
                None,
                value.get("result").and_then(Value::as_str),
                value.get("usage").cloned(),
            )];
        }
        let role = value.pointer("/message/role").and_then(Value::as_str);
        let blocks = value.pointer("/message/content").and_then(Value::as_array);
        let mut events = Vec::new();
        for block in blocks.into_iter().flatten() {
            let block_type = block
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            match (role, block_type) {
                (_, "thinking" | "redacted_thinking") => {}
                (Some("assistant"), "text") => events.push(AdapterEvent::bounded(
                    AdapterEventKind::AssistantMessage,
                    "assistant.text",
                    self.native_session_id(),
                    None,
                    block.get("text").and_then(Value::as_str),
                    None,
                )),
                (Some("assistant"), "tool_use") => events.push(AdapterEvent::bounded(
                    AdapterEventKind::ToolCall,
                    "assistant.tool_use",
                    self.native_session_id(),
                    block.get("id").and_then(Value::as_str),
                    block.get("name").and_then(Value::as_str),
                    None,
                )),
                (Some("user"), "tool_result") => events.push(AdapterEvent::bounded(
                    AdapterEventKind::ToolResult,
                    "user.tool_result",
                    self.native_session_id(),
                    block.get("tool_use_id").and_then(Value::as_str),
                    None,
                    None,
                )),
                _ => events.push(AdapterEvent::bounded(
                    AdapterEventKind::AdapterError,
                    block_type,
                    self.native_session_id(),
                    None,
                    Some("unrecognized Claude stream-json content block"),
                    None,
                )),
            }
        }
        if events.is_empty() && blocks.is_none() {
            events.push(AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                event_type,
                self.native_session_id(),
                None,
                Some("unrecognized Claude stream-json event"),
                None,
            ));
        }
        events
    }

    fn normalize_agy(&mut self, value: &Value) -> Vec<AdapterEvent> {
        let event_type = value
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let payload = value.get(event_type).unwrap_or(value);
        if let Some(session_id) = value
            .get("conversation_id")
            .or_else(|| payload.get("conversation_id"))
            .and_then(Value::as_str)
        {
            self.native_session_id = Some(session_id.to_owned());
        }
        match event_type {
            "init" => {
                self.state = AdapterState::Working;
                vec![AdapterEvent::bounded(
                    AdapterEventKind::Session,
                    "init",
                    self.native_session_id(),
                    None,
                    None,
                    Some(payload.clone()),
                )]
            }
            "step_update" => {
                let step_type = payload
                    .get("step_type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let correlation = payload.get("step_index").map(|value| value.to_string());
                let mut events = Vec::new();
                match step_type {
                    "agent_response" => events.push(AdapterEvent::bounded(
                        AdapterEventKind::AssistantMessageDelta,
                        "step_update.agent_response",
                        self.native_session_id(),
                        correlation.as_deref(),
                        payload.get("text_delta").and_then(Value::as_str),
                        None,
                    )),
                    "tool" => {
                        let tool = payload.get("tool_info").unwrap_or(payload);
                        events.push(AdapterEvent::bounded(
                            AdapterEventKind::ToolCall,
                            "step_update.tool",
                            self.native_session_id(),
                            correlation.as_deref(),
                            payload
                                .get("tool_name")
                                .or_else(|| tool.get("name"))
                                .and_then(Value::as_str),
                            tool.get("parameters").cloned(),
                        ));
                        if tool.get("output").is_some() || tool.get("error").is_some() {
                            events.push(AdapterEvent::bounded(
                                AdapterEventKind::ToolResult,
                                "step_update.tool_result",
                                self.native_session_id(),
                                correlation.as_deref(),
                                tool.get("output").and_then(Value::as_str),
                                tool.get("error").cloned(),
                            ));
                        }
                    }
                    "user_input" | "checkpoint" => events.push(AdapterEvent::bounded(
                        AdapterEventKind::State,
                        &format!("step_update.{step_type}"),
                        self.native_session_id(),
                        correlation.as_deref(),
                        payload.get("state").and_then(Value::as_str),
                        None,
                    )),
                    _ if payload.get("subagent_info").is_some() => {
                        events.push(AdapterEvent::bounded(
                            AdapterEventKind::Subagent,
                            "step_update.subagent",
                            self.native_session_id(),
                            correlation.as_deref(),
                            None,
                            payload.get("subagent_info").cloned(),
                        ))
                    }
                    _ => events.push(AdapterEvent::bounded(
                        AdapterEventKind::AdapterError,
                        "step_update.unknown",
                        self.native_session_id(),
                        correlation.as_deref(),
                        Some(
                            "unrecognized Agy step_update was retained as a bounded adapter error",
                        ),
                        Some(payload.clone()),
                    )),
                }
                if let Some(usage) = payload.get("usage") {
                    events.push(AdapterEvent::bounded(
                        AdapterEventKind::Usage,
                        "step_update.usage",
                        self.native_session_id(),
                        correlation.as_deref(),
                        None,
                        Some(usage.clone()),
                    ));
                }
                events
            }
            "result" => {
                let status = payload
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("INVALID");
                let successful = status == "SUCCESS";
                self.state = if successful {
                    AdapterState::Completed
                } else {
                    AdapterState::Failed
                };
                let mut events = Vec::new();
                if let Some(usage) = payload.get("usage") {
                    events.push(AdapterEvent::bounded(
                        AdapterEventKind::Usage,
                        "result.usage",
                        self.native_session_id(),
                        None,
                        None,
                        Some(usage.clone()),
                    ));
                }
                events.push(AdapterEvent::bounded(
                    if successful {
                        AdapterEventKind::Completed
                    } else {
                        AdapterEventKind::Error
                    },
                    "result",
                    self.native_session_id(),
                    None,
                    if successful {
                        payload.get("response").and_then(Value::as_str)
                    } else {
                        payload.get("error").and_then(Value::as_str)
                    },
                    None,
                ));
                events
            }
            _ => vec![AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                event_type,
                self.native_session_id(),
                None,
                Some("unrecognized Agy stream-json event"),
                Some(value.clone()),
            )],
        }
    }

    fn codex_command(
        &mut self,
        operation: AdapterOperation,
        text: Option<&str>,
    ) -> Result<Vec<ProtocolFrame>, AdapterError> {
        let session_id = self
            .native_session_id()
            .ok_or(AdapterError::UnexpectedResponse {
                phase: self.phase_name(),
                reason: "Codex thread is not ready",
            })?
            .to_owned();
        match operation {
            AdapterOperation::Send | AdapterOperation::FollowUp => {
                if self.active_turn_id.is_some()
                    || self
                        .pending_codex
                        .values()
                        .any(|pending| pending.response == CodexResponseKind::TurnStart)
                {
                    return Err(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "a turn is active; use steer or wait for completion",
                    });
                }
                self.phase = Phase::CodexTurn;
                self.state = AdapterState::Starting;
                Ok(vec![self.codex_turn(text.unwrap_or_default())?])
            }
            AdapterOperation::Steer => {
                let turn_id =
                    self.active_turn_id
                        .as_deref()
                        .ok_or(AdapterError::UnexpectedResponse {
                            phase: self.phase_name(),
                            reason: "Codex turn/steer requires an active turn",
                        })?;
                Ok(vec![self.codex_request(
                    "turn/steer",
                    json!({
                        "threadId": session_id,
                        "expectedTurnId": turn_id,
                        "input": [{"type": "text", "text": text.unwrap_or_default()}]
                    }),
                    CodexResponseKind::TurnSteer,
                )?])
            }
            AdapterOperation::Cancel => {
                let turn_id =
                    self.active_turn_id
                        .as_deref()
                        .ok_or(AdapterError::UnexpectedResponse {
                            phase: self.phase_name(),
                            reason: "Codex turn/interrupt requires an active turn",
                        })?;
                Ok(vec![self.codex_request(
                    "turn/interrupt",
                    json!({"threadId": session_id, "turnId": turn_id}),
                    CodexResponseKind::TurnInterrupt,
                )?])
            }
            AdapterOperation::State => Ok(vec![self.codex_request(
                "thread/read",
                json!({"threadId": session_id, "includeTurns": false}),
                CodexResponseKind::ThreadRead,
            )?]),
            AdapterOperation::ModelDiscovery => Ok(vec![self.codex_request(
                "model/list",
                json!({"limit": 100}),
                CodexResponseKind::ModelList,
            )?]),
            AdapterOperation::Close => Ok(vec![self.codex_request(
                "thread/archive",
                json!({"threadId": session_id}),
                CodexResponseKind::ThreadArchive,
            )?]),
            _ => Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation,
                reason: "operation is not a live Codex protocol command",
            }),
        }
    }

    fn acp_command(
        &mut self,
        operation: AdapterOperation,
        text: Option<&str>,
    ) -> Result<Vec<ProtocolFrame>, AdapterError> {
        match operation {
            AdapterOperation::Send | AdapterOperation::FollowUp => {
                self.phase = Phase::AcpPrompt;
                self.state = AdapterState::Starting;
                Ok(vec![self.acp_prompt(text.unwrap_or_default())?])
            }
            AdapterOperation::Cancel => {
                let session_id = self
                    .native_session_id()
                    .ok_or(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "ACP session is not ready",
                    })?
                    .to_owned();
                Ok(vec![self.json_rpc_request_with_id(
                    "session/cancel",
                    json!({"sessionId": session_id}),
                )?])
            }
            AdapterOperation::Close => {
                self.phase = Phase::Terminal;
                Ok(Vec::new())
            }
            _ => Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation,
                reason: "ACP peer did not negotiate this operation",
            }),
        }
    }

    fn pi_operation(
        &mut self,
        operation: AdapterOperation,
        text: Option<&str>,
    ) -> Result<Vec<ProtocolFrame>, AdapterError> {
        let command = match operation {
            AdapterOperation::Send => "prompt",
            AdapterOperation::Steer => "steer",
            AdapterOperation::FollowUp => "follow_up",
            AdapterOperation::Cancel => "abort",
            AdapterOperation::State => "get_state",
            AdapterOperation::Replay => "get_messages",
            AdapterOperation::ModelDiscovery => "get_available_models",
            AdapterOperation::Close => {
                self.phase = Phase::Terminal;
                return Ok(Vec::new());
            }
            _ => {
                return Err(AdapterError::UnsupportedOperation {
                    adapter: self.kind,
                    operation,
                    reason: "operation is not a Pi RPC command",
                });
            }
        };
        Ok(vec![self.pi_command(command, text)?])
    }

    fn codex_turn(&mut self, prompt: &str) -> Result<ProtocolFrame, AdapterError> {
        let session_id = self
            .native_session_id()
            .ok_or(AdapterError::UnexpectedResponse {
                phase: self.phase_name(),
                reason: "Codex thread ID is unavailable",
            })?
            .to_owned();
        let mut params = json!({
            "threadId": session_id,
            "input": [{"type": "text", "text": prompt}],
            "approvalPolicy": self.codex_approval_policy(),
            "approvalsReviewer": "user",
            "sandboxPolicy": self.codex_turn_sandbox_policy(),
        });
        if let Some(model) = &self.model {
            params["model"] = Value::String(model.clone());
        }
        if let Some(effort) = &self.effort {
            params["effort"] = Value::String(effort.clone());
        }
        self.codex_request("turn/start", params, CodexResponseKind::TurnStart)
    }

    const fn codex_approval_policy(&self) -> &'static str {
        match self.approval_context.effective_policy {
            EffectiveApprovalPolicy::Never
                if self.approval_context.required_risk_classes.is_empty() =>
            {
                "never"
            }
            EffectiveApprovalPolicy::Never => "on-request",
            EffectiveApprovalPolicy::Always => "untrusted",
            EffectiveApprovalPolicy::OutsideScope | EffectiveApprovalPolicy::RiskClasses => {
                "on-request"
            }
        }
    }

    fn codex_approval_requires_bridge(&self, method: &str) -> bool {
        match self.approval_context.effective_policy {
            EffectiveApprovalPolicy::Always | EffectiveApprovalPolicy::OutsideScope => true,
            EffectiveApprovalPolicy::RiskClasses | EffectiveApprovalPolicy::Never => {
                let required = self.approval_context.required_risk_classes;
                if required.is_empty() {
                    return self.approval_context.effective_policy
                        == EffectiveApprovalPolicy::RiskClasses;
                }
                codex_known_approval_risks(method)
                    .is_none_or(|classified| required.intersects(classified))
            }
        }
    }

    const fn codex_sandbox_mode(&self) -> &'static str {
        match self.effective_sandbox_policy {
            EffectiveSandboxPolicy::ReadOnly => "read-only",
            EffectiveSandboxPolicy::WorkspaceWrite => "workspace-write",
            EffectiveSandboxPolicy::External | EffectiveSandboxPolicy::DangerFullAccess => {
                "danger-full-access"
            }
        }
    }

    fn codex_turn_sandbox_policy(&self) -> Value {
        match self.effective_sandbox_policy {
            EffectiveSandboxPolicy::ReadOnly => json!({"type":"readOnly","networkAccess":false}),
            EffectiveSandboxPolicy::External => {
                json!({"type":"externalSandbox","networkAccess":"restricted"})
            }
            EffectiveSandboxPolicy::WorkspaceWrite => json!({
                "type":"workspaceWrite",
                "writableRoots":[self.cwd],
                "networkAccess":false,
                "excludeTmpdirEnvVar":true,
                "excludeSlashTmp":true
            }),
            EffectiveSandboxPolicy::DangerFullAccess => json!({"type":"dangerFullAccess"}),
        }
    }

    fn acp_prompt(&mut self, prompt: &str) -> Result<ProtocolFrame, AdapterError> {
        let session_id = self
            .native_session_id()
            .ok_or(AdapterError::UnexpectedResponse {
                phase: self.phase_name(),
                reason: "ACP session ID is unavailable",
            })?
            .to_owned();
        let id = if self.next_request_id <= 3 {
            self.next_request_id = 4;
            3
        } else {
            self.take_request_id()
        };
        self.pending_acp_prompt_id = Some(id);
        ProtocolFrame::json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/prompt",
            "params": {"sessionId": session_id, "prompt": [{"type": "text", "text": prompt}]}
        }))
    }

    fn pi_command(
        &mut self,
        command: &str,
        text: Option<&str>,
    ) -> Result<ProtocolFrame, AdapterError> {
        let id = format!("conduit-{}", self.take_request_id());
        let mut value = json!({"id": id, "type": command});
        if let Some(text) = text {
            value["message"] = Value::String(text.to_owned());
        }
        ProtocolFrame::json(&value)
    }

    fn codex_request(
        &mut self,
        method: &'static str,
        params: Value,
        response: CodexResponseKind,
    ) -> Result<ProtocolFrame, AdapterError> {
        if self.pending_codex.len() >= MAX_PENDING_CODEX_REQUESTS {
            return Err(AdapterError::UnexpectedResponse {
                phase: "codex_pending_requests",
                reason: "bounded Codex pending request map is full",
            });
        }
        let id = self.take_request_id();
        let frame = ProtocolFrame::json(&json!({"id": id, "method": method, "params": params}))?;
        self.pending_codex.insert(
            id,
            PendingCodexRequest {
                method,
                response,
                completed_turn_id: None,
            },
        );
        Ok(frame)
    }

    fn json_rpc_request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<ProtocolFrame, AdapterError> {
        let id = self.take_request_id();
        ProtocolFrame::json(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
    }

    fn json_rpc_request_with_id(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<ProtocolFrame, AdapterError> {
        self.json_rpc_request(method, params)
    }

    fn terminal_provider_request_outcome(
        &mut self,
        key: &str,
        method: &str,
        params_digest: &str,
        correlation_id: &str,
    ) -> Option<(Vec<ProtocolFrame>, Vec<AdapterEvent>)> {
        let terminal = self.provider_request_terminals.get(key)?.clone();
        let same_commitment = terminal.method == method && terminal.params_digest == params_digest;
        if !same_commitment {
            self.phase = Phase::Terminal;
            self.state = AdapterState::Failed;
        }
        let event = AdapterEvent::bounded(
            if same_commitment {
                AdapterEventKind::State
            } else {
                AdapterEventKind::AdapterError
            },
            method,
            self.native_session_id(),
            Some(correlation_id),
            Some(if same_commitment {
                "exact duplicate provider request replayed its recorded terminal response"
            } else {
                "settled provider request id was reused with a changed commitment; the adapter failed without emitting a second response"
            }),
            Some(json!({
                "existingMethod": terminal.method,
                "existingParametersDigest": terminal.params_digest,
                "duplicateParametersDigest": params_digest,
                "sameCommitment": same_commitment
            })),
        );
        Some((
            if same_commitment {
                vec![terminal.response.clone()]
            } else {
                Vec::new()
            },
            vec![event],
        ))
    }

    fn provider_request_slots_used(&self) -> usize {
        self.provider_request_terminals.len()
            + self.pending_codex_approvals.len()
            + usize::from(self.pending_acp_permission.is_some())
            + usize::from(self.pending_pi_dialog.is_some())
    }

    fn provider_request_admission_error(
        &self,
        method: &str,
        correlation_id: &str,
        reason: &'static str,
    ) -> (Vec<ProtocolFrame>, Vec<AdapterEvent>) {
        (
            Vec::new(),
            vec![AdapterEvent::bounded(
                AdapterEventKind::AdapterError,
                method,
                self.native_session_id(),
                Some(correlation_id),
                Some(reason),
                Some(json!({"providerRequestTerminalLimit": MAX_PROVIDER_REQUEST_TERMINALS})),
            )],
        )
    }

    fn provider_request_capacity_error(
        &mut self,
        method: &str,
        correlation_id: &str,
    ) -> (Vec<ProtocolFrame>, Vec<AdapterEvent>) {
        self.phase = Phase::Terminal;
        self.state = AdapterState::Failed;
        self.provider_request_admission_error(
            method,
            correlation_id,
            "provider request terminal capacity is exhausted; adapter failed without responding to the new id",
        )
    }

    fn mark_provider_request_settled(&mut self) {
        if self.state != AdapterState::Failed {
            self.state = AdapterState::Working;
        }
    }

    fn record_provider_request_terminal(
        &mut self,
        key: String,
        method: &str,
        params_digest: String,
        response: ProtocolFrame,
    ) -> Result<ProtocolFrame, AdapterError> {
        if self.provider_request_terminals.len() >= MAX_PROVIDER_REQUEST_TERMINALS {
            self.phase = Phase::Terminal;
            self.state = AdapterState::Failed;
            return Err(AdapterError::UnexpectedResponse {
                phase: "provider_request_terminal_capacity",
                reason: "provider request terminal map is full",
            });
        }
        self.provider_request_terminals.insert(
            key,
            ProviderRequestTerminal {
                method: method.to_owned(),
                params_digest,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn take_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        id
    }

    fn push_event(&mut self, event: AdapterEvent) {
        if self.replay.len() == MAX_REPLAY_EVENTS {
            self.replay.pop_front();
        }
        self.replay.push_back(event);
    }

    const fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::CodexInitialize => "codex_initialize",
            Phase::CodexThread => "codex_thread",
            Phase::CodexTurn => "codex_turn",
            Phase::AcpInitialize => "acp_initialize",
            Phase::AcpSession => "acp_session",
            Phase::AcpPrompt => "acp_prompt",
            Phase::Ready => "ready",
            Phase::Active => "active",
            Phase::OneShot => "one_shot",
            Phase::Terminal => "terminal",
        }
    }
}

fn parse_frame(record: &[u8]) -> Result<Value, AdapterError> {
    if record.is_empty()
        || record.len() > MAX_PROTOCOL_FRAME_BYTES
        || !record.ends_with(b"\n")
        || record[..record.len() - 1].contains(&b'\n')
    {
        return Err(AdapterError::InvalidFrame);
    }
    let body = record
        .strip_suffix(b"\n")
        .ok_or(AdapterError::InvalidFrame)?
        .strip_suffix(b"\r")
        .unwrap_or(&record[..record.len() - 1]);
    serde_json::from_slice(body).map_err(|_| AdapterError::InvalidFrame)
}

fn require_result<'a>(value: &'a Value, phase: &'static str) -> Result<&'a Value, AdapterError> {
    value.get("result").ok_or(AdapterError::UnexpectedResponse {
        phase,
        reason: "correlated response omitted result",
    })
}

fn request_id_text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn acp_allow_once_option(value: &Value) -> Option<String> {
    value
        .pointer("/params/options")
        .and_then(Value::as_array)
        .and_then(|options| {
            options.iter().find_map(|option| {
                (option.get("kind").and_then(Value::as_str) == Some("allow_once"))
                    .then(|| option.get("optionId").and_then(Value::as_str))
                    .flatten()
                    .map(str::to_owned)
            })
        })
}

fn acp_permission_selected(
    request_id: &Value,
    option_id: &str,
) -> Result<ProtocolFrame, AdapterError> {
    ProtocolFrame::json(&json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"outcome": {"outcome": "selected", "optionId": option_id}}
    }))
}

fn acp_permission_cancelled(request_id: &Value) -> Result<ProtocolFrame, AdapterError> {
    ProtocolFrame::json(&json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"outcome": {"outcome": "cancelled"}}
    }))
}

fn acp_fail_closed_response(
    method: &str,
    request_id: &Value,
) -> Result<ProtocolFrame, AdapterError> {
    ProtocolFrame::json(&json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": format!("ACP client method is unavailable: {method}"),
            "data": {"failClosed": true}
        }
    }))
}

fn pi_dialog_cancelled(request_id: &Value) -> Result<ProtocolFrame, AdapterError> {
    ProtocolFrame::json(&json!({
        "type": "extension_ui_response",
        "id": request_id,
        "cancelled": true
    }))
}

fn pi_tool_result_text(value: &Value) -> Option<&str> {
    value.get("error").and_then(Value::as_str).or_else(|| {
        value
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
    })
}

const CODEX_SERVER_REQUEST_METHODS: [&str; 11] = [
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/tool/requestUserInput",
    "mcpServer/elicitation/request",
    "item/permissions/requestApproval",
    "item/tool/call",
    "account/chatgptAuthTokens/refresh",
    "attestation/generate",
    "currentTime/read",
    "applyPatchApproval",
    "execCommandApproval",
];

fn is_codex_server_request(method: &str) -> bool {
    CODEX_SERVER_REQUEST_METHODS.contains(&method)
}

fn is_codex_approval_method(method: &str) -> bool {
    matches!(
        method,
        "item/commandExecution/requestApproval"
            | "item/fileChange/requestApproval"
            | "applyPatchApproval"
            | "execCommandApproval"
    )
}

fn codex_approval_method(method: &str) -> Option<&'static str> {
    match method {
        "item/commandExecution/requestApproval" => Some("item/commandExecution/requestApproval"),
        "item/fileChange/requestApproval" => Some("item/fileChange/requestApproval"),
        "applyPatchApproval" => Some("applyPatchApproval"),
        "execCommandApproval" => Some("execCommandApproval"),
        _ => None,
    }
}

fn codex_known_approval_risks(method: &str) -> Option<ApprovalRiskClassSet> {
    match method {
        // A file-change callback authorizes mutation of existing workspace data. Treat it as
        // destructive-delete risk conservatively; no path content leaves the Device.
        "item/fileChange/requestApproval" | "applyPatchApproval" => {
            Some(ApprovalRiskClassSet::DESTRUCTIVE_DELETE)
        }
        // Arbitrary commands cannot be classified completely from a display string. Any
        // authoritative required-risk set therefore keeps the request on the typed bridge.
        "item/commandExecution/requestApproval" | "execCommandApproval" => None,
        _ => None,
    }
}

fn codex_approval_response(
    method: &str,
    id: &Value,
    allow: bool,
) -> Result<ProtocolFrame, AdapterError> {
    let result = match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            json!({"decision": if allow { "accept" } else { "decline" }})
        }
        "applyPatchApproval" | "execCommandApproval" => {
            if allow {
                json!({"decision": "approved"})
            } else {
                json!({
                    "decision": {
                        "denied": {
                            "rejection": "Conduit denied the commitment-bound approval request"
                        }
                    }
                })
            }
        }
        _ => {
            return Err(AdapterError::UnexpectedResponse {
                phase: "codex_server_request",
                reason: "approval response requested for a non-approval method",
            });
        }
    };
    ProtocolFrame::json(&json!({"id": id, "result": result}))
}

fn server_request_key(id: &Value) -> Option<String> {
    match id {
        Value::String(value) => Some(format!("s:{value}")),
        Value::Number(value) if value.as_i64().is_some() || value.as_u64().is_some() => {
            Some(format!("n:{value}"))
        }
        _ => None,
    }
}

fn canonical_digest(value: &Value) -> Result<String, AdapterError> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(value)?)))
}

fn pi_ui_params_digest(value: &Value) -> Result<String, AdapterError> {
    let mut params = value.clone();
    if let Some(params) = params.as_object_mut() {
        params.remove("type");
        params.remove("id");
        params.remove("method");
    }
    canonical_digest(&params)
}

fn codex_approval_summary(method: &str, params: &Value, params_digest: &str) -> Value {
    match method {
        "item/commandExecution/requestApproval" | "execCommandApproval" => {
            let command = params
                .get("command")
                .map(|value| match value {
                    Value::String(value) => value.clone(),
                    Value::Array(values) => values
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => String::new(),
                })
                .unwrap_or_default();
            let tokens = command.split_whitespace().collect::<Vec<_>>();
            let executable_label = tokens
                .first()
                .map(|token| {
                    token
                        .trim_matches(['\'', '"'])
                        .rsplit('/')
                        .next()
                        .unwrap_or("command")
                })
                .map(|value| crate::types::bound_utf8(value, 128))
                .unwrap_or_else(|| "command".to_owned());
            json!({
                "effect": "command_execution",
                "executableLabel": executable_label,
                "argumentCount": tokens.len().saturating_sub(1),
                "deviceOnlyDetails": true,
                "parametersDigest": params_digest
            })
        }
        "item/fileChange/requestApproval" | "applyPatchApproval" => {
            let change_count = params
                .get("changes")
                .and_then(Value::as_array)
                .map_or(1, Vec::len);
            json!({
                "effect": "file_change",
                "changeCount": change_count,
                "deviceOnlyDetails": true,
                "parametersDigest": params_digest
            })
        }
        _ => json!({"effect":"unsupported","parametersDigest":params_digest}),
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn codex_fail_closed_response(
    method: &str,
    id: &Value,
    known: bool,
) -> Result<ProtocolFrame, AdapterError> {
    let (code, message) = if known {
        (
            -32004,
            "Codex server request capability was not advertised by Conduit",
        )
    } else {
        (-32601, "Unknown Codex server request")
    };
    ProtocolFrame::json(&json!({
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": {"method": method, "failClosed": true}
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn request() -> LaunchRequest {
        LaunchRequest {
            cwd: PathBuf::from("/tmp/conduit-adapter-test"),
            prompt: Some("inspect the fixture".to_owned()),
            native_session_id: None,
            model: None,
            effort: None,
            session_data_dir: Some(PathBuf::from("/tmp/conduit-adapter-sessions")),
        }
    }

    fn context(
        effective_policy: EffectiveApprovalPolicy,
        bridge: ApprovalBridgeOwnership,
    ) -> ApprovalContext {
        ApprovalContext {
            effective_policy,
            bridge,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        }
    }

    fn ready_acp_driver(approval_context: ApprovalContext) -> ProtocolDriver {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::OpenCode,
            &request(),
            approval_context,
        )
        .unwrap();
        driver.native_session_id = Some("session-1".to_owned());
        driver.phase = Phase::Ready;
        driver.state = AdapterState::Completed;
        driver
    }

    #[test]
    fn codex_requires_correlated_thread_and_turn_receipts() {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        assert!(
            String::from_utf8(driver.start().unwrap()[0].0.clone())
                .unwrap()
                .contains("initialize")
        );
        let (frames, _) = driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        assert_eq!(frames.len(), 2);
        assert!(
            String::from_utf8(frames[1].0.clone())
                .unwrap()
                .contains("thread/start")
        );
        let (frames, events) = driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::Session);
        assert!(
            String::from_utf8(frames[0].0.clone())
                .unwrap()
                .contains("turn/start")
        );
        let (_, events) = driver
            .on_record(b"{\"id\":3,\"result\":{\"turn\":{\"id\":\"turn-1\"}}}\n")
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::PromptAccepted);
        assert_eq!(driver.state(), AdapterState::Working);
    }

    #[test]
    fn codex_steer_binds_expected_active_turn() {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        driver.start().unwrap();
        driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        driver
            .on_record(b"{\"id\":3,\"result\":{\"turn\":{\"id\":\"turn-1\"}}}\n")
            .unwrap();
        let frame = driver
            .command(AdapterOperation::Steer, Some("new constraint"))
            .unwrap()
            .remove(0);
        let value: Value = serde_json::from_slice(&frame.0).unwrap();
        assert_eq!(
            value.pointer("/params/expectedTurnId"),
            Some(&json!("turn-1"))
        );
        let response = serde_json::to_vec(&json!({
            "id": value["id"], "result": {"turnId": "turn-1"}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[response.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].vendor_type, "turn/steer");
        assert_eq!(events[0].kind, AdapterEventKind::PromptAccepted);
    }

    fn ready_codex_driver() -> ProtocolDriver {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        driver.start().unwrap();
        driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        driver
            .on_record(b"{\"id\":3,\"result\":{\"turn\":{\"id\":\"turn-1\"}}}\n")
            .unwrap();
        driver
    }

    #[test]
    fn codex_correlates_out_of_order_read_and_model_responses() {
        let mut driver = ready_codex_driver();
        let state: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::State, None)
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let models: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::ModelDiscovery, None)
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let model_response = serde_json::to_vec(&json!({
            "id": models["id"],
            "result": {"data": [{"id": "gpt-5"}], "nextCursor": null}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[model_response.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].vendor_type, "model/list");
        let state_response = serde_json::to_vec(&json!({
            "id": state["id"],
            "result": {"thread": {"id": "thread-1"}}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[state_response.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].vendor_type, "thread/read");
    }

    #[test]
    fn codex_wrong_and_duplicate_ids_never_consume_an_outstanding_request() {
        let mut driver = ready_codex_driver();
        let request: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::State, None)
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let (_, wrong) = driver
            .on_record(b"{\"id\":9999,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        assert_eq!(wrong[0].kind, AdapterEventKind::AdapterError);

        let response = serde_json::to_vec(&json!({
            "id": request["id"],
            "result": {"thread": {"id": "thread-1"}}
        }))
        .unwrap();
        let record = [response.as_slice(), b"\n"].concat();
        let (_, first) = driver.on_record(&record).unwrap();
        assert_eq!(first[0].vendor_type, "thread/read");
        let (_, duplicate) = driver.on_record(&record).unwrap();
        assert_eq!(duplicate[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(duplicate[0].vendor_type, "unexpected_response");
    }

    #[test]
    fn codex_malformed_exact_id_response_fails_terminally() {
        let mut driver = ready_codex_driver();
        let request: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::State, None)
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let malformed = serde_json::to_vec(&json!({"id": request["id"], "result": {}})).unwrap();
        let (_, events) = driver
            .on_record(&[malformed.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(driver.phase, Phase::Terminal);
    }

    #[test]
    fn codex_interrupt_and_steer_responses_are_bound_to_the_active_turn() {
        let mut driver = ready_codex_driver();
        let steer: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::Steer, Some("constraint"))
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let interrupt: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::Cancel, None)
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let interrupt_response = serde_json::to_vec(&json!({
            "id": interrupt["id"], "result": {}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[interrupt_response.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].vendor_type, "turn/interrupt");

        let wrong_turn = serde_json::to_vec(&json!({
            "id": steer["id"], "result": {"turnId": "turn-other"}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[wrong_turn.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.native_session_id(), Some("thread-1"));
    }

    #[test]
    fn codex_supports_a_fresh_follow_up_turn_after_completion() {
        let mut driver = ready_codex_driver();
        driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-1\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        assert_eq!(driver.state(), AdapterState::Completed);
        let request: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::FollowUp, Some("second turn"))
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        let response = serde_json::to_vec(&json!({
            "id": request["id"], "result": {"turn": {"id": "turn-2"}}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[response.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::PromptAccepted);
        assert_eq!(events[0].correlation_id.as_deref(), Some("turn-2"));
        assert_eq!(driver.state(), AdapterState::Working);
        driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-2\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        assert_eq!(driver.state(), AdapterState::Completed);
    }

    #[test]
    fn codex_delayed_turn_start_response_is_consumed_without_resurrecting_completed_turn() {
        let mut driver = ready_codex_driver();
        driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-1\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        let request: Value = serde_json::from_slice(
            &driver
                .command(AdapterOperation::FollowUp, Some("second turn"))
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        driver
            .on_record(b"{\"method\":\"turn/started\",\"params\":{\"turn\":{\"id\":\"turn-2\"}}}\n")
            .unwrap();
        driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-2\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        let delayed = serde_json::to_vec(&json!({
            "id": request["id"],
            "result": {"turn": {"id": "turn-2"}}
        }))
        .unwrap();
        let (_, events) = driver
            .on_record(&[delayed.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::State);
        assert_eq!(
            events[0].data.as_ref().unwrap()["turnAlreadyCompleted"],
            true
        );
        assert_eq!(driver.state(), AdapterState::Completed);
        assert!(driver.active_turn_id.is_none());
        assert!(driver.pending_codex.is_empty());

        let mut mismatched = ready_codex_driver();
        mismatched
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-1\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        let request: Value = serde_json::from_slice(
            &mismatched
                .command(AdapterOperation::FollowUp, Some("second turn"))
                .unwrap()
                .remove(0)
                .0,
        )
        .unwrap();
        mismatched
            .on_record(b"{\"method\":\"turn/started\",\"params\":{\"turn\":{\"id\":\"turn-2\"}}}\n")
            .unwrap();
        mismatched
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-2\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        let delayed = serde_json::to_vec(&json!({
            "id": request["id"],
            "result": {"turn": {"id": "different-turn"}}
        }))
        .unwrap();
        let (_, events) = mismatched
            .on_record(&[delayed.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(mismatched.state(), AdapterState::Failed);
        assert_eq!(mismatched.phase, Phase::Terminal);
    }

    #[test]
    fn codex_rejects_parallel_turn_start_and_stale_turn_notifications() {
        let mut driver = ready_codex_driver();
        let (_, events) = driver
            .on_record(
                b"{\"method\":\"turn/started\",\"params\":{\"turn\":{\"id\":\"stale-turn\"}}}\n",
            )
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        let (_, events) = driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"stale-turn\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Working);

        driver
            .on_record(b"{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"turn-1\",\"status\":{\"type\":\"completed\"}}}}\n")
            .unwrap();
        driver
            .command(AdapterOperation::FollowUp, Some("first"))
            .unwrap();
        assert!(
            driver
                .command(AdapterOperation::FollowUp, Some("parallel"))
                .is_err()
        );
    }

    #[test]
    fn codex_effective_authority_is_sent_on_thread_and_turn_start() {
        let context = ApprovalContext {
            effective_policy: EffectiveApprovalPolicy::OutsideScope,
            bridge: ApprovalBridgeOwnership::Typed,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        };
        let mut driver = ProtocolDriver::new_with_authority_context(
            AdapterKind::Codex,
            &request(),
            EffectiveAccessScope::ProjectFull,
            EffectiveSandboxPolicy::External,
            context,
        )
        .unwrap();
        driver.start().unwrap();
        let (frames, _) = driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        let thread: Value = serde_json::from_slice(&frames[1].0).unwrap();
        assert_eq!(
            thread.pointer("/params/approvalPolicy"),
            Some(&json!("on-request"))
        );
        assert_eq!(
            thread.pointer("/params/sandbox"),
            Some(&json!("danger-full-access"))
        );
        let (frames, _) = driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        let turn: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(
            turn.pointer("/params/approvalPolicy"),
            Some(&json!("on-request"))
        );
        assert_eq!(
            turn.pointer("/params/sandboxPolicy/type"),
            Some(&json!("externalSandbox"))
        );
    }

    #[test]
    fn codex_typed_approval_rejects_wrong_commitment_and_settles_same_id() {
        let context = ApprovalContext {
            effective_policy: EffectiveApprovalPolicy::Always,
            bridge: ApprovalBridgeOwnership::Typed,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        };
        let mut driver = ProtocolDriver::new_with_authority_context(
            AdapterKind::Codex,
            &request(),
            EffectiveAccessScope::ReadOnly,
            EffectiveSandboxPolicy::ReadOnly,
            context,
        )
        .unwrap();
        let (frames, events) = driver
            .on_record(b"{\"id\":\"approval-7\",\"method\":\"item/commandExecution/requestApproval\",\"params\":{\"command\":\"pwd\"}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(driver.state(), AdapterState::WaitingApproval);
        let digest = events[0]
            .data
            .as_ref()
            .and_then(|data| data.get("parametersDigest"))
            .and_then(Value::as_str)
            .unwrap();
        let expires = events[0]
            .data
            .as_ref()
            .and_then(|data| data.get("expiresAtUnixMs"))
            .and_then(Value::as_u64)
            .unwrap();
        let (second_frames, second_events) = driver
            .on_record(b"{\"id\":\"approval-8\",\"method\":\"item/fileChange/requestApproval\",\"params\":{\"changes\":[]}}\n")
            .unwrap();
        let second: Value = serde_json::from_slice(&second_frames[0].0).unwrap();
        assert_eq!(second["id"], json!("approval-8"));
        assert_eq!(second.pointer("/result/decision"), Some(&json!("decline")));
        assert_eq!(second_events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::WaitingApproval);
        assert!(
            driver
                .resolve_codex_approval(
                    &json!("approval-7"),
                    "item/commandExecution/requestApproval",
                    &"0".repeat(64),
                    true,
                    expires - 1,
                )
                .is_err()
        );
        let frame = driver
            .resolve_codex_approval(
                &json!("approval-7"),
                "item/commandExecution/requestApproval",
                digest,
                true,
                expires - 1,
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&frame.0).unwrap();
        assert_eq!(response["id"], json!("approval-7"));
        assert_eq!(response.pointer("/result/decision"), Some(&json!("accept")));
        assert!(
            driver
                .resolve_codex_approval(
                    &json!("approval-7"),
                    "item/commandExecution/requestApproval",
                    digest,
                    true,
                    expires - 1,
                )
                .is_err()
        );
    }

    #[test]
    fn codex_required_risk_snapshot_controls_preauthorization() {
        let mut never_without_required = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::Never,
                bridge: ApprovalBridgeOwnership::Typed,
                required_risk_classes: ApprovalRiskClassSet::EMPTY,
            },
        )
        .unwrap();
        let (frames, events) = never_without_required
            .on_record(b"{\"id\":1,\"method\":\"item/commandExecution/requestApproval\",\"params\":{\"command\":\"pwd\"}}\n")
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(events[0].data.as_ref().unwrap()["preAuthorized"], true);

        let mut never_with_required = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::Never,
                bridge: ApprovalBridgeOwnership::Typed,
                required_risk_classes: ApprovalRiskClassSet::DESTRUCTIVE_DELETE,
            },
        )
        .unwrap();
        let (frames, events) = never_with_required
            .on_record(b"{\"id\":2,\"method\":\"item/fileChange/requestApproval\",\"params\":{\"grantRoot\":null}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(events[0].data.as_ref().unwrap()["preAuthorized"], false);
        assert_eq!(never_with_required.state(), AdapterState::WaitingApproval);

        let mut disjoint = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::RiskClasses,
                bridge: ApprovalBridgeOwnership::Typed,
                required_risk_classes: ApprovalRiskClassSet::LAN_ACCESS,
            },
        )
        .unwrap();
        let (frames, events) = disjoint
            .on_record(b"{\"id\":3,\"method\":\"item/fileChange/requestApproval\",\"params\":{\"grantRoot\":null}}\n")
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(events[0].data.as_ref().unwrap()["preAuthorized"], true);

        let mut unknown_command = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::RiskClasses,
                bridge: ApprovalBridgeOwnership::Typed,
                required_risk_classes: ApprovalRiskClassSet::LAN_ACCESS,
            },
        )
        .unwrap();
        let (frames, _) = unknown_command
            .on_record(b"{\"id\":4,\"method\":\"execCommandApproval\",\"params\":{\"command\":\"tool\"}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(unknown_command.state(), AdapterState::WaitingApproval);
    }

    #[test]
    fn codex_never_with_required_risks_advertises_callbacks() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            ApprovalContext {
                effective_policy: EffectiveApprovalPolicy::Never,
                bridge: ApprovalBridgeOwnership::Typed,
                required_risk_classes: ApprovalRiskClassSet::DESTRUCTIVE_DELETE,
            },
        )
        .unwrap();
        driver.start().unwrap();
        let (frames, _) = driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        let thread: Value = serde_json::from_slice(&frames[1].0).unwrap();
        assert_eq!(
            thread.pointer("/params/approvalPolicy"),
            Some(&json!("on-request"))
        );
        let (frames, _) = driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        let turn: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(
            turn.pointer("/params/approvalPolicy"),
            Some(&json!("on-request"))
        );
    }

    #[test]
    fn codex_duplicate_approval_ids_leave_original_pending_without_a_response() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            context(
                EffectiveApprovalPolicy::Always,
                ApprovalBridgeOwnership::Typed,
            ),
        )
        .unwrap();
        let original = b"{\"id\":\"dup\",\"method\":\"item/commandExecution/requestApproval\",\"params\":{\"command\":\"pwd\"}}\n";
        let (_, original_events) = driver.on_record(original).unwrap();
        let digest = original_events[0].data.as_ref().unwrap()["parametersDigest"]
            .as_str()
            .unwrap()
            .to_owned();

        let (frames, exact) = driver.on_record(original).unwrap();
        assert!(frames.is_empty());
        assert_eq!(exact[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(exact[0].data.as_ref().unwrap()["sameCommitment"], true);

        let (frames, changed) = driver
            .on_record(b"{\"id\":\"dup\",\"method\":\"item/fileChange/requestApproval\",\"params\":{\"changes\":[]}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(changed[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(changed[0].data.as_ref().unwrap()["sameCommitment"], false);

        let response = driver
            .resolve_codex_approval(
                &json!("dup"),
                "item/commandExecution/requestApproval",
                &digest,
                false,
                unix_ms(),
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&response.0).unwrap();
        assert_eq!(response["id"], "dup");
        assert_eq!(
            response.pointer("/result/decision"),
            Some(&json!("decline"))
        );
    }

    #[test]
    fn codex_settled_ids_replay_exact_bytes_and_reject_changed_or_unknown_reuse() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            context(
                EffectiveApprovalPolicy::Always,
                ApprovalBridgeOwnership::Typed,
            ),
        )
        .unwrap();
        let original = b"{\"id\":\"settled-codex\",\"method\":\"item/commandExecution/requestApproval\",\"params\":{\"command\":\"pwd\"}}\n";
        let (_, approval) = driver.on_record(original).unwrap();
        let data = approval[0].data.as_ref().unwrap();
        let digest = data["parametersDigest"].as_str().unwrap().to_owned();
        let expires = data["expiresAtUnixMs"].as_u64().unwrap();
        let terminal = driver
            .resolve_codex_approval(
                &json!("settled-codex"),
                "item/commandExecution/requestApproval",
                &digest,
                true,
                expires - 1,
            )
            .unwrap();

        let (exact_frames, exact_events) = driver.on_record(original).unwrap();
        assert_eq!(exact_frames, vec![terminal.clone()]);
        assert_eq!(exact_events[0].kind, AdapterEventKind::State);

        let (changed_frames, changed_events) = driver
            .on_record(b"{\"id\":\"settled-codex\",\"method\":\"item/commandExecution/requestApproval\",\"params\":{\"command\":\"whoami\"}}\n")
            .unwrap();
        assert!(changed_frames.is_empty());
        assert_eq!(changed_events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(driver.phase, Phase::Terminal);

        let (unknown_frames, unknown_events) = driver
            .on_record(b"{\"id\":\"settled-codex\",\"method\":\"future/unsafe\",\"params\":{\"command\":\"pwd\"}}\n")
            .unwrap();
        assert!(unknown_frames.is_empty());
        assert_eq!(unknown_events[0].kind, AdapterEventKind::AdapterError);
    }

    #[test]
    fn codex_typed_approval_expires_with_one_correlated_decline() {
        let context = ApprovalContext {
            effective_policy: EffectiveApprovalPolicy::Always,
            bridge: ApprovalBridgeOwnership::Typed,
            required_risk_classes: ApprovalRiskClassSet::EMPTY,
        };
        let mut driver = ProtocolDriver::new_with_authority_context(
            AdapterKind::Codex,
            &request(),
            EffectiveAccessScope::ReadOnly,
            EffectiveSandboxPolicy::ReadOnly,
            context,
        )
        .unwrap();
        let (_, events) = driver
            .on_record(b"{\"id\":-7,\"method\":\"item/fileChange/requestApproval\",\"params\":{\"changes\":[]}}\n")
            .unwrap();
        let expires = events[0].data.as_ref().unwrap()["expiresAtUnixMs"]
            .as_u64()
            .unwrap();
        let (frames, events) = driver.expire_codex_approvals(expires).unwrap();
        assert_eq!(frames.len(), 1);
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(response["id"], json!(-7));
        assert_eq!(
            response.pointer("/result/decision"),
            Some(&json!("decline"))
        );
        assert_eq!(
            events[0].data.as_ref().unwrap()["approvalExpired"],
            json!(true)
        );
        assert!(
            driver
                .expire_codex_approvals(expires + 1)
                .unwrap()
                .0
                .is_empty()
        );
        assert!(
            driver
                .resolve_codex_approval(
                    &json!(-7),
                    "item/fileChange/requestApproval",
                    events[0].data.as_ref().unwrap()["parametersDigest"]
                        .as_str()
                        .unwrap(),
                    true,
                    expires,
                )
                .is_err()
        );
    }

    #[test]
    fn codex_approval_resolution_denies_at_the_expiry_boundary() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Codex,
            &request(),
            context(
                EffectiveApprovalPolicy::Always,
                ApprovalBridgeOwnership::Typed,
            ),
        )
        .unwrap();
        let (_, events) = driver
            .on_record(b"{\"id\":\"boundary\",\"method\":\"item/fileChange/requestApproval\",\"params\":{\"changes\":[]}}\n")
            .unwrap();
        let data = events[0].data.as_ref().unwrap();
        let response = driver
            .resolve_codex_approval(
                &json!("boundary"),
                "item/fileChange/requestApproval",
                data["parametersDigest"].as_str().unwrap(),
                true,
                data["expiresAtUnixMs"].as_u64().unwrap(),
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&response.0).unwrap();
        assert_eq!(
            response.pointer("/result/decision"),
            Some(&json!("decline"))
        );
    }

    #[test]
    fn codex_current_server_request_union_always_receives_a_correlated_response() {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        let generated: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/codex-app-server-v2-server-request-methods.json"
        ))
        .unwrap();
        let methods = generated["methods"].as_array().unwrap();
        assert_eq!(methods.len(), 11, "generated ServerRequest union changed");
        for (index, method) in methods
            .iter()
            .map(|value| value.as_str().unwrap())
            .enumerate()
        {
            assert!(
                is_codex_server_request(method),
                "generated method {method} is not classified"
            );
            let id = format!("server-{index}");
            let record = serde_json::to_vec(&json!({
                "id": id,
                "method": method,
                "params": {}
            }))
            .unwrap();
            let mut record = record;
            record.push(b'\n');
            let (frames, events) = driver.on_record(&record).unwrap();
            assert_eq!(frames.len(), 1, "{method} was left pending");
            assert_eq!(events.len(), 1);
            let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
            assert_eq!(response.get("id"), Some(&json!(id)));
            if is_codex_approval_method(method) {
                assert!(response.get("result").is_some(), "{method}");
                assert_eq!(events[0].kind, AdapterEventKind::ApprovalRequest);
            } else {
                assert_eq!(
                    response.pointer("/error/data/failClosed"),
                    Some(&json!(true))
                );
                assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
            }
        }
    }

    #[test]
    fn codex_unknown_server_request_is_correlated_and_fail_closed() {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        let (frames, events) = driver
            .on_record(b"{\"id\":9223372036854775807,\"method\":\"future/unsafe\",\"params\":{}}\n")
            .unwrap();
        assert_eq!(frames.len(), 1);
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(response.get("id"), Some(&json!(9223372036854775807_i64)));
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32601)));
        assert_eq!(
            response.pointer("/error/data/failClosed"),
            Some(&json!(true))
        );
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(
            events[0].correlation_id.as_deref(),
            Some("9223372036854775807")
        );
    }

    #[test]
    fn pi_distinguishes_prompt_admission_from_completion() {
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
        let frames = driver.start().unwrap();
        assert!(
            String::from_utf8(frames[0].0.clone())
                .unwrap()
                .contains("\"type\":\"prompt\"")
        );
        let (_, events) = driver
            .on_record(b"{\"id\":\"conduit-1\",\"type\":\"response\",\"command\":\"prompt\",\"success\":true}\n")
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::PromptAccepted);
        assert_eq!(driver.state(), AdapterState::Working);
        let (_, events) = driver
            .on_record(b"{\"type\":\"agent_end\",\"willRetry\":true}\n")
            .unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::State);
        assert_eq!(driver.state(), AdapterState::Working);
        driver.on_record(b"{\"type\":\"agent_settled\"}\n").unwrap();
        assert_eq!(driver.state(), AdapterState::Completed);
    }

    #[test]
    fn pi_dialog_requests_are_correlated_and_cancelled_without_a_typed_bridge() {
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
        for (index, method) in ["select", "confirm", "input", "editor"]
            .into_iter()
            .enumerate()
        {
            let id = format!("dialog-{index}");
            let mut record = serde_json::to_vec(&json!({
                "type": "extension_ui_request",
                "id": id,
                "method": method,
                "title": "typed input"
            }))
            .unwrap();
            record.push(b'\n');
            let (frames, events) = driver.on_record(&record).unwrap();
            assert_eq!(frames.len(), 1, "{method} was left pending");
            let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
            assert_eq!(response["type"], "extension_ui_response");
            assert_eq!(response["id"], id);
            assert_eq!(response["cancelled"], true);
            assert_eq!(events[0].kind, AdapterEventKind::ApprovalRequest);
        }
    }

    #[test]
    fn pi_unknown_ui_request_is_correlated_and_fail_closed() {
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
        let (frames, events) = driver
            .on_record(
                b"{\"type\":\"extension_ui_request\",\"id\":\"future-1\",\"method\":\"future_dialog\"}\n",
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(response["id"], "future-1");
        assert_eq!(response["cancelled"], true);
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
    }

    #[test]
    fn pi_typed_dialog_keeps_one_correlated_request_and_resolves_fail_closed() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Pi,
            &request(),
            context(
                EffectiveApprovalPolicy::Always,
                ApprovalBridgeOwnership::Typed,
            ),
        )
        .unwrap();
        let (frames, _) = driver
            .on_record(b"{\"type\":\"extension_ui_request\",\"id\":\"dialog-1\",\"method\":\"confirm\",\"title\":\"Continue?\"}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(driver.state(), AdapterState::WaitingApproval);

        let (frames, events) = driver
            .on_record(b"{\"type\":\"extension_ui_request\",\"id\":\"dialog-2\",\"method\":\"input\",\"title\":\"Value\"}\n")
            .unwrap();
        let second: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(second["id"], "dialog-2");
        assert_eq!(second["cancelled"], true);
        assert_eq!(events[0].kind, AdapterEventKind::ApprovalRequest);

        assert!(matches!(
            driver.approval_response(&json!("wrong-dialog"), false),
            Err(AdapterError::UnexpectedResponse { .. })
        ));
        assert_eq!(driver.state(), AdapterState::WaitingApproval);

        let timeout = driver.approval_response(&json!("dialog-1"), false).unwrap();
        let timeout: Value = serde_json::from_slice(&timeout.0).unwrap();
        assert_eq!(timeout["id"], "dialog-1");
        assert_eq!(timeout["cancelled"], true);
        assert_eq!(driver.state(), AdapterState::Working);
    }

    #[test]
    fn pi_duplicate_dialog_ids_leave_original_pending_without_a_response() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::Pi,
            &request(),
            context(
                EffectiveApprovalPolicy::Always,
                ApprovalBridgeOwnership::Typed,
            ),
        )
        .unwrap();
        let original = b"{\"type\":\"extension_ui_request\",\"id\":\"dialog-1\",\"method\":\"confirm\",\"title\":\"Continue?\"}\n";
        assert!(driver.on_record(original).unwrap().0.is_empty());

        let (frames, exact) = driver.on_record(original).unwrap();
        assert!(frames.is_empty());
        assert_eq!(exact[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(exact[0].data.as_ref().unwrap()["sameCommitment"], true);

        let (frames, changed) = driver
            .on_record(b"{\"type\":\"extension_ui_request\",\"id\":\"dialog-1\",\"method\":\"input\",\"title\":\"Changed\"}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(changed[0].data.as_ref().unwrap()["sameCommitment"], false);

        let response = driver.approval_response(&json!("dialog-1"), false).unwrap();
        let response: Value = serde_json::from_slice(&response.0).unwrap();
        assert_eq!(response["id"], "dialog-1");
        assert_eq!(response["cancelled"], true);
    }

    #[test]
    fn pi_settled_cancel_ids_replay_exact_bytes_and_reject_changed_reuse() {
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
        let original = b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"confirm\",\"title\":\"Continue?\"}\n";
        let (terminal_frames, _) = driver.on_record(original).unwrap();
        let terminal = terminal_frames[0].clone();

        let (exact_frames, exact_events) = driver.on_record(original).unwrap();
        assert_eq!(exact_frames, vec![terminal]);
        assert_eq!(exact_events[0].kind, AdapterEventKind::State);

        let (changed_frames, changed_events) = driver
            .on_record(b"{\"type\":\"extension_ui_request\",\"id\":\"settled-pi\",\"method\":\"input\",\"title\":\"Changed\"}\n")
            .unwrap();
        assert!(changed_frames.is_empty());
        assert_eq!(changed_events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(driver.phase, Phase::Terminal);
    }

    #[test]
    fn pi_legacy_stream_without_settlement_fails_protocol_incomplete() {
        let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
        driver.start().unwrap();
        let (_, events) = driver
            .on_record(b"{\"type\":\"agent_end\",\"messages\":[]}\n")
            .unwrap();
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(events[0].data.as_ref().unwrap()["protocolIncomplete"], true);
        assert_eq!(
            events[0].data.as_ref().unwrap()["missingEvent"],
            "agent_settled"
        );
    }

    #[test]
    fn acp_permission_requests_follow_effective_policy_and_bridge_ownership() {
        let permission = b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"session-1\",\"toolCall\":{\"toolCallId\":\"tool-1\"},\"options\":[{\"optionId\":\"persist\",\"name\":\"Always\",\"kind\":\"allow_always\"},{\"optionId\":\"once\",\"name\":\"Once\",\"kind\":\"allow_once\"}]}}\n";

        let mut unavailable = ready_acp_driver(context(
            EffectiveApprovalPolicy::Always,
            ApprovalBridgeOwnership::Unavailable,
        ));
        let (frames, _) = unavailable.on_record(permission).unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(response["id"], 77);
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("cancelled"))
        );

        let mut preauthorized = ready_acp_driver(context(
            EffectiveApprovalPolicy::Never,
            ApprovalBridgeOwnership::Unavailable,
        ));
        let (frames, _) = preauthorized.on_record(permission).unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("selected"))
        );
        assert_eq!(
            response.pointer("/result/outcome/optionId"),
            Some(&json!("once"))
        );

        let mut typed = ready_acp_driver(context(
            EffectiveApprovalPolicy::RiskClasses,
            ApprovalBridgeOwnership::Typed,
        ));
        let (frames, events) = typed.on_record(permission).unwrap();
        assert!(frames.is_empty());
        assert_eq!(events[0].correlation_id.as_deref(), Some("77"));
        assert_eq!(typed.state(), AdapterState::WaitingApproval);
        let response: Value =
            serde_json::from_slice(&typed.approval_response(&json!(77), true).unwrap().0).unwrap();
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("selected"))
        );
        assert_eq!(
            response.pointer("/result/outcome/optionId"),
            Some(&json!("once"))
        );
    }

    #[test]
    fn acp_permission_validates_session_and_duplicate_ids_before_authorization() {
        let mut wrong_session = ready_acp_driver(context(
            EffectiveApprovalPolicy::Never,
            ApprovalBridgeOwnership::Unavailable,
        ));
        let (frames, events) = wrong_session
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"other-session\",\"toolCall\":{\"toolCallId\":\"tool-1\"},\"options\":[{\"optionId\":\"once\",\"kind\":\"allow_once\"}]}}\n")
            .unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("cancelled"))
        );
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);

        let mut typed = ready_acp_driver(context(
            EffectiveApprovalPolicy::Always,
            ApprovalBridgeOwnership::Typed,
        ));
        let original = b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"session-1\",\"toolCall\":{\"toolCallId\":\"tool-1\"},\"options\":[{\"optionId\":\"once\",\"kind\":\"allow_once\"}]}}\n";
        let (_, approval) = typed.on_record(original).unwrap();
        let approval_data = approval[0].data.as_ref().unwrap().clone();

        let (frames, exact) = typed.on_record(original).unwrap();
        assert!(frames.is_empty());
        assert_eq!(exact[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(exact[0].data.as_ref().unwrap()["sameCommitment"], true);

        let (frames, changed) = typed
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"other-session\",\"toolCall\":{\"toolCallId\":\"tool-2\"},\"options\":[]}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(changed[0].data.as_ref().unwrap()["sameCommitment"], false);

        assert!(
            typed
                .resolve_acp_permission(
                    &json!(77),
                    "session/request_permission",
                    "session-1",
                    "wrong-tool",
                    approval_data["parametersDigest"].as_str().unwrap(),
                    true,
                    approval_data["expiresAtUnixMs"].as_u64().unwrap() - 1,
                )
                .is_err()
        );
        let response = typed
            .resolve_acp_permission(
                &json!(77),
                "session/request_permission",
                "session-1",
                "tool-1",
                approval_data["parametersDigest"].as_str().unwrap(),
                true,
                approval_data["expiresAtUnixMs"].as_u64().unwrap(),
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&response.0).unwrap();
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("cancelled"))
        );
    }

    #[test]
    fn acp_settled_selected_ids_replay_exact_bytes_and_reject_changed_or_unknown_reuse() {
        let mut driver = ready_acp_driver(context(
            EffectiveApprovalPolicy::Never,
            ApprovalBridgeOwnership::Unavailable,
        ));
        let original = b"{\"jsonrpc\":\"2.0\",\"id\":\"settled-acp\",\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"session-1\",\"toolCall\":{\"toolCallId\":\"tool-1\"},\"options\":[{\"optionId\":\"once\",\"kind\":\"allow_once\"}]}}\n";
        let (terminal_frames, _) = driver.on_record(original).unwrap();
        let terminal = terminal_frames[0].clone();
        let terminal_value: Value = serde_json::from_slice(&terminal.0).unwrap();
        assert_eq!(
            terminal_value.pointer("/result/outcome/outcome"),
            Some(&json!("selected"))
        );

        let (exact_frames, exact_events) = driver.on_record(original).unwrap();
        assert_eq!(exact_frames, vec![terminal]);
        assert_eq!(exact_events[0].kind, AdapterEventKind::State);

        let (changed_frames, changed_events) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"settled-acp\",\"method\":\"session/request_permission\",\"params\":{\"sessionId\":\"session-1\",\"toolCall\":{\"toolCallId\":\"tool-2\"},\"options\":[]}}\n")
            .unwrap();
        assert!(changed_frames.is_empty());
        assert_eq!(changed_events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(driver.phase, Phase::Terminal);

        let (unknown_frames, unknown_events) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"settled-acp\",\"method\":\"future/client_request\",\"params\":{}}\n")
            .unwrap();
        assert!(unknown_frames.is_empty());
        assert_eq!(unknown_events[0].kind, AdapterEventKind::AdapterError);
    }

    #[test]
    fn acp_correlates_multiple_generated_follow_up_prompt_ids() {
        let mut driver = ready_acp_driver(context(
            EffectiveApprovalPolicy::Always,
            ApprovalBridgeOwnership::Unavailable,
        ));
        for expected_id in [3, 4, 5] {
            let request: Value = serde_json::from_slice(
                &driver
                    .command(AdapterOperation::FollowUp, Some("continue"))
                    .unwrap()
                    .remove(0)
                    .0,
            )
            .unwrap();
            assert_eq!(request["id"], expected_id);
            let response = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": expected_id,
                "result": {"stopReason": "end_turn"}
            }))
            .unwrap();
            let (_, events) = driver
                .on_record(&[response.as_slice(), b"\n"].concat())
                .unwrap();
            assert_eq!(events[0].kind, AdapterEventKind::Completed);
            assert_eq!(driver.state(), AdapterState::Completed);
        }
    }

    #[test]
    fn provider_terminal_capacity_fails_adapter_without_eviction_or_response() {
        let mut driver = ready_acp_driver(context(
            EffectiveApprovalPolicy::Always,
            ApprovalBridgeOwnership::Unavailable,
        ));
        let mut first_terminal = None;
        for index in 0..MAX_PROVIDER_REQUEST_TERMINALS {
            let mut record = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": format!("terminal-{index}"),
                "method": "future/client_request",
                "params": {}
            }))
            .unwrap();
            record.push(b'\n');
            let (frames, _) = driver.on_record(&record).unwrap();
            assert_eq!(frames.len(), 1);
            if index == 0 {
                first_terminal = Some(frames[0].clone());
            }
        }
        assert_eq!(
            driver.provider_request_terminals.len(),
            MAX_PROVIDER_REQUEST_TERMINALS
        );

        let (frames, events) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"overflow\",\"method\":\"future/client_request\",\"params\":{}}\n")
            .unwrap();
        assert!(frames.is_empty());
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
        assert_eq!(driver.state(), AdapterState::Failed);
        assert_eq!(driver.phase, Phase::Terminal);

        let (frames, _) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"terminal-0\",\"method\":\"future/client_request\",\"params\":{}}\n")
            .unwrap();
        assert_eq!(frames, vec![first_terminal.unwrap()]);
        assert_eq!(
            driver.provider_request_terminals.len(),
            MAX_PROVIDER_REQUEST_TERMINALS
        );
    }

    #[test]
    fn acp_never_does_not_expand_authority_to_allow_always_and_unknown_requests_fail_closed() {
        let mut driver = ProtocolDriver::new_with_approval_context(
            AdapterKind::OpenCode,
            &request(),
            context(
                EffectiveApprovalPolicy::Never,
                ApprovalBridgeOwnership::Unavailable,
            ),
        )
        .unwrap();
        let (frames, _) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"permission-1\",\"method\":\"session/request_permission\",\"params\":{\"options\":[{\"optionId\":\"persist\",\"kind\":\"allow_always\"}]}}\n")
            .unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(
            response.pointer("/result/outcome/outcome"),
            Some(&json!("cancelled"))
        );

        let (frames, events) = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":\"future-1\",\"method\":\"future/client_request\",\"params\":{}}\n")
            .unwrap();
        let response: Value = serde_json::from_slice(&frames[0].0).unwrap();
        assert_eq!(response["id"], "future-1");
        assert_eq!(response.pointer("/error/code"), Some(&json!(-32601)));
        assert_eq!(
            response.pointer("/error/data/failClosed"),
            Some(&json!(true))
        );
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
    }

    #[test]
    fn hidden_reasoning_is_not_normalized() {
        let mut driver = ProtocolDriver::new(AdapterKind::ClaudeCode, &request()).unwrap();
        driver.start().unwrap();
        let (_, events) = driver
            .on_record(b"{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"thinking\",\"thinking\":\"private\"},{\"type\":\"text\",\"text\":\"visible\"}]}}\n")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].text.as_deref(), Some("visible"));
    }

    #[test]
    fn unknown_vendor_events_remain_visible() {
        let mut driver = ProtocolDriver::new(AdapterKind::Agy, &request()).unwrap();
        driver.start().unwrap();
        let (_, events) = driver.on_record(b"{\"type\":\"future_event\"}\n").unwrap();
        assert_eq!(events[0].kind, AdapterEventKind::AdapterError);
    }

    #[test]
    fn rejects_oversize_and_non_lf_frames_before_json_parsing() {
        assert!(matches!(
            parse_frame(b"{}"),
            Err(AdapterError::InvalidFrame)
        ));
        let oversized = vec![b'x'; MAX_PROTOCOL_FRAME_BYTES + 1];
        assert!(matches!(
            parse_frame(&oversized),
            Err(AdapterError::InvalidFrame)
        ));
    }
}
