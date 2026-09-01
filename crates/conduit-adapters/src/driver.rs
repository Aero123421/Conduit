use std::collections::VecDeque;

use serde_json::{Value, json};

use crate::types::{
    AdapterError, AdapterEvent, AdapterEventKind, AdapterKind, AdapterOperation, AdapterState,
    LaunchRequest, MAX_PROTOCOL_FRAME_BYTES, ProtocolFrame, validate_launch_request,
};

const MAX_REPLAY_EVENTS: usize = 4_096;

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
pub struct ProtocolDriver {
    kind: AdapterKind,
    phase: Phase,
    state: AdapterState,
    prompt: Option<String>,
    cwd: String,
    requested_session_id: Option<String>,
    native_session_id: Option<String>,
    active_turn_id: Option<String>,
    next_request_id: u64,
    replay: VecDeque<AdapterEvent>,
}

impl ProtocolDriver {
    pub fn new(kind: AdapterKind, request: &LaunchRequest) -> Result<Self, AdapterError> {
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
            requested_session_id: request.native_session_id.clone(),
            native_session_id: None,
            active_turn_id: None,
            next_request_id: 1,
            replay: VecDeque::new(),
        })
    }

    pub fn start(&mut self) -> Result<Vec<ProtocolFrame>, AdapterError> {
        match self.phase {
            Phase::CodexInitialize => Ok(vec![self.request(
                "initialize",
                json!({
                    "clientInfo": {"name": "conduit", "title": "Conduit", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"experimentalApi": true}
                }),
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
            AdapterKind::Pi => (Vec::new(), self.normalize_pi(&value)),
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
        &self,
        request_id: &Value,
        allow: bool,
    ) -> Result<ProtocolFrame, AdapterError> {
        match self.kind {
            AdapterKind::Codex => ProtocolFrame::json(&json!({
                "id": request_id,
                "result": {"decision": if allow { "accept" } else { "decline" }}
            })),
            AdapterKind::OpenCode => ProtocolFrame::json(&json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"outcome": if allow { "selected" } else { "cancelled" }}
            })),
            _ => Err(AdapterError::UnsupportedOperation {
                adapter: self.kind,
                operation: AdapterOperation::Send,
                reason: "adapter has no correlated approval response protocol",
            }),
        }
    }

    fn on_codex(
        &mut self,
        value: &Value,
    ) -> Result<(Vec<ProtocolFrame>, Vec<AdapterEvent>), AdapterError> {
        if let Some(method) = value.get("method").and_then(Value::as_str) {
            if let Some(request_id) = value.get("id") {
                let correlation_id = request_id_text(request_id);
                if is_codex_approval_method(method) {
                    // Conduit does not advertise a synchronous approval callback
                    // capability to app-server yet.  Explicitly decline instead of
                    // leaving a server-initiated request pending indefinitely.
                    let frame = codex_approval_decline(method, request_id)?;
                    let event = AdapterEvent::bounded(
                        AdapterEventKind::ApprovalRequest,
                        method,
                        self.native_session_id(),
                        Some(&correlation_id),
                        Some("declined because the Conduit approval bridge is not advertised"),
                        value.get("params").cloned(),
                    );
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
                    value.get("params").cloned(),
                );
                return Ok((vec![frame], vec![event]));
            }
            return Ok((Vec::new(), self.normalize_codex_notification(method, value)));
        }
        if value.get("error").is_some() {
            self.state = AdapterState::Failed;
            return Ok((
                Vec::new(),
                vec![AdapterEvent::bounded(
                    AdapterEventKind::Error,
                    "json_rpc_error",
                    self.native_session_id(),
                    value.get("id").map(request_id_text).as_deref(),
                    value.pointer("/error/message").and_then(Value::as_str),
                    None,
                )],
            ));
        }
        let id = value.get("id").map(request_id_text);
        match self.phase {
            Phase::CodexInitialize if id.as_deref() == Some("1") => {
                require_result(value, self.phase_name())?;
                self.phase = Phase::CodexThread;
                let params = self.requested_session_id.as_ref().map_or_else(
                    || json!({"cwd": self.cwd}),
                    |session_id| json!({"threadId": session_id, "cwd": self.cwd, "excludeTurns": true}),
                );
                let method = if self.requested_session_id.is_some() {
                    "thread/resume"
                } else {
                    "thread/start"
                };
                Ok((
                    vec![
                        ProtocolFrame::json(&json!({"method": "initialized"}))?,
                        self.request(method, params)?,
                    ],
                    Vec::new(),
                ))
            }
            Phase::CodexThread if id.as_deref() == Some("2") => {
                let session_id = value
                    .pointer("/result/thread/id")
                    .and_then(Value::as_str)
                    .ok_or(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "thread response omitted result.thread.id",
                    })?
                    .to_owned();
                self.native_session_id = Some(session_id.clone());
                self.state = AdapterState::Ready;
                let session_event = AdapterEvent::bounded(
                    AdapterEventKind::Session,
                    "thread/ready",
                    Some(&session_id),
                    None,
                    None,
                    None,
                );
                if let Some(prompt) = self.prompt.clone() {
                    self.phase = Phase::CodexTurn;
                    self.state = AdapterState::Starting;
                    let frame = self.codex_turn(&prompt)?;
                    Ok((vec![frame], vec![session_event]))
                } else {
                    self.phase = Phase::Ready;
                    Ok((Vec::new(), vec![session_event]))
                }
            }
            Phase::CodexTurn if id.as_deref() == Some("3") => {
                let turn_id = value
                    .pointer("/result/turn/id")
                    .and_then(Value::as_str)
                    .ok_or(AdapterError::UnexpectedResponse {
                        phase: self.phase_name(),
                        reason: "turn response omitted result.turn.id",
                    })?
                    .to_owned();
                self.active_turn_id = Some(turn_id.clone());
                self.phase = Phase::Active;
                self.state = AdapterState::Working;
                Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        AdapterEventKind::PromptAccepted,
                        "turn/start",
                        self.native_session_id(),
                        Some(&turn_id),
                        None,
                        None,
                    )],
                ))
            }
            _ => Ok((
                Vec::new(),
                vec![AdapterEvent::bounded(
                    AdapterEventKind::AdapterError,
                    "unexpected_response",
                    self.native_session_id(),
                    id.as_deref(),
                    Some("response did not match the active Codex request"),
                    None,
                )],
            )),
        }
    }

    fn normalize_codex_notification(&mut self, method: &str, value: &Value) -> Vec<AdapterEvent> {
        let params = value.get("params");
        let event = match method {
            "turn/started" => {
                let turn_id = params
                    .and_then(|params| params.pointer("/turn/id"))
                    .and_then(Value::as_str);
                if let Some(turn_id) = turn_id {
                    self.active_turn_id = Some(turn_id.to_owned());
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
                self.active_turn_id = None;
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
            if value.get("id").is_some() {
                let kind = if method == "session/request_permission" {
                    self.state = AdapterState::WaitingApproval;
                    AdapterEventKind::ApprovalRequest
                } else {
                    AdapterEventKind::AdapterError
                };
                return Ok((
                    Vec::new(),
                    vec![AdapterEvent::bounded(
                        kind,
                        method,
                        self.native_session_id(),
                        value.get("id").map(request_id_text).as_deref(),
                        None,
                        value.get("params").cloned(),
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
            Phase::AcpPrompt if id.as_deref() == Some("3") => {
                require_result(value, self.phase_name())?;
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

    fn normalize_pi(&mut self, value: &Value) -> Vec<AdapterEvent> {
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
                value.get("error").and_then(Value::as_str),
                value.get("toolCallId").and_then(Value::as_str),
            ),
            "auto_compaction_start" | "auto_compaction_end" => {
                (AdapterEventKind::State, None, None)
            }
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
            None,
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
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Some(session_id) = value.get("session_id").and_then(Value::as_str) {
            self.native_session_id = Some(session_id.to_owned());
        }
        let (kind, text, correlation) = match event_type {
            "init" => {
                self.state = AdapterState::Working;
                (AdapterEventKind::Session, None, None)
            }
            "message" if value.get("role").and_then(Value::as_str) == Some("assistant") => (
                if value.get("delta").and_then(Value::as_bool) == Some(true) {
                    AdapterEventKind::AssistantMessageDelta
                } else {
                    AdapterEventKind::AssistantMessage
                },
                value.get("content").and_then(Value::as_str),
                None,
            ),
            "message" => return Vec::new(),
            "tool_use" => (
                AdapterEventKind::ToolCall,
                value.get("tool_name").and_then(Value::as_str),
                value.get("tool_id").and_then(Value::as_str),
            ),
            "tool_result" => (
                AdapterEventKind::ToolResult,
                value
                    .get("output")
                    .or_else(|| value.get("error"))
                    .and_then(Value::as_str),
                value.get("tool_id").and_then(Value::as_str),
            ),
            "result" => {
                self.state = AdapterState::Completed;
                (
                    AdapterEventKind::Completed,
                    value.get("status").and_then(Value::as_str),
                    None,
                )
            }
            "error" => {
                self.state = AdapterState::Failed;
                (
                    AdapterEventKind::Error,
                    value.get("message").and_then(Value::as_str),
                    None,
                )
            }
            _ => (AdapterEventKind::AdapterError, None, None),
        };
        vec![AdapterEvent::bounded(
            kind,
            event_type,
            self.native_session_id(),
            correlation,
            text,
            None,
        )]
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
                if self.active_turn_id.is_some() {
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
                Ok(vec![self.request_with_id(
                    "turn/steer",
                    json!({
                        "threadId": session_id,
                        "expectedTurnId": turn_id,
                        "input": [{"type": "text", "text": text.unwrap_or_default()}]
                    }),
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
                Ok(vec![self.request_with_id(
                    "turn/interrupt",
                    json!({"threadId": session_id, "turnId": turn_id}),
                )?])
            }
            AdapterOperation::State => Ok(vec![self.request_with_id(
                "thread/read",
                json!({"threadId": session_id, "includeTurns": false}),
            )?]),
            AdapterOperation::ModelDiscovery => Ok(vec![
                self.request_with_id("model/list", json!({"limit": 100}))?,
            ]),
            AdapterOperation::Close => {
                self.phase = Phase::Terminal;
                Ok(vec![self.request_with_id(
                    "thread/archive",
                    json!({"threadId": session_id}),
                )?])
            }
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
        let id = if self.next_request_id <= 3 {
            self.next_request_id = 4;
            3
        } else {
            self.take_request_id()
        };
        ProtocolFrame::json(&json!({
            "id": id,
            "method": "turn/start",
            "params": {
                "threadId": session_id,
                "input": [{"type": "text", "text": prompt}]
            }
        }))
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

    fn request(&mut self, method: &str, params: Value) -> Result<ProtocolFrame, AdapterError> {
        let id = self.take_request_id();
        ProtocolFrame::json(&json!({"id": id, "method": method, "params": params}))
    }

    fn request_with_id(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<ProtocolFrame, AdapterError> {
        self.request(method, params)
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

const CODEX_SERVER_REQUEST_METHODS: [&str; 10] = [
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/tool/requestUserInput",
    "mcpServer/elicitation/request",
    "item/permissions/requestApproval",
    "item/tool/call",
    "account/chatgptAuthTokens/refresh",
    "attestation/generate",
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

fn codex_approval_decline(method: &str, id: &Value) -> Result<ProtocolFrame, AdapterError> {
    let result = match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            json!({"decision": "decline"})
        }
        "applyPatchApproval" | "execCommandApproval" => json!({
            "decision": {
                "denied": {
                    "rejection": "Conduit did not advertise a synchronous approval bridge"
                }
            }
        }),
        _ => {
            return Err(AdapterError::UnexpectedResponse {
                phase: "codex_server_request",
                reason: "approval response requested for a non-approval method",
            });
        }
    };
    ProtocolFrame::json(&json!({"id": id, "result": result}))
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
    }

    #[test]
    fn codex_current_server_request_union_always_receives_a_correlated_response() {
        let mut driver = ProtocolDriver::new(AdapterKind::Codex, &request()).unwrap();
        for (index, method) in CODEX_SERVER_REQUEST_METHODS.into_iter().enumerate() {
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
        driver.on_record(b"{\"type\":\"agent_end\"}\n").unwrap();
        assert_eq!(driver.state(), AdapterState::Completed);
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
