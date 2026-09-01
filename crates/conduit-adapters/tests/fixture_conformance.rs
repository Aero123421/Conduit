use std::{fs, path::PathBuf};

use conduit_adapters::{
    AdapterEventKind, AdapterKind, AdapterState, LaunchRequest, ProtocolDriver,
};

fn request() -> LaunchRequest {
    LaunchRequest {
        cwd: PathBuf::from("/tmp/conduit-fixture-workspace"),
        prompt: Some("process the fixture".to_owned()),
        native_session_id: None,
        model: None,
        effort: None,
        session_data_dir: Some(PathBuf::from("/tmp/conduit-fixture-sessions")),
    }
}

fn run_fixture(kind: AdapterKind, name: &str) -> (ProtocolDriver, Vec<AdapterEventKind>) {
    let mut driver = ProtocolDriver::new(kind, &request()).unwrap();
    driver.start().unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let bytes = fs::read(path).unwrap();
    let mut kinds = Vec::new();
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let (_, events) = driver.on_record(line).unwrap();
        kinds.extend(events.into_iter().map(|event| event.kind));
    }
    (driver, kinds)
}

#[test]
fn every_required_adapter_fixture_reaches_a_truthful_terminal_state() {
    for (kind, fixture) in [
        (AdapterKind::Codex, "codex-app-server-v2.jsonl"),
        (AdapterKind::ClaudeCode, "claude-stream-json-v1.jsonl"),
        (AdapterKind::OpenCode, "opencode-acp-v1.jsonl"),
        (AdapterKind::Pi, "pi-rpc-v1.jsonl"),
        (AdapterKind::Agy, "agy-stream-json-v1.jsonl"),
    ] {
        let (driver, events) = run_fixture(kind, fixture);
        assert!(
            matches!(driver.state(), AdapterState::Completed),
            "{kind:?} did not complete"
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                AdapterEventKind::AssistantMessage | AdapterEventKind::AssistantMessageDelta
            )),
            "{kind:?} did not emit visible output"
        );
        assert!(
            events
                .iter()
                .all(|event| *event != AdapterEventKind::AdapterError),
            "{kind:?} fixture contained an unrecognized event"
        );
    }
}

#[test]
fn pi_retry_queue_and_tool_error_remain_visible_until_agent_settles() {
    let mut driver = ProtocolDriver::new(AdapterKind::Pi, &request()).unwrap();
    driver.start().unwrap();
    driver
        .on_record(b"{\"id\":\"conduit-1\",\"type\":\"response\",\"command\":\"prompt\",\"success\":true}\n")
        .unwrap();
    driver.on_record(b"{\"type\":\"agent_start\"}\n").unwrap();

    let (_, tool_events) = driver
        .on_record(
            b"{\"type\":\"tool_execution_end\",\"toolCallId\":\"tool-error-1\",\"toolName\":\"read\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"fixture tool error\"}]},\"isError\":true}\n",
        )
        .unwrap();
    assert_eq!(tool_events[0].kind, AdapterEventKind::ToolResult);
    assert_eq!(tool_events[0].correlation_id.as_deref(), Some("tool-error-1"));
    assert_eq!(tool_events[0].text.as_deref(), Some("fixture tool error"));
    assert_eq!(
        tool_events[0]
            .data
            .as_ref()
            .and_then(|data| data.get("isError"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let (_, queue_events) = driver
        .on_record(
            b"{\"type\":\"queue_update\",\"steering\":[],\"followUp\":[\"summarize after retry\"]}\n",
        )
        .unwrap();
    assert_eq!(queue_events[0].kind, AdapterEventKind::State);
    assert_eq!(driver.state(), AdapterState::Working);

    driver
        .on_record(b"{\"type\":\"agent_end\",\"messages\":[],\"willRetry\":true}\n")
        .unwrap();
    assert_eq!(driver.state(), AdapterState::Working);
    driver
        .on_record(b"{\"type\":\"agent_settled\"}\n")
        .unwrap();
    assert_eq!(driver.state(), AdapterState::Completed);
}
