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
