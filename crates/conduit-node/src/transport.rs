use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_node_store::{
    DeviceIdentity, Direction, MAX_FRAME_BYTES, NodeStore, ReceiveResult, StoreError,
    TransportFrame,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket, client_tls_with_config, stream::MaybeTlsStream};
use url::Url;

pub const PROTOCOL: &str = "conduit.node/1";
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("frame_too_large")]
    FrameTooLarge,
    #[error("frame_malformed")]
    Malformed,
    #[error("payload_digest_mismatch")]
    DigestMismatch,
    #[error("connection_epoch_stale")]
    StaleEpoch,
    #[error("sequence_gap:{0}")]
    SequenceGap(u64),
    #[error("sequence_conflict")]
    SequenceConflict,
    #[error("protocol_version_unsupported")]
    ProtocolUnsupported,
    #[error("WebSocket failed: {0}")]
    WebSocket(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Hello<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    device_id: &'a str,
    key_id: &'a str,
    supported_protocols: [&'static str; 1],
    capability_digest: &'a str,
    client_nonce: String,
    node_boot_id: &'a str,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    connection_id: String,
    server_nonce: String,
    selected_protocol: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Proof<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    connection_id: &'a str,
    device_id: &'a str,
    key_id: &'a str,
    signature: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Accepted {
    #[serde(rename = "type")]
    kind: String,
    connection_epoch: String,
    selected_protocol: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub protocol: String,
    pub message_id: String,
    pub device_id: String,
    pub connection_epoch: String,
    pub direction: String,
    pub sequence: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub payload_digest: String,
    pub payload: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileSummary {
    pub device_id: String,
    pub connection_epoch: String,
    pub node_boot_id: String,
    pub journal_generation: String,
    pub last_control_sequence: String,
    pub last_node_sequence_acknowledged: String,
    pub active_runtime_ids: Vec<String>,
    pub unresolved_operation_ids: Vec<String>,
    pub truncated: bool,
}

pub struct TransportSession {
    store: NodeStore,
    device_id: String,
    epoch: u64,
    reconciliation_complete: bool,
}
impl TransportSession {
    pub fn new(store: NodeStore, device_id: String, epoch: u64) -> Result<Self, TransportError> {
        if epoch < store.connection_epoch()? {
            return Err(TransportError::StaleEpoch);
        }
        if epoch > store.connection_epoch()? {
            store.set_connection_epoch(epoch)?
        }
        Ok(Self {
            store,
            device_id,
            epoch,
            reconciliation_complete: false,
        })
    }
    pub fn mark_reconciliation_complete(&mut self) {
        self.reconciliation_complete = true
    }
    pub fn persist_plan(&self, plan_id: &str, payload: &Value) -> Result<(), TransportError> {
        let bytes = serde_jcs::to_vec(payload).map_err(|_| TransportError::Malformed)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        self.store
            .persist_reconciliation_plan(plan_id, self.epoch, &digest, &bytes)?;
        Ok(())
    }
    pub fn complete_plan(&mut self, plan_id: &str) -> Result<(), TransportError> {
        self.store.complete_reconciliation(plan_id)?;
        self.reconciliation_complete = true;
        Ok(())
    }
    pub fn remote_work_allowed(&self) -> bool {
        self.reconciliation_complete
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<(Envelope, ReceiveResult), TransportError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameTooLarge);
        }
        let e: Envelope = serde_json::from_slice(bytes).map_err(|_| TransportError::Malformed)?;
        if e.protocol != PROTOCOL {
            return Err(TransportError::ProtocolUnsupported);
        }
        if e.device_id != self.device_id
            || e.connection_epoch.parse::<u64>().ok() != Some(self.epoch)
        {
            return Err(TransportError::StaleEpoch);
        }
        if e.direction != "control_to_node" {
            return Err(TransportError::Malformed);
        }
        let canonical = serde_jcs::to_vec(&e.payload).map_err(|_| TransportError::Malformed)?;
        let digest = hex::encode(Sha256::digest(&canonical));
        if digest != e.payload_digest {
            return Err(TransportError::DigestMismatch);
        }
        let sequence = e.sequence.parse().map_err(|_| TransportError::Malformed)?;
        let result = self
            .store
            .receive(
                Direction::ControlToNode,
                &TransportFrame {
                    sequence,
                    message_id: e.message_id.clone(),
                    payload_digest: e.payload_digest.clone(),
                    frame: bytes.to_vec(),
                },
            )
            .map_err(|x| match x {
                StoreError::SequenceConflict => TransportError::SequenceConflict,
                other => TransportError::Store(other),
            })?;
        Ok((e, result))
    }
    pub fn queue_outbound(
        &self,
        message_id: &str,
        kind: &str,
        correlation_id: Option<String>,
        payload: Value,
        priority: u8,
    ) -> Result<Envelope, TransportError> {
        let canonical = serde_jcs::to_vec(&payload).map_err(|_| TransportError::Malformed)?;
        let digest = hex::encode(Sha256::digest(&canonical));
        let base = Envelope {
            protocol: PROTOCOL.into(),
            message_id: message_id.into(),
            device_id: self.device_id.clone(),
            connection_epoch: self.epoch.to_string(),
            direction: "node_to_control".into(),
            sequence: "0".into(),
            kind: kind.into(),
            correlation_id,
            payload_digest: digest.clone(),
            payload,
        };
        let (_, bytes) = self.store.append_outbound_with(
            Direction::NodeToControl,
            message_id,
            &digest,
            priority,
            |seq| {
                let mut exact = base.clone();
                exact.sequence = seq.to_string();
                serde_json::to_vec(&exact)
                    .map_err(|_| StoreError::Invalid("outbound frame encoding failed".into()))
            },
        )?;
        serde_json::from_slice(&bytes).map_err(|_| TransportError::Malformed)
    }
    pub fn replay(&self, from: u64) -> Result<Vec<Vec<u8>>, TransportError> {
        Ok(self
            .store
            .replay_outbound(Direction::NodeToControl, from, 512)?
            .into_iter()
            .map(|v| v.frame)
            .collect())
    }
}

/// Synchronous bounded WSS client used by the service loop. It only accepts
/// `wss:` and completes authenticated challenge/proof before returning.
pub struct WssClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    pub session: TransportSession,
}
impl WssClient {
    pub fn connect(
        url: &str,
        store: NodeStore,
        identity: &DeviceIdentity,
        device_id: &str,
        capability_digest: &str,
        node_boot_id: &str,
    ) -> Result<Self, TransportError> {
        let url = Url::parse(url).map_err(|_| TransportError::Malformed)?;
        if url.scheme() != "wss" {
            return Err(TransportError::WebSocket(
                "outbound endpoint must use wss".into(),
            ));
        }
        let host = url.host_str().ok_or(TransportError::Malformed)?;
        let port = url
            .port_or_known_default()
            .ok_or(TransportError::Malformed)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = None;
        for addr in (host, port)
            .to_socket_addrs()
            .map_err(|e| TransportError::WebSocket(e.to_string()))?
            .take(16)
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(s) = TcpStream::connect_timeout(&addr, remaining.min(Duration::from_secs(5)))
            {
                stream = Some(s);
                break;
            }
        }
        let stream =
            stream.ok_or_else(|| TransportError::WebSocket("bounded WSS connect failed".into()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        let mut config = tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_FRAME_BYTES);
        config.max_frame_size = Some(MAX_FRAME_BYTES);
        let request = url
            .as_str()
            .into_client_request()
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        let (mut socket, _) = client_tls_with_config(request, stream, Some(config), None)
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        set_timeouts(&mut socket);
        let mut nonce = [0u8; 24];
        getrandom_fill(&mut nonce)?;
        let hello = Hello {
            kind: "device.hello",
            device_id,
            key_id: identity.key_id(),
            supported_protocols: [PROTOCOL],
            capability_digest,
            client_nonce: URL_SAFE_NO_PAD.encode(nonce),
            node_boot_id,
        };
        write_json(&mut socket, &hello)?;
        let challenge: Challenge = read_json(&mut socket)?;
        if challenge.kind != "device.challenge" || challenge.selected_protocol != PROTOCOL {
            return Err(TransportError::ProtocolUnsupported);
        }
        let transcript=serde_jcs::to_vec(&serde_json::json!({"clientNonce":URL_SAFE_NO_PAD.encode(nonce),"connectionId":challenge.connection_id,"deviceId":device_id,"keyId":identity.key_id(),"protocol":PROTOCOL,"serverNonce":challenge.server_nonce})).map_err(|_|TransportError::Malformed)?;
        let proof = Proof {
            kind: "device.proof",
            connection_id: &challenge.connection_id,
            device_id,
            key_id: identity.key_id(),
            signature: identity.sign(&transcript),
        };
        write_json(&mut socket, &proof)?;
        let accepted: Accepted = read_json(&mut socket)?;
        if accepted.kind != "transport.accepted" || accepted.selected_protocol != PROTOCOL {
            return Err(TransportError::ProtocolUnsupported);
        }
        let epoch = accepted
            .connection_epoch
            .parse()
            .map_err(|_| TransportError::Malformed)?;
        let session = TransportSession::new(store, device_id.into(), epoch)?;
        Ok(Self { socket, session })
    }
    pub fn send(&mut self, frame: &Envelope) -> Result<(), TransportError> {
        let b = serde_json::to_vec(frame).map_err(|_| TransportError::Malformed)?;
        if b.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameTooLarge);
        }
        self.socket
            .send(Message::Text(
                String::from_utf8(b)
                    .map_err(|_| TransportError::Malformed)?
                    .into(),
            ))
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }
    pub fn receive(&mut self) -> Result<(Envelope, ReceiveResult), TransportError> {
        match self
            .socket
            .read()
            .map_err(|e| TransportError::WebSocket(e.to_string()))?
        {
            Message::Text(v) => self.session.receive(v.as_bytes()),
            Message::Ping(v) => {
                self.socket
                    .send(Message::Pong(v))
                    .map_err(|e| TransportError::WebSocket(e.to_string()))?;
                self.receive()
            }
            _ => Err(TransportError::Malformed),
        }
    }
}
use tungstenite::client::IntoClientRequest;
fn set_timeouts(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    match socket.get_mut() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(45)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.get_mut().set_read_timeout(Some(Duration::from_secs(45)));
            let _ = s.get_mut().set_write_timeout(Some(Duration::from_secs(15)));
        }
        _ => {}
    }
}
fn write_json<T: Serialize>(
    s: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    v: &T,
) -> Result<(), TransportError> {
    let b = serde_json::to_vec(v).map_err(|_| TransportError::Malformed)?;
    if b.len() > MAX_FRAME_BYTES {
        return Err(TransportError::FrameTooLarge);
    }
    s.send(Message::Text(
        String::from_utf8(b)
            .map_err(|_| TransportError::Malformed)?
            .into(),
    ))
    .map_err(|e| TransportError::WebSocket(e.to_string()))
}
fn read_json<T: for<'de> Deserialize<'de>>(
    s: &mut WebSocket<MaybeTlsStream<TcpStream>>,
) -> Result<T, TransportError> {
    match s
        .read()
        .map_err(|e| TransportError::WebSocket(e.to_string()))?
    {
        Message::Text(v) if v.len() <= MAX_FRAME_BYTES => {
            serde_json::from_str(&v).map_err(|_| TransportError::Malformed)
        }
        _ => Err(TransportError::Malformed),
    }
}
fn getrandom_fill(bytes: &mut [u8]) -> Result<(), TransportError> {
    use std::fs::File;
    use std::io::Read;
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(bytes))
        .map_err(|e| TransportError::WebSocket(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    fn digest(v: &Value) -> String {
        hex::encode(Sha256::digest(serde_jcs::to_vec(v).unwrap()))
    }
    fn envelope(seq: u64, p: Value) -> Envelope {
        Envelope {
            protocol: PROTOCOL.into(),
            message_id: format!("cmsg_{seq:08}"),
            device_id: "dev_12345678".into(),
            connection_epoch: "1".into(),
            direction: "control_to_node".into(),
            sequence: seq.to_string(),
            kind: "transport.ack".into(),
            correlation_id: None,
            payload_digest: digest(&p),
            payload: p,
        }
    }
    #[test]
    fn fences_epoch_and_sequences() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let t = TransportSession::new(s.clone(), "dev_12345678".into(), 1).unwrap();
        let e = envelope(1, serde_json::json!({"x":1}));
        let b = serde_json::to_vec(&e).unwrap();
        assert_eq!(t.receive(&b).unwrap().1, ReceiveResult::Applied);
        assert_eq!(t.receive(&b).unwrap().1, ReceiveResult::Duplicate);
        let gap = serde_json::to_vec(&envelope(3, serde_json::json!({"x":3}))).unwrap();
        assert_eq!(
            t.receive(&gap).unwrap().1,
            ReceiveResult::Gap { expected: 2 }
        );
        assert!(matches!(
            TransportSession::new(s, "dev_12345678".into(), 0),
            Err(TransportError::StaleEpoch)
        ));
    }
    #[test]
    fn replay_contains_exact_allocated_sequence() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let t = TransportSession::new(s, "dev_12345678".into(), 1).unwrap();
        let e = t
            .queue_outbound(
                "nmsg_12345678",
                "reconcile.summary",
                None,
                serde_json::json!({"ok":true}),
                0,
            )
            .unwrap();
        assert_eq!(e.sequence, "1");
        let replay = t.replay(1).unwrap();
        let durable: Envelope = serde_json::from_slice(&replay[0]).unwrap();
        assert_eq!(durable.sequence, "1");
    }
}
