use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use conduit_node_store::{
    DeviceIdentity, Direction, MAX_FRAME_BYTES, NodeStore, ReceiveResult, StoreError,
    TransportFrame,
};
use conduit_protocol::{NodeProtocolV1, ValidatedDocument};
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
/// The service loop must wake often enough to honour event/ACK coalescing
/// timers even when the WebSocket is otherwise idle.  Handshake I/O keeps its
/// longer timeout; this value is installed only after authentication.
const SERVICE_POLL_TIMEOUT: Duration = Duration::from_millis(100);
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
    #[error("reconciliation_required")]
    ReconciliationRequired,
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
    server_time: String,
    expires_in_ms: u64,
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
    connection_id: String,
    device_id: String,
    connection_epoch: String,
    selected_protocol: String,
    control_next_sequence: String,
    node_stored_through_sequence: String,
    reconciliation_required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Highest contiguous control-to-node sequence that this node has
    /// applied when it built the frame.  It is optional on the wire for
    /// backwards-compatible peers, but every current Node outbound frame
    /// carries it so health, reconciliation, and ordinary receipts expose the
    /// same applied-control frontier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_applied_through: Option<String>,
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
    preexisting_control_frontier: u64,
    reconciliation_complete: bool,
}
impl TransportSession {
    pub fn new(store: NodeStore, device_id: String, epoch: u64) -> Result<Self, TransportError> {
        let frontier = store.transport_positions()?.control_received_through;
        Self::new_with_control_frontier(store, device_id, epoch, frontier)
    }
    pub(crate) fn new_with_control_frontier(
        store: NodeStore,
        device_id: String,
        epoch: u64,
        preexisting_control_frontier: u64,
    ) -> Result<Self, TransportError> {
        if epoch <= store.connection_epoch()? {
            return Err(TransportError::StaleEpoch);
        }
        if preexisting_control_frontier < store.transport_positions()?.control_received_through {
            return Err(TransportError::Malformed);
        }
        store.set_connection_epoch(epoch)?;
        Ok(Self {
            store,
            device_id,
            epoch,
            preexisting_control_frontier,
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

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn preexisting_control_replay_allowed(&self, sequence: u64) -> bool {
        !self.reconciliation_complete && sequence <= self.preexisting_control_frontier
    }
    pub fn control_frame_allowed(&self, kind: &str, sequence: u64) -> bool {
        !matches!(
            kind,
            "operation.offer"
                | "operation.input"
                | "operation.cancel"
                | "runtime.control"
                | "operation.approval"
        ) || self.reconciliation_complete
            || self.preexisting_control_replay_allowed(sequence)
    }
    pub fn receive(&self, bytes: &[u8]) -> Result<(Envelope, ReceiveResult), TransportError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameTooLarge);
        }
        let validated = ValidatedDocument::<NodeProtocolV1>::from_slice(bytes)
            .map_err(|_| TransportError::Malformed)?;
        let e: Envelope = serde_json::from_value(validated.into_value())
            .map_err(|_| TransportError::Malformed)?;
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
        if !self.control_frame_allowed(&e.kind, sequence) {
            return Err(TransportError::ReconciliationRequired);
        }
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
        let control_applied_through = Some(
            self.store
                .inbound_applied_through(Direction::ControlToNode)?
                .to_string(),
        );
        let base = Envelope {
            protocol: PROTOCOL.into(),
            message_id: message_id.into(),
            device_id: self.device_id.clone(),
            connection_epoch: self.epoch.to_string(),
            direction: "node_to_control".into(),
            sequence: "0".into(),
            kind: kind.into(),
            correlation_id,
            control_applied_through,
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
                let bytes = serde_json::to_vec(&exact)
                    .map_err(|_| StoreError::Invalid("outbound frame encoding failed".into()))?;
                ValidatedDocument::<NodeProtocolV1>::from_slice(&bytes).map_err(|_| {
                    StoreError::Invalid("outbound frame violates protocol schema".into())
                })?;
                Ok(bytes)
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
    reconciliation_required: bool,
    /// Highest Node sequence written successfully on this live socket.
    ///
    /// TCP/WebSocket already provides reliable ordered delivery while the
    /// connection remains open. Re-sending every durable-but-not-yet-ACKed
    /// frame on each 100 ms service poll only creates an application-level
    /// replay loop. A new connection starts at the peer's durable custody
    /// frontier, so disconnect/restart recovery still replays everything the
    /// peer did not report as stored.
    socket_sent_through: u64,
    application_sends: u64,
}
impl WssClient {
    #[cfg(test)]
    pub(crate) fn from_test_stream(
        stream: TcpStream,
        session: TransportSession,
        reconciliation_required: bool,
    ) -> Self {
        let socket_sent_through = session
            .store
            .transport_positions()
            .map(|positions| positions.node_acknowledged_through)
            .unwrap_or(0);
        Self {
            socket: WebSocket::from_raw_socket(
                MaybeTlsStream::Plain(stream),
                tungstenite::protocol::Role::Client,
                None,
            ),
            session,
            reconciliation_required,
            socket_sent_through,
            application_sends: 0,
        }
    }

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
        let (socket, _) = client_tls_with_config(request, stream, Some(config), None)
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        Self::authenticate(
            socket,
            &url,
            store,
            identity,
            device_id,
            capability_digest,
            node_boot_id,
        )
    }

    #[cfg(test)]
    pub(crate) fn connect_loopback(
        url: &str,
        store: NodeStore,
        identity: &DeviceIdentity,
        device_id: &str,
        capability_digest: &str,
        node_boot_id: &str,
    ) -> Result<Self, TransportError> {
        use tungstenite::client::client_with_config;
        let url = Url::parse(url).map_err(|_| TransportError::Malformed)?;
        if url.scheme() != "ws" || !matches!(url.host_str(), Some("127.0.0.1" | "localhost")) {
            return Err(TransportError::WebSocket(
                "test endpoint must be loopback ws".into(),
            ));
        }
        let stream = TcpStream::connect((
            url.host_str().ok_or(TransportError::Malformed)?,
            url.port_or_known_default()
                .ok_or(TransportError::Malformed)?,
        ))
        .map_err(|error| TransportError::WebSocket(error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|error| TransportError::WebSocket(error.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|error| TransportError::WebSocket(error.to_string()))?;
        let mut config = tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_FRAME_BYTES);
        config.max_frame_size = Some(MAX_FRAME_BYTES);
        let request = url
            .as_str()
            .into_client_request()
            .map_err(|error| TransportError::WebSocket(error.to_string()))?;
        let (socket, _) = client_with_config(request, MaybeTlsStream::Plain(stream), Some(config))
            .map_err(|error| TransportError::WebSocket(error.to_string()))?;
        Self::authenticate(
            socket,
            &url,
            store,
            identity,
            device_id,
            capability_digest,
            node_boot_id,
        )
    }

    fn authenticate(
        mut socket: WebSocket<MaybeTlsStream<TcpStream>>,
        url: &Url,
        store: NodeStore,
        identity: &DeviceIdentity,
        device_id: &str,
        capability_digest: &str,
        node_boot_id: &str,
    ) -> Result<Self, TransportError> {
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
        let challenge: Challenge = read_validated_json(&mut socket)?;
        if challenge.kind != "device.challenge" || challenge.selected_protocol != PROTOCOL {
            return Err(TransportError::ProtocolUnsupported);
        }
        if !(1_000..=300_000).contains(&challenge.expires_in_ms)
            || challenge.server_time.len() > 64
            || !challenge.server_time.ends_with('Z')
        {
            return Err(TransportError::Malformed);
        }
        let transcript=serde_jcs::to_vec(&serde_json::json!({"domain":"conduit.device-auth.v1","origin":web_origin(url)?,"clientNonce":URL_SAFE_NO_PAD.encode(nonce),"connectionId":challenge.connection_id,"deviceId":device_id,"keyId":identity.key_id(),"protocol":PROTOCOL,"serverNonce":challenge.server_nonce,"serverTime":challenge.server_time})).map_err(|_|TransportError::Malformed)?;
        let proof = Proof {
            kind: "device.proof",
            connection_id: &challenge.connection_id,
            device_id,
            key_id: identity.key_id(),
            signature: identity.sign(&transcript),
        };
        write_json(&mut socket, &proof)?;
        let accepted: Accepted = read_validated_json(&mut socket)?;
        if accepted.kind != "transport.accepted" || accepted.selected_protocol != PROTOCOL {
            return Err(TransportError::ProtocolUnsupported);
        }
        if accepted.connection_id != challenge.connection_id || accepted.device_id != device_id {
            return Err(TransportError::Malformed);
        }
        let epoch = accepted
            .connection_epoch
            .parse()
            .map_err(|_| TransportError::Malformed)?;
        let control_next: u64 = accepted
            .control_next_sequence
            .parse()
            .map_err(|_| TransportError::Malformed)?;
        let node_stored: u64 = accepted
            .node_stored_through_sequence
            .parse()
            .map_err(|_| TransportError::Malformed)?;
        let positions = store.transport_positions()?;
        let preexisting_control_frontier = validate_accepted_positions(
            control_next,
            node_stored,
            accepted.reconciliation_required,
            positions,
        )?;
        let session = TransportSession::new_with_control_frontier(
            store.clone(),
            device_id.into(),
            epoch,
            preexisting_control_frontier,
        )?;
        store.ack_outbound(Direction::NodeToControl, node_stored)?;
        let mut client = Self {
            socket,
            session,
            reconciliation_required: accepted.reconciliation_required,
            socket_sent_through: node_stored,
            application_sends: 0,
        };
        client.set_poll_timeout(SERVICE_POLL_TIMEOUT)?;
        Ok(client)
    }
    fn send_durable(&mut self, b: &[u8]) -> Result<(), TransportError> {
        self.socket
            .send(Message::Text(
                String::from_utf8(b.to_vec())
                    .map_err(|_| TransportError::Malformed)?
                    .into(),
            ))
            .map_err(|e| TransportError::WebSocket(e.to_string()))?;
        self.application_sends = self.application_sends.saturating_add(1);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn application_sends(&self) -> u64 {
        self.application_sends
    }

    #[cfg(test)]
    pub(crate) fn reset_application_sends(&mut self) {
        self.application_sends = 0;
    }

    /// Replay an already durable application envelope without allocating a
    /// new transport sequence.  The health checkpoint uses this only for an
    /// unchanged semantic snapshot; the control plane can therefore observe
    /// the checkpoint without another outbox/inbox row.  A frame from an old
    /// connection epoch is never sent on the new socket.
    pub fn replay_envelope(&mut self, envelope: &Envelope) -> Result<(), TransportError> {
        if envelope.protocol != PROTOCOL
            || envelope.device_id != self.session.device_id
            || envelope.connection_epoch != self.session.epoch.to_string()
            || envelope.direction != "node_to_control"
            || envelope.kind != "device.health"
        {
            return Err(TransportError::StaleEpoch);
        }
        let bytes = serde_json::to_vec(envelope).map_err(|_| TransportError::Malformed)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameTooLarge);
        }
        self.send_durable(&bytes)
    }
    pub fn flush_unacknowledged(&mut self, from: u64) -> Result<usize, TransportError> {
        let from = from.max(self.socket_sent_through.saturating_add(1));
        let frames = self.session.store.unacknowledged_outbound(from, 512)?;
        for frame in &frames {
            self.send_durable(&frame.frame)?;
            self.socket_sent_through = frame.sequence;
        }
        Ok(frames.len())
    }
    pub fn replay_range(&mut self, from: u64, through: u64) -> Result<usize, TransportError> {
        let frames = self
            .session
            .store
            .replay_outbound(Direction::NodeToControl, from, 512)?;
        let mut sent = 0;
        for frame in frames.into_iter().take_while(|f| f.sequence <= through) {
            self.send_durable(&frame.frame)?;
            sent += 1
        }
        Ok(sent)
    }
    pub fn reconciliation_required(&self) -> bool {
        self.reconciliation_required
    }
    fn set_poll_timeout(&mut self, timeout: Duration) -> Result<(), TransportError> {
        let result = match self.socket.get_mut() {
            MaybeTlsStream::Plain(stream) => stream.set_read_timeout(Some(timeout)),
            MaybeTlsStream::Rustls(stream) => stream.get_mut().set_read_timeout(Some(timeout)),
            _ => Ok(()),
        };
        result.map_err(|error| TransportError::WebSocket(error.to_string()))
    }
    #[cfg(test)]
    pub(crate) fn await_idle_e2e_settled(&mut self, count: usize) -> Result<(), TransportError> {
        self.set_poll_timeout(Duration::from_secs(15))?;
        let result = (0..count).try_for_each(|_| {
            match self
                .socket
                .read()
                .map_err(|error| TransportError::WebSocket(error.to_string()))?
            {
                Message::Text(value) if value.as_str() == "{\"type\":\"idle_e2e.settled\"}" => {
                    Ok(())
                }
                _ => Err(TransportError::Malformed),
            }
        });
        self.set_poll_timeout(SERVICE_POLL_TIMEOUT)?;
        result
    }
    /// Send a WebSocket protocol ping.  This is deliberately separate from
    /// semantic `device.health`: a keepalive proves only that the socket peer
    /// can answer the protocol control frame and never advances device state.
    pub fn protocol_ping(&mut self) -> Result<(), TransportError> {
        self.socket
            .send(Message::Ping(Vec::new().into()))
            .map_err(|e| TransportError::WebSocket(e.to_string()))
    }
    pub fn receive(&mut self) -> Result<(Envelope, ReceiveResult), TransportError> {
        self.poll()?
            .ok_or_else(|| TransportError::WebSocket("read_timeout".into()))
    }
    pub fn poll(&mut self) -> Result<Option<(Envelope, ReceiveResult)>, TransportError> {
        loop {
            let message = match self.socket.read() {
                Ok(v) => v,
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(TransportError::WebSocket(e.to_string())),
            };
            match message {
                Message::Text(v) => return self.session.receive(v.as_bytes()).map(Some),
                Message::Ping(v) => {
                    self.socket
                        .send(Message::Pong(v))
                        .map_err(|e| TransportError::WebSocket(e.to_string()))?;
                }
                // Tungstenite consumes protocol pong frames internally for
                // liveness. They are not Conduit envelopes and must not be
                // mistaken for semantic health.
                Message::Pong(_) => {}
                Message::Close(_) => {
                    return Err(TransportError::WebSocket("peer closed WebSocket".into()));
                }
                _ => return Err(TransportError::Malformed),
            }
        }
    }
}

fn validate_accepted_positions(
    control_next: u64,
    node_stored: u64,
    reconciliation_required: bool,
    positions: conduit_node_store::TransportPositions,
) -> Result<u64, TransportError> {
    let local_control_next = positions.control_received_through.saturating_add(1);
    if control_next == 0
        || control_next < local_control_next
        || node_stored > positions.node_sent_through
    {
        return Err(TransportError::Malformed);
    }
    if !reconciliation_required
        && (control_next != local_control_next || node_stored != positions.node_sent_through)
    {
        return Err(TransportError::Malformed);
    }
    Ok(control_next - 1)
}

fn web_origin(url: &Url) -> Result<String, TransportError> {
    let mut origin = url.clone();
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => return Err(TransportError::Malformed),
    };
    origin
        .set_scheme(scheme)
        .map_err(|_| TransportError::Malformed)?;
    Ok(origin.origin().ascii_serialization())
}
use tungstenite::client::IntoClientRequest;
fn set_timeouts(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    match socket.get_mut() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.get_mut().set_read_timeout(Some(Duration::from_secs(15)));
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
fn read_validated_json<T: for<'de> Deserialize<'de>>(
    s: &mut WebSocket<MaybeTlsStream<TcpStream>>,
) -> Result<T, TransportError> {
    match s
        .read()
        .map_err(|e| TransportError::WebSocket(e.to_string()))?
    {
        Message::Text(v) => {
            let validated = ValidatedDocument::<NodeProtocolV1>::from_slice(v.as_bytes())
                .map_err(|_| TransportError::Malformed)?;
            serde_json::from_value(validated.into_value()).map_err(|_| TransportError::Malformed)
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
            control_applied_through: None,
            payload_digest: digest(&p),
            payload: p,
        }
    }
    fn operation_offer_envelope(seq: u64) -> Envelope {
        let payload = serde_json::json!({"operation":{"schemaVersion":1,"operationId":format!("op_replay_{seq:08}"),"idempotencyKey":format!("replay-operation-key-{seq:08}"),"actorPrincipalId":"prin_replay_0001","clientId":"conduit.test","deviceId":"dev_12345678","capability":"command.start","sourceRevisions":[],"runtime":{"kind":"native","providerId":"native.linux","configurationRevision":1},"accessScope":"full_user","approvalMode":"never","requiredApprovalRiskClasses":[],"connectorPolicyId":"cpol_replay_0001","connectorPolicyRevision":1,"arguments":{"argv":["true"]},"payloadDigest":"11".repeat(32),"issuedAt":"2026-09-01T00:00:00Z","expiresAt":"2026-09-01T00:05:00Z","validForMs":300000}});
        Envelope {
            protocol: PROTOCOL.into(),
            message_id: format!("cmsg_offer_{seq:08}"),
            device_id: "dev_12345678".into(),
            connection_epoch: "1".into(),
            direction: "control_to_node".into(),
            sequence: seq.to_string(),
            kind: "operation.offer".into(),
            correlation_id: Some(format!("op_replay_{seq:08}")),
            control_applied_through: None,
            payload_digest: digest(&payload),
            payload,
        }
    }

    #[test]
    fn websocket_origin_uses_the_matching_http_scheme() {
        assert_eq!(
            web_origin(&Url::parse("wss://control.example/devices/connect?token=ignored").unwrap())
                .unwrap(),
            "https://control.example"
        );
        assert_eq!(
            web_origin(&Url::parse("ws://127.0.0.1:8787/devices/connect").unwrap()).unwrap(),
            "http://127.0.0.1:8787"
        );
    }

    #[test]
    fn fences_epoch_and_sequences() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let t = TransportSession::new(s.clone(), "dev_12345678".into(), 1).unwrap();
        let e = envelope(
            1,
            serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
        );
        let b = serde_json::to_vec(&e).unwrap();
        assert_eq!(t.receive(&b).unwrap().1, ReceiveResult::Applied);
        t.store
            .mark_inbound_applied(Direction::ControlToNode, 1)
            .unwrap();
        assert_eq!(t.receive(&b).unwrap().1, ReceiveResult::Duplicate);
        let gap = serde_json::to_vec(&envelope(
            3,
            serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
        ))
        .unwrap();
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
                serde_json::json!({"nodeBootId":"boot_123456789012","journalGeneration":"2","capabilityDigest":"11".repeat(32),"lastControlSequenceApplied":"0","lastNodeSequenceAcknowledged":"0","lastNodeSequenceRetained":"0","runs":[],"retainedEventRanges":[],"unresolvedCount":0,"truncated":false,"storageHealth":"healthy"}),
                0,
            )
            .unwrap();
        assert_eq!(e.sequence, "1");
        let replay = t.replay(1).unwrap();
        let durable: Envelope = serde_json::from_slice(&replay[0]).unwrap();
        assert_eq!(durable.sequence, "1");
    }

    #[test]
    fn unchanged_health_replay_keeps_wire_identity_and_does_not_allocate() {
        use std::net::TcpListener;

        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let session = TransportSession::new(store.clone(), "dev_12345678".into(), 1).unwrap();
        let health = session
            .queue_outbound(
                "nmsg_health_checkpoint_01",
                "device.health",
                None,
                serde_json::json!({
                    "observedAt":"2026-09-01T00:00:00Z",
                    "nodeState":"ready",
                    "journalState":"healthy",
                    "storageState":"healthy",
                    "controlAppliedThrough":"0",
                    "activeCommands":0,
                    "activeAgentRuns":0,
                    "activeRuntimes":0
                }),
                1,
            )
            .unwrap();
        let before = store.transport_positions().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let mut server = WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(peer),
            tungstenite::protocol::Role::Server,
            None,
        );
        let mut client = WssClient::from_test_stream(stream, session, false);
        let expected_wire = serde_json::to_vec(&health).unwrap();
        client.replay_envelope(&health).unwrap();
        let received = match server.read().unwrap() {
            Message::Text(value) => value,
            other => panic!("expected replayed text, got {other:?}"),
        };
        assert_eq!(received.as_bytes(), expected_wire.as_slice());
        let received: Envelope = serde_json::from_slice(received.as_bytes()).unwrap();
        assert_eq!(received, health);
        assert_eq!(store.transport_positions().unwrap(), before);
    }

    #[test]
    fn ack_frontier_progress_does_not_reallocate_unchanged_health_checkpoint() {
        use std::net::TcpListener;

        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let session = TransportSession::new(store.clone(), "dev_12345678".into(), 1).unwrap();
        let health = session
            .queue_outbound(
                "nmsg_health_feedback_01",
                "device.health",
                None,
                serde_json::json!({
                    "observedAt":"2026-09-01T00:00:00Z",
                    "nodeState":"ready",
                    "journalState":"healthy",
                    "storageState":"healthy",
                    "controlAppliedThrough":"0",
                    "activeCommands":0,
                    "activeAgentRuns":0,
                    "activeRuntimes":0
                }),
                1,
            )
            .unwrap();
        let health_state = crate::batching::HealthState {
            node_state: "ready".into(),
            journal_state: "healthy".into(),
            storage_state: "healthy".into(),
            active_commands: 0,
            active_agent_runs: 0,
            active_runtimes: 0,
        };
        let checkpoint_start = Instant::now();
        let mut health_tracker = crate::batching::HealthTracker::default();
        assert!(health_tracker.consider(health_state.clone(), checkpoint_start, true));
        let initial_positions = store.transport_positions().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let mut server = WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(peer),
            tungstenite::protocol::Role::Server,
            None,
        );
        let mut client = WssClient::from_test_stream(stream, session, false);
        let mut exact_replays = 0;
        for sequence in 1_u64..=144 {
            let checkpoint_at = checkpoint_start
                + Duration::from_secs(
                    sequence.saturating_mul(crate::batching::DEFAULT_HEALTH_CHECKPOINT.as_secs()),
                );
            assert!(health_tracker.should_emit(&health_state, checkpoint_at, false));
            assert!(health_tracker.unchanged_checkpoint_due(&health_state, checkpoint_at));
            let control = envelope(
                sequence,
                serde_json::json!({
                    "direction":"node_to_control",
                    "throughSequence":"1"
                }),
            );
            let bytes = serde_json::to_vec(&control).unwrap();
            assert_eq!(
                client.session.receive(&bytes).unwrap().1,
                ReceiveResult::Applied
            );
            client
                .session
                .store
                .mark_inbound_applied(Direction::ControlToNode, sequence)
                .unwrap();
            client.replay_envelope(&health).unwrap();
            let received = match server.read().unwrap() {
                Message::Text(value) => value,
                other => panic!("expected replayed health text, got {other:?}"),
            };
            assert_eq!(received.as_bytes(), serde_json::to_vec(&health).unwrap());
            health_tracker.record(health_state.clone(), checkpoint_at);
            exact_replays += 1;
        }
        let positions = store.transport_positions().unwrap();
        assert_eq!(positions.control_received_through, 144);
        assert_eq!(positions.node_sent_through, 1);
        assert_eq!(exact_replays, 144, "ten-minute checkpoints over 24h");
        assert_eq!(
            positions.node_sent_through - initial_positions.node_sent_through,
            0,
            "ACK-only frontier movement must not allocate health rows"
        );
    }

    #[test]
    fn health_state_change_force_and_reconnect_allocate_fresh_sequences() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let session = TransportSession::new(store.clone(), "dev_12345678".into(), 1).unwrap();
        let health_payload = |observed_at: &str, node_state: &str| {
            serde_json::json!({
                "observedAt": observed_at,
                "nodeState": node_state,
                "journalState":"healthy",
                "storageState":"healthy",
                "controlAppliedThrough":"0",
                "activeCommands":0,
                "activeAgentRuns":0,
                "activeRuntimes":0
            })
        };
        let initial = session
            .queue_outbound(
                "nmsg_health_identity_initial",
                "device.health",
                None,
                health_payload("2026-09-01T00:00:00Z", "ready"),
                1,
            )
            .unwrap();
        let changed = session
            .queue_outbound(
                "nmsg_health_identity_changed",
                "device.health",
                None,
                health_payload("2026-09-01T00:00:01Z", "degraded"),
                1,
            )
            .unwrap();
        let forced = session
            .queue_outbound(
                "nmsg_health_identity_forced",
                "device.health",
                None,
                health_payload("2026-09-01T00:00:02Z", "degraded"),
                1,
            )
            .unwrap();
        assert_eq!(initial.sequence, "1");
        assert_eq!(changed.sequence, "2");
        assert_eq!(forced.sequence, "3");
        assert_ne!(initial.sequence, changed.sequence);
        assert_ne!(changed.sequence, forced.sequence);

        let reconnected = TransportSession::new(store.clone(), "dev_12345678".into(), 2).unwrap();
        let reconnect_health = reconnected
            .queue_outbound(
                "nmsg_health_identity_reconnect",
                "device.health",
                None,
                health_payload("2026-09-01T00:00:03Z", "ready"),
                1,
            )
            .unwrap();
        assert_eq!(reconnect_health.sequence, "4");
        assert_eq!(reconnect_health.connection_epoch, "2");
    }

    #[test]
    fn outbound_frames_share_the_applied_control_frontier() {
        let d = tempdir().unwrap();
        let store = NodeStore::open(d.path()).unwrap();
        let session = TransportSession::new(store.clone(), "dev_12345678".into(), 1).unwrap();
        let first = session
            .queue_outbound(
                "nmsg_frontier_01",
                "device.health",
                None,
                serde_json::json!({
                    "observedAt":"2026-09-01T00:00:00Z",
                    "nodeState":"ready",
                    "journalState":"healthy",
                    "storageState":"healthy",
                    "controlAppliedThrough":"0"
                }),
                1,
            )
            .unwrap();
        assert_eq!(first.control_applied_through.as_deref(), Some("0"));

        let control = envelope(
            1,
            serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
        );
        let bytes = serde_json::to_vec(&control).unwrap();
        store
            .receive(
                Direction::ControlToNode,
                &TransportFrame {
                    sequence: 1,
                    message_id: control.message_id,
                    payload_digest: control.payload_digest,
                    frame: bytes,
                },
            )
            .unwrap();
        store
            .mark_inbound_applied(Direction::ControlToNode, 1)
            .unwrap();
        let second = session
            .queue_outbound(
                "nmsg_frontier_02",
                "operation.status",
                None,
                serde_json::json!({
                    "operationId":"op_frontier_01",
                    "requestDigest":"11".repeat(32),
                    "state":"admitted",
                    "controllerEpoch":"1",
                    "revision":"1",
                    "observedAt":"2026-09-01T00:00:00Z"
                }),
                0,
            )
            .unwrap();
        assert_eq!(second.control_applied_through.as_deref(), Some("1"));
    }

    #[test]
    fn shared_handshake_fixture_is_versioned_and_schema_valid() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/handshake-v1.json")).unwrap();
        assert_eq!(fixture["version"], 1);
        for field in ["hello", "challenge", "proof", "accepted"] {
            let bytes = serde_json::to_vec(&fixture[field]).unwrap();
            ValidatedDocument::<NodeProtocolV1>::from_slice(&bytes).unwrap();
        }
        let accepted: Accepted = serde_json::from_value(fixture["accepted"].clone()).unwrap();
        assert_eq!(accepted.connection_id, "conn_fixture_01");
        assert_eq!(accepted.device_id, "dev_fixture_01");
        assert_eq!(accepted.connection_epoch, "42");
        assert_eq!(accepted.control_next_sequence, "101");
        assert_eq!(accepted.node_stored_through_sequence, "75");
        assert!(accepted.reconciliation_required);
    }
    #[test]
    fn outbound_control_payloads_match_protocol_schema() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let t = TransportSession::new(s, "dev_12345678".into(), 1).unwrap();
        let values = [
            (
                "transport.ack",
                serde_json::json!({"direction":"control_to_node","throughSequence":"1"}),
            ),
            (
                "transport.replay_required",
                serde_json::json!({"direction":"control_to_node","expectedSequence":"2","receivedSequence":"3"}),
            ),
            (
                "transport.error",
                serde_json::json!({"code":"capability_unavailable","retryable":false,"details":{"messageType":"operation.input"}}),
            ),
            (
                "device.health",
                serde_json::json!({"observedAt":"2026-09-01T00:00:00Z","nodeState":"ready","journalState":"healthy","storageState":"healthy","activeCommands":0,"activeAgentRuns":0,"activeRuntimes":0}),
            ),
            (
                "reconcile.complete",
                serde_json::json!({"reconciliationId":"rec_fixture_01","lastControlSequenceApplied":"1","lastNodeSequenceAcknowledged":"0","unresolvedRunIds":[]}),
            ),
        ];
        for (index, (kind, payload)) in values.into_iter().enumerate() {
            t.queue_outbound(&format!("nmsg_fixture_{index:02}"), kind, None, payload, 0)
                .unwrap();
        }
    }

    #[test]
    fn protocol_ping_is_a_websocket_control_frame() {
        use std::net::TcpListener;

        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let session = TransportSession::new(store, "dev_12345678".into(), 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut server = WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(peer),
            tungstenite::protocol::Role::Server,
            None,
        );
        let mut client = WssClient::from_test_stream(stream, session, false);
        if let MaybeTlsStream::Plain(stream) = client.socket.get_mut() {
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
        }
        client.protocol_ping().unwrap();
        assert!(matches!(server.read().unwrap(), Message::Ping(_)));
        server.send(Message::Pong(Vec::new().into())).unwrap();
        // `poll` consumes the protocol Pong and returns no Conduit envelope
        // after its bounded read timeout.  In particular it cannot synthesize
        // a semantic `device.health` message.
        assert!(client.poll().unwrap().is_none());
        // Unexpected data frames are a transport fault, not a health event;
        // fail closed so the service can persist a degraded observation and
        // reconnect/reconcile.
        server.send(Message::Binary(vec![0xff].into())).unwrap();
        assert!(matches!(client.poll(), Err(TransportError::Malformed)));
    }

    #[test]
    fn accepted_frontier_allows_bounded_contiguous_replay_before_new_effects() {
        let positions = conduit_node_store::TransportPositions {
            control_received_through: 3,
            node_sent_through: 9,
            node_acknowledged_through: 7,
        };
        assert_eq!(
            validate_accepted_positions(44, 7, true, positions).unwrap(),
            43
        );
        assert!(validate_accepted_positions(3, 7, true, positions).is_err());
        assert_eq!(
            validate_accepted_positions(4, 9, false, positions).unwrap(),
            3
        );
        assert!(validate_accepted_positions(44, 9, false, positions).is_err());

        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let mut session = TransportSession::new_with_control_frontier(
            store.clone(),
            "dev_12345678".into(),
            1,
            43,
        )
        .unwrap();
        for sequence in 1..=3 {
            let bytes = serde_json::to_vec(&envelope(
                sequence,
                serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
            ))
            .unwrap();
            assert_eq!(session.receive(&bytes).unwrap().1, ReceiveResult::Applied);
            store
                .mark_inbound_applied(Direction::ControlToNode, sequence)
                .unwrap();
        }
        let sentinel = serde_json::to_vec(&envelope(
            44,
            serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
        ))
        .unwrap();
        assert_eq!(
            session.receive(&sentinel).unwrap().1,
            ReceiveResult::Gap { expected: 4 }
        );
        for sequence in 4..=35 {
            let bytes = serde_json::to_vec(&envelope(
                sequence,
                serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
            ))
            .unwrap();
            assert_eq!(session.receive(&bytes).unwrap().1, ReceiveResult::Applied);
            assert!(session.preexisting_control_replay_allowed(sequence));
            if sequence == 4 {
                assert_eq!(
                    session.receive(&bytes).unwrap().1,
                    ReceiveResult::DuplicatePending
                );
            }
            store
                .mark_inbound_applied(Direction::ControlToNode, sequence)
                .unwrap();
        }
        assert_eq!(
            session.receive(&sentinel).unwrap().1,
            ReceiveResult::Gap { expected: 36 }
        );
        for sequence in 36..=43 {
            let bytes = serde_json::to_vec(&envelope(
                sequence,
                serde_json::json!({"direction":"node_to_control","throughSequence":"0"}),
            ))
            .unwrap();
            assert_eq!(session.receive(&bytes).unwrap().1, ReceiveResult::Applied);
            assert!(session.preexisting_control_replay_allowed(sequence));
            store
                .mark_inbound_applied(Direction::ControlToNode, sequence)
                .unwrap();
        }
        assert!(!session.preexisting_control_replay_allowed(44));
        assert_eq!(
            session.receive(&sentinel).unwrap().1,
            ReceiveResult::Applied
        );
        store
            .mark_inbound_applied(Direction::ControlToNode, 44)
            .unwrap();
        session.mark_reconciliation_complete();
        assert!(session.remote_work_allowed());
        assert!(!session.preexisting_control_replay_allowed(43));
    }

    #[test]
    fn replayed_offer_duplicate_pending_reapplies_but_new_offer_is_not_persisted() {
        let directory = tempdir().unwrap();
        let store = NodeStore::open(directory.path()).unwrap();
        let mut session =
            TransportSession::new_with_control_frontier(store.clone(), "dev_12345678".into(), 1, 1)
                .unwrap();
        let replayed = serde_json::to_vec(&operation_offer_envelope(1)).unwrap();
        assert_eq!(
            session.receive(&replayed).unwrap().1,
            ReceiveResult::Applied
        );
        assert_eq!(
            session.receive(&replayed).unwrap().1,
            ReceiveResult::DuplicatePending
        );
        let new_effect = serde_json::to_vec(&operation_offer_envelope(2)).unwrap();
        assert!(matches!(
            session.receive(&new_effect),
            Err(TransportError::ReconciliationRequired)
        ));
        assert_eq!(
            store
                .transport_positions()
                .unwrap()
                .control_received_through,
            1
        );
        store
            .mark_inbound_applied(Direction::ControlToNode, 1)
            .unwrap();
        assert_eq!(
            session.receive(&replayed).unwrap().1,
            ReceiveResult::Duplicate
        );
        session.mark_reconciliation_complete();
        assert_eq!(
            session.receive(&new_effect).unwrap().1,
            ReceiveResult::Applied
        );
    }
}
