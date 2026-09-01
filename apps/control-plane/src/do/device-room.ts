import { DurableObject } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds, type NodeV1PostAuthFrame } from "@conduit/schema";
import { canonicalJson, newId, nowIso, randomToken, sha256Hex, verifyEd25519 } from "../crypto.ts";
import { ensureOperationConcurrencyReleased, type DeviceRoomOffer } from "../dispatch.ts";
import type { DeviceRoomApproval } from "../approval-dispatch.ts";
import type { ControlPlaneEnv, QueueEventMessage } from "../types.ts";

interface SocketAttachment {
  deviceId: string;
  connectionId: string;
  stage: "new" | "challenged" | "authenticated";
  keyId?: string;
  clientNonce?: string;
  serverNonce?: string;
  serverTime?: string;
  selectedProtocol?: string;
  capabilityDigest?: string;
  nodeBootId?: string;
  epoch?: string;
  reconciling?: boolean;
  reconciliationId?: string;
}

interface StoredOutboundFrame {
  [key: string]: string | number | null;
  sequence: number;
  message_id: string;
  correlation_id: string | null;
  payload_digest: string;
  frame_json: string;
  state: "queued" | "sent";
  expires_at: string;
  dispatch_attempts: number;
  next_attempt_at: string;
}

interface StoredDispatchReceipt {
  [key: string]: string | number | null;
  message_id: string;
  correlation_id: string | null;
  payload_digest: string;
  sequence: number;
  state: "queued" | "sent" | "acknowledged";
  expires_at: string;
}

interface StoredControlReplayIntent {
  [key: string]: string | number;
  request_sequence: number;
  request_message_id: string;
  from_sequence: number;
  through_sequence: number;
  attempt_count: number;
  next_attempt_at: string;
}

interface ValidatedControlReplay {
  intent: StoredControlReplayIntent;
  frames: StoredOutboundFrame[];
}

const MAX_CONTROL_REPLAY_FRAMES = 32;
const EFFECTFUL_CONTROL_TYPES = new Set<NodeV1PostAuthFrame["type"]>([
  "operation.offer",
  "operation.input",
  "operation.cancel",
  "operation.approval",
]);

export class DeviceRoom extends DurableObject<ControlPlaneEnv> {
  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS connection_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), device_id TEXT NOT NULL, epoch INTEGER NOT NULL, key_id TEXT, connection_id TEXT, protocol TEXT, capability_digest TEXT, reconciliation_state TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transport_positions(direction TEXT PRIMARY KEY, durable_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS outbound_frames(sequence INTEGER PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, correlation_id TEXT, payload_digest TEXT NOT NULL, frame_json TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS inbound_frames(sequence INTEGER PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, correlation_id TEXT, payload_digest TEXT NOT NULL, frame_json TEXT NOT NULL, projected INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS auth_challenges(connection_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, client_nonce TEXT NOT NULL, server_nonce TEXT NOT NULL, server_time TEXT NOT NULL, protocol TEXT NOT NULL, capability_digest TEXT NOT NULL, node_boot_id TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS reconciliation_sessions(id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, state TEXT NOT NULL, summary_json TEXT, plan_json TEXT, created_at TEXT NOT NULL, completed_at TEXT);
        CREATE TABLE IF NOT EXISTS terminal_receipt_cache(operation_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbound_message_receipts(message_id TEXT PRIMARY KEY, correlation_id TEXT, payload_digest TEXT NOT NULL, sequence INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','sent','acknowledged')), expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS control_replay_intents(request_sequence INTEGER PRIMARY KEY, request_message_id TEXT NOT NULL UNIQUE, from_sequence INTEGER NOT NULL, through_sequence INTEGER NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS outbound_receipt_expiry_idx ON outbound_message_receipts(expires_at);
        CREATE INDEX IF NOT EXISTS control_replay_due_idx ON control_replay_intents(next_attempt_at,request_sequence);
        INSERT OR IGNORE INTO transport_positions(direction,durable_sequence,acknowledged_sequence) VALUES ('control_to_node',0,0),('node_to_control',0,0);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
      `);
      const challengeColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(auth_challenges)").toArray().map((column) => column.name));
      if (!challengeColumns.has("capability_digest")) this.ctx.storage.sql.exec("ALTER TABLE auth_challenges ADD COLUMN capability_digest TEXT NOT NULL DEFAULT 'unknown'");
      if (!challengeColumns.has("node_boot_id")) this.ctx.storage.sql.exec("ALTER TABLE auth_challenges ADD COLUMN node_boot_id TEXT NOT NULL DEFAULT 'unknown'");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (2,datetime('now'))");
      const outboundColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(outbound_frames)").toArray().map((column) => column.name));
      if (!outboundColumns.has("dispatch_attempts")) this.ctx.storage.sql.exec("ALTER TABLE outbound_frames ADD COLUMN dispatch_attempts INTEGER NOT NULL DEFAULT 0");
      if (!outboundColumns.has("next_attempt_at")) this.ctx.storage.sql.exec("ALTER TABLE outbound_frames ADD COLUMN next_attempt_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'");
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS outbound_dispatch_due_idx ON outbound_frames(state,next_attempt_at,expires_at)");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (3,datetime('now'))");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (4,datetime('now'))");
      this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    });
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("WebSocket required", { status: 426 });
    const match = new URL(request.url).pathname.match(/^\/v1\/devices\/([^/]+)\/connect$/);
    if (match?.[1] === undefined) return new Response("Device target required", { status: 400 });
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const attachment: SocketAttachment = { deviceId: match[1], connectionId: newId("conn"), stage: "new" };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string" || new TextEncoder().encode(message).byteLength > 65_536) {
      ws.close(1009, "frame_too_large");
      return;
    }
    let value: unknown;
    try { value = parseWireDocumentText(schemaIds.nodeV1, message); } catch { ws.close(1007, "frame_malformed"); return; }
    const body = value as unknown as Record<string, unknown>;
    const attachment = ws.deserializeAttachment() as SocketAttachment | null;
    if (attachment === null) { ws.close(1011, "connection_state_missing"); return; }
    if (attachment.stage === "new") { await this.hello(ws, attachment, body); return; }
    if (attachment.stage === "challenged") { await this.authenticate(ws, attachment, body); return; }
    await this.acceptFrame(ws, attachment, body);
  }

  private async hello(ws: WebSocket, attachment: SocketAttachment, body: Record<string, unknown>): Promise<void> {
    if (body.type !== "device.hello" || body.deviceId !== attachment.deviceId || typeof body.keyId !== "string" || typeof body.clientNonce !== "string" || typeof body.capabilityDigest !== "string" || !/^[a-f0-9]{64}$/.test(body.capabilityDigest) || typeof body.nodeBootId !== "string" || body.nodeBootId.length < 16 || body.nodeBootId.length > 128 || !Array.isArray(body.supportedProtocols) || !body.supportedProtocols.includes("conduit.node/1")) {
      ws.close(1008, "protocol_version_unsupported"); return;
    }
    const device = await this.env.DB.prepare("SELECT status FROM devices WHERE id=?1 LIMIT 1").bind(attachment.deviceId).first<{ status: string }>();
    if (device === null || device.status !== "active") { ws.close(1008, device?.status === "revoked" ? "device_revoked" : "device_not_enrolled"); return; }
    const serverNonce = randomToken();
    const serverTime = nowIso();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    this.ctx.storage.sql.exec("INSERT INTO auth_challenges(connection_id,key_id,client_nonce,server_nonce,server_time,protocol,capability_digest,node_boot_id,expires_at) VALUES (?,?,?,?,?,?,?,?,?)", attachment.connectionId, body.keyId, body.clientNonce, serverNonce, serverTime, "conduit.node/1", body.capabilityDigest, body.nodeBootId, expiresAt);
    const next: SocketAttachment = { ...attachment, stage: "challenged", keyId: body.keyId, clientNonce: body.clientNonce, serverNonce, serverTime, selectedProtocol: "conduit.node/1", capabilityDigest: body.capabilityDigest, nodeBootId: body.nodeBootId };
    ws.serializeAttachment(next);
    ws.send(JSON.stringify({ type: "device.challenge", connectionId: attachment.connectionId, serverNonce, serverTime, expiresInMs: 60_000, selectedProtocol: "conduit.node/1" }));
  }

  private async authenticate(ws: WebSocket, attachment: SocketAttachment, body: Record<string, unknown>): Promise<void> {
    if (body.type !== "device.proof" || body.connectionId !== attachment.connectionId || body.deviceId !== attachment.deviceId || body.keyId !== attachment.keyId || typeof body.signature !== "string") { ws.close(1008, "device_key_invalid"); return; }
    const challenge = this.ctx.storage.sql.exec<{ consumed: number; expires_at: string }>("SELECT consumed,expires_at FROM auth_challenges WHERE connection_id=?", attachment.connectionId).toArray()[0];
    if (challenge === undefined || challenge.consumed !== 0 || Date.parse(challenge.expires_at) <= Date.now()) { ws.close(1008, "device_key_invalid"); return; }
    this.ctx.storage.sql.exec("UPDATE auth_challenges SET consumed=1 WHERE connection_id=? AND consumed=0", attachment.connectionId);
    const key = await this.env.DB.prepare("SELECT public_jwk_json,status FROM device_keys WHERE id=?1 AND device_id=?2 LIMIT 1").bind(attachment.keyId, attachment.deviceId).first<{ public_jwk_json: string; status: string }>();
    if (key === null || !["active", "retiring"].includes(key.status)) { ws.close(1008, "device_key_invalid"); return; }
    const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: this.env.PUBLIC_ORIGIN, clientNonce: attachment.clientNonce, connectionId: attachment.connectionId, deviceId: attachment.deviceId, keyId: attachment.keyId, protocol: attachment.selectedProtocol, serverNonce: attachment.serverNonce, serverTime: attachment.serverTime });
    if (!await verifyEd25519(JSON.parse(key.public_jwk_json) as JsonWebKey, body.signature, transcript)) { ws.close(1008, "device_key_invalid"); return; }
    const current = this.ctx.storage.sql.exec<{ epoch: number }>("SELECT epoch FROM connection_state WHERE singleton=1").toArray()[0]?.epoch ?? 0;
    const epoch = current + 1;
    const reconciliationId = newId("rec");
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO connection_state(singleton,device_id,epoch,key_id,connection_id,protocol,capability_digest,reconciliation_state,updated_at) VALUES (1,?,?,?,?,?,?,'required',?) ON CONFLICT(singleton) DO UPDATE SET device_id=excluded.device_id,epoch=excluded.epoch,key_id=excluded.key_id,connection_id=excluded.connection_id,protocol=excluded.protocol,capability_digest=excluded.capability_digest,reconciliation_state='required',updated_at=excluded.updated_at", attachment.deviceId, epoch, attachment.keyId, attachment.connectionId, attachment.selectedProtocol, attachment.capabilityDigest, nowIso());
      this.ctx.storage.sql.exec("INSERT INTO reconciliation_sessions(id,epoch,state,created_at) VALUES (?,?,'required',?)", reconciliationId, epoch, nowIso());
    });
    for (const socket of this.ctx.getWebSockets()) {
      if (socket !== ws) {
        const other = socket.deserializeAttachment() as SocketAttachment | null;
        if (other?.stage === "authenticated") socket.close(1008, "connection_fenced");
      }
    }
    const next: SocketAttachment = { ...attachment, stage: "authenticated", epoch: String(epoch), reconciling: true, reconciliationId };
    ws.serializeAttachment(next);
    await this.env.DB.prepare("UPDATE devices SET connection_epoch=?1,last_observed_at=?2,updated_at=?2 WHERE id=?3 AND status='active'").bind(String(epoch), nowIso(), attachment.deviceId).run();
    const positions = this.ctx.storage.sql.exec<{ direction: string; durable_sequence: number }>("SELECT direction,durable_sequence FROM transport_positions").toArray();
    const controlStored = positions.find((item) => item.direction === "control_to_node")?.durable_sequence ?? 0;
    const nodeStored = positions.find((item) => item.direction === "node_to_control")?.durable_sequence ?? 0;
    ws.send(JSON.stringify({ type: "transport.accepted", connectionId: attachment.connectionId, deviceId: attachment.deviceId, connectionEpoch: String(epoch), selectedProtocol: attachment.selectedProtocol, controlNextSequence: String(controlStored + 1), nodeStoredThroughSequence: String(nodeStored), reconciliationRequired: true }));
  }

  private async acceptFrame(ws: WebSocket, attachment: SocketAttachment, body: Record<string, unknown>): Promise<void> {
    if (body.protocol !== "conduit.node/1" || body.deviceId !== attachment.deviceId || body.connectionEpoch !== attachment.epoch || body.direction !== "node_to_control" || typeof body.sequence !== "string" || !/^\d+$/.test(body.sequence) || typeof body.messageId !== "string" || typeof body.type !== "string" || typeof body.payloadDigest !== "string" || body.payload === null || typeof body.payload !== "object" || Array.isArray(body.payload)) {
      ws.close(1008, "frame_malformed"); return;
    }
    if (attachment.reconciling && body.type !== "reconcile.summary" && body.type !== "reconcile.complete" && body.type !== "transport.ack" && body.type !== "transport.replay_required") { await this.enqueueControlFrame("transport.error", { code: "reconciliation_required", retryable: true }, undefined, new Date(Date.now() + 300_000).toISOString(), ws); return; }
    const digest = await sha256Hex(canonicalJson(body.payload));
    if (digest !== body.payloadDigest) { ws.close(1008, "payload_digest_mismatch"); return; }
    const sequence = BigInt(body.sequence);
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence;
    if (sequence <= BigInt(position)) {
      const prior = this.ctx.storage.sql.exec<{ message_id: string; payload_digest: string; frame_json: string; projected: number }>("SELECT message_id,payload_digest,frame_json,projected FROM inbound_frames WHERE sequence=?", Number(sequence)).toArray()[0];
      if (prior?.message_id === body.messageId && prior.payload_digest === body.payloadDigest) {
        if (body.type === "transport.replay_required") {
          const intent = this.ctx.storage.sql.exec<StoredControlReplayIntent>("SELECT * FROM control_replay_intents WHERE request_sequence=? AND request_message_id=?", Number(sequence), body.messageId).toArray()[0];
          if (intent !== undefined) await this.dispatchControlReplayIntent(intent, ws);
        }
        if (prior.projected === 0) {
          const persisted = parseWireDocumentText(schemaIds.nodeV1, prior.frame_json);
          if ("protocol" in persisted) {
            if (persisted.type === "operation.approval_request") await this.projectApprovalOrDeadletter(persisted);
            else this.ctx.waitUntil(this.project(persisted));
          }
        }
        if (body.type !== "transport.ack") await this.enqueueControlFrame("transport.ack", { direction: "node_to_control", throughSequence: String(position) }, undefined, new Date(Date.now() + 300_000).toISOString(), ws);
        return;
      }
      ws.close(1008, "sequence_conflict"); return;
    }
    if (sequence !== BigInt(position) + 1n) { await this.enqueueControlFrame("transport.replay_required", { direction: "node_to_control", expectedSequence: String(position + 1), receivedSequence: String(sequence) }, undefined, new Date(Date.now() + 300_000).toISOString(), ws); return; }
    const frame = body as unknown as NodeV1PostAuthFrame;
    const replay = frame.type === "transport.replay_required" ? await this.validateControlReplayRequest(ws, frame) : undefined;
    if (frame.type === "transport.replay_required" && replay === null) return;
    if (replay !== undefined && replay !== null) await this.scheduleOutboxAlarm(Date.now() + 1_000);
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,created_at) VALUES (?,?,?,?,?,?)", Number(sequence), frame.messageId, frame.correlationId ?? null, frame.payloadDigest, JSON.stringify(frame), nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction='node_to_control'", Number(sequence));
      if (replay !== undefined && replay !== null) this.ctx.storage.sql.exec("INSERT INTO control_replay_intents(request_sequence,request_message_id,from_sequence,through_sequence,next_attempt_at,created_at) VALUES (?,?,?,?,?,?)", replay.intent.request_sequence, replay.intent.request_message_id, replay.intent.from_sequence, replay.intent.through_sequence, replay.intent.next_attempt_at, nowIso());
      if (frame.type === "operation.terminal" && typeof frame.payload.operationId === "string" && typeof frame.payload.requestDigest === "string") this.ctx.storage.sql.exec("INSERT OR REPLACE INTO terminal_receipt_cache(operation_id,request_digest,receipt_json,created_at) VALUES (?,?,?,?)", frame.payload.operationId, frame.payload.requestDigest, JSON.stringify(frame.payload), nowIso());
    });
    if (frame.type === "reconcile.summary") await this.planReconciliation(ws, attachment, frame);
    if (frame.type === "reconcile.complete") await this.completeReconciliation(ws, attachment, frame);
    if (replay !== undefined && replay !== null) await this.dispatchControlReplayIntent(replay.intent, ws, replay.frames);
    if (frame.type === "operation.approval_request") {
      await this.scheduleOutboxAlarm(Date.now() + 1_000);
      await this.projectApprovalOrDeadletter(frame);
    }
    if (frame.type === "transport.ack") {
      const acknowledged = BigInt(frame.payload.throughSequence);
      const controlPosition = this.ctx.storage.sql.exec<{ durable_sequence: number; acknowledged_sequence: number }>("SELECT durable_sequence,acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one();
      if (acknowledged > BigInt(controlPosition.durable_sequence)) { ws.close(1008, "acknowledgement_out_of_range"); return; }
      if (acknowledged > BigInt(controlPosition.acknowledged_sequence)) this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("UPDATE transport_positions SET acknowledged_sequence=? WHERE direction='control_to_node'", Number(acknowledged));
        this.ctx.storage.sql.exec("UPDATE outbound_message_receipts SET state='acknowledged',updated_at=? WHERE sequence<=?", nowIso(), Number(acknowledged));
        this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE sequence<=?", Number(acknowledged));
        this.ctx.storage.sql.exec("DELETE FROM control_replay_intents WHERE through_sequence<=?", Number(acknowledged));
      });
    } else {
      await this.enqueueControlFrame("transport.ack", { direction: "node_to_control", throughSequence: frame.sequence }, undefined, new Date(Date.now() + 300_000).toISOString(), ws);
    }
    if (frame.type !== "operation.approval_request") this.ctx.waitUntil(this.project(frame));
  }

  private async validateControlReplayRequest(ws: WebSocket, frame: Extract<NodeV1PostAuthFrame, { type: "transport.replay_required" }>): Promise<ValidatedControlReplay | null> {
    if (frame.payload.direction !== "control_to_node") { ws.close(1008, "replay_direction_invalid"); return null; }
    const expected = BigInt(frame.payload.expectedSequence);
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number; acknowledged_sequence: number }>("SELECT durable_sequence,acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one();
    const through = frame.payload.receivedSequence === undefined ? BigInt(position.durable_sequence) : BigInt(frame.payload.receivedSequence);
    if (expected < 1n || expected > through || through > BigInt(position.durable_sequence) || through > BigInt(Number.MAX_SAFE_INTEGER)) { ws.close(1008, "replay_range_invalid"); return null; }
    if (expected <= BigInt(position.acknowledged_sequence)) { ws.close(1008, "replay_range_acknowledged"); return null; }
    const chunkEnd = expected + BigInt(MAX_CONTROL_REPLAY_FRAMES - 1);
    const chunkThrough = through < chunkEnd ? through : chunkEnd;
    const chunkLength = Number(chunkThrough - expected + 1n);
    const rows = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence BETWEEN ? AND ? ORDER BY sequence", Number(expected), Number(chunkThrough)).toArray();
    if (rows.length !== chunkLength) { ws.close(1011, "replay_range_unavailable"); return null; }
    if (chunkThrough < through) {
      const sentinel = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence=?", Number(through)).toArray()[0];
      if (sentinel === undefined) { ws.close(1011, "replay_range_unavailable"); return null; }
      rows.push(sentinel);
    }
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index]!;
      let persisted: unknown;
      try { persisted = parseWireDocumentText(schemaIds.nodeV1, row.frame_json); } catch { ws.close(1011, "replay_record_invalid"); return null; }
      if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) { ws.close(1011, "replay_record_invalid"); return null; }
      const wire = persisted as Record<string, unknown>;
      const expectedSequence = index < chunkLength ? expected + BigInt(index) : through;
      if (!Number.isSafeInteger(row.sequence) || BigInt(row.sequence) !== expectedSequence || !["queued", "sent"].includes(row.state) || wire.protocol !== "conduit.node/1" || wire.direction !== "control_to_node" || wire.sequence !== String(expectedSequence) || wire.messageId !== row.message_id || (wire.correlationId ?? null) !== row.correlation_id || wire.payloadDigest !== row.payload_digest || wire.payload === null || typeof wire.payload !== "object" || Array.isArray(wire.payload) || await sha256Hex(canonicalJson(wire.payload)) !== row.payload_digest || Date.parse(row.expires_at) <= Date.now()) {
        ws.close(1011, "replay_record_invalid"); return null;
      }
    }
    return {
      intent: { request_sequence: Number(frame.sequence), request_message_id: frame.messageId, from_sequence: Number(expected), through_sequence: Number(through), attempt_count: 0, next_attempt_at: nowIso() },
      frames: rows,
    };
  }

  private controlReplayFrames(intent: StoredControlReplayIntent): StoredOutboundFrame[] {
    const from = BigInt(intent.from_sequence);
    const through = BigInt(intent.through_sequence);
    const chunkEnd = from + BigInt(MAX_CONTROL_REPLAY_FRAMES - 1);
    const chunkThrough = through < chunkEnd ? through : chunkEnd;
    const rows = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence BETWEEN ? AND ? ORDER BY sequence", Number(from), Number(chunkThrough)).toArray();
    if (rows.length !== Number(chunkThrough - from + 1n)) throw new TypeError("control replay chunk is unavailable");
    if (chunkThrough < through) {
      const sentinel = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence=?", Number(through)).toArray()[0];
      if (sentinel === undefined) throw new TypeError("control replay sentinel is unavailable");
      rows.push(sentinel);
    }
    return rows;
  }

  private async dispatchControlReplayIntent(intent: StoredControlReplayIntent, socket?: WebSocket, validatedFrames?: StoredOutboundFrame[]): Promise<void> {
    let frames: StoredOutboundFrame[];
    try { frames = validatedFrames ?? this.controlReplayFrames(intent); } catch {
      this.ctx.storage.sql.exec("DELETE FROM control_replay_intents WHERE request_sequence=?", intent.request_sequence);
      return;
    }
    for (const frame of frames) await this.sendStoredFrame(frame, socket);
    const attempts = intent.attempt_count + 1;
    const delay = Math.min(60_000, 2 ** Math.min(attempts, 6) * 1_000);
    const next = new Date(Date.now() + delay).toISOString();
    this.ctx.storage.sql.exec("UPDATE control_replay_intents SET attempt_count=?,next_attempt_at=? WHERE request_sequence=?", attempts, next, intent.request_sequence);
    await this.scheduleOutboxAlarm(Date.parse(next));
  }

  private async planReconciliation(ws: WebSocket, attachment: SocketAttachment, frame: Extract<NodeV1PostAuthFrame, { type: "reconcile.summary" }>): Promise<void> {
    if (attachment.reconciliationId === undefined) { ws.close(1011, "reconciliation_state_missing"); return; }
    const summary = frame.payload;
    const controlStored = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='control_to_node'").one().durable_sequence;
    const applied = BigInt(summary.lastControlSequenceApplied);
    if (applied > BigInt(controlStored)) { ws.close(1008, "reconciliation_position_invalid"); return; }
    const controlReplay = applied < BigInt(controlStored) ? [{ from: String(applied + 1n), through: String(controlStored) }] : [];
    const eventReplay: Array<{ runId: string; from: string; through: string }> = [];
    for (const range of summary.retainedEventRanges.slice(0, 512)) {
      const local = await this.env.DB.prepare("SELECT last_sequence FROM trace_indexes WHERE run_id=?1 LIMIT 1").bind(range.runId).first<{ last_sequence: string }>();
      const next = local === null ? BigInt(range.fromSequence) : BigInt(local.last_sequence) + 1n;
      const floor = BigInt(range.fromSequence);
      const from = next > floor ? next : floor;
      if (from <= BigInt(range.throughSequence)) eventReplay.push({ runId: range.runId, from: String(from), through: range.throughSequence });
    }
    const statusRunIds: string[] = [];
    const cancelOperationIds: string[] = [];
    const quarantineRunIds: string[] = [];
    for (const run of summary.runs.slice(0, 256)) {
      const intended = await this.env.DB.prepare("SELECT payload_digest,state FROM operation_journal WHERE id=?1 LIMIT 1").bind(run.operationId).first<{ payload_digest: string; state: string }>();
      if (intended === null || intended.payload_digest !== run.requestDigest) quarantineRunIds.push(run.runId);
      else if (intended.state === "cancelled") cancelOperationIds.push(run.operationId);
      else if (!["completed", "failed", "cancelled", "expired", "rejected"].includes(intended.state)) statusRunIds.push(run.runId);
    }
    const payload = { reconciliationId: attachment.reconciliationId, controlReplay, nodeReplay: [], eventReplay, statusRunIds: [...new Set(statusRunIds)], cancelOperationIds: [...new Set(cancelOperationIds)], quarantineRunIds: [...new Set(quarantineRunIds)] };
    const delivery = await this.enqueueControlFrame("reconcile.plan", payload, attachment.reconciliationId, new Date(Date.now() + 300_000).toISOString(), ws);
    this.ctx.storage.sql.exec("UPDATE reconciliation_sessions SET state='plan_sent',summary_json=?,plan_json=? WHERE id=? AND epoch=?", JSON.stringify(summary), JSON.stringify({ payload, planSequence: delivery.sequence }), attachment.reconciliationId, Number(attachment.epoch));
    this.ctx.storage.sql.exec("UPDATE connection_state SET reconciliation_state='plan_sent',updated_at=? WHERE singleton=1", nowIso());
  }

  private async completeReconciliation(ws: WebSocket, attachment: SocketAttachment, frame: Extract<NodeV1PostAuthFrame, { type: "reconcile.complete" }>): Promise<void> {
    if (attachment.reconciliationId === undefined || frame.payload.reconciliationId !== attachment.reconciliationId) { ws.close(1008, "reconciliation_id_mismatch"); return; }
    const session = this.ctx.storage.sql.exec<{ plan_json: string; state: string }>("SELECT plan_json,state FROM reconciliation_sessions WHERE id=? AND epoch=?", attachment.reconciliationId, Number(attachment.epoch)).toArray()[0];
    if (session === undefined || session.state !== "plan_sent") { ws.close(1008, "reconciliation_plan_missing"); return; }
    const plan = JSON.parse(session.plan_json) as { planSequence: string };
    const positions = this.ctx.storage.sql.exec<{ direction: string; durable_sequence: number }>("SELECT direction,durable_sequence FROM transport_positions").toArray();
    const controlStored = positions.find((item) => item.direction === "control_to_node")?.durable_sequence ?? 0;
    const nodeStored = positions.find((item) => item.direction === "node_to_control")?.durable_sequence ?? 0;
    if (BigInt(frame.payload.lastControlSequenceApplied) < BigInt(plan.planSequence) || BigInt(frame.payload.lastControlSequenceApplied) > BigInt(controlStored) || BigInt(frame.payload.lastNodeSequenceAcknowledged) > BigInt(nodeStored) || frame.payload.unresolvedRunIds.length > 0) {
      this.ctx.storage.sql.exec("UPDATE reconciliation_sessions SET state='review_required' WHERE id=?", attachment.reconciliationId);
      await this.enqueueControlFrame("transport.error", { code: "reconciliation_incomplete", retryable: true }, attachment.reconciliationId, new Date(Date.now() + 300_000).toISOString(), ws);
      return;
    }
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE reconciliation_sessions SET state='complete',completed_at=? WHERE id=?", nowIso(), attachment.reconciliationId);
      this.ctx.storage.sql.exec("UPDATE connection_state SET reconciliation_state='complete',updated_at=? WHERE singleton=1", nowIso());
    });
    attachment.reconciling = false;
    ws.serializeAttachment(attachment);
  }

  private async project(frame: NodeV1PostAuthFrame): Promise<void> {
    if (frame.type === "operation.approval_request") {
      const request = frame.payload;
      const issuedAt = Date.parse(request.issuedAt);
      const expiresAt = Date.parse(request.expiresAt);
      if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt >= expiresAt || expiresAt <= Date.now() || expiresAt - issuedAt > request.validForMs || !/^[1-9][0-9]*$/.test(request.controllerEpoch) || request.localPolicyRevision < 1) throw new TypeError("approval request validity is invalid");
      const operation = await this.env.DB.prepare("SELECT id,payload_digest,actor_principal_id,client_id,device_id,run_id,request_json FROM operation_journal WHERE id=?1 LIMIT 1")
        .bind(request.operationId)
        .first<{ id: string; payload_digest: string; actor_principal_id: string; client_id: string; device_id: string; run_id: string | null; request_json: string }>();
      if (operation === null || operation.device_id !== frame.deviceId || operation.device_id !== request.deviceId || operation.run_id !== request.runId || operation.actor_principal_id !== request.requesterPrincipalId || operation.client_id !== request.clientId) throw new TypeError("approval request target does not match operation custody");
      const operationRequest = JSON.parse(operation.request_json) as { accessScope?: unknown; approvalMode?: unknown; arguments?: { adapterId?: unknown } };
      if (operationRequest.accessScope !== request.accessScope || operationRequest.approvalMode !== request.approvalMode || operationRequest.arguments?.adapterId !== request.adapterId || request.approvalMode === "never") throw new TypeError("approval request authority differs from immutable operation");
      const expected = await sha256Hex(canonicalJson({
        domain: "conduit.agent-approval.v1",
        operationId: request.operationId,
        runId: request.runId,
        requestDigest: operation.payload_digest,
        providerRequestId: request.providerRequestId,
        method: request.method,
        parametersDigest: request.parametersDigest,
        argumentsSummary: request.argumentsSummary,
        approvalExpiresAtUnixMs: Date.parse(request.expiresAt),
        adapterId: request.adapterId,
        accessScope: request.accessScope,
        approvalMode: request.approvalMode,
        controllerEpoch: request.controllerEpoch,
        localPolicyRevision: request.localPolicyRevision,
      }));
      if (expected !== request.operationDigest) throw new TypeError("approval request commitment mismatch");
      const normalized = canonicalJson({ providerRequestId: request.providerRequestId, method: request.method, parametersDigest: request.parametersDigest, argumentsSummary: request.argumentsSummary, adapterId: request.adapterId, accessScope: request.accessScope, approvalMode: request.approvalMode });
      const revisions = canonicalJson({ controllerEpoch: request.controllerEpoch, localPolicyRevision: request.localPolicyRevision });
      await this.env.DB.prepare("INSERT OR IGNORE INTO approvals(id,operation_id,requester_principal_id,client_id,device_id,run_id,commitment_digest,operation_type,normalized_arguments_json,revisions_json,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)")
        .bind(request.approvalId, request.operationId, request.requesterPrincipalId, request.clientId, request.deviceId, request.runId, request.operationDigest, request.method, normalized, revisions, request.expiresAt, request.issuedAt).run();
      const stored = await this.env.DB.prepare("SELECT commitment_digest,normalized_arguments_json,revisions_json FROM approvals WHERE id=?1 LIMIT 1").bind(request.approvalId).first<{ commitment_digest: string; normalized_arguments_json: string; revisions_json: string }>();
      if (stored === null || stored.commitment_digest !== request.operationDigest || stored.normalized_arguments_json !== normalized || stored.revisions_json !== revisions) throw new TypeError("approval id is bound to a different commitment");
    }
    if (frame.type === "operation.terminal") {
      const operation = await this.env.DB.prepare("SELECT payload_digest,connector_grant_id,concurrency_class,state FROM operation_journal WHERE id=?1 LIMIT 1").bind(frame.payload.operationId).first<{ payload_digest: string; connector_grant_id: string | null; concurrency_class: "commands" | "agentRuns" | "runtimeStarts" | null; state: string }>();
      if (operation === null) {
        await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'device_terminal.unknown_operation',?2,?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, receiptDigest: frame.payload.receiptDigest }), nowIso()).run();
      } else if (operation.payload_digest !== frame.payload.requestDigest) {
        await this.env.DB.batch([
          this.env.DB.prepare("UPDATE operation_journal SET state='uncertain',result_json=?1,updated_at=?2 WHERE id=?3 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(JSON.stringify({ denialCode: "request_digest_mismatch", terminal: frame.payload }), nowIso(), frame.payload.operationId),
          this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'device_terminal.request_digest_mismatch',?2,?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, expected: operation.payload_digest, received: frame.payload.requestDigest }), nowIso()),
        ]);
      } else {
        const projectedState = frame.payload.state === "completed" ? "completed" : frame.payload.state === "cancelled" ? "cancelled" : frame.payload.state === "rejected" || frame.payload.state === "expired" ? frame.payload.state : frame.payload.state === "uncertain" || frame.payload.state === "lost" || frame.payload.state === "recovery_required" ? "uncertain" : "failed";
        await this.env.DB.prepare("UPDATE operation_journal SET state=?1,result_json=?2,updated_at=?3 WHERE id=?4 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(projectedState, JSON.stringify(frame.payload), nowIso(), frame.payload.operationId).run();
        if (operation.connector_grant_id !== null && operation.concurrency_class !== null) await ensureOperationConcurrencyReleased(this.env, frame.payload.operationId);
      }
    }
    if (frame.type === "event.batch" && Array.isArray(frame.payload.events)) {
      for (const event of frame.payload.events.slice(0, 128)) {
        if (event !== null && typeof event === "object" && !Array.isArray(event)) await this.env.EVENT_INGESTION.send(event as QueueEventMessage, { contentType: "json" });
      }
    }
    this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=1 WHERE sequence=?", Number(frame.sequence));
  }

  private async projectApprovalOrDeadletter(frame: Extract<NodeV1PostAuthFrame, { type: "operation.approval_request" }>): Promise<void> {
    try {
      await this.project(frame);
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      const reason = error instanceof Error ? error.message.slice(0, 192) : "approval_projection_failed";
      await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'agent_approval.invalid_request',?2,?3,?4)")
        .bind(newId("sevt"), frame.deviceId, JSON.stringify({ approvalId: frame.payload.approvalId, operationId: frame.payload.operationId, reason }), nowIso()).run();
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=2 WHERE sequence=?", Number(frame.sequence));
    }
  }

  private async enqueueControlFrame(type: NodeV1PostAuthFrame["type"], payload: Record<string, unknown>, correlationId: string | undefined, expiresAt: string, preferredSocket?: WebSocket, suppliedMessageId?: string): Promise<{ sequence: string; delivered: boolean }> {
    const messageId = suppliedMessageId ?? newId("cmsg");
    const payloadDigest = await sha256Hex(canonicalJson(payload));
    const prior = suppliedMessageId === undefined ? undefined : this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE message_id=?", suppliedMessageId).toArray()[0];
    if (prior !== undefined) {
      if (prior.payload_digest !== payloadDigest || prior.correlation_id !== (correlationId ?? null)) throw new TypeError("control message id is bound to another payload");
      const delivered = await this.sendStoredFrame(prior, preferredSocket);
      return { sequence: String(prior.sequence), delivered };
    }
    const receipt = suppliedMessageId === undefined ? undefined : this.ctx.storage.sql.exec<StoredDispatchReceipt>("SELECT * FROM outbound_message_receipts WHERE message_id=?", suppliedMessageId).toArray()[0];
    if (receipt !== undefined) {
      if (receipt.payload_digest !== payloadDigest || receipt.correlation_id !== (correlationId ?? null)) throw new TypeError("control message id is bound to another payload");
      return { sequence: String(receipt.sequence), delivered: receipt.state === "acknowledged" || receipt.state === "sent" };
    }
    const connection = this.ctx.storage.sql.exec<{ epoch: number; reconciliation_state: string }>("SELECT epoch,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0];
    const onlineReconciliation = connection?.reconciliation_state !== "complete" && this.ctx.getWebSockets().some((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      return item?.stage === "authenticated" && item.reconciling && item.epoch === String(connection?.epoch);
    });
    if (EFFECTFUL_CONTROL_TYPES.has(type) && onlineReconciliation) {
      throw new TypeError("effectful control delivery waits for reconciliation completion");
    }
    const current = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='control_to_node'").one().durable_sequence;
    const sequence = current + 1;
    const state = this.ctx.storage.sql.exec<{ device_id: string; epoch: number }>("SELECT device_id,epoch FROM connection_state WHERE singleton=1").toArray()[0];
    const payloadDeviceId = type === "operation.offer" && payload.operation !== null && typeof payload.operation === "object" && !Array.isArray(payload.operation) && typeof (payload.operation as Record<string, unknown>).deviceId === "string"
      ? String((payload.operation as Record<string, unknown>).deviceId)
      : undefined;
    const wire = { protocol: "conduit.node/1", messageId, deviceId: state?.device_id ?? payloadDeviceId ?? "unconnected", connectionEpoch: String(state?.epoch ?? 0), direction: "control_to_node", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest, payload };
    parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(wire));
    const createdAt = nowIso();
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO outbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,state,expires_at,created_at,dispatch_attempts,next_attempt_at) VALUES (?,?,?,?,?,'queued',?,?,0,?)", sequence, messageId, correlationId ?? null, payloadDigest, JSON.stringify(wire), expiresAt, createdAt, createdAt);
      this.ctx.storage.sql.exec("INSERT INTO outbound_message_receipts(message_id,correlation_id,payload_digest,sequence,state,expires_at,created_at,updated_at) VALUES (?,?,?,?,'queued',?,?,?)", messageId, correlationId ?? null, payloadDigest, sequence, expiresAt, createdAt, createdAt);
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction='control_to_node'", sequence);
    });
    const stored = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence=?", sequence).one();
    return { sequence: String(sequence), delivered: await this.sendStoredFrame(stored, preferredSocket) };
  }

  private eligibleSocket(frame: StoredOutboundFrame): WebSocket | undefined {
    const connection = this.ctx.storage.sql.exec<{ epoch: number; reconciliation_state: string }>("SELECT epoch,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0];
    const wire = JSON.parse(frame.frame_json) as { type?: unknown };
    return this.ctx.getWebSockets().find((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      const ready = !EFFECTFUL_CONTROL_TYPES.has(wire.type as NodeV1PostAuthFrame["type"]) || connection?.reconciliation_state === "complete" && !item?.reconciling;
      return item?.stage === "authenticated" && item.epoch === String(connection?.epoch) && ready;
    });
  }

  private async scheduleOutboxAlarm(at: number): Promise<void> {
    const scheduled = await this.ctx.storage.getAlarm();
    if (scheduled === null || at < scheduled) await this.ctx.storage.setAlarm(at);
  }

  private async sendStoredFrame(frame: StoredOutboundFrame, preferredSocket?: WebSocket): Promise<boolean> {
    if (Date.parse(frame.expires_at) <= Date.now()) {
      this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE sequence=? AND state='queued'", frame.sequence);
      return false;
    }
    const socket = preferredSocket ?? this.eligibleSocket(frame);
    if (socket === undefined) {
      const next = new Date(Date.now() + 30_000).toISOString();
      this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='queued',next_attempt_at=? WHERE sequence=?", next, frame.sequence);
      await this.scheduleOutboxAlarm(Date.parse(next));
      return false;
    }
    const connection = this.ctx.storage.sql.exec<{ device_id: string; epoch: number }>("SELECT device_id,epoch FROM connection_state WHERE singleton=1").toArray()[0];
    const persisted: unknown = JSON.parse(frame.frame_json);
    if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) throw new TypeError("persisted control frame is invalid");
    const wire = { ...(persisted as Record<string, unknown>), ...(connection === undefined ? {} : { deviceId: connection.device_id, connectionEpoch: String(connection.epoch) }) };
    parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(wire));
    try {
      socket.send(JSON.stringify(wire));
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='sent',frame_json=?,dispatch_attempts=dispatch_attempts+1 WHERE sequence=?", JSON.stringify(wire), frame.sequence);
        this.ctx.storage.sql.exec("UPDATE outbound_message_receipts SET state='sent',updated_at=? WHERE message_id=?", nowIso(), frame.message_id);
      });
      return true;
    } catch {
      const attempts = frame.dispatch_attempts + 1;
      const delay = Math.min(60_000, 2 ** Math.min(attempts, 6) * 1_000);
      const next = new Date(Date.now() + delay).toISOString();
      this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='queued',dispatch_attempts=?,next_attempt_at=? WHERE sequence=?", attempts, next, frame.sequence);
      await this.scheduleOutboxAlarm(Date.parse(next));
      return false;
    }
  }

  private async dispatchQueuedFrames(): Promise<void> {
    const now = nowIso();
    this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE state='queued' AND expires_at<=?", now);
    this.ctx.storage.sql.exec("DELETE FROM outbound_message_receipts WHERE expires_at<=?", now);
    const rows = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE state='queued' AND next_attempt_at<=? ORDER BY sequence LIMIT 32", now).toArray();
    for (const row of rows) await this.sendStoredFrame(row);
    const replayIntents = this.ctx.storage.sql.exec<StoredControlReplayIntent>("SELECT * FROM control_replay_intents WHERE next_attempt_at<=? ORDER BY next_attempt_at,request_sequence LIMIT 8", now).toArray();
    for (const intent of replayIntents) await this.dispatchControlReplayIntent(intent);
    const next = this.ctx.storage.sql.exec<{ next_attempt_at: string }>("SELECT next_attempt_at FROM (SELECT next_attempt_at FROM outbound_frames WHERE state='queued' UNION ALL SELECT next_attempt_at FROM control_replay_intents) ORDER BY next_attempt_at LIMIT 1").toArray()[0];
    if (next !== undefined) await this.scheduleOutboxAlarm(Math.max(Date.now() + 1_000, Date.parse(next.next_attempt_at)));
  }

  override async alarm(): Promise<void> {
    const unprojected = this.ctx.storage.sql.exec<{ frame_json: string }>("SELECT frame_json FROM inbound_frames WHERE projected=0 ORDER BY sequence LIMIT 32").toArray();
    for (const row of unprojected) {
      const frame = JSON.parse(row.frame_json) as NodeV1PostAuthFrame;
      if (frame.type === "operation.approval_request") await this.projectApprovalOrDeadletter(frame);
      else await this.project(frame);
    }
    await this.dispatchQueuedFrames();
  }

  async offer(frame: DeviceRoomOffer): Promise<{ sequence: string; delivered: boolean }> {
    const computed = await sha256Hex(canonicalJson(frame.payload));
    if (computed !== frame.payloadDigest) throw new TypeError("operation offer payload digest mismatch");
    const operation = frame.payload.operation;
    if (operation === null || typeof operation !== "object" || Array.isArray(operation) || (operation as Record<string, unknown>).deviceId !== frame.deviceId) throw new TypeError("operation offer device target mismatch");
    const connection = this.ctx.storage.sql.exec<{ epoch: number; reconciliation_state: string }>("SELECT epoch,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0];
    const persistedDevice = this.ctx.storage.sql.exec<{ device_id: string }>("SELECT device_id FROM connection_state WHERE singleton=1").toArray()[0]?.device_id;
    if (persistedDevice !== undefined && persistedDevice !== frame.deviceId) throw new TypeError("operation offer device target conflicts with room identity");
    const socket = this.ctx.getWebSockets().find((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      return item?.stage === "authenticated" && connection?.reconciliation_state === "complete" && !item.reconciling && item.epoch === String(connection?.epoch);
    });
    return this.enqueueControlFrame("operation.offer", frame.payload, frame.correlationId, frame.expiresAt, socket, frame.messageId);
  }

  async deliverApproval(frame: DeviceRoomApproval): Promise<{ sequence: string; delivered: boolean }> {
    const computed = await sha256Hex(canonicalJson(frame.payload));
    if (computed !== frame.payloadDigest) throw new TypeError("approval payload digest mismatch");
    if (frame.payload.approvalId !== frame.correlationId || frame.payload.operationId === undefined) throw new TypeError("approval correlation mismatch");
    const persistedDevice = this.ctx.storage.sql.exec<{ device_id: string }>("SELECT device_id FROM connection_state WHERE singleton=1").toArray()[0]?.device_id;
    if (persistedDevice !== undefined && persistedDevice !== frame.deviceId) throw new TypeError("approval device target conflicts with room identity");
    return this.enqueueControlFrame("operation.approval", frame.payload, frame.correlationId, frame.expiresAt, undefined, frame.messageId);
  }

  async revoke(reason: string): Promise<void> {
    this.ctx.storage.sql.exec("UPDATE connection_state SET reconciliation_state='revoked',updated_at=? WHERE singleton=1", nowIso());
    for (const socket of this.ctx.getWebSockets()) socket.close(1008, reason.slice(0, 120));
  }
}
