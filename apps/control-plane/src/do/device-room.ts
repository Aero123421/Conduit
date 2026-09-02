import { DurableObject } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds, type NodeV1PostAuthFrame } from "@conduit/schema";
import { canonicalJson, newId, nowIso, randomToken, sha256Hex, verifyEd25519 } from "../crypto.ts";
import { ensureOperationConcurrencyReleased, type DeviceRoomOffer } from "../dispatch.ts";
import type { DeviceRoomApproval } from "../approval-dispatch.ts";
import { PublicError } from "../errors.ts";
import { projectNodeState, type NodeProjectionEvent } from "../node-projection.ts";
import { queueRealtimeProjection, reconcileRealtimeProjections } from "../realtime-outbox.ts";
import { projectDeviceTerminalSubmission } from "../review-workflow.ts";
import { commitDurableInboxBatch, enqueueEventBatch, eventIngestionMode, parseEventBatch } from "../ingestion.ts";
import { planReconciliationSets } from "../reconciliation-set.ts";
import { usageProfileForEnv } from "../usage-profile.ts";
import { instrumentD1, type InstrumentedD1 } from "../usage-instrumentation.ts";
import type { ControlPlaneEnv } from "../types.ts";
import { isPrivilegeFrameType, parsePrivilegeTransportFrame, privilegeDenialResult, privilegeRegistrationResultType, privilegeResultType, projectPrivilegeFrame, requireVerifiedPrivilegeReceipt, type PrivilegeTransportFrame } from "../privilege.ts";

type ProjectableDeviceFrame = NodeV1PostAuthFrame | PrivilegeTransportFrame;

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
  kind: "control" | "ack";
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
  kind: "control" | "ack";
  expires_at: string;
}

interface StoredControlReplayIntent {
  [key: string]: string | number | null;
  request_sequence: number;
  request_message_id: string;
  from_sequence: number;
  through_sequence: number;
  attempt_count: number;
  next_attempt_at: string;
  lease_token: string | null;
  lease_expires_at: string | null;
}

interface ValidatedControlReplay {
  intent: StoredControlReplayIntent;
  frames: StoredOutboundFrame[];
}

interface RoomWorkMarker {
  [key: string]: string | number | null;
  singleton: number;
  pending: number;
  min_due_at: number | null;
  retention_pending: number;
  retention_due_at: number | null;
  realtime_pending: number;
  realtime_min_due_at: number | null;
  realtime_device_id: string | null;
  ack_pending_through: number;
  ack_pending_at: number | null;
  ack_sent_through: number;
  ack_message_id: string | null;
  health_semantic_json: string | null;
  health_last_projected_at: number | null;
  updated_at: string;
}

interface RetentionCompactionRow {
  [key: string]: string | number | null;
  direction: string;
  compacted_through: number;
  compacted_digest: string;
  updated_at: string;
}

interface OutboundMessageTombstone {
  [key: string]: string | number | null;
  message_id: string;
  correlation_id: string | null;
  payload_digest: string;
  sequence: number;
  kind: "control" | "ack";
  state: "queued" | "sent" | "acknowledged";
  expires_at: string;
  created_at: string;
}

const MAX_CONTROL_REPLAY_FRAMES = 32;
// One event.batch projection uses up to four D1 statements. Keeping a
// four-frame outer-alarm page leaves substantial headroom for realtime or
// terminal follow-up before the 40-statement release ceiling. Remaining
// custody rows immediately re-arm the same alarm.
const MAX_D1_PROJECTIONS_PER_ALARM = 4;
const MAX_INBOUND_FRAMES = 512;
const MAX_OUTBOUND_TOMBSTONES = 512;
const MAX_AUTH_CHALLENGES = 128;
const MAX_RECONCILIATION_SESSIONS = 64;
const MAX_TERMINAL_RECEIPTS = 256;
const PROJECTION_LEASE_MS = 5 * 60_000;
// Node health frames may arrive every 5--10 minutes, but unchanged semantic
// health is projected to D1 at most once per 15 minutes.  This keeps the
// durable-object checkpoint useful while staying inside the daily write
// budget for an idle device.
const HEALTH_CHECKPOINT_MS = 15 * 60_000;
const HOT_RETENTION_MS = 24 * 60 * 60_000;
const RECEIPT_RETENTION_MS = 7 * 24 * 60 * 60_000;
// ACKs are protocol custody receipts, not effectful work. Keep their exact
// digest/sequence proof long enough for reconnect/replay, but do not make a
// five-minute ACK expiry turn every heartbeat into a retention alarm.
const ACK_RETENTION_MS = HOT_RETENTION_MS;
const EFFECTFUL_CONTROL_TYPES = new Set<string>([
  "operation.offer",
  "operation.input",
  "operation.cancel",
  "runtime.control",
  "operation.approval",
  privilegeResultType(),
  privilegeRegistrationResultType(),
]);
const ACK_IMMEDIATE_TYPES = new Set<NodeV1PostAuthFrame["type"]>([
  "reconcile.summary",
  "reconcile.complete",
  "operation.terminal",
  "transport.error",
  "transport.replay_required",
]);

export class DeviceRoom extends DurableObject<ControlPlaneEnv> {
  private alarmActive = false;
  private idleProbe: {
    incomingMessages: number;
    sqlStatements: number;
    sqlRowsRead: number;
    sqlRowsWritten: number;
    setAlarm: number;
    deleteAlarm: number;
    alarmInvocations: number;
  } | null = null;
  private idleProbeD1: InstrumentedD1 | null = null;
  private idleProbeNowMs: number | null = null;
  private idleProbeHealthOrdinal = 0;

  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    const probeEnabled = (env as ControlPlaneEnv & { CLOUDFLARE_IDLE_E2E_PROBE?: string }).CLOUDFLARE_IDLE_E2E_PROBE === "enabled";
    if (probeEnabled) {
      this.idleProbe = { incomingMessages: 0, sqlStatements: 0, sqlRowsRead: 0, sqlRowsWritten: 0, setAlarm: 0, deleteAlarm: 0, alarmInvocations: 0 };
      this.idleProbeD1 = instrumentD1(env.DB);
      const instrumentedEnv = new Proxy(env, {
        get: (target, property, receiver) => property === "DB" ? this.idleProbeD1!.db : Reflect.get(target, property, receiver),
      });
      Object.defineProperty(this, "env", { value: instrumentedEnv, configurable: true });
      const sql = ctx.storage.sql;
      const originalExec = sql.exec.bind(sql);
      sql.exec = ((query: string, ...bindings: SqlStorageValue[]) => {
        const probe = this.idleProbe!;
        probe.sqlStatements += query.split(";").filter((part) => part.trim().length > 0).length;
        const cursor = originalExec(query, ...bindings);
        probe.sqlRowsRead += cursor.rowsRead;
        probe.sqlRowsWritten += cursor.rowsWritten;
        return cursor;
      }) as typeof sql.exec;
      const originalSetAlarm = ctx.storage.setAlarm.bind(ctx.storage);
      ctx.storage.setAlarm = (async (scheduledTime: number | Date, options?: DurableObjectSetAlarmOptions) => {
        this.idleProbe!.setAlarm += 1;
        await originalSetAlarm(scheduledTime, options);
      }) as typeof ctx.storage.setAlarm;
      const originalDeleteAlarm = ctx.storage.deleteAlarm.bind(ctx.storage);
      ctx.storage.deleteAlarm = (async (options?: DurableObjectSetAlarmOptions) => {
        this.idleProbe!.deleteAlarm += 1;
        await originalDeleteAlarm(options);
      }) as typeof ctx.storage.deleteAlarm;
    }
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS connection_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), device_id TEXT NOT NULL, epoch INTEGER NOT NULL, key_id TEXT, connection_id TEXT, protocol TEXT, capability_digest TEXT, reconciliation_state TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transport_positions(direction TEXT PRIMARY KEY, durable_sequence INTEGER NOT NULL, acknowledged_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS outbound_frames(sequence INTEGER PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, correlation_id TEXT, payload_digest TEXT NOT NULL, frame_json TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS inbound_frames(sequence INTEGER PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, correlation_id TEXT, payload_digest TEXT NOT NULL, frame_json TEXT NOT NULL, projected INTEGER NOT NULL DEFAULT 0, projection_claimed_at TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS auth_challenges(connection_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, client_nonce TEXT NOT NULL, server_nonce TEXT NOT NULL, server_time TEXT NOT NULL, protocol TEXT NOT NULL, capability_digest TEXT NOT NULL, node_boot_id TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS reconciliation_sessions(id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, state TEXT NOT NULL, summary_json TEXT, plan_json TEXT, created_at TEXT NOT NULL, completed_at TEXT);
        CREATE TABLE IF NOT EXISTS terminal_receipt_cache(operation_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbound_message_receipts(message_id TEXT PRIMARY KEY, correlation_id TEXT, payload_digest TEXT NOT NULL, sequence INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','sent','acknowledged')), expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS control_replay_intents(request_sequence INTEGER PRIMARY KEY, request_message_id TEXT NOT NULL UNIQUE, from_sequence INTEGER NOT NULL, through_sequence INTEGER NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, lease_token TEXT, lease_expires_at TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS room_work_marker(singleton INTEGER PRIMARY KEY CHECK(singleton=1), pending INTEGER NOT NULL DEFAULT 0, min_due_at INTEGER, retention_pending INTEGER NOT NULL DEFAULT 0, retention_due_at INTEGER, realtime_pending INTEGER NOT NULL DEFAULT 0, realtime_min_due_at INTEGER, realtime_device_id TEXT, ack_pending_through INTEGER NOT NULL DEFAULT 0, ack_pending_at INTEGER, ack_sent_through INTEGER NOT NULL DEFAULT 0, ack_message_id TEXT, health_semantic_json TEXT, health_last_projected_at INTEGER, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transport_compaction(direction TEXT PRIMARY KEY, compacted_through INTEGER NOT NULL DEFAULT 0, compacted_digest TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbound_message_tombstones(message_id TEXT PRIMARY KEY, correlation_id TEXT, payload_digest TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS outbound_receipt_expiry_idx ON outbound_message_receipts(expires_at);
        CREATE INDEX IF NOT EXISTS control_replay_due_idx ON control_replay_intents(next_attempt_at,request_sequence);
        CREATE INDEX IF NOT EXISTS inbound_projection_idx ON inbound_frames(projected,sequence);
        CREATE INDEX IF NOT EXISTS auth_challenge_expiry_idx ON auth_challenges(expires_at,consumed);
        CREATE INDEX IF NOT EXISTS reconciliation_session_created_idx ON reconciliation_sessions(created_at,state);
        CREATE INDEX IF NOT EXISTS terminal_receipt_created_idx ON terminal_receipt_cache(created_at);
        CREATE INDEX IF NOT EXISTS outbound_tombstone_created_idx ON outbound_message_tombstones(created_at);
        INSERT OR IGNORE INTO transport_positions(direction,durable_sequence,acknowledged_sequence) VALUES ('control_to_node',0,0),('node_to_control',0,0);
        INSERT OR IGNORE INTO transport_compaction(direction,compacted_through,compacted_digest,updated_at) VALUES ('control_to_node',0,'',datetime('now')),('node_to_control',0,'',datetime('now'));
        INSERT OR IGNORE INTO room_work_marker(singleton,pending,updated_at) VALUES (1,0,datetime('now'));
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
      `);
      const challengeColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(auth_challenges)").toArray().map((column) => column.name));
      if (!challengeColumns.has("capability_digest")) this.ctx.storage.sql.exec("ALTER TABLE auth_challenges ADD COLUMN capability_digest TEXT NOT NULL DEFAULT 'unknown'");
      if (!challengeColumns.has("node_boot_id")) this.ctx.storage.sql.exec("ALTER TABLE auth_challenges ADD COLUMN node_boot_id TEXT NOT NULL DEFAULT 'unknown'");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (2,datetime('now'))");
      const outboundColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(outbound_frames)").toArray().map((column) => column.name));
      if (!outboundColumns.has("dispatch_attempts")) this.ctx.storage.sql.exec("ALTER TABLE outbound_frames ADD COLUMN dispatch_attempts INTEGER NOT NULL DEFAULT 0");
      if (!outboundColumns.has("next_attempt_at")) this.ctx.storage.sql.exec("ALTER TABLE outbound_frames ADD COLUMN next_attempt_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z'");
      if (!outboundColumns.has("kind")) this.ctx.storage.sql.exec("ALTER TABLE outbound_frames ADD COLUMN kind TEXT NOT NULL DEFAULT 'control'");
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS outbound_dispatch_due_idx ON outbound_frames(state,next_attempt_at,expires_at)");
      const receiptColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(outbound_message_receipts)").toArray().map((column) => column.name));
      if (!receiptColumns.has("kind")) this.ctx.storage.sql.exec("ALTER TABLE outbound_message_receipts ADD COLUMN kind TEXT NOT NULL DEFAULT 'control'");
      const positionColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(transport_positions)").toArray().map((column) => column.name));
      if (!positionColumns.has("retained_sequence")) this.ctx.storage.sql.exec("ALTER TABLE transport_positions ADD COLUMN retained_sequence INTEGER NOT NULL DEFAULT 0");
      if (!positionColumns.has("projected_sequence")) this.ctx.storage.sql.exec("ALTER TABLE transport_positions ADD COLUMN projected_sequence INTEGER NOT NULL DEFAULT 0");
      const inboundColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(inbound_frames)").toArray().map((column) => column.name));
      if (!inboundColumns.has("kind")) this.ctx.storage.sql.exec("ALTER TABLE inbound_frames ADD COLUMN kind TEXT NOT NULL DEFAULT 'app'");
      if (!inboundColumns.has("projection_claimed_at")) this.ctx.storage.sql.exec("ALTER TABLE inbound_frames ADD COLUMN projection_claimed_at TEXT");
      const replayColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(control_replay_intents)").toArray().map((column) => column.name));
      if (!replayColumns.has("lease_token")) this.ctx.storage.sql.exec("ALTER TABLE control_replay_intents ADD COLUMN lease_token TEXT");
      if (!replayColumns.has("lease_expires_at")) this.ctx.storage.sql.exec("ALTER TABLE control_replay_intents ADD COLUMN lease_expires_at TEXT");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (3,datetime('now'))");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (4,datetime('now'))");
      this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    });
  }

  private workMarker(): RoomWorkMarker {
    return this.ctx.storage.sql.exec<RoomWorkMarker>("SELECT * FROM room_work_marker WHERE singleton=1").one();
  }

  private healthClockNow(): number {
    return this.idleProbeNowMs ?? Date.now();
  }

  /** Loopback E2E-only counters. No production deployment enables the flag. */
  async resetIdleE2EProbe(nowMs: number): Promise<void> {
    if (this.idleProbe === null || this.idleProbeD1 === null || !Number.isFinite(nowMs)) throw new TypeError("idle_e2e_probe_unavailable");
    this.ctx.storage.sql.exec("UPDATE room_work_marker SET health_last_projected_at=? WHERE singleton=1 AND health_semantic_json IS NOT NULL", nowMs);
    Object.assign(this.idleProbe, { incomingMessages: 0, sqlStatements: 0, sqlRowsRead: 0, sqlRowsWritten: 0, setAlarm: 0, deleteAlarm: 0, alarmInvocations: 0 });
    this.idleProbeD1.reset();
    this.idleProbeNowMs = nowMs;
    this.idleProbeHealthOrdinal = 0;
  }

  async inspectIdleE2EProbe(): Promise<Record<string, unknown>> {
    if (this.idleProbe === null || this.idleProbeD1 === null) throw new TypeError("idle_e2e_probe_unavailable");
    const counters = { ...this.idleProbe };
    const d1 = this.idleProbeD1.snapshot();
    const rows = this.ctx.storage.sql.exec<{ inbound: number; ack_rows: number }>("SELECT (SELECT COUNT(*) FROM inbound_frames) AS inbound,(SELECT COUNT(*) FROM outbound_message_receipts WHERE kind='ack') AS ack_rows").one();
    const alarmAt = await this.ctx.storage.getAlarm();
    // Inspection must not perturb the next sample.
    Object.assign(this.idleProbe, counters);
    return { ...counters, d1, inboundRows: rows.inbound, ackRows: rows.ack_rows, alarmAt, nowMs: this.idleProbeNowMs };
  }

  /**
   * Isolated live-E2E courier entrypoint. The production configuration never
   * defines either binding, so this cannot be enabled by an HTTP request. The
   * dedicated loopback fixture uses it to exercise the same durable inbox,
   * D1 privilege projection, and durable result outbox without manufacturing
   * a browser- or Device-auth bypass in the production Worker entrypoint.
   */
  async projectFullDeviceLiveE2E(token: string, document: unknown): Promise<Record<string, unknown>> {
    const liveEnv = this.env as ControlPlaneEnv & {
      FULL_DEVICE_LIVE_E2E?: string;
      FULL_DEVICE_LIVE_E2E_TOKEN?: string;
    };
    if (liveEnv.FULL_DEVICE_LIVE_E2E !== "enabled" || liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN === undefined || token !== liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN) {
      throw new TypeError("full_device_live_e2e_unavailable");
    }
    const frame = parsePrivilegeTransportFrame(parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(document)));
    const computed = await sha256Hex(canonicalJson(frame.payload));
    if (computed !== frame.payloadDigest) throw new TypeError("payload_digest_mismatch");
    const sequence = Number(frame.sequence);
    if (!Number.isSafeInteger(sequence) || sequence < 1) throw new TypeError("sequence_out_of_range");
    const state = this.ctx.storage.sql.exec<{ device_id: string; epoch: number }>("SELECT device_id,epoch FROM connection_state WHERE singleton=1").toArray()[0];
    if (state === undefined) {
      this.ctx.storage.sql.exec("INSERT INTO connection_state(singleton,device_id,epoch,key_id,connection_id,protocol,capability_digest,reconciliation_state,updated_at) VALUES (1,?,?,?,?,?,?,\'complete\',?)", frame.deviceId, Number(frame.connectionEpoch), null, "full-device-live-e2e", "conduit.node/1", "full-device-live-e2e", nowIso());
    } else if (state.device_id !== frame.deviceId || String(state.epoch) !== frame.connectionEpoch) {
      throw new TypeError("full_device_live_e2e_room_identity_conflict");
    }
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction=\'node_to_control\'").one().durable_sequence;
    if (sequence !== position + 1) throw new TypeError("full_device_live_e2e_sequence_conflict");
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,projected,kind,created_at) VALUES (?,?,?,?,?,3,\'app\',?)", sequence, frame.messageId, frame.correlationId ?? null, frame.payloadDigest, JSON.stringify(frame), nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction=\'node_to_control\'", sequence);
    });
    try {
      let result: Record<string, unknown>;
      try {
        result = await projectPrivilegeFrame(this.env, frame);
      } catch (error) {
        if (!(error instanceof PublicError) && !(error instanceof TypeError)) throw error;
        result = privilegeDenialResult(String(frame.payload.requestId ?? frame.messageId), error);
      }
      if (frame.type === "privilege.ticket_request") {
        await this.enqueueControlFrame(privilegeResultType(), result, String(frame.payload.requestId), new Date(Date.now() + 300_000).toISOString(), undefined, `cmsg_${String(frame.payload.requestId)}`, frame.deviceId);
      }
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=1 WHERE sequence=? AND projected=3", sequence);
      const counts = this.ctx.storage.sql.exec<{ inbound: number; outbound: number }>("SELECT (SELECT COUNT(*) FROM inbound_frames) AS inbound,(SELECT COUNT(*) FROM outbound_message_receipts) AS outbound").one();
      return { result, durableSequence: String(sequence), inboundRows: counts.inbound, outboundRows: counts.outbound };
    } catch (error) {
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=0 WHERE sequence=? AND projected=3", sequence);
      throw error;
    }
  }

  async inspectFullDeviceLiveE2E(token: string): Promise<Record<string, unknown>> {
    const liveEnv = this.env as ControlPlaneEnv & { FULL_DEVICE_LIVE_E2E?: string; FULL_DEVICE_LIVE_E2E_TOKEN?: string };
    if (liveEnv.FULL_DEVICE_LIVE_E2E !== "enabled" || liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN === undefined || token !== liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN) throw new TypeError("full_device_live_e2e_unavailable");
    const positions = this.ctx.storage.sql.exec<{ direction: string; durable_sequence: number }>("SELECT direction,durable_sequence FROM transport_positions ORDER BY direction").toArray();
    const rows = this.ctx.storage.sql.exec<{ inbound: number; projected: number; outbound: number }>("SELECT (SELECT COUNT(*) FROM inbound_frames) AS inbound,(SELECT COUNT(*) FROM inbound_frames WHERE projected=1) AS projected,(SELECT COUNT(*) FROM outbound_message_receipts) AS outbound").one();
    const connection = this.ctx.storage.sql.exec<{ device_id: string; epoch: number; connection_id: string; reconciliation_state: string }>("SELECT device_id,epoch,connection_id,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0] ?? null;
    const activeSocketCount = this.ctx.getWebSockets().length;
    return { ...rows, positions, connection, activeSocketCount };
  }

  async acknowledgeFullDeviceLiveRegistrationE2E(token: string, installationId: string): Promise<void> {
    const liveEnv = this.env as ControlPlaneEnv & { FULL_DEVICE_LIVE_E2E?: string; FULL_DEVICE_LIVE_E2E_TOKEN?: string };
    if (liveEnv.FULL_DEVICE_LIVE_E2E !== "enabled" || liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN === undefined || token !== liveEnv.FULL_DEVICE_LIVE_E2E_TOKEN) throw new TypeError("full_device_live_e2e_unavailable");
    const messageId = `cmsg_preg_${installationId}`;
    const queued = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", messageId).one().count;
    if (queued !== 1) throw new TypeError("full_device_live_registration_delivery_missing");
    // Model the isolated client's application plus cumulative ACK. Removing
    // this exact test delivery permits a later policy attestation to reuse the
    // production registration correlation identity during the same live run.
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE message_id=?", messageId);
      this.ctx.storage.sql.exec("DELETE FROM outbound_message_receipts WHERE message_id=?", messageId);
    });
  }

  /**
   * Mark work before returning custody of a row. The marker is deliberately
   * local to this DO: it is the durable wake-up hint, not a second source of
   * truth for any protocol record.
   */
  private notePending(dueAt = Date.now()): void {
    if (!Number.isFinite(dueAt)) dueAt = Date.now();
    const marker = this.workMarker();
    const minDueAt = marker.min_due_at === null ? dueAt : Math.min(marker.min_due_at, dueAt);
    if (marker.pending === 1 && marker.min_due_at === minDueAt) return;
    this.ctx.storage.sql.exec(
      "UPDATE room_work_marker SET pending=1,min_due_at=?,updated_at=? WHERE singleton=1",
      minDueAt,
      nowIso(),
    );
  }

  private noteRealtimePending(deviceId: string, dueAt = Date.now()): void {
    if (!Number.isFinite(dueAt)) dueAt = Date.now();
    const marker = this.workMarker();
    const minDueAt = marker.realtime_min_due_at === null ? dueAt : Math.min(marker.realtime_min_due_at, dueAt);
    this.ctx.storage.sql.exec(
      "UPDATE room_work_marker SET realtime_pending=1,realtime_min_due_at=?,realtime_device_id=?,pending=1,min_due_at=CASE WHEN min_due_at IS NULL OR min_due_at>? THEN ? ELSE min_due_at END,updated_at=? WHERE singleton=1",
      minDueAt,
      deviceId,
      minDueAt,
      minDueAt,
      nowIso(),
    );
  }

  private noteAckPending(throughSequence: number, immediate = false): void {
    if (!Number.isSafeInteger(throughSequence) || throughSequence < 1) return;
    const marker = this.workMarker();
    // `transport_positions.durable_sequence` is the authoritative contiguous
    // receive frontier. Once an ACK is pending, later frames only advance that
    // position; repeatedly rewriting the marker for every health heartbeat is
    // needless DO row churn. The flush path reads the latest frontier when it
    // emits the cumulative ACK. An immediate boundary may pull the due time
    // forward once, but still never rewrites the watermark per frame.
    if (marker.ack_pending_through > marker.ack_sent_through) {
      if (immediate && (marker.ack_pending_at === null || marker.ack_pending_at > Date.now())) {
        const now = Date.now();
        this.ctx.storage.sql.exec(
          "UPDATE room_work_marker SET ack_pending_at=?,min_due_at=CASE WHEN min_due_at IS NULL OR min_due_at>? THEN ? ELSE min_due_at END,updated_at=? WHERE singleton=1",
          now,
          now,
          now,
          nowIso(),
        );
      }
      return;
    }
    const ackCoalesceMs = usageProfileForEnv(this.env).ackCoalesceMs;
    const pendingAt = immediate ? Date.now() : marker.ack_pending_at ?? Date.now();
    const dueAt = immediate ? Date.now() : pendingAt + ackCoalesceMs;
    const nextThrough = Math.max(marker.ack_pending_through, throughSequence);
    this.ctx.storage.sql.exec(
      "UPDATE room_work_marker SET ack_pending_through=?,ack_pending_at=?,pending=1,min_due_at=CASE WHEN min_due_at IS NULL OR min_due_at>? THEN ? ELSE min_due_at END,updated_at=? WHERE singleton=1",
      nextThrough,
      pendingAt,
      dueAt,
      dueAt,
      nowIso(),
    );
  }

  private setHealthMarker(semanticJson: string, projectedAt?: number): void {
    const marker = this.workMarker();
    const at = projectedAt ?? marker.health_last_projected_at;
    if (marker.health_semantic_json === semanticJson && marker.health_last_projected_at === at) return;
    this.ctx.storage.sql.exec(
      "UPDATE room_work_marker SET health_semantic_json=?,health_last_projected_at=?,updated_at=? WHERE singleton=1",
      semanticJson,
      at,
      nowIso(),
    );
  }

  private setRealtimeResult(deviceId: string, nextAttemptAt: string | null | undefined): void {
    // A pending outbox result without a due timestamp is still pending. Keep a
    // durable local wake-up rather than accidentally clearing the marker.
    if (nextAttemptAt === undefined) {
      const marker = this.workMarker();
      this.noteRealtimePending(deviceId, marker.realtime_min_due_at ?? Date.now() + 30_000);
      return;
    }
    if (nextAttemptAt === null) {
      this.ctx.storage.sql.exec(
        "UPDATE room_work_marker SET realtime_pending=0,realtime_min_due_at=NULL,realtime_device_id=NULL,updated_at=? WHERE singleton=1",
        nowIso(),
      );
      return;
    }
    const dueAt = Date.parse(nextAttemptAt);
    this.noteRealtimePending(deviceId, Number.isFinite(dueAt) ? dueAt : Date.now());
  }

  private healthSemantic(frame: Extract<NodeV1PostAuthFrame, { type: "device.health" }>): string {
    const payload = frame.payload;
    return canonicalJson({
      nodeState: payload.nodeState,
      journalState: payload.journalState,
      storageState: payload.storageState,
      activeCommands: payload.activeCommands ?? 0,
      activeAgentRuns: payload.activeAgentRuns ?? 0,
      activeRuntimes: payload.activeRuntimes ?? 0,
      privilegedHelper: (payload as unknown as Record<string, unknown>).privilegedHelper ?? null,
    });
  }

  private hasCurrentAuthenticatedSocket(): boolean {
    const connection = this.ctx.storage.sql.exec<{ epoch: number }>("SELECT epoch FROM connection_state WHERE singleton=1").toArray()[0];
    return connection !== undefined && this.ctx.getWebSockets().some((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      return item?.stage === "authenticated" && item.epoch === String(connection.epoch);
    });
  }

  private shouldProjectHealth(frame: Extract<NodeV1PostAuthFrame, { type: "device.health" }>, now = this.healthClockNow()): boolean {
    const marker = this.workMarker();
    const semantic = this.healthSemantic(frame);
    if (marker.health_semantic_json !== semantic) return true;
    const d1HealthTouchMs = usageProfileForEnv(this.env).d1HealthTouchMs;
    return marker.health_last_projected_at === null || now - marker.health_last_projected_at >= Math.max(HEALTH_CHECKPOINT_MS, d1HealthTouchMs);
  }

  private async syncWorkMarker(minimumAlarmDelayMs = 1): Promise<void> {
    const marker = this.workMarker();
    const nowMs = Date.now();
    const now = new Date(nowMs).toISOString();
    const cutoff = new Date(nowMs - HOT_RETENTION_MS).toISOString();
    const status = this.ctx.storage.sql.exec<{
      inbound_pending: number;
      outbound_due: string | null;
      replay_due: string | null;
      retention_pending: number;
      inbound_retention_from: string | null;
      receipt_retention_due: string | null;
      auth_retention_due: string | null;
      reconciliation_retention_from: string | null;
      terminal_retention_from: string | null;
    }>(
      `SELECT
         EXISTS(SELECT 1 FROM inbound_frames WHERE projected=0 OR (projected=3 AND (projection_claimed_at IS NULL OR projection_claimed_at<=?))) AS inbound_pending,
         (SELECT MIN(next_attempt_at) FROM outbound_frames WHERE state='queued') AS outbound_due,
         (SELECT MIN(next_attempt_at) FROM control_replay_intents) AS replay_due,
         CASE WHEN
           EXISTS(SELECT 1 FROM inbound_frames WHERE projected IN (1,2) AND NOT (kind='app' AND json_extract(frame_json,'$.type')='device.health' AND sequence=(SELECT MAX(sequence) FROM inbound_frames WHERE kind='app' AND json_extract(frame_json,'$.type')='device.health')) AND created_at<=?)
           OR (SELECT COUNT(*) FROM inbound_frames WHERE projected IN (1,2))>?
           OR EXISTS(SELECT 1 FROM outbound_message_receipts WHERE
             (state='acknowledged' AND updated_at<=?)
             OR (expires_at<=? AND NOT (kind='ack' AND state IN ('queued','sent') AND sequence=(SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent'))))
             OR (kind='ack' AND state='sent' AND sequence <= (SELECT acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'))
             OR (kind='ack' AND state IN ('queued','sent') AND sequence < (SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent'))))
           OR (SELECT COUNT(*) FROM outbound_message_tombstones)>?
           OR EXISTS(SELECT 1 FROM auth_challenges WHERE expires_at<=? OR (consumed=1 AND expires_at<=?))
           OR (SELECT COUNT(*) FROM auth_challenges)>?
           OR EXISTS(SELECT 1 FROM reconciliation_sessions WHERE state='complete' AND created_at<=?)
           OR (SELECT COUNT(*) FROM reconciliation_sessions WHERE epoch IS NOT (SELECT epoch FROM connection_state WHERE singleton=1))>?
           OR EXISTS(SELECT 1 FROM terminal_receipt_cache WHERE created_at<=?)
           OR (SELECT COUNT(*) FROM terminal_receipt_cache)>?
         THEN 1 ELSE 0 END AS retention_pending,
         (SELECT MIN(created_at) FROM inbound_frames WHERE projected IN (1,2) AND NOT (kind='app' AND json_extract(frame_json,'$.type')='device.health' AND sequence=(SELECT MAX(sequence) FROM inbound_frames WHERE kind='app' AND json_extract(frame_json,'$.type')='device.health'))) AS inbound_retention_from,
         (SELECT MIN(expires_at) FROM outbound_message_receipts WHERE NOT (kind='ack' AND state IN ('queued','sent') AND sequence=(SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent')))) AS receipt_retention_due,
         (SELECT MIN(expires_at) FROM auth_challenges) AS auth_retention_due,
         (SELECT MIN(created_at) FROM reconciliation_sessions WHERE state='complete') AS reconciliation_retention_from,
         (SELECT MIN(created_at) FROM terminal_receipt_cache) AS terminal_retention_from`,
      new Date(nowMs - PROJECTION_LEASE_MS).toISOString(),
      cutoff,
      MAX_INBOUND_FRAMES,
      cutoff,
      now,
      MAX_OUTBOUND_TOMBSTONES,
      now,
      cutoff,
      MAX_AUTH_CHALLENGES,
      cutoff,
      MAX_RECONCILIATION_SESSIONS,
      new Date(nowMs - RECEIPT_RETENTION_MS).toISOString(),
      MAX_TERMINAL_RECEIPTS,
    ).one();

    const hasAuthenticatedSocket = this.hasCurrentAuthenticatedSocket();
    const replayPending = status.replay_due !== null && !hasAuthenticatedSocket;
    // Do not reserve an alarm merely because a retained proof will become old
    // in the future. A later connection/message detects expired rows, and all
    // local tables also have hard cardinality bounds. Alarms are demand-driven
    // only once retention work is actually due or over its bound.
    const retentionDueAt = status.retention_pending !== 0 ? nowMs : null;
    const retentionScheduled = retentionDueAt !== null;
    const dueCandidates: number[] = [];
    if (status.inbound_pending !== 0) dueCandidates.push(nowMs);
    if (status.outbound_due !== null) {
      const due = Date.parse(status.outbound_due);
      if (Number.isFinite(due)) dueCandidates.push(due);
    }
    if (replayPending) {
      const due = Date.parse(status.replay_due!);
      if (Number.isFinite(due)) dueCandidates.push(due);
    }
    if (marker.ack_pending_through > marker.ack_sent_through) dueCandidates.push((marker.ack_pending_at ?? nowMs) + usageProfileForEnv(this.env).ackCoalesceMs);
    if (marker.realtime_pending !== 0) dueCandidates.push(marker.realtime_min_due_at ?? nowMs);
    if (retentionDueAt !== null) dueCandidates.push(retentionDueAt);
    const pending = status.inbound_pending !== 0
      || status.outbound_due !== null
      || replayPending
      || retentionScheduled
      || marker.realtime_pending !== 0
      || marker.ack_pending_through > marker.ack_sent_through;
    const minDueAt = pending && dueCandidates.length > 0 ? Math.min(...dueCandidates) : null;
    const markerChanged = marker.pending !== (pending ? 1 : 0)
      || marker.min_due_at !== minDueAt
      || marker.retention_pending !== (retentionScheduled ? 1 : 0)
      || marker.retention_due_at !== retentionDueAt;
    if (markerChanged) {
      this.ctx.storage.sql.exec(
        "UPDATE room_work_marker SET pending=?,min_due_at=?,retention_pending=?,retention_due_at=?,updated_at=? WHERE singleton=1",
        pending ? 1 : 0,
        minDueAt,
        retentionScheduled ? 1 : 0,
        retentionDueAt,
        nowIso(),
      );
    }

    if (this.alarmActive) return;
    const scheduled = await this.ctx.storage.getAlarm();
    if (!pending) {
      if (scheduled !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    if (minDueAt === null) return;
    if (scheduled === null || minDueAt < scheduled) await this.ctx.storage.setAlarm(Math.max(Date.now() + minimumAlarmDelayMs, minDueAt));
  }

  private async projectAndSync(frame: ProjectableDeviceFrame): Promise<void> {
    // Projection can cross the D1 boundary and may yield while publishing a
    // realtime event. Claim the durable inbox row first so an alarm waking at
    // the same time as the websocket handler cannot project the same terminal
    // receipt twice. `3` is an in-flight value local to this DO; failures put
    // the row back to `0`, while the approval dead-letter path deliberately
    // changes it to `2`.
    const claimedAt = nowIso();
    const staleBefore = new Date(Date.now() - PROJECTION_LEASE_MS).toISOString();
    let claimed = false;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=3,projection_claimed_at=? WHERE sequence=? AND (projected=0 OR (projected=3 AND (projection_claimed_at IS NULL OR projection_claimed_at<=?)))", claimedAt, Number(frame.sequence), staleBefore);
      claimed = this.ctx.storage.sql.exec<{ changes: number }>("SELECT changes() AS changes").one().changes === 1;
    });
    if (!claimed) return;
    try {
      if (frame.type === "operation.approval_request") await this.projectApprovalOrDeadletter(frame);
      else await this.project(frame);
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=1,projection_claimed_at=NULL WHERE sequence=? AND projected=3 AND projection_claimed_at=?", Number(frame.sequence), claimedAt);
    } catch (error) {
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=0,projection_claimed_at=NULL WHERE sequence=? AND projected=3 AND projection_claimed_at=?", Number(frame.sequence), claimedAt);
      throw error;
    } finally {
      await this.syncWorkMarker();
    }
  }

  /**
   * Refresh the D1 observation timestamp for an exact health replay without
   * manufacturing a new node sequence or projection receipt. The original
   * health frame already owns the receipt and its semantic state; a replay is
   * only a fresh observation of that same state. A newer health sequence wins
   * over an old replay, so this helper is deliberately a no-op in that case.
   */
  private async projectExactHealthCheckpoint(frame: Extract<NodeV1PostAuthFrame, { type: "device.health" }>): Promise<void> {
    const observedAt = nowIso();
    // Keep the common exact-checkpoint path to one D1 binding call. Sequence
    // values are canonical unsigned decimal strings, so length followed by
    // lexical order is the same as numeric order without narrowing to SQLite's
    // signed INTEGER range. The diagnostic SELECT only runs for the exceptional
    // no-change path, preserving the stale-epoch fail-closed distinction.
    const updated = await this.env.DB.prepare(`
      UPDATE devices
      SET health_sequence=?1,last_observed_at=?2,updated_at=?2
      WHERE id=?3 AND status='active' AND connection_epoch=?4
        AND (
          length(health_sequence) < length(?1)
          OR (length(health_sequence) = length(?1) AND health_sequence <= ?1)
        )
      RETURNING id
    `).bind(frame.sequence, observedAt, frame.deviceId, frame.connectionEpoch).all<{ id: string }>();
    if (updated.results.length === 1) return;

    const device = await this.env.DB.prepare("SELECT connection_epoch,health_sequence FROM devices WHERE id=?1 AND status='active' LIMIT 1")
      .bind(frame.deviceId)
      .first<{ connection_epoch: string; health_sequence: string }>();
    if (device === null || device.connection_epoch !== frame.connectionEpoch) throw new TypeError("stale_connection_epoch");
    if (BigInt(device.health_sequence) > BigInt(frame.sequence)) return;
    throw new TypeError("health_checkpoint_projection_conflict");
  }

  private compactedThrough(direction: "control_to_node" | "node_to_control"): number {
    return this.ctx.storage.sql.exec<RetentionCompactionRow>("SELECT * FROM transport_compaction WHERE direction=?", direction).toArray()[0]?.compacted_through ?? 0;
  }

  private isLatestUnacknowledgedAck(sequence: number): boolean {
    const latest = this.ctx.storage.sql.exec<{ sequence: number | null }>(
      "SELECT MAX(sequence) AS sequence FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent')",
    ).one().sequence;
    return latest === sequence;
  }

  private async compactInboundFrames(now = Date.now()): Promise<number> {
    const cutoff = new Date(now - HOT_RETENTION_MS).toISOString();
    const projectionStaleAt = new Date(now - PROJECTION_LEASE_MS).toISOString();
    const oldestUnprojected = this.ctx.storage.sql.exec<{ sequence: number | null }>("SELECT MIN(sequence) AS sequence FROM inbound_frames WHERE projected=0 OR (projected=3 AND (projection_claimed_at IS NULL OR projection_claimed_at<=?))", projectionStaleAt).one().sequence;
    const retentionBatch = usageProfileForEnv(this.env).retentionBatchRows;
    const rows = this.ctx.storage.sql.exec<{ sequence: number; payload_digest: string }>(
      "SELECT sequence,payload_digest FROM inbound_frames WHERE projected IN (1,2) AND sequence<? AND NOT (kind='app' AND json_extract(frame_json,'$.type')='device.health' AND sequence=(SELECT MAX(sequence) FROM inbound_frames WHERE kind='app' AND json_extract(frame_json,'$.type')='device.health')) AND (created_at<=? OR sequence <= (SELECT COALESCE(MAX(sequence)-?,0) FROM inbound_frames WHERE projected IN (1,2))) ORDER BY sequence LIMIT ?",
      oldestUnprojected ?? Number.MAX_SAFE_INTEGER,
      cutoff,
      MAX_INBOUND_FRAMES,
      retentionBatch,
    ).toArray();
    if (rows.length === 0) return 0;
    const current = this.ctx.storage.sql.exec<RetentionCompactionRow>("SELECT * FROM transport_compaction WHERE direction='node_to_control'").toArray()[0];
    let compactedDigest = current?.compacted_digest ?? "";
    for (const row of rows) compactedDigest = await sha256Hex(canonicalJson({ previous: compactedDigest, sequence: String(row.sequence), payloadDigest: row.payload_digest }));
    const through = Math.max(current?.compacted_through ?? 0, ...rows.map((row) => row.sequence));
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM inbound_frames WHERE sequence IN (SELECT sequence FROM inbound_frames WHERE projected IN (1,2) AND sequence<? AND NOT (kind='app' AND json_extract(frame_json,'$.type')='device.health' AND sequence=(SELECT MAX(sequence) FROM inbound_frames WHERE kind='app' AND json_extract(frame_json,'$.type')='device.health')) AND (created_at<=? OR sequence <= (SELECT COALESCE(MAX(sequence)-?,0) FROM inbound_frames WHERE projected IN (1,2))) ORDER BY sequence LIMIT ?)", oldestUnprojected ?? Number.MAX_SAFE_INTEGER, cutoff, MAX_INBOUND_FRAMES, retentionBatch);
      this.ctx.storage.sql.exec("UPDATE transport_compaction SET compacted_through=?,compacted_digest=?,updated_at=? WHERE direction='node_to_control'", through, compactedDigest, nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET retained_sequence=MAX(retained_sequence,?),projected_sequence=MAX(projected_sequence,?) WHERE direction='node_to_control'", through, through);
    });
    return rows.length;
  }

  private async compactOutboundReceipts(now = Date.now()): Promise<number> {
    const nowIsoValue = new Date(now).toISOString();
    const retentionBatch = usageProfileForEnv(this.env).retentionBatchRows;
    const acknowledgedThrough = this.ctx.storage.sql.exec<{ acknowledged_sequence: number }>("SELECT acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one().acknowledged_sequence;
    const rows = this.ctx.storage.sql.exec<OutboundMessageTombstone>(
      "SELECT message_id,correlation_id,payload_digest,sequence,kind,state,expires_at,created_at FROM outbound_message_receipts WHERE (state='acknowledged' AND updated_at<=?) OR (expires_at<=? AND NOT (kind='ack' AND state IN ('queued','sent') AND sequence=(SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent')))) OR (kind='ack' AND state='sent' AND sequence<=?) OR (kind='ack' AND state IN ('queued','sent') AND sequence < (SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent'))) ORDER BY updated_at,sequence LIMIT ?",
      new Date(now - HOT_RETENTION_MS).toISOString(),
      nowIsoValue,
      acknowledgedThrough,
      retentionBatch,
    ).toArray();
    if (rows.length === 0) return 0;
    const current = this.ctx.storage.sql.exec<RetentionCompactionRow>("SELECT * FROM transport_compaction WHERE direction='control_to_node'").toArray()[0];
    let compactedDigest = current?.compacted_digest ?? "";
    for (const row of [...rows].sort((left, right) => left.sequence - right.sequence)) {
      compactedDigest = await sha256Hex(canonicalJson({ previous: compactedDigest, sequence: String(row.sequence), payloadDigest: row.payload_digest }));
    }
    const through = Math.max(current?.compacted_through ?? 0, ...rows.map((row) => row.sequence));
    this.ctx.storage.transactionSync(() => {
      for (const row of rows) {
        this.ctx.storage.sql.exec(
          "INSERT OR REPLACE INTO outbound_message_tombstones(message_id,correlation_id,payload_digest,sequence,kind,state,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
          row.message_id,
          row.correlation_id,
          row.payload_digest,
          row.sequence,
          row.kind,
          row.state,
          row.expires_at,
          row.created_at,
        );
        this.ctx.storage.sql.exec("DELETE FROM outbound_message_receipts WHERE message_id=?", row.message_id);
        this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE message_id=? AND (expires_at<=? OR state='sent')", row.message_id, nowIsoValue);
      }
      this.ctx.storage.sql.exec("DELETE FROM outbound_message_tombstones WHERE rowid IN (SELECT rowid FROM outbound_message_tombstones ORDER BY created_at,message_id LIMIT (SELECT CASE WHEN COUNT(*)>? THEN COUNT(*)-? ELSE 0 END FROM outbound_message_tombstones))", MAX_OUTBOUND_TOMBSTONES, MAX_OUTBOUND_TOMBSTONES);
      this.ctx.storage.sql.exec("UPDATE transport_compaction SET compacted_through=?,compacted_digest=?,updated_at=? WHERE direction='control_to_node'", through, compactedDigest, nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET retained_sequence=MAX(retained_sequence,?) WHERE direction='control_to_node'", through);
    });
    return rows.length;
  }

  private compactAuthChallenges(now = Date.now()): number {
    const cutoff = new Date(now - HOT_RETENTION_MS).toISOString();
    const nowValue = new Date(now).toISOString();
    const result = this.ctx.storage.sql.exec<{ count: number }>(
      "SELECT COUNT(*) AS count FROM auth_challenges WHERE expires_at<=? OR (consumed=1 AND expires_at<=?)",
      nowValue,
      cutoff,
    ).one();
    const over = this.ctx.storage.sql.exec<{ count: number }>("SELECT CASE WHEN COUNT(*)>? THEN COUNT(*)-? ELSE 0 END AS count FROM auth_challenges", MAX_AUTH_CHALLENGES, MAX_AUTH_CHALLENGES).one().count;
    const limit = Math.min(usageProfileForEnv(this.env).retentionBatchRows, Math.max(result.count, over));
    if (limit === 0) return 0;
    // If an attacker or a crashed client leaves more than the local cap,
    // evict the oldest challenge (consumed first). The evicted proof fails
    // closed; keeping an unbounded set would turn challenge custody into a
    // durable write amplifier.
    this.ctx.storage.sql.exec("DELETE FROM auth_challenges WHERE rowid IN (SELECT rowid FROM auth_challenges WHERE expires_at<=? OR (consumed=1 AND expires_at<=?) OR ?>0 ORDER BY consumed DESC,expires_at,connection_id LIMIT ?)", nowValue, cutoff, over, limit);
    return limit;
  }

  private compactReconciliationSessions(now = Date.now()): number {
    const cutoff = new Date(now - HOT_RETENTION_MS).toISOString();
    const currentEpoch = this.ctx.storage.sql.exec<{ epoch: number | null }>("SELECT epoch FROM connection_state WHERE singleton=1").toArray()[0]?.epoch ?? null;
    const old = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM reconciliation_sessions WHERE state='complete' AND created_at<=?", cutoff).one().count;
    const over = this.ctx.storage.sql.exec<{ count: number }>("SELECT CASE WHEN COUNT(*)>? THEN COUNT(*)-? ELSE 0 END AS count FROM reconciliation_sessions WHERE epoch IS NOT ?", MAX_RECONCILIATION_SESSIONS, MAX_RECONCILIATION_SESSIONS, currentEpoch).one().count;
    const limit = Math.min(usageProfileForEnv(this.env).retentionBatchRows, Math.max(old, over));
    if (limit === 0) return 0;
    this.ctx.storage.sql.exec("DELETE FROM reconciliation_sessions WHERE rowid IN (SELECT rowid FROM reconciliation_sessions WHERE (state='complete' AND created_at<=?) OR (epoch IS NOT ? AND ?>0) ORDER BY CASE WHEN state='complete' THEN 0 ELSE 1 END,created_at,id LIMIT ?)", cutoff, currentEpoch, over, limit);
    return limit;
  }

  private compactTerminalReceipts(now = Date.now()): number {
    const cutoff = new Date(now - RECEIPT_RETENTION_MS).toISOString();
    const old = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM terminal_receipt_cache WHERE created_at<=?", cutoff).one().count;
    const over = this.ctx.storage.sql.exec<{ count: number }>("SELECT CASE WHEN COUNT(*)>? THEN COUNT(*)-? ELSE 0 END AS count FROM terminal_receipt_cache", MAX_TERMINAL_RECEIPTS, MAX_TERMINAL_RECEIPTS).one().count;
    const limit = Math.min(usageProfileForEnv(this.env).retentionBatchRows, Math.max(old, over));
    if (limit === 0) return 0;
    this.ctx.storage.sql.exec("DELETE FROM terminal_receipt_cache WHERE rowid IN (SELECT rowid FROM terminal_receipt_cache ORDER BY created_at,operation_id LIMIT ?)", limit);
    return limit;
  }

  private compactTombstones(): number {
    const count = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_tombstones").one().count;
    const limit = Math.min(usageProfileForEnv(this.env).retentionBatchRows, Math.max(count - MAX_OUTBOUND_TOMBSTONES, 0));
    if (limit === 0) return 0;
    this.ctx.storage.sql.exec("DELETE FROM outbound_message_tombstones WHERE rowid IN (SELECT rowid FROM outbound_message_tombstones ORDER BY created_at,message_id LIMIT ?)", limit);
    return limit;
  }

  private async runRetentionMaintenance(now = Date.now()): Promise<number> {
    let removed = 0;
    removed += await this.compactInboundFrames(now);
    removed += await this.compactOutboundReceipts(now);
    removed += this.compactAuthChallenges(now);
    removed += this.compactReconciliationSessions(now);
    removed += this.compactTerminalReceipts(now);
    removed += this.compactTombstones();
    return removed;
  }

  private async acknowledgeControlThrough(through: bigint): Promise<void> {
    if (through < 0n || through > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError("acknowledgement_out_of_range");
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number; acknowledged_sequence: number }>("SELECT durable_sequence,acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one();
    if (through > BigInt(position.durable_sequence)) throw new TypeError("acknowledgement_out_of_range");
    if (through <= BigInt(position.acknowledged_sequence)) return;
    const acknowledged = Number(through);
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE transport_positions SET acknowledged_sequence=? WHERE direction='control_to_node'", acknowledged);
      this.ctx.storage.sql.exec("UPDATE outbound_message_receipts SET state='acknowledged',updated_at=? WHERE sequence<=?", nowIso(), acknowledged);
      this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE sequence<=?", acknowledged);
      this.ctx.storage.sql.exec("DELETE FROM control_replay_intents WHERE through_sequence<=?", acknowledged);
    });
  }

  private async flushPendingAck(preferredSocket?: WebSocket, force = false): Promise<void> {
    const marker = this.workMarker();
    const receivePosition = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence;
    const through = Math.max(marker.ack_pending_through, receivePosition);
    if (through <= marker.ack_sent_through) {
      if (marker.ack_pending_through !== 0 || marker.ack_pending_at !== null || marker.ack_message_id !== null) {
        this.ctx.storage.sql.exec("UPDATE room_work_marker SET ack_pending_through=0,ack_pending_at=NULL,ack_message_id=NULL,updated_at=? WHERE singleton=1", nowIso());
      }
      return;
    }
    if (!force && marker.ack_pending_at !== null && marker.ack_pending_at + usageProfileForEnv(this.env).ackCoalesceMs > Date.now()) return;

    let messageId = marker.ack_message_id;
    let existing = messageId === null
      ? undefined
      : this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE message_id=?", messageId).toArray()[0];
    if (existing !== undefined && existing.state === "sent") {
      // A sent ACK already covers this watermark only when the durable marker
      // was advanced with the send. Allocate a fresh identity for a newer one.
      messageId = null;
      existing = undefined;
    }
    if (messageId !== null && existing === undefined) {
      // The previous ACK may have been frontier-pruned (or acknowledged by a
      // reconciliation update) while its marker update was still in flight.
      // Never reuse that durable identity for a different throughSequence.
      const priorReceipt = this.ctx.storage.sql.exec<StoredDispatchReceipt>("SELECT * FROM outbound_message_receipts WHERE message_id=?", messageId).toArray()[0];
      const priorTombstone = this.ctx.storage.sql.exec<OutboundMessageTombstone>("SELECT * FROM outbound_message_tombstones WHERE message_id=?", messageId).toArray()[0];
      if (priorReceipt !== undefined || priorTombstone !== undefined) messageId = null;
    }
    if (messageId === null) {
      messageId = newId("cmsg_ack");
      this.ctx.storage.sql.exec("UPDATE room_work_marker SET ack_message_id=?,updated_at=? WHERE singleton=1", messageId, nowIso());
    }

    const payload = { direction: "node_to_control", throughSequence: String(through) };
    if (existing !== undefined && existing.state === "queued") {
      const digest = await sha256Hex(canonicalJson(payload));
      const parsed = JSON.parse(existing.frame_json) as Record<string, unknown>;
      const previousPayload = parsed.payload;
      const previousThrough = previousPayload !== null && typeof previousPayload === "object" && !Array.isArray(previousPayload) && typeof (previousPayload as Record<string, unknown>).throughSequence === "string"
        ? BigInt((previousPayload as Record<string, unknown>).throughSequence as string)
        : 0n;
      if (previousThrough < BigInt(through)) {
        parsed.payload = payload;
        parsed.payloadDigest = digest;
        this.ctx.storage.transactionSync(() => {
          const ackExpiresAt = new Date(Date.now() + ACK_RETENTION_MS).toISOString();
          this.ctx.storage.sql.exec("UPDATE outbound_frames SET payload_digest=?,frame_json=?,expires_at=? WHERE message_id=? AND state='queued'", digest, JSON.stringify(parsed), ackExpiresAt, messageId);
          this.ctx.storage.sql.exec("UPDATE outbound_message_receipts SET payload_digest=?,expires_at=?,updated_at=? WHERE message_id=? AND state='queued'", digest, ackExpiresAt, nowIso(), messageId);
        });
        existing = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE message_id=?", messageId).toArray()[0];
      }
    }
    const delivery = existing === undefined
      ? await this.enqueueControlFrame("transport.ack", payload, undefined, new Date(Date.now() + ACK_RETENTION_MS).toISOString(), preferredSocket, messageId)
      : { sequence: String(existing.sequence), delivered: await this.sendStoredFrame(existing, preferredSocket) };
    if (!delivery.delivered) {
      this.notePending(Date.now() + 30_000);
      await this.syncWorkMarker();
    }
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
    const attachment = ws.deserializeAttachment() as SocketAttachment | null;
    if (attachment === null) { ws.close(1011, "connection_state_missing"); return; }
    let value: unknown;
    try { value = parseWireDocumentText(schemaIds.nodeV1, message); }
    catch { ws.close(1007, "frame_malformed"); return; }
    const body = value as unknown as Record<string, unknown>;
    if (attachment.stage === "new") { await this.hello(ws, attachment, body); return; }
    if (attachment.stage === "challenged") { await this.authenticate(ws, attachment, body); return; }
    if (isPrivilegeFrameType(body.type)) {
      let privilegeFrame: PrivilegeTransportFrame;
      try { privilegeFrame = parsePrivilegeTransportFrame(value); }
      catch { ws.close(1007, "frame_malformed"); return; }
      await this.acceptPrivilegeFrame(ws, attachment, privilegeFrame);
      return;
    }
    let idleHealthProject: boolean | undefined;
    if (this.idleProbe !== null) {
      this.idleProbe.incomingMessages += 1;
      if (body.type === "device.health" && this.idleProbeNowMs !== null) {
        this.idleProbeNowMs += 10 * 60_000;
        this.idleProbeHealthOrdinal += 1;
        // The accelerated clock represents observations at ten-minute
        // boundaries. The fifteen-minute projection threshold is therefore
        // first reached by every second observation. Claim that decision
        // synchronously before any binding await so a burst still measures
        // the same 72 projections as sequential delivery.
        idleHealthProject = this.idleProbeHealthOrdinal % 2 === 0;
      }
    }
    await this.acceptFrame(ws, attachment, body, idleHealthProject);
    // Test-only application barrier: one response proves one real DeviceRoom
    // handler completed. The accelerated harness counts all responses after
    // sending its checkpoint burst. This is not a transport ACK and creates no
    // durable row.
    if (this.idleProbe !== null && this.idleProbeNowMs !== null && body.type === "device.health") ws.send('{"type":"idle_e2e.settled"}');
  }

  private async acceptPrivilegeFrame(ws: WebSocket, attachment: SocketAttachment, frame: PrivilegeTransportFrame): Promise<void> {
    if (frame.deviceId !== attachment.deviceId || frame.connectionEpoch !== attachment.epoch) { ws.close(1008, "frame_malformed"); return; }
    if (attachment.reconciling && frame.type === "privilege.ticket_request") {
      await this.enqueueControlFrame("transport.error", { code: "reconciliation_required", retryable: true }, frame.correlationId, new Date(Date.now() + 300_000).toISOString(), ws);
      return;
    }
    const digest = await sha256Hex(canonicalJson(frame.payload));
    if (digest !== frame.payloadDigest) { ws.close(1008, "payload_digest_mismatch"); return; }
    const sequence = BigInt(frame.sequence);
    if (sequence < 1n || sequence > BigInt(Number.MAX_SAFE_INTEGER)) { ws.close(1008, "sequence_out_of_range"); return; }
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence;
    if (sequence <= BigInt(position)) {
      const prior = this.ctx.storage.sql.exec<{ message_id: string; payload_digest: string; frame_json: string; projected: number }>("SELECT message_id,payload_digest,frame_json,projected FROM inbound_frames WHERE sequence=?", Number(sequence)).toArray()[0];
      if (prior?.message_id !== frame.messageId || prior.payload_digest !== frame.payloadDigest) { ws.close(1008, "sequence_conflict"); return; }
      if (prior.projected === 0 || prior.projected === 3) {
        this.notePending(Date.now());
        await this.projectAndSync(parsePrivilegeTransportFrame(parseWireDocumentText(schemaIds.nodeV1, prior.frame_json)));
      }
      this.noteAckPending(Number(sequence), true);
      await this.flushPendingAck(ws, true);
      await this.dispatchQueuedFrames();
      await this.syncWorkMarker();
      return;
    }
    if (sequence !== BigInt(position) + 1n) {
      await this.enqueueControlFrame("transport.replay_required", { direction: "node_to_control", expectedSequence: String(position + 1), receivedSequence: String(sequence) }, frame.correlationId, new Date(Date.now() + 300_000).toISOString(), ws);
      await this.syncWorkMarker();
      return;
    }
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,projected,kind,created_at) VALUES (?,?,?,?,?,0,'app',?)", Number(sequence), frame.messageId, frame.correlationId ?? null, frame.payloadDigest, JSON.stringify(frame), nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction='node_to_control'", Number(sequence));
      this.notePending(Date.now());
      this.noteAckPending(Number(sequence), true);
    });
    await this.projectAndSync(frame);
    await this.flushPendingAck(ws, true);
    await this.syncWorkMarker();
  }

  override async webSocketClose(): Promise<void> {
    // Replay intents are intentionally quiet while a current socket is
    // connected. Reconcile the marker after disconnect so the same durable
    // intent gets one retry alarm without requiring a periodic keepalive.
    await this.syncWorkMarker();
  }

  override async webSocketError(): Promise<void> {
    await this.syncWorkMarker();
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
    await this.env.DB.prepare("UPDATE devices SET connection_epoch=?1,node_boot_id=?2,last_observed_at=?3,updated_at=?3 WHERE id=?4 AND status='active'").bind(String(epoch), attachment.nodeBootId ?? null, nowIso(), attachment.deviceId).run();
    const positions = this.ctx.storage.sql.exec<{ direction: string; durable_sequence: number }>("SELECT direction,durable_sequence FROM transport_positions").toArray();
    const controlStored = positions.find((item) => item.direction === "control_to_node")?.durable_sequence ?? 0;
    const nodeStored = positions.find((item) => item.direction === "node_to_control")?.durable_sequence ?? 0;
    ws.send(JSON.stringify({ type: "transport.accepted", connectionId: attachment.connectionId, deviceId: attachment.deviceId, connectionEpoch: String(epoch), selectedProtocol: attachment.selectedProtocol, controlNextSequence: String(controlStored + 1), nodeStoredThroughSequence: String(nodeStored), reconciliationRequired: true }));
    await this.syncWorkMarker();
  }

  private async acceptFrame(ws: WebSocket, attachment: SocketAttachment, body: Record<string, unknown>, idleHealthProject?: boolean): Promise<void> {
    if (body.protocol !== "conduit.node/1" || body.deviceId !== attachment.deviceId || body.connectionEpoch !== attachment.epoch || body.direction !== "node_to_control" || typeof body.sequence !== "string" || !/^\d+$/.test(body.sequence) || typeof body.messageId !== "string" || typeof body.type !== "string" || typeof body.payloadDigest !== "string" || body.payload === null || typeof body.payload !== "object" || Array.isArray(body.payload)) {
      ws.close(1008, "frame_malformed"); return;
    }
    if (attachment.reconciling && body.type !== "reconcile.summary" && body.type !== "reconcile.complete" && body.type !== "transport.ack" && body.type !== "transport.replay_required" && body.type !== "device.health") { await this.enqueueControlFrame("transport.error", { code: "reconciliation_required", retryable: true }, undefined, new Date(Date.now() + 300_000).toISOString(), ws); return; }
    const digest = await sha256Hex(canonicalJson(body.payload));
    if (digest !== body.payloadDigest) { ws.close(1008, "payload_digest_mismatch"); return; }
    const sequence = BigInt(body.sequence);
    if (sequence < 1n || sequence > BigInt(Number.MAX_SAFE_INTEGER)) { ws.close(1008, "sequence_out_of_range"); return; }
    const position = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence;
    if (sequence <= BigInt(position)) {
      const prior = this.ctx.storage.sql.exec<{ message_id: string; payload_digest: string; frame_json: string; projected: number }>("SELECT message_id,payload_digest,frame_json,projected FROM inbound_frames WHERE sequence=?", Number(sequence)).toArray()[0];
      if (prior?.message_id === body.messageId && prior.payload_digest === body.payloadDigest) {
        if (body.type === "transport.replay_required") {
          const intent = this.ctx.storage.sql.exec<StoredControlReplayIntent>("SELECT * FROM control_replay_intents WHERE request_sequence=? AND request_message_id=?", Number(sequence), body.messageId).toArray()[0];
          if (intent !== undefined) await this.dispatchControlReplayIntent(intent, ws);
        }
        const persisted = parseWireDocumentText(schemaIds.nodeV1, prior.frame_json);
        if ("protocol" in persisted) {
          if (body.type === "device.health") {
            // Node health checkpoints may intentionally replay the last exact
            // frame instead of allocating a fresh transport sequence. Such a
            // replay is already in custody: do not append an inbound row,
            // advance the receive frontier, or emit another ACK. Only refresh
            // the D1 observation after the bounded semantic checkpoint.
            const persistedHealth = persisted as Extract<NodeV1PostAuthFrame, { type: "device.health" }>;
            const priorAck = this.ctx.storage.sql.exec<StoredOutboundFrame>(
              "SELECT * FROM outbound_frames WHERE kind='ack' AND state IN ('queued','sent') AND json_extract(frame_json,'$.payload.direction')='node_to_control' AND json_extract(frame_json,'$.payload.throughSequence')=? ORDER BY sequence DESC LIMIT 1",
              body.sequence,
            ).toArray()[0];
            if (priorAck !== undefined) this.resendStoredAckWithoutMutation(priorAck, ws);
            if (prior.projected === 0 || prior.projected === 3) {
              this.notePending(Date.now());
              await this.projectAndSync(persistedHealth);
            } else if (idleHealthProject ?? this.shouldProjectHealth(persistedHealth)) {
              await this.projectExactHealthCheckpoint(persistedHealth);
              this.setHealthMarker(this.healthSemantic(persistedHealth), this.healthClockNow());
            }
          } else if (prior.projected === 0 || prior.projected === 3) {
            this.notePending(Date.now());
            this.ctx.waitUntil(this.projectAndSync(persisted));
          }
        }
        if (body.type !== "transport.ack" && body.type !== "device.health") {
          this.noteAckPending(Number(sequence), ACK_IMMEDIATE_TYPES.has(body.type as NodeV1PostAuthFrame["type"]));
          await this.flushPendingAck(ws, ACK_IMMEDIATE_TYPES.has(body.type as NodeV1PostAuthFrame["type"]));
        }
        await this.syncWorkMarker();
        return;
      }
      if (sequence <= BigInt(this.compactedThrough("node_to_control"))) {
        await this.enqueueControlFrame("transport.error", {
          code: "reconciliation_required",
          retryable: true,
          retryAfterMs: 1_000,
          details: { direction: "node_to_control", sequence: body.sequence, reason: "duplicate_retention_expired" },
        }, undefined, new Date(Date.now() + 300_000).toISOString(), ws, `cmsg_reconciliation_required_${body.sequence}`);
        await this.syncWorkMarker();
        return;
      }
      ws.close(1008, "sequence_conflict"); return;
    }
    if (sequence !== BigInt(position) + 1n) {
      await this.enqueueControlFrame("transport.replay_required", { direction: "node_to_control", expectedSequence: String(position + 1), receivedSequence: String(sequence) }, undefined, new Date(Date.now() + 300_000).toISOString(), ws);
      await this.syncWorkMarker();
      return;
    }
    const frame = body as unknown as NodeV1PostAuthFrame;
    const replay = frame.type === "transport.replay_required" ? await this.validateControlReplayRequest(ws, frame) : undefined;
    if (frame.type === "transport.replay_required" && replay === null) return;
    const payloadAppliedThrough = frame.type === "device.health" ? frame.payload.controlAppliedThrough : undefined;
    if (frame.controlAppliedThrough !== undefined && payloadAppliedThrough !== undefined && frame.controlAppliedThrough !== payloadAppliedThrough) {
      ws.close(1008, "reconciliation_position_invalid"); return;
    }
    const controlAppliedThrough = frame.controlAppliedThrough ?? payloadAppliedThrough;
    if (controlAppliedThrough !== undefined) {
      const applied = BigInt(controlAppliedThrough);
      const controlStored = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='control_to_node'").one().durable_sequence;
      if (applied > BigInt(controlStored) || applied > BigInt(Number.MAX_SAFE_INTEGER)) { ws.close(1008, "reconciliation_position_invalid"); return; }
    }
    const healthProject = frame.type === "device.health" ? this.shouldProjectHealth(frame) : true;
    const inlineProjection = frame.type === "operation.approval_request" || frame.type === "operation.terminal" || frame.type === "device.health";
    this.ctx.storage.transactionSync(() => {
      const projected = frame.type === "transport.ack" || (frame.type === "device.health" && !healthProject) ? 1 : 0;
      this.ctx.storage.sql.exec("INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,projected,kind,created_at) VALUES (?,?,?,?,?,?,?,?)", Number(sequence), frame.messageId, frame.correlationId ?? null, frame.payloadDigest, JSON.stringify(frame), projected, frame.type === "transport.ack" ? "ack" : "app", nowIso());
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction='node_to_control'", Number(sequence));
      if (projected === 0) this.notePending(Date.now());
      if (frame.type !== "transport.ack" && frame.type !== "device.health") this.noteAckPending(Number(sequence), ACK_IMMEDIATE_TYPES.has(frame.type));
      if (replay !== undefined && replay !== null) this.ctx.storage.sql.exec("INSERT INTO control_replay_intents(request_sequence,request_message_id,from_sequence,through_sequence,next_attempt_at,created_at) VALUES (?,?,?,?,?,?)", replay.intent.request_sequence, replay.intent.request_message_id, replay.intent.from_sequence, replay.intent.through_sequence, replay.intent.next_attempt_at, nowIso());
      if (frame.type === "operation.terminal" && typeof frame.payload.operationId === "string" && typeof frame.payload.requestDigest === "string") this.ctx.storage.sql.exec("INSERT OR REPLACE INTO terminal_receipt_cache(operation_id,request_digest,receipt_json,created_at) VALUES (?,?,?,?)", frame.payload.operationId, frame.payload.requestDigest, JSON.stringify(frame.payload), nowIso());
      if (frame.type === "device.health" && healthProject) this.ctx.storage.sql.exec("UPDATE room_work_marker SET health_semantic_json=?,updated_at=? WHERE singleton=1", this.healthSemantic(frame), nowIso());
    });
    if (frame.type === "reconcile.summary") await this.planReconciliation(ws, attachment, frame);
    if (frame.type === "reconcile.complete") await this.completeReconciliation(ws, attachment, frame);
    if (replay !== undefined && replay !== null) await this.dispatchControlReplayIntent(replay.intent, ws, replay.frames);
    if (frame.type === "operation.approval_request") await this.projectAndSync(frame);
    if (frame.type === "operation.terminal") await this.projectAndSync(frame);
    if (frame.type === "device.health" && healthProject) {
      await this.projectAndSync(frame);
      this.setHealthMarker(this.healthSemantic(frame), this.healthClockNow());
    }
    if (controlAppliedThrough !== undefined) {
      try { await this.acknowledgeControlThrough(BigInt(controlAppliedThrough)); }
      catch { ws.close(1008, "reconciliation_position_invalid"); return; }
    }
    if (frame.type === "transport.ack") {
      try { await this.acknowledgeControlThrough(BigInt(frame.payload.throughSequence)); }
      catch { ws.close(1008, "acknowledgement_out_of_range"); return; }
    } else {
      await this.flushPendingAck(ws, frame.type === "device.health" || ACK_IMMEDIATE_TYPES.has(frame.type));
    }
    // event.batch is deliberately left in the DO inbox for the bounded alarm
    // worker. That path commits the whole batch in one ingestion operation (or
    // emits one Queue envelope in queue mode) after custody is durable.
    if (!inlineProjection && frame.type !== "transport.ack" && frame.type !== "event.batch") {
      this.ctx.waitUntil(this.projectAndSync(frame));
    }
    await this.syncWorkMarker();
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
    if (rows.length !== chunkLength) {
      if (expected <= BigInt(this.compactedThrough("control_to_node"))) {
        await this.enqueueControlFrame("transport.error", {
          code: "reconciliation_required",
          retryable: true,
          retryAfterMs: 1_000,
          details: { direction: "control_to_node", expectedSequence: String(expected), throughSequence: String(through), reason: "replay_retention_expired" },
        }, frame.correlationId, new Date(Date.now() + 300_000).toISOString(), ws, `cmsg_replay_retention_${String(expected)}_${String(through)}`);
        return null;
      }
      ws.close(1011, "replay_range_unavailable"); return null;
    }
    if (chunkThrough < through) {
      const sentinel = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence=?", Number(through)).toArray()[0];
      if (sentinel === undefined) {
        if (through <= BigInt(this.compactedThrough("control_to_node"))) {
          await this.enqueueControlFrame("transport.error", {
            code: "reconciliation_required",
            retryable: true,
            retryAfterMs: 1_000,
            details: { direction: "control_to_node", expectedSequence: String(expected), throughSequence: String(through), reason: "replay_retention_expired" },
          }, frame.correlationId, new Date(Date.now() + 300_000).toISOString(), ws, `cmsg_replay_retention_${String(expected)}_${String(through)}`);
          return null;
        }
        ws.close(1011, "replay_range_unavailable"); return null;
      }
      rows.push(sentinel);
    }
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index]!;
      let persisted: unknown;
      try { persisted = parseWireDocumentText(schemaIds.nodeV1, row.frame_json); } catch { ws.close(1011, "replay_record_invalid"); return null; }
      if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) { ws.close(1011, "replay_record_invalid"); return null; }
      const wire = persisted as Record<string, unknown>;
      const expectedSequence = index < chunkLength ? expected + BigInt(index) : through;
      const expired = Date.parse(row.expires_at) <= Date.now();
      const retainedLatestAck = row.kind === "ack" && this.isLatestUnacknowledgedAck(row.sequence);
      if (!Number.isSafeInteger(row.sequence) || BigInt(row.sequence) !== expectedSequence || !["queued", "sent"].includes(row.state) || wire.protocol !== "conduit.node/1" || wire.direction !== "control_to_node" || wire.sequence !== String(expectedSequence) || wire.messageId !== row.message_id || (wire.correlationId ?? null) !== row.correlation_id || wire.payloadDigest !== row.payload_digest || wire.payload === null || typeof wire.payload !== "object" || Array.isArray(wire.payload) || await sha256Hex(canonicalJson(wire.payload)) !== row.payload_digest || (expired && !retainedLatestAck)) {
        ws.close(1011, "replay_record_invalid"); return null;
      }
    }
    return {
      intent: { request_sequence: Number(frame.sequence), request_message_id: frame.messageId, from_sequence: Number(expected), through_sequence: Number(through), attempt_count: 0, next_attempt_at: nowIso(), lease_token: null, lease_expires_at: null },
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
    const now = Date.now();
    const leaseToken = newId("replay_lease");
    const leaseExpiresAt = new Date(now + 30_000).toISOString();
    let claimed = false;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        "UPDATE control_replay_intents SET attempt_count=attempt_count+1,lease_token=?,lease_expires_at=? WHERE request_sequence=? AND next_attempt_at<=? AND (lease_token IS NULL OR lease_expires_at<=?)",
        leaseToken,
        leaseExpiresAt,
        intent.request_sequence,
        new Date(now).toISOString(),
        new Date(now).toISOString(),
      );
      claimed = this.ctx.storage.sql.exec<{ changes: number }>("SELECT changes() AS changes").one().changes === 1;
    });
    if (!claimed) return;
    const claimedIntent = this.ctx.storage.sql.exec<StoredControlReplayIntent>("SELECT * FROM control_replay_intents WHERE request_sequence=? AND lease_token=?", intent.request_sequence, leaseToken).toArray()[0];
    if (claimedIntent === undefined) return;
    let frames: StoredOutboundFrame[];
    try { frames = validatedFrames ?? this.controlReplayFrames(claimedIntent); } catch {
      this.ctx.storage.sql.exec("DELETE FROM control_replay_intents WHERE request_sequence=? AND lease_token=?", intent.request_sequence, leaseToken);
      await this.syncWorkMarker();
      return;
    }
    let allDelivered = true;
    for (const frame of frames) allDelivered = (await this.sendStoredFrame(frame, socket)) && allDelivered;
    const attempts = claimedIntent.attempt_count;
    // A successful replay does not need a tight alarm loop: the node's
    // cumulative ACK/reconciliation frontier is the durable confirmation.
    // Keep a slower recovery retry for a disconnect between send and ACK, and
    // use the normal exponential backoff when any frame could not be sent.
    const delay = allDelivered ? 60_000 : Math.min(60_000, 2 ** Math.min(attempts, 6) * 1_000);
    const next = new Date(Date.now() + delay).toISOString();
    this.ctx.storage.sql.exec("UPDATE control_replay_intents SET next_attempt_at=?,lease_token=NULL,lease_expires_at=NULL WHERE request_sequence=? AND lease_token=?", next, intent.request_sequence, leaseToken);
    this.notePending(Date.parse(next));
    await this.scheduleOutboxAlarm(Date.parse(next));
  }

  private async planReconciliation(ws: WebSocket, attachment: SocketAttachment, frame: Extract<NodeV1PostAuthFrame, { type: "reconcile.summary" }>): Promise<void> {
    if (attachment.reconciliationId === undefined) { ws.close(1011, "reconciliation_state_missing"); return; }
    const summary = frame.payload;
    const controlStored = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='control_to_node'").one().durable_sequence;
    const applied = BigInt(summary.lastControlSequenceApplied);
    const nodeStored = this.ctx.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='node_to_control'").one().durable_sequence;
    const observedNodeAck = BigInt(summary.lastNodeSequenceAcknowledged);
    if (applied > BigInt(controlStored) || observedNodeAck > BigInt(nodeStored) || applied > BigInt(Number.MAX_SAFE_INTEGER) || observedNodeAck > BigInt(Number.MAX_SAFE_INTEGER)) { ws.close(1008, "reconciliation_position_invalid"); return; }
    await this.acknowledgeControlThrough(applied);
    if (observedNodeAck > 0n) this.ctx.storage.sql.exec("UPDATE transport_positions SET acknowledged_sequence=MAX(acknowledged_sequence,?) WHERE direction='node_to_control'", Number(observedNodeAck));
    const controlReplay = applied < BigInt(controlStored) ? [{ from: String(applied + 1n), through: String(controlStored) }] : [];
    // Resolve the bounded summary sets with the two json_each joins. This is
    // the same maximum-size path used by reconciliation-set tests and avoids
    // one D1 round trip per run/range during a reconnect storm.
    const setPlan = await planReconciliationSets(this.env, {
      retainedEventRanges: summary.retainedEventRanges.slice(0, 512),
      runs: summary.runs.slice(0, 256),
    });
    const payload = { reconciliationId: attachment.reconciliationId, controlReplay, nodeReplay: [], eventReplay: setPlan.eventReplay, statusRunIds: setPlan.statusRunIds, cancelOperationIds: setPlan.cancelOperationIds, quarantineRunIds: setPlan.quarantineRunIds };
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
    const lastControlApplied = BigInt(frame.payload.lastControlSequenceApplied);
    const lastNodeAcknowledged = BigInt(frame.payload.lastNodeSequenceAcknowledged);
    if (lastControlApplied < BigInt(plan.planSequence) || lastControlApplied > BigInt(controlStored) || lastNodeAcknowledged > BigInt(nodeStored) || lastControlApplied > BigInt(Number.MAX_SAFE_INTEGER) || lastNodeAcknowledged > BigInt(Number.MAX_SAFE_INTEGER) || frame.payload.unresolvedRunIds.length > 0) {
      this.ctx.storage.sql.exec("UPDATE reconciliation_sessions SET state='review_required' WHERE id=?", attachment.reconciliationId);
      await this.enqueueControlFrame("transport.error", { code: "reconciliation_incomplete", retryable: true }, attachment.reconciliationId, new Date(Date.now() + 300_000).toISOString(), ws);
      return;
    }
    await this.acknowledgeControlThrough(lastControlApplied);
    if (lastNodeAcknowledged > 0n) this.ctx.storage.sql.exec("UPDATE transport_positions SET acknowledged_sequence=MAX(acknowledged_sequence,?) WHERE direction='node_to_control'", Number(lastNodeAcknowledged));
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE reconciliation_sessions SET state='complete',completed_at=? WHERE id=?", nowIso(), attachment.reconciliationId);
      this.ctx.storage.sql.exec("UPDATE connection_state SET reconciliation_state='complete',updated_at=? WHERE singleton=1", nowIso());
    });
    attachment.reconciling = false;
    ws.serializeAttachment(attachment);
  }

  private async project(frame: ProjectableDeviceFrame): Promise<void> {
    if (isPrivilegeFrameType(frame.type)) {
      let result: Record<string, unknown>;
      try { result = await projectPrivilegeFrame(this.env, frame as PrivilegeTransportFrame); }
      catch (error) {
        if (!(error instanceof PublicError) && !(error instanceof TypeError)) throw error;
        result = privilegeDenialResult((frame as PrivilegeTransportFrame).payload.requestId, error);
      }
      if (frame.type === "privilege.ticket_request") {
        const requestId = typeof frame.payload.requestId === "string" ? frame.payload.requestId : frame.messageId;
        await this.enqueueControlFrame(privilegeResultType(), result, requestId, new Date(Date.now() + 300_000).toISOString(), undefined, `cmsg_${requestId}`, frame.deviceId);
      }
      return;
    }
    if (frame.type === "operation.admission" || frame.type === "operation.status" || frame.type === "runtime.control_result" || frame.type === "device.health") {
      const events = await projectNodeState(this.env, frame);
      for (const event of events) await this.publishProjection(frame.deviceId, event);
    }
    if (frame.type === "transport.error") await this.projectControlTransportError(frame);
    if (frame.type === "operation.approval_request") {
      const request = frame.payload;
      const issuedAt = Date.parse(request.issuedAt);
      const expiresAt = Date.parse(request.expiresAt);
      if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt >= expiresAt || expiresAt <= Date.now() || expiresAt - issuedAt > request.validForMs || !/^[1-9][0-9]*$/.test(request.controllerEpoch) || request.localPolicyRevision < 1) throw new TypeError("approval request validity is invalid");
      const operation = await this.env.DB.prepare("SELECT id,payload_digest,actor_principal_id,client_id,device_id,run_id,request_json FROM operation_journal WHERE id=?1 LIMIT 1")
        .bind(request.operationId)
        .first<{ id: string; payload_digest: string; actor_principal_id: string; client_id: string; device_id: string; run_id: string | null; request_json: string }>();
      if (operation === null || operation.device_id !== frame.deviceId || operation.device_id !== request.deviceId || operation.run_id !== request.runId || operation.actor_principal_id !== request.requesterPrincipalId || operation.client_id !== request.clientId) throw new TypeError("approval request target does not match operation custody");
      const operationRequest = JSON.parse(operation.request_json) as { accessScope?: unknown; approvalMode?: unknown; requiredApprovalRiskClasses?: unknown; arguments?: { adapterId?: unknown } };
      const immutableRiskClasses = Array.isArray(operationRequest.requiredApprovalRiskClasses)
        ? operationRequest.requiredApprovalRiskClasses.filter((value): value is string => typeof value === "string")
        : [];
      const effectiveRiskClasses = request.effectiveRequiredApprovalRiskClasses;
      if (
        operationRequest.accessScope !== request.accessScope
        || operationRequest.approvalMode !== request.approvalMode
        || operationRequest.arguments?.adapterId !== request.adapterId
        || immutableRiskClasses.length !== (operationRequest.requiredApprovalRiskClasses as unknown[])?.length
        || immutableRiskClasses.some((riskClass) => !effectiveRiskClasses.includes(riskClass as (typeof effectiveRiskClasses)[number]))
        || (request.approvalMode === "never" && effectiveRiskClasses.length === 0)
      ) throw new TypeError("approval request authority differs from immutable operation");
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
        effectiveRequiredApprovalRiskClasses: request.effectiveRequiredApprovalRiskClasses,
        controllerEpoch: request.controllerEpoch,
        localPolicyRevision: request.localPolicyRevision,
      }));
      if (expected !== request.operationDigest) throw new TypeError("approval request commitment mismatch");
      const normalized = canonicalJson({ providerRequestId: request.providerRequestId, method: request.method, parametersDigest: request.parametersDigest, argumentsSummary: request.argumentsSummary, adapterId: request.adapterId, accessScope: request.accessScope, approvalMode: request.approvalMode, effectiveRequiredApprovalRiskClasses: request.effectiveRequiredApprovalRiskClasses });
      const revisions = canonicalJson({ controllerEpoch: request.controllerEpoch, localPolicyRevision: request.localPolicyRevision });
      await this.env.DB.prepare("INSERT OR IGNORE INTO approvals(id,operation_id,requester_principal_id,client_id,device_id,run_id,commitment_digest,operation_type,normalized_arguments_json,revisions_json,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)")
        .bind(request.approvalId, request.operationId, request.requesterPrincipalId, request.clientId, request.deviceId, request.runId, request.operationDigest, request.method, normalized, revisions, request.expiresAt, request.issuedAt).run();
      const stored = await this.env.DB.prepare("SELECT commitment_digest,normalized_arguments_json,revisions_json FROM approvals WHERE id=?1 LIMIT 1").bind(request.approvalId).first<{ commitment_digest: string; normalized_arguments_json: string; revisions_json: string }>();
      if (stored === null || stored.commitment_digest !== request.operationDigest || stored.normalized_arguments_json !== normalized || stored.revisions_json !== revisions) throw new TypeError("approval id is bound to a different commitment");
    }
    if (frame.type === "operation.terminal") {
      const operation = await this.env.DB.prepare("SELECT payload_digest,connector_grant_id,concurrency_class,state,result_json,device_id,run_id,assignment_id,session_id,operation_kind FROM operation_journal WHERE id=?1 LIMIT 1").bind(frame.payload.operationId).first<{ payload_digest: string; connector_grant_id: string | null; concurrency_class: "commands" | "agentRuns" | "runtimeStarts" | null; state: string; result_json: string | null; device_id: string; run_id: string | null; assignment_id: string | null; session_id: string | null; operation_kind: string }>();
      if (operation === null) {
        await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'device_terminal.unknown_operation',?2,?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, receiptDigest: frame.payload.receiptDigest }), nowIso()).run();
      } else if (operation.device_id !== frame.deviceId || frame.correlationId !== frame.payload.operationId || operation.payload_digest !== frame.payload.requestDigest) {
        const mismatchAt = nowIso();
        const statements: D1PreparedStatement[] = [
          this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_terminal.custody_mismatch',?2,'terminal_custody_mismatch',?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, expectedDeviceId: operation.device_id, correlationId: frame.correlationId ?? null, expectedDigest: operation.payload_digest, receivedDigest: frame.payload.requestDigest }), mismatchAt),
        ];
        if (operation.device_id === frame.deviceId && frame.correlationId === frame.payload.operationId && operation.payload_digest !== frame.payload.requestDigest) {
          const result = JSON.stringify({ denialCode: "request_digest_mismatch", terminal: frame.payload });
          statements.push(
            this.env.DB.prepare("UPDATE operation_journal SET state='uncertain',result_json=?1,updated_at=?2 WHERE id=?3 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(result, mismatchAt, frame.payload.operationId),
            this.env.DB.prepare("UPDATE idempotency_records SET state='uncertain',response_json=?1 WHERE operation_id=?2").bind(result, frame.payload.operationId),
          );
        }
        await this.env.DB.batch(statements);
      } else if (["completed", "failed", "cancelled", "expired", "rejected", "uncertain"].includes(operation.state) && operation.result_json !== JSON.stringify(frame.payload)) {
        await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_terminal.conflicting_terminal',?2,'terminal_already_committed',?3,?4)")
          .bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, committedState: operation.state, receivedState: frame.payload.state, receiptDigest: frame.payload.receiptDigest }), nowIso()).run();
      } else {
        const terminalPayload = frame.payload as unknown as Record<string, unknown>;
        await requireVerifiedPrivilegeReceipt(this.env, { operationId: frame.payload.operationId, deviceId: frame.deviceId, runId: operation.run_id, requestDigest: operation.payload_digest, receiptDigest: terminalPayload.privilegeReceiptDigest, transition: "terminal", runtimeId: terminalPayload.targetRuntimeId, controllerEpoch: terminalPayload.controllerEpoch });
        const projectedState = frame.payload.state === "completed" ? "completed" : frame.payload.state === "cancelled" ? "cancelled" : frame.payload.state === "rejected" || frame.payload.state === "expired" ? frame.payload.state : frame.payload.state === "uncertain" || frame.payload.state === "lost" || frame.payload.state === "recovery_required" ? "uncertain" : "failed";
        let runProjectionState = projectedState;
        const terminalAt = nowIso();
        await this.env.DB.batch([
          this.env.DB.prepare("UPDATE operation_journal SET state=?1,result_json=?2,updated_at=?3 WHERE id=?4 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(projectedState, JSON.stringify(frame.payload), terminalAt, frame.payload.operationId),
          this.env.DB.prepare("UPDATE idempotency_records SET state=?1,response_json=?2 WHERE operation_id=?3").bind(projectedState, JSON.stringify({ operationId: frame.payload.operationId, state: projectedState, terminal: frame.payload }), frame.payload.operationId),
        ]);
        if (operation.operation_kind === "start") {
          const agentState = projectedState === "completed" ? "closed" : projectedState === "cancelled" ? "cancelled" : "failed";
          await this.env.DB.batch([
            this.env.DB.prepare("UPDATE agent_sessions SET state=?1,revision=revision+1,lease_expires_at=NULL,last_activity_at=?2,updated_at=?2 WHERE start_operation_id=?3 AND state IN ('starting','running','waiting_input','waiting_approval','closing')").bind(agentState, terminalAt, frame.payload.operationId),
            this.env.DB.prepare("UPDATE runtime_custody SET state=?1,revision=revision+1,updated_at=?2 WHERE start_operation_id=?3 AND state NOT IN ('stopped','destroyed','failed','lost','uncertain','recovery_required')").bind(projectedState === "completed" || projectedState === "cancelled" ? "stopped" : "failed", terminalAt, frame.payload.operationId),
          ]);
        }
        const summary = frame.payload.resultSummary as Record<string, unknown> | undefined;
        const submission = summary?.submission;
        if (operation.operation_kind === "start" && operation.run_id !== null && frame.payload.state === "completed" && submission !== undefined) {
          try {
            const projectedSubmission = await projectDeviceTerminalSubmission(this.env, { operationId: frame.payload.operationId, runId: operation.run_id, deviceId: frame.deviceId, submission });
            if (typeof projectedSubmission.runState === "string") runProjectionState = projectedSubmission.runState;
          } catch (error) {
            if (!(error instanceof PublicError)) throw error;
            const committed = await this.env.DB.prepare("SELECT run.state AS run_state FROM change_sets AS change_set JOIN runs AS run ON run.id=change_set.run_id WHERE change_set.run_id=?1 LIMIT 1").bind(operation.run_id).first<{ run_state: string }>();
            if (committed === null) {
              runProjectionState = "failed";
              const reason = error.message.slice(0, 192);
              await this.env.DB.batch([
                this.env.DB.prepare("UPDATE runs SET state='failed',revision=revision+1,updated_at=?1 WHERE id=?2 AND state NOT IN ('ready_for_review','accepted','completed','cancelled','failed')").bind(terminalAt, operation.run_id),
                this.env.DB.prepare("UPDATE assignments SET state='failed',revision=revision+1,updated_at=?1 WHERE id=?2 AND state IN ('queued','active','waiting_input','waiting_approval')").bind(terminalAt, operation.assignment_id),
                this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_terminal.submission_rejected',?2,'submission_invalid',?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, runId: operation.run_id, terminalState: frame.payload.state, reason }), terminalAt),
              ]);
            } else runProjectionState = committed.run_state;
          }
        } else if (operation.operation_kind === "start" && operation.run_id !== null) {
          const terminalRunState = projectedState === "completed" ? "completed" : projectedState === "cancelled" ? "cancelled" : "failed";
          const assignmentState = terminalRunState === "cancelled" ? "cancelled" : "failed";
          const statements: D1PreparedStatement[] = [
            this.env.DB.prepare("UPDATE runs SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND state NOT IN ('ready_for_review','accepted','completed','cancelled','failed')").bind(terminalRunState, terminalAt, operation.run_id),
          ];
          if (operation.assignment_id !== null) statements.push(this.env.DB.prepare("UPDATE assignments SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND state IN ('queued','active','waiting_input','waiting_approval')").bind(assignmentState, terminalAt, operation.assignment_id));
          if (submission !== undefined) {
            statements.push(this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_terminal.submission_rejected',?2,'terminal_state_not_completed',?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, runId: operation.run_id, terminalState: frame.payload.state }), terminalAt));
          } else if (frame.payload.state === "completed") {
            statements.push(this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_terminal.submission_missing',?2,'completed_without_submission',?3,?4)").bind(newId("sevt"), frame.deviceId, JSON.stringify({ operationId: frame.payload.operationId, runId: operation.run_id }), terminalAt));
          }
          await this.env.DB.batch(statements);
        }
        if (operation.connector_grant_id !== null && operation.concurrency_class !== null) await ensureOperationConcurrencyReleased(this.env, frame.payload.operationId);
        if (operation.session_id !== null && operation.run_id !== null) {
          const projectedRun = operation.operation_kind === "start"
            ? await this.env.DB.prepare("SELECT state,revision FROM runs WHERE id=?1 LIMIT 1").bind(operation.run_id).first<{ state: string; revision: number }>()
            : null;
          const realtimeType = operation.operation_kind === "start" ? `run.${projectedRun?.state ?? runProjectionState}` : `operation.${projectedState}`;
          await this.publishProjection(frame.deviceId, { sessionId: operation.session_id, eventId: `bevt_${frame.messageId}`, type: realtimeType, recordId: operation.run_id, revision: projectedRun?.revision ?? 1 });
        }
      }
    }
    if (frame.type === "event.batch") {
      const parsed = parseEventBatch(frame, frame.messageId);
      if (parsed === null) throw new TypeError("event batch payload is invalid");
      // The Device inbox row is already durable before this hook runs. The
      // free profile commits the whole bounded node batch from that custody;
      // Queue mode sends exactly one queue envelope for the node batch (with
      // the producer's byte/count safeguards applied by the adapter).
      if (eventIngestionMode(this.env) === "queue") await enqueueEventBatch(this.env, parsed.batch);
      else await commitDurableInboxBatch(this.env, parsed.batch, { messageId: frame.messageId });
    }
  }

  private async projectControlTransportError(frame: Extract<NodeV1PostAuthFrame, { type: "transport.error" }>): Promise<void> {
    const messageType = frame.payload.details?.messageType;
    if (messageType !== "operation.input" && messageType !== "operation.cancel" && messageType !== "runtime.control") return;
    const operationId = frame.correlationId;
    const terminalAt = nowIso();
    if (operationId === undefined) {
      await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_control.transport_error_rejected',?2,'correlation_missing',?3,?4)")
        .bind(newId("sevt"), frame.deviceId, JSON.stringify({ messageId: frame.messageId, messageType, code: frame.payload.code }), terminalAt).run();
      return;
    }
    const operation = await this.env.DB.prepare(`
      SELECT operation.id,operation.device_id,operation.run_id,operation.session_id,operation.operation_kind,
             operation.state,operation.connector_grant_id,operation.concurrency_class,outbox.frame_type
      FROM operation_journal AS operation
      LEFT JOIN operation_dispatch_outbox AS outbox ON outbox.operation_id=operation.id
      WHERE operation.id=?1 LIMIT 1
    `).bind(operationId).first<{
      id: string;
      device_id: string;
      run_id: string | null;
      session_id: string | null;
      operation_kind: string;
      state: string;
      connector_grant_id: string | null;
      concurrency_class: "commands" | "agentRuns" | "runtimeStarts" | null;
      frame_type: string | null;
    }>();
    const expectedKind = messageType === "runtime.control" ? "runtime_control" : "agent_control";
    if (operation === null || operation.device_id !== frame.deviceId || operation.operation_kind !== expectedKind || operation.frame_type !== messageType) {
      await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_control.transport_error_rejected',?2,'control_custody_mismatch',?3,?4)")
        .bind(newId("sevt"), frame.deviceId, JSON.stringify({ messageId: frame.messageId, operationId, messageType, code: frame.payload.code }), terminalAt).run();
      return;
    }
    if (["completed", "failed", "cancelled", "expired", "rejected", "uncertain"].includes(operation.state)) {
      const evidence = await this.env.DB.prepare("SELECT id FROM security_events WHERE event_type='device_control.transport_error' AND device_id=?1 AND json_extract(metadata_json,'$.messageId')=?2 AND json_extract(metadata_json,'$.operationId')=?3 LIMIT 1")
        .bind(frame.deviceId, frame.messageId, operationId).first<{ id: string }>();
      if (evidence !== null) {
        if (operation.connector_grant_id !== null && operation.concurrency_class !== null) await ensureOperationConcurrencyReleased(this.env, operationId);
        if (operation.session_id !== null && operation.run_id !== null && (operation.state === "failed" || operation.state === "uncertain")) {
          await this.publishProjection(frame.deviceId, { sessionId: operation.session_id, eventId: `bevt_${frame.messageId}`, type: `operation.${operation.state}`, recordId: operation.run_id, revision: 1 });
        }
      }
      return;
    }
    const state = frame.payload.retryable ? "uncertain" : "failed";
    const result = canonicalJson({ operationId, state, denialCode: "node_transport_error", transportError: frame.payload });
    const updates = await this.env.DB.batch([
      this.env.DB.prepare("UPDATE operation_journal SET state=?1,result_json=?2,updated_at=?3 WHERE id=?4 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(state, result, terminalAt, operationId),
      this.env.DB.prepare("UPDATE idempotency_records SET state=?1,response_json=?2 WHERE operation_id=?3").bind(state, result, operationId),
      this.env.DB.prepare("UPDATE operation_dispatch_outbox SET result_json=?1,last_error_code=?2,updated_at=?3 WHERE operation_id=?4").bind(result, frame.payload.code, terminalAt, operationId),
      this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at) VALUES (?1,'device_control.transport_error',?2,?3,?4,?5)").bind(newId("sevt"), frame.deviceId, frame.payload.code, JSON.stringify({ messageId: frame.messageId, operationId, messageType, retryable: frame.payload.retryable }), terminalAt),
    ]);
    if (updates[0]?.meta.changes !== 1) return;
    if (operation.connector_grant_id !== null && operation.concurrency_class !== null) await ensureOperationConcurrencyReleased(this.env, operationId);
    if (operation.session_id !== null && operation.run_id !== null) {
      await this.publishProjection(frame.deviceId, { sessionId: operation.session_id, eventId: `bevt_${frame.messageId}`, type: `operation.${state}`, recordId: operation.run_id, revision: 1 });
    }
  }

  private async publishProjection(deviceId: string, event: NodeProjectionEvent): Promise<void> {
    // Set the local wake-up marker before crossing the D1 boundary. If the
    // isolate is evicted after D1 custody but before the publisher returns,
    // the next alarm still knows that reconciliation is required.
    this.noteRealtimePending(deviceId, Date.now());
    const result = await queueRealtimeProjection(this.env, deviceId, event);
    this.setRealtimeResult(deviceId, result.state === "pending" ? result.nextAttemptAt ?? null : null);
    await this.syncWorkMarker();
  }

  private async projectApprovalOrDeadletter(frame: Extract<NodeV1PostAuthFrame, { type: "operation.approval_request" }>): Promise<void> {
    try {
      await this.project(frame);
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      const reason = error instanceof Error ? error.message.slice(0, 192) : "approval_projection_failed";
      await this.env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'agent_approval.invalid_request',?2,?3,?4)")
        .bind(newId("sevt"), frame.deviceId, JSON.stringify({ approvalId: frame.payload.approvalId, operationId: frame.payload.operationId, reason }), nowIso()).run();
      this.ctx.storage.sql.exec("UPDATE inbound_frames SET projected=2,projection_claimed_at=NULL WHERE sequence=?", Number(frame.sequence));
    }
  }

  private async enqueueControlFrame(type: NodeV1PostAuthFrame["type"] | string, payload: Record<string, unknown>, correlationId: string | undefined, expiresAt: string, preferredSocket?: WebSocket, suppliedMessageId?: string, targetDeviceId?: string): Promise<{ sequence: string; delivered: boolean }> {
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
    const tombstone = suppliedMessageId === undefined ? undefined : this.ctx.storage.sql.exec<OutboundMessageTombstone>("SELECT * FROM outbound_message_tombstones WHERE message_id=?", suppliedMessageId).toArray()[0];
    if (tombstone !== undefined) {
      if (tombstone.payload_digest !== payloadDigest || tombstone.correlation_id !== (correlationId ?? null)) throw new TypeError("control message id is bound to another payload");
      // A compacted, already-custodied message is an idempotent success. The
      // tombstone remains the exact digest/correlation proof and prevents a
      // later retry from creating a second effect.
      return { sequence: String(tombstone.sequence), delivered: true };
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
    const wire = { protocol: "conduit.node/1", messageId, deviceId: state?.device_id ?? payloadDeviceId ?? targetDeviceId ?? "unconnected", connectionEpoch: String(state?.epoch ?? 0), direction: "control_to_node", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest, payload };
    if (type === privilegeResultType()) {
      if (payload.status !== "issued" && payload.status !== "denied") throw new TypeError("privilege ticket result is invalid");
      if (typeof payload.requestId !== "string" || payload.requestId !== correlationId) throw new TypeError("privilege ticket result correlation is invalid");
    } else if (type === privilegeRegistrationResultType()) {
      if (payload.status !== "active" || typeof payload.installationId !== "string" || payload.installationId !== correlationId || !Array.isArray(payload.issuerKeys) || payload.issuerKeys.length > 4) throw new TypeError("privilege registration result is invalid");
    }
    parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(wire));
    const createdAt = nowIso();
    const kind = type === "transport.ack" ? "ack" : "control";
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("INSERT INTO outbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,state,kind,expires_at,created_at,dispatch_attempts,next_attempt_at) VALUES (?,?,?,?,?,'queued',?,?,?,0,?)", sequence, messageId, correlationId ?? null, payloadDigest, JSON.stringify(wire), kind, expiresAt, createdAt, createdAt);
      this.ctx.storage.sql.exec("INSERT INTO outbound_message_receipts(message_id,correlation_id,payload_digest,sequence,state,kind,expires_at,created_at,updated_at) VALUES (?,?,?,?,'queued',?,?,?,?)", messageId, correlationId ?? null, payloadDigest, sequence, kind, expiresAt, createdAt, createdAt);
      this.ctx.storage.sql.exec("UPDATE transport_positions SET durable_sequence=? WHERE direction='control_to_node'", sequence);
      this.notePending(Date.now());
    });
    const stored = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE sequence=?", sequence).one();
    return { sequence: String(sequence), delivered: await this.sendStoredFrame(stored, preferredSocket) };
  }

  private eligibleSocket(frame: StoredOutboundFrame): WebSocket | undefined {
    const connection = this.ctx.storage.sql.exec<{ epoch: number; reconciliation_state: string }>("SELECT epoch,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0];
    const wire = JSON.parse(frame.frame_json) as { type?: unknown };
    return this.ctx.getWebSockets().find((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      const ready = !EFFECTFUL_CONTROL_TYPES.has(String(wire.type)) || connection?.reconciliation_state === "complete" && !item?.reconciling;
      return item?.stage === "authenticated" && item.epoch === String(connection?.epoch) && ready;
    });
  }

  private async scheduleOutboxAlarm(at: number): Promise<void> {
    if (!Number.isFinite(at)) return;
    if (this.alarmActive) return;
    const marker = this.workMarker();
    // An alarm is a wake-up for durable work, never a keepalive.  Callers may
    // race with marker reconciliation, so re-check the marker immediately
    // before reserving the alarm.
    if (marker.pending === 0) return;
    const dueAt = marker.min_due_at === null ? at : Math.min(marker.min_due_at, at);
    const scheduled = await this.ctx.storage.getAlarm();
    if (scheduled === null || dueAt < scheduled) await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, dueAt));
  }

  /**
   * Replay an already-custodied ACK without touching its durable state. This
   * is used only by an exact health replay: the original ACK envelope remains
   * the proof of custody, while a reconnect may need the bytes sent again if
   * the peer disconnected before observing them. The normal outbox path still
   * records state transitions and retries every effectful/control message.
   */
  private resendStoredAckWithoutMutation(frame: StoredOutboundFrame, preferredSocket?: WebSocket): boolean {
    // The latest unacknowledged cumulative ACK is intentionally retained as a
    // bounded replay proof even after its nominal hot expiry. Older/superseded
    // ACKs are removed by compactOutboundReceipts before this path can use
    // them, so expiry must not make the retained latest ACK unreplayable.
    if (frame.kind !== "ack" || !["queued", "sent"].includes(frame.state)) return false;
    const socket = preferredSocket ?? this.eligibleSocket(frame);
    if (socket === undefined) return false;
    const connection = this.ctx.storage.sql.exec<{ device_id: string; epoch: number }>("SELECT device_id,epoch FROM connection_state WHERE singleton=1").toArray()[0];
    const persisted: unknown = JSON.parse(frame.frame_json);
    if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) return false;
    const wire = { ...(persisted as Record<string, unknown>), ...(connection === undefined ? {} : { deviceId: connection.device_id, connectionEpoch: String(connection.epoch) }) } as Record<string, unknown>;
    try {
      parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(wire));
      socket.send(JSON.stringify(wire));
      return true;
    } catch {
      return false;
    }
  }

  private async sendStoredFrame(frame: StoredOutboundFrame, preferredSocket?: WebSocket): Promise<boolean> {
    if (Date.parse(frame.expires_at) <= Date.now() && !this.isLatestUnacknowledgedAck(frame.sequence)) {
      this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE sequence=? AND state='queued'", frame.sequence);
      await this.syncWorkMarker();
      return false;
    }
    const socket = preferredSocket ?? this.eligibleSocket(frame);
    if (socket === undefined) {
      const next = new Date(Date.now() + 30_000).toISOString();
      this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='queued',next_attempt_at=? WHERE sequence=?", next, frame.sequence);
      this.notePending(Date.parse(next));
      await this.scheduleOutboxAlarm(Date.parse(next));
      return false;
    }
    const connection = this.ctx.storage.sql.exec<{ device_id: string; epoch: number }>("SELECT device_id,epoch FROM connection_state WHERE singleton=1").toArray()[0];
    const persisted: unknown = JSON.parse(frame.frame_json);
    if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) throw new TypeError("persisted control frame is invalid");
    const wire = { ...(persisted as Record<string, unknown>), ...(connection === undefined ? {} : { deviceId: connection.device_id, connectionEpoch: String(connection.epoch) }) } as Record<string, unknown>;
    parseWireDocumentText(schemaIds.nodeV1, JSON.stringify(wire));
    try {
      socket.send(JSON.stringify(wire));
      const ackPayload = wire.type === "transport.ack" && wire.payload !== null && typeof wire.payload === "object" && !Array.isArray(wire.payload)
        ? wire.payload as Record<string, unknown>
        : null;
      const ackThrough = ackPayload !== null && ackPayload.direction === "node_to_control" && typeof ackPayload.throughSequence === "string" && /^\d+$/.test(ackPayload.throughSequence)
        ? Number(ackPayload.throughSequence)
        : null;
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='sent',frame_json=?,dispatch_attempts=dispatch_attempts+1 WHERE sequence=?", JSON.stringify(wire), frame.sequence);
        this.ctx.storage.sql.exec("UPDATE outbound_message_receipts SET state='sent',updated_at=? WHERE message_id=?", nowIso(), frame.message_id);
        if (ackThrough !== null && Number.isSafeInteger(ackThrough)) {
          this.ctx.storage.sql.exec(
            "UPDATE room_work_marker SET ack_sent_through=MAX(ack_sent_through,?),ack_pending_through=CASE WHEN ack_pending_through<=? THEN 0 ELSE ack_pending_through END,ack_pending_at=CASE WHEN ack_pending_through<=? THEN NULL ELSE ack_pending_at END,ack_message_id=CASE WHEN ack_pending_through<=? THEN NULL ELSE ack_message_id END,updated_at=? WHERE singleton=1",
            ackThrough,
            ackThrough,
            ackThrough,
            ackThrough,
            nowIso(),
          );
        }
      });
      await this.syncWorkMarker();
      return true;
    } catch {
      const attempts = frame.dispatch_attempts + 1;
      const delay = Math.min(60_000, 2 ** Math.min(attempts, 6) * 1_000);
      const next = new Date(Date.now() + delay).toISOString();
      this.ctx.storage.sql.exec("UPDATE outbound_frames SET state='queued',dispatch_attempts=?,next_attempt_at=? WHERE sequence=?", attempts, next, frame.sequence);
      this.notePending(Date.parse(next));
      await this.scheduleOutboxAlarm(Date.parse(next));
      return false;
    }
  }

  private async dispatchQueuedFrames(): Promise<void> {
    const now = nowIso();
    this.ctx.storage.sql.exec("DELETE FROM outbound_frames WHERE state='queued' AND expires_at<=? AND NOT (kind='ack' AND sequence=(SELECT MAX(sequence) FROM outbound_message_receipts WHERE kind='ack' AND state IN ('queued','sent')))", now);
    const rows = this.ctx.storage.sql.exec<StoredOutboundFrame>("SELECT * FROM outbound_frames WHERE state='queued' AND next_attempt_at<=? ORDER BY sequence LIMIT 32", now).toArray();
    for (const row of rows) await this.sendStoredFrame(row);
    // A current authenticated socket owns explicit replay requests.  Letting
    // the alarm claim the same intent while that request is being validated
    // can send a replay plan before the websocket path has installed its
    // lease, which is both wasteful and observable as a duplicate replay.
    // Once the socket disconnects, the durable intent remains available for
    // the next alarm retry.
    const hasAuthenticatedSocket = this.hasCurrentAuthenticatedSocket();
    if (!hasAuthenticatedSocket) {
      const replayIntents = this.ctx.storage.sql.exec<StoredControlReplayIntent>("SELECT * FROM control_replay_intents WHERE next_attempt_at<=? ORDER BY next_attempt_at,request_sequence LIMIT 8", now).toArray();
      for (const intent of replayIntents) await this.dispatchControlReplayIntent(intent);
    }
    const next = this.ctx.storage.sql.exec<{ next_attempt_at: string }>(hasAuthenticatedSocket
      ? "SELECT next_attempt_at FROM outbound_frames WHERE state='queued' ORDER BY next_attempt_at LIMIT 1"
      : "SELECT next_attempt_at FROM (SELECT next_attempt_at FROM outbound_frames WHERE state='queued' UNION ALL SELECT next_attempt_at FROM control_replay_intents) ORDER BY next_attempt_at LIMIT 1").toArray()[0];
    if (next !== undefined) {
      this.notePending(Date.parse(next.next_attempt_at));
      await this.scheduleOutboxAlarm(Math.max(Date.now() + 1_000, Date.parse(next.next_attempt_at)));
    }
    await this.syncWorkMarker();
  }

  override async alarm(): Promise<void> {
    if (this.idleProbe !== null) this.idleProbe.alarmInvocations += 1;
    this.alarmActive = true;
    try {
      // Alarm delivery consumes the platform reservation. Recompute from the
      // local marker/table state before doing any work so an idle wake-up is a
      // no-op and does not recreate a periodic alarm loop. Scheduling is
      // deferred until the single final marker sync below.
      await this.syncWorkMarker();
      const marker = this.workMarker();
      if (marker.pending === 0) return;
      const now = Date.now();
      if (marker.ack_pending_through > marker.ack_sent_through && (marker.ack_pending_at === null || marker.ack_pending_at + usageProfileForEnv(this.env).ackCoalesceMs <= now)) {
        await this.flushPendingAck(undefined, false);
      }
      const projectionStaleAt = new Date(now - PROJECTION_LEASE_MS).toISOString();
      const unprojected = this.ctx.storage.sql.exec<{ frame_json: string }>("SELECT frame_json FROM inbound_frames WHERE projected=0 OR (projected=3 AND (projection_claimed_at IS NULL OR projection_claimed_at<=?)) ORDER BY sequence LIMIT ?", projectionStaleAt, MAX_D1_PROJECTIONS_PER_ALARM).toArray();
      const parsedFrames = unprojected.map((row) => {
        const validated = parseWireDocumentText(schemaIds.nodeV1, row.frame_json);
        const raw = validated as unknown as Record<string, unknown>;
        return isPrivilegeFrameType(raw.type) ? parsePrivilegeTransportFrame(validated) : validated as NodeV1PostAuthFrame;
      });
      // Ticket authority and root-receipt verification perform a larger D1
      // join than ordinary event projection. If one is present in the page,
      // reserve the whole outer invocation for the oldest row and re-arm for
      // the remainder. This keeps the measured <=40 statement/binding ceiling
      // without reordering the Device sequence.
      const projectionPage = parsedFrames.some((frame) => isPrivilegeFrameType(frame.type)) ? parsedFrames.slice(0, 1) : parsedFrames;
      for (const frame of projectionPage) {
        await this.projectAndSync(frame);
      }
      const afterProjection = this.workMarker();
      if (afterProjection.realtime_pending !== 0 && afterProjection.realtime_device_id !== null && (afterProjection.realtime_min_due_at === null || afterProjection.realtime_min_due_at <= now)) {
        const realtime = await reconcileRealtimeProjections(this.env, afterProjection.realtime_device_id);
        this.setRealtimeResult(afterProjection.realtime_device_id, realtime.nextAttemptAt);
      }
      const afterRealtime = this.workMarker();
      if (afterRealtime.retention_pending !== 0 && (afterRealtime.retention_due_at === null || afterRealtime.retention_due_at <= now)) await this.runRetentionMaintenance(now);
      await this.dispatchQueuedFrames();
    } finally {
      this.alarmActive = false;
      // Keep the next bounded projection page in a distinct platform
      // invocation so its D1 reservation cannot merge into this alarm turn.
      await this.syncWorkMarker(1_000);
    }
  }

  async offer(frame: DeviceRoomOffer): Promise<{ sequence: string; delivered: boolean }> {
    const computed = await sha256Hex(canonicalJson(frame.payload));
    if (computed !== frame.payloadDigest) throw new TypeError("control payload digest mismatch");
    const frameType = frame.frameType ?? "operation.offer";
    const operation = frame.payload.operation;
    if (frameType === "operation.offer" && (operation === null || typeof operation !== "object" || Array.isArray(operation) || (operation as Record<string, unknown>).deviceId !== frame.deviceId)) throw new TypeError("operation offer device target mismatch");
    if (frameType !== "operation.offer" && frame.payload.operationId !== frame.correlationId) throw new TypeError("existing-target control correlation mismatch");
    const connection = this.ctx.storage.sql.exec<{ epoch: number; reconciliation_state: string }>("SELECT epoch,reconciliation_state FROM connection_state WHERE singleton=1").toArray()[0];
    const persistedDevice = this.ctx.storage.sql.exec<{ device_id: string }>("SELECT device_id FROM connection_state WHERE singleton=1").toArray()[0]?.device_id;
    if (persistedDevice !== undefined && persistedDevice !== frame.deviceId) throw new TypeError("operation offer device target conflicts with room identity");
    const socket = this.ctx.getWebSockets().find((candidate) => {
      const item = candidate.deserializeAttachment() as SocketAttachment | null;
      return item?.stage === "authenticated" && connection?.reconciliation_state === "complete" && !item.reconciling && item.epoch === String(connection?.epoch);
    });
    return this.enqueueControlFrame(frameType, frame.payload, frame.correlationId, frame.expiresAt, socket, frame.messageId, frame.deviceId);
  }

  async deliverApproval(frame: DeviceRoomApproval): Promise<{ sequence: string; delivered: boolean }> {
    const computed = await sha256Hex(canonicalJson(frame.payload));
    if (computed !== frame.payloadDigest) throw new TypeError("approval payload digest mismatch");
    if (frame.payload.approvalId !== frame.correlationId || frame.payload.operationId === undefined) throw new TypeError("approval correlation mismatch");
    const persistedDevice = this.ctx.storage.sql.exec<{ device_id: string }>("SELECT device_id FROM connection_state WHERE singleton=1").toArray()[0]?.device_id;
    if (persistedDevice !== undefined && persistedDevice !== frame.deviceId) throw new TypeError("approval device target conflicts with room identity");
    return this.enqueueControlFrame("operation.approval", frame.payload, frame.correlationId, frame.expiresAt, undefined, frame.messageId);
  }

  async deliverPrivilegeRegistration(payload: Record<string, unknown>): Promise<{ sequence: string; delivered: boolean }> {
    const installationId = typeof payload.installationId === "string" ? payload.installationId : "";
    if (installationId === "") throw new TypeError("privilege registration identity is missing");
    const persistedDevice = this.ctx.storage.sql.exec<{ device_id: string }>("SELECT device_id FROM connection_state WHERE singleton=1").toArray()[0]?.device_id;
    const targetDevice = await this.env.DB.prepare("SELECT device_id FROM device_privilege_installations WHERE installation_id=?1 AND status='active' LIMIT 1").bind(installationId).first<{ device_id: string }>();
    if (targetDevice === null || (persistedDevice !== undefined && persistedDevice !== targetDevice.device_id)) throw new TypeError("privilege registration target conflicts with room identity");
    return this.enqueueControlFrame(privilegeRegistrationResultType(), payload, installationId, new Date(Date.now() + 300_000).toISOString(), undefined, `cmsg_preg_${installationId}`, targetDevice.device_id);
  }

  async revoke(reason: string): Promise<void> {
    this.ctx.storage.sql.exec("UPDATE connection_state SET reconciliation_state='revoked',updated_at=? WHERE singleton=1", nowIso());
    for (const socket of this.ctx.getWebSockets()) socket.close(1008, reason.slice(0, 120));
  }
}
