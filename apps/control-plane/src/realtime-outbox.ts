import { nowIso } from "./crypto.ts";
import type { ControlPlaneEnv } from "./types.ts";

export interface RealtimeProjectionEvent {
  sessionId: string;
  eventId: string;
  type: string;
  recordId: string;
  revision: number;
}

export interface RealtimeProjectionPublisher {
  publish(event: RealtimeProjectionEvent): Promise<number>;
}

interface RealtimeOutboxRow {
  event_id: string;
  device_id: string;
  session_id: string;
  event_type: string;
  record_id: string;
  revision: number;
  event_json: string;
  state: "pending" | "publishing" | "published";
  attempt_count: number;
  next_attempt_at: string;
  lease_token: string | null;
  lease_expires_at: string | null;
}

interface ProjectionReceiptRow {
  message_id: string;
  frame_type: "operation.admission" | "operation.status" | "runtime.control_result";
  result_json: string;
  session_id: string;
  run_id: string;
  operation_result_json: string | null;
}

export interface RealtimeProjectionAttempt {
  eventId: string;
  state: "pending" | "published";
  attemptCount: number;
  nextAttemptAt?: string;
}

export interface RealtimeProjectionReconciliation {
  recovered: number;
  attempted: number;
  published: number;
  pending: number;
  nextAttemptAt: string | null;
}

const LEASE_MS = 30_000;
const DEFAULT_LIMIT = 32;

function retryAt(now: Date, attemptCount: number): string {
  const seconds = Math.min(60, 2 ** Math.min(Math.max(attemptCount, 1), 6));
  return new Date(now.getTime() + seconds * 1_000).toISOString();
}

function eventFromRow(row: RealtimeOutboxRow): RealtimeProjectionEvent {
  return JSON.parse(row.event_json) as RealtimeProjectionEvent;
}

function recoverReceiptEvent(row: ProjectionReceiptRow): RealtimeProjectionEvent | null {
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(row.result_json) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (row.frame_type === "operation.admission") {
    if (typeof receipt.state !== "string") return null;
    return { sessionId: row.session_id, eventId: `bevt_${row.message_id}`, type: `operation.${receipt.state}`, recordId: row.run_id, revision: 1 };
  }
  const revision = typeof receipt.revision === "number" && Number.isSafeInteger(receipt.revision) && receipt.revision >= 1 ? receipt.revision : null;
  if (revision === null || typeof receipt.state !== "string") return null;
  if (row.frame_type === "operation.status") {
    return { sessionId: row.session_id, eventId: `bevt_${row.message_id}`, type: `run.${receipt.state}`, recordId: row.run_id, revision };
  }
  let operationResult: Record<string, unknown>;
  try {
    operationResult = row.operation_result_json === null ? {} : JSON.parse(row.operation_result_json) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (typeof operationResult.control !== "string") return null;
  return { sessionId: row.session_id, eventId: `bevt_${row.message_id}`, type: `runtime.${operationResult.control}.${receipt.state}`, recordId: row.run_id, revision };
}

async function rowFor(env: ControlPlaneEnv, eventId: string): Promise<RealtimeOutboxRow | null> {
  return env.DB.prepare("SELECT * FROM realtime_projection_outbox WHERE event_id=?1 LIMIT 1").bind(eventId).first<RealtimeOutboxRow>();
}

export async function persistRealtimeProjection(
  env: ControlPlaneEnv,
  deviceId: string,
  event: RealtimeProjectionEvent,
  now = new Date(),
): Promise<RealtimeOutboxRow> {
  const eventJson = JSON.stringify({ sessionId: event.sessionId, eventId: event.eventId, type: event.type, recordId: event.recordId, revision: event.revision });
  const at = now.toISOString();
  await env.DB.prepare("INSERT OR IGNORE INTO realtime_projection_outbox(event_id,device_id,session_id,event_type,record_id,revision,event_json,state,next_attempt_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',?8,?8,?8)")
    .bind(event.eventId, deviceId, event.sessionId, event.type, event.recordId, event.revision, eventJson, at).run();
  const row = await rowFor(env, event.eventId);
  if (row === null) throw new TypeError("realtime projection outbox insert was not durable");
  if (row.device_id !== deviceId || row.session_id !== event.sessionId || row.event_type !== event.type || row.record_id !== event.recordId || row.revision !== event.revision || row.event_json !== eventJson) {
    throw new TypeError("realtime projection event ID is bound to another projection");
  }
  return row;
}

export async function attemptRealtimeProjection(
  env: ControlPlaneEnv,
  eventId: string,
  options: { now?: Date; force?: boolean; publisher?: RealtimeProjectionPublisher } = {},
): Promise<RealtimeProjectionAttempt> {
  const now = options.now ?? new Date();
  const at = now.toISOString();
  const leaseToken = crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + LEASE_MS).toISOString();
  const due = options.force === true
    ? "state='pending' OR (state='publishing' AND lease_expires_at<=?3)"
    : "(state='pending' AND next_attempt_at<=?3) OR (state='publishing' AND lease_expires_at<=?3)";
  const claimed = await env.DB.prepare(`UPDATE realtime_projection_outbox SET state='publishing',lease_token=?1,lease_expires_at=?2,updated_at=?3 WHERE event_id=?4 AND (${due})`)
    .bind(leaseToken, leaseExpiresAt, at, eventId).run();
  if (claimed.meta.changes !== 1) {
    const current = await rowFor(env, eventId);
    if (current === null) throw new TypeError("realtime projection outbox row is missing");
    return current.state === "published"
      ? { eventId, state: "published", attemptCount: current.attempt_count }
      : { eventId, state: "pending", attemptCount: current.attempt_count, nextAttemptAt: current.state === "publishing" ? current.lease_expires_at ?? current.next_attempt_at : current.next_attempt_at };
  }
  const row = await env.DB.prepare("SELECT * FROM realtime_projection_outbox WHERE event_id=?1 AND lease_token=?2 LIMIT 1").bind(eventId, leaseToken).first<RealtimeOutboxRow>();
  if (row === null) throw new TypeError("realtime projection lease was lost");
  const attemptCount = row.attempt_count + 1;
  const publisher = options.publisher ?? {
    publish: (event: RealtimeProjectionEvent) => env.BOARD_ROOMS.getByName(event.sessionId).publish(event),
  };
  try {
    await publisher.publish(eventFromRow(row));
    await env.DB.prepare("UPDATE realtime_projection_outbox SET state='published',attempt_count=?1,lease_token=NULL,lease_expires_at=NULL,last_error_code=NULL,published_at=?2,updated_at=?2 WHERE event_id=?3 AND lease_token=?4")
      .bind(attemptCount, nowIso(), eventId, leaseToken).run();
    return { eventId, state: "published", attemptCount };
  } catch {
    const nextAttemptAt = retryAt(now, attemptCount);
    await env.DB.prepare("UPDATE realtime_projection_outbox SET state='pending',attempt_count=?1,next_attempt_at=?2,lease_token=NULL,lease_expires_at=NULL,last_error_code='board_room_publish_failed',updated_at=?3 WHERE event_id=?4 AND lease_token=?5")
      .bind(attemptCount, nextAttemptAt, at, eventId, leaseToken).run();
    return { eventId, state: "pending", attemptCount, nextAttemptAt };
  }
}

export async function queueRealtimeProjection(
  env: ControlPlaneEnv,
  deviceId: string,
  event: RealtimeProjectionEvent,
  options: { now?: Date; publisher?: RealtimeProjectionPublisher } = {},
): Promise<RealtimeProjectionAttempt> {
  await persistRealtimeProjection(env, deviceId, event, options.now);
  return attemptRealtimeProjection(env, event.eventId, { ...options, force: true });
}

async function recoverMissingNodeProjections(env: ControlPlaneEnv, deviceId: string, now: Date, limit: number): Promise<number> {
  const rows = await env.DB.prepare(`
    SELECT receipt.message_id,receipt.frame_type,receipt.result_json,
           operation.session_id,operation.run_id,operation.result_json AS operation_result_json
    FROM node_projection_receipts AS receipt
    JOIN operation_journal AS operation ON operation.id=receipt.operation_id
    LEFT JOIN realtime_projection_outbox AS outbox ON outbox.event_id='bevt_' || receipt.message_id
    WHERE receipt.device_id=?1 AND receipt.projection_state='applied'
      AND receipt.frame_type IN ('operation.admission','operation.status','runtime.control_result')
      AND operation.session_id IS NOT NULL AND operation.run_id IS NOT NULL
      AND outbox.event_id IS NULL
    ORDER BY receipt.created_at,receipt.message_id
    LIMIT ?2
  `).bind(deviceId, limit).all<ProjectionReceiptRow>();
  let recovered = 0;
  for (const row of rows.results) {
    const event = recoverReceiptEvent(row);
    if (event === null) continue;
    await persistRealtimeProjection(env, deviceId, event, now);
    recovered += 1;
  }
  return recovered;
}

export async function reconcileRealtimeProjections(
  env: ControlPlaneEnv,
  deviceId: string,
  options: { now?: Date; limit?: number; publisher?: RealtimeProjectionPublisher } = {},
): Promise<RealtimeProjectionReconciliation> {
  const now = options.now ?? new Date();
  const limit = Math.max(1, Math.min(options.limit ?? DEFAULT_LIMIT, 128));
  const recovered = await recoverMissingNodeProjections(env, deviceId, now, limit);
  const rows = await env.DB.prepare("SELECT event_id FROM realtime_projection_outbox WHERE device_id=?1 AND ((state='pending' AND next_attempt_at<=?2) OR (state='publishing' AND lease_expires_at<=?2)) ORDER BY next_attempt_at,event_id LIMIT ?3")
    .bind(deviceId, now.toISOString(), limit).all<{ event_id: string }>();
  let published = 0;
  let pending = 0;
  for (const row of rows.results) {
    const result = await attemptRealtimeProjection(env, row.event_id, { now, ...(options.publisher === undefined ? {} : { publisher: options.publisher }) });
    if (result.state === "published") published += 1; else pending += 1;
  }
  const next = await env.DB.prepare("SELECT MIN(CASE WHEN state='publishing' THEN lease_expires_at ELSE next_attempt_at END) AS next_attempt_at FROM realtime_projection_outbox WHERE device_id=?1 AND state IN ('pending','publishing')")
    .bind(deviceId).first<{ next_attempt_at: string | null }>();
  const continuation = next?.next_attempt_at ?? (recovered === limit ? new Date(now.getTime() + 1_000).toISOString() : null);
  return { recovered, attempted: rows.results.length, published, pending, nextAttemptAt: continuation };
}
