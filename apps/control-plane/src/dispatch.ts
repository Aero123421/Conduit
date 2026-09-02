import type { ControlPlaneEnv } from "./types.ts";

const DISPATCH_LEASE_MS = 30_000;
const MAX_RECONCILE_BATCH = 32;

export interface DeviceRoomOffer {
  deviceId: string;
  messageId: string;
  correlationId: string;
  payloadDigest: string;
  payload: Record<string, unknown>;
  frameType?: "operation.offer" | "operation.input" | "operation.cancel" | "runtime.control";
  expiresAt: string;
}

export interface DeviceRoomDelivery {
  sequence: string;
  delivered: boolean;
}

export interface OperationDispatcher {
  offer(env: ControlPlaneEnv, frame: DeviceRoomOffer): Promise<DeviceRoomDelivery>;
}

export const durableObjectOperationDispatcher: OperationDispatcher = {
  async offer(env, frame) {
    return env.DEVICE_ROOMS.getByName(frame.deviceId).offer(frame);
  },
};

interface DispatchRow {
  operation_id: string;
  device_id: string;
  message_id: string;
  correlation_id: string;
  payload_digest: string;
  payload_json: string;
  frame_type: "operation.offer" | "operation.input" | "operation.cancel" | "runtime.control";
  state: "pending" | "dispatching" | "offered" | "expired";
  attempt_count: number;
  next_attempt_at: string;
  lease_token: string | null;
  lease_expires_at: string | null;
  result_json: string | null;
  expires_at: string;
}

interface OperationRow {
  id: string;
  state: string;
  payload_digest: string;
  expires_at: string;
  connector_grant_id: string | null;
  concurrency_class: "commands" | "agentRuns" | "runtimeStarts" | null;
  concurrency_released_at: string | null;
}

export interface DispatchAttemptResult {
  operationId: string;
  state: "queued" | "offered" | "expired";
  payloadDigest: string;
  expiresAt: string;
  delivery?: DeviceRoomDelivery;
  dispatch?: { state: "pending"; attemptCount: number; nextAttemptAt: string };
}

export interface DispatchReconcileResult {
  examined: number;
  offered: number;
  pending: number;
  expired: number;
}

function parsePayload(value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("persisted dispatch payload is invalid");
  return parsed as Record<string, unknown>;
}

function retryAt(now: Date, attemptCount: number): string {
  const seconds = Math.min(60, 2 ** Math.min(Math.max(attemptCount, 1), 6));
  return new Date(now.getTime() + seconds * 1_000).toISOString();
}

async function operationRow(env: ControlPlaneEnv, operationId: string): Promise<OperationRow | null> {
  return env.DB.prepare("SELECT id,state,payload_digest,expires_at,connector_grant_id,concurrency_class,concurrency_released_at FROM operation_journal WHERE id=?1 LIMIT 1")
    .bind(operationId)
    .first<OperationRow>();
}

async function ensureConcurrencyReleased(env: ControlPlaneEnv, operation: OperationRow, now: Date): Promise<void> {
  if (operation.concurrency_released_at !== null) return;
  if (operation.connector_grant_id !== null && operation.concurrency_class !== null) {
    await env.CONNECTOR_LIMITERS.getByName(operation.connector_grant_id).release(operation.id, operation.concurrency_class);
  }
  await env.DB.prepare("UPDATE operation_journal SET concurrency_released_at=?1 WHERE id=?2 AND concurrency_released_at IS NULL")
    .bind(now.toISOString(), operation.id)
    .run();
}

export async function ensureOperationConcurrencyReleased(env: ControlPlaneEnv, operationId: string, now = new Date()): Promise<void> {
  const operation = await operationRow(env, operationId);
  if (operation !== null) await ensureConcurrencyReleased(env, operation, now);
}

async function repairOfferedProjection(env: ControlPlaneEnv, row: DispatchRow, response: DispatchAttemptResult, now: Date): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE operation_journal SET state='offered',updated_at=?1,result_json=?2 WHERE id=?3 AND state='queued' AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?3 AND state='offered')")
      .bind(now.toISOString(), JSON.stringify(response.delivery ?? {}), row.operation_id),
    env.DB.prepare("UPDATE idempotency_records SET state='offered',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?2 AND state='offered')")
      .bind(JSON.stringify(response), row.operation_id),
  ]);
}

async function repairExpiredProjection(env: ControlPlaneEnv, row: DispatchRow, response: DispatchAttemptResult, now: Date): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE operation_journal SET state='expired',result_json=?1,updated_at=?2 WHERE id=?3 AND state='queued' AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?3 AND state='expired')")
      .bind(JSON.stringify(response), now.toISOString(), row.operation_id),
    env.DB.prepare("UPDATE idempotency_records SET state='expired',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?2 AND state='expired')")
      .bind(JSON.stringify(response), row.operation_id),
  ]);
  const projected = await operationRow(env, row.operation_id);
  if (projected !== null && projected.state === "expired") await ensureConcurrencyReleased(env, projected, now);
}

async function expireDispatch(env: ControlPlaneEnv, row: DispatchRow, now: Date): Promise<DispatchAttemptResult> {
  const operation = await operationRow(env, row.operation_id);
  if (operation === null) throw new TypeError("dispatch operation is missing");
  const response: DispatchAttemptResult = {
    operationId: operation.id,
    state: "expired",
    payloadDigest: operation.payload_digest,
    expiresAt: operation.expires_at,
  };
  await env.DB.batch([
    env.DB.prepare("UPDATE operation_dispatch_outbox SET state='expired',lease_token=NULL,lease_expires_at=NULL,result_json=?1,last_error_code='operation_expired',updated_at=?2 WHERE operation_id=?3 AND state IN ('pending','dispatching')")
      .bind(JSON.stringify(response), now.toISOString(), row.operation_id),
    env.DB.prepare("UPDATE operation_journal SET state='expired',result_json=?1,updated_at=?2 WHERE id=?3 AND state='queued' AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?3 AND state='expired')")
      .bind(JSON.stringify(response), now.toISOString(), row.operation_id),
    env.DB.prepare("UPDATE idempotency_records SET state='expired',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?2 AND state='expired')")
      .bind(JSON.stringify(response), row.operation_id),
  ]);
  const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(row.operation_id).first<DispatchRow>();
  if (latest === null) return response;
  if (latest.state === "expired") {
    const projected = await operationRow(env, row.operation_id);
    if (projected !== null) await ensureConcurrencyReleased(env, projected, now);
  }
  return currentResult(env, latest);
}

async function currentResult(env: ControlPlaneEnv, row: DispatchRow): Promise<DispatchAttemptResult> {
  const operation = await operationRow(env, row.operation_id);
  if (operation === null) throw new TypeError("dispatch operation is missing");
  const response: DispatchAttemptResult = row.result_json !== null ? JSON.parse(row.result_json) as DispatchAttemptResult : {
    operationId: operation.id,
    state: row.state === "offered" ? "offered" : row.state === "expired" ? "expired" : "queued",
    payloadDigest: operation.payload_digest,
    expiresAt: operation.expires_at,
  };
  if (row.state === "offered") await repairOfferedProjection(env, row, response, new Date());
  if (row.state === "expired") await repairExpiredProjection(env, row, response, new Date());
  return response;
}

export async function attemptOperationDispatch(
  env: ControlPlaneEnv,
  operationId: string,
  options: { force?: boolean; now?: Date; dispatcher?: OperationDispatcher } = {},
): Promise<DispatchAttemptResult | null> {
  const now = options.now ?? new Date();
  const nowValue = now.toISOString();
  const existing = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
  if (existing === null) return null;
  if (existing.state === "offered" || existing.state === "expired") return currentResult(env, existing);
  if (Date.parse(existing.expires_at) <= now.getTime()) return expireDispatch(env, existing, now);

  const leaseToken = crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + DISPATCH_LEASE_MS).toISOString();
  const claimSql = options.force === true
    ? "UPDATE operation_dispatch_outbox SET state='dispatching',lease_token=?1,lease_expires_at=?2,updated_at=?3 WHERE operation_id=?4 AND ((state='pending') OR (state='dispatching' AND lease_expires_at<=?3))"
    : "UPDATE operation_dispatch_outbox SET state='dispatching',lease_token=?1,lease_expires_at=?2,updated_at=?3 WHERE operation_id=?4 AND ((state='pending' AND next_attempt_at<=?3) OR (state='dispatching' AND lease_expires_at<=?3))";
  const claimed = await env.DB.prepare(claimSql).bind(leaseToken, leaseExpiresAt, nowValue, operationId).run();
  if (claimed.meta.changes !== 1) {
    const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
    return latest === null ? null : currentResult(env, latest);
  }

  const row = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 AND lease_token=?2 LIMIT 1").bind(operationId, leaseToken).first<DispatchRow>();
  if (row === null) return null;
  const operation = await operationRow(env, operationId);
  if (operation === null) throw new TypeError("dispatch operation is missing");
  const attemptCount = row.attempt_count + 1;
  try {
    const delivery = await (options.dispatcher ?? durableObjectOperationDispatcher).offer(env, {
      deviceId: row.device_id,
      messageId: row.message_id,
      correlationId: row.correlation_id,
      payloadDigest: row.payload_digest,
      payload: parsePayload(row.payload_json),
      frameType: row.frame_type,
      expiresAt: row.expires_at,
    });
    const response: DispatchAttemptResult = {
      operationId: operation.id,
      state: "offered",
      payloadDigest: operation.payload_digest,
      expiresAt: operation.expires_at,
      delivery,
    };
    await env.DB.batch([
      env.DB.prepare("UPDATE operation_dispatch_outbox SET state='offered',attempt_count=?1,lease_token=NULL,lease_expires_at=NULL,result_json=?2,last_error_code=NULL,updated_at=?3 WHERE operation_id=?4 AND lease_token=?5")
        .bind(attemptCount, JSON.stringify(response), nowValue, operationId, leaseToken),
      env.DB.prepare("UPDATE operation_journal SET state='offered',updated_at=?1,result_json=?2 WHERE id=?3 AND state='queued' AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?3 AND state='offered')")
        .bind(nowValue, JSON.stringify(delivery), operationId),
      env.DB.prepare("UPDATE idempotency_records SET state='offered',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?2 AND state='offered')")
        .bind(JSON.stringify(response), operationId),
    ]);
    const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
    return latest === null ? response : currentResult(env, latest);
  } catch {
    const nextAttemptAt = retryAt(now, attemptCount);
    const response: DispatchAttemptResult = {
      operationId: operation.id,
      state: "queued",
      payloadDigest: operation.payload_digest,
      expiresAt: operation.expires_at,
      dispatch: { state: "pending", attemptCount, nextAttemptAt },
    };
    await env.DB.batch([
      env.DB.prepare("UPDATE operation_dispatch_outbox SET state='pending',attempt_count=?1,next_attempt_at=?2,lease_token=NULL,lease_expires_at=NULL,result_json=?3,last_error_code='device_room_offer_failed',updated_at=?4 WHERE operation_id=?5 AND lease_token=?6")
        .bind(attemptCount, nextAttemptAt, JSON.stringify(response), nowValue, operationId, leaseToken),
      env.DB.prepare("UPDATE idempotency_records SET state='queued',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_dispatch_outbox WHERE operation_id=?2 AND state='pending' AND result_json=?1)")
        .bind(JSON.stringify(response), operationId),
    ]);
    const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
    if (latest !== null && latest.state !== "pending") return currentResult(env, latest);
    console.error(JSON.stringify({ message: "operation dispatch failed", operationId, deviceId: row.device_id, attemptCount, code: "device_room_offer_failed" }));
    return response;
  }
}

export async function reconcileOperationDispatches(
  env: ControlPlaneEnv,
  options: { now?: Date; limit?: number; dispatcher?: OperationDispatcher } = {},
): Promise<DispatchReconcileResult> {
  const now = options.now ?? new Date();
  const limit = Math.min(Math.max(options.limit ?? MAX_RECONCILE_BATCH, 1), MAX_RECONCILE_BATCH);
  const rows = await env.DB.prepare("SELECT outbox.operation_id FROM operation_dispatch_outbox AS outbox JOIN operation_journal AS operation ON operation.id=outbox.operation_id LEFT JOIN idempotency_records AS idem ON idem.operation_id=outbox.operation_id WHERE (outbox.state IN ('pending','dispatching') AND (outbox.expires_at<=?1 OR (outbox.state='pending' AND outbox.next_attempt_at<=?1) OR (outbox.state='dispatching' AND outbox.lease_expires_at<=?1))) OR (outbox.state='offered' AND (operation.state='queued' OR idem.state<>'offered')) OR (outbox.state='expired' AND (operation.state='queued' OR idem.state<>'expired' OR operation.concurrency_released_at IS NULL)) ORDER BY outbox.expires_at,outbox.next_attempt_at,outbox.operation_id LIMIT ?2")
    .bind(now.toISOString(), limit)
    .all<{ operation_id: string }>();
  const result: DispatchReconcileResult = { examined: 0, offered: 0, pending: 0, expired: 0 };
  for (const item of rows.results) {
    const attempted = await attemptOperationDispatch(env, item.operation_id, {
      now,
      ...(options.dispatcher === undefined ? {} : { dispatcher: options.dispatcher }),
    });
    if (attempted === null) continue;
    result.examined += 1;
    if (attempted.state === "offered") result.offered += 1;
    else if (attempted.state === "expired") result.expired += 1;
    else result.pending += 1;
  }
  return result;
}
