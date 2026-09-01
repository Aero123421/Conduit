import type { ControlPlaneEnv } from "./types.ts";

const DISPATCH_LEASE_MS = 30_000;
const MAX_RECONCILE_BATCH = 32;

export interface DeviceRoomOffer {
  deviceId: string;
  messageId: string;
  correlationId: string;
  payloadDigest: string;
  payload: Record<string, unknown>;
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
  payload_digest: string;
  expires_at: string;
  connector_grant_id: string | null;
  concurrency_class: "commands" | "agentRuns" | "runtimeStarts" | null;
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
  return env.DB.prepare("SELECT id,payload_digest,expires_at,connector_grant_id,concurrency_class FROM operation_journal WHERE id=?1 LIMIT 1")
    .bind(operationId)
    .first<OperationRow>();
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
  const claimed = await env.DB.prepare("UPDATE operation_dispatch_outbox SET state='expired',lease_token=NULL,lease_expires_at=NULL,result_json=?1,last_error_code='operation_expired',updated_at=?2 WHERE operation_id=?3 AND state IN ('pending','dispatching')")
    .bind(JSON.stringify(response), now.toISOString(), row.operation_id)
    .run();
  if (claimed.meta.changes !== 1) {
    const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(row.operation_id).first<DispatchRow>();
    return latest === null ? response : currentResult(env, latest);
  }
  const projected = await env.DB.batch([
    env.DB.prepare("UPDATE operation_journal SET state='expired',result_json=?1,updated_at=?2 WHERE id=?3 AND state='queued'")
      .bind(JSON.stringify(response), now.toISOString(), row.operation_id),
    env.DB.prepare("UPDATE idempotency_records SET state='expired',response_json=?1 WHERE operation_id=?2")
      .bind(JSON.stringify(response), row.operation_id),
  ]);
  if (projected[0]?.meta.changes === 1 && operation.connector_grant_id !== null && operation.concurrency_class !== null) {
    await env.CONNECTOR_LIMITERS.getByName(operation.connector_grant_id).release(operation.concurrency_class);
  }
  return response;
}

async function currentResult(env: ControlPlaneEnv, row: DispatchRow): Promise<DispatchAttemptResult> {
  if (row.result_json !== null) return JSON.parse(row.result_json) as DispatchAttemptResult;
  const operation = await operationRow(env, row.operation_id);
  if (operation === null) throw new TypeError("dispatch operation is missing");
  return {
    operationId: operation.id,
    state: row.state === "offered" ? "offered" : row.state === "expired" ? "expired" : "queued",
    payloadDigest: operation.payload_digest,
    expiresAt: operation.expires_at,
  };
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
      expiresAt: row.expires_at,
    });
    const response: DispatchAttemptResult = {
      operationId: operation.id,
      state: "offered",
      payloadDigest: operation.payload_digest,
      expiresAt: operation.expires_at,
      delivery,
    };
    const stored = await env.DB.prepare("UPDATE operation_dispatch_outbox SET state='offered',attempt_count=?1,lease_token=NULL,lease_expires_at=NULL,result_json=?2,last_error_code=NULL,updated_at=?3 WHERE operation_id=?4 AND lease_token=?5")
      .bind(attemptCount, JSON.stringify(response), nowValue, operationId, leaseToken)
      .run();
    if (stored.meta.changes !== 1) {
      const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
      return latest === null ? response : currentResult(env, latest);
    }
    await env.DB.batch([
      env.DB.prepare("UPDATE operation_journal SET state='offered',updated_at=?1,result_json=?2 WHERE id=?3 AND state='queued'")
        .bind(nowValue, JSON.stringify(delivery), operationId),
      env.DB.prepare("UPDATE idempotency_records SET state='offered',response_json=?1 WHERE operation_id=?2")
        .bind(JSON.stringify(response), operationId),
    ]);
    return response;
  } catch {
    const nextAttemptAt = retryAt(now, attemptCount);
    const response: DispatchAttemptResult = {
      operationId: operation.id,
      state: "queued",
      payloadDigest: operation.payload_digest,
      expiresAt: operation.expires_at,
      dispatch: { state: "pending", attemptCount, nextAttemptAt },
    };
    const stored = await env.DB.prepare("UPDATE operation_dispatch_outbox SET state='pending',attempt_count=?1,next_attempt_at=?2,lease_token=NULL,lease_expires_at=NULL,result_json=?3,last_error_code='device_room_offer_failed',updated_at=?4 WHERE operation_id=?5 AND lease_token=?6")
      .bind(attemptCount, nextAttemptAt, JSON.stringify(response), nowValue, operationId, leaseToken)
      .run();
    if (stored.meta.changes === 1) {
      await env.DB.prepare("UPDATE idempotency_records SET state='queued',response_json=?1 WHERE operation_id=?2")
        .bind(JSON.stringify(response), operationId)
        .run();
    } else {
      const latest = await env.DB.prepare("SELECT * FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<DispatchRow>();
      if (latest !== null) return currentResult(env, latest);
    }
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
  const rows = await env.DB.prepare("SELECT operation_id FROM operation_dispatch_outbox WHERE state IN ('pending','dispatching') AND (expires_at<=?1 OR (state='pending' AND next_attempt_at<=?1) OR (state='dispatching' AND lease_expires_at<=?1)) ORDER BY expires_at,next_attempt_at,operation_id LIMIT ?2")
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
