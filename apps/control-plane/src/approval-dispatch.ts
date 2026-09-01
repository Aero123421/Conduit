import { canonicalJson, nowIso, sha256Hex } from "./crypto.ts";
import type { ControlPlaneEnv } from "./types.ts";

const LEASE_MS = 30_000;

interface ApprovalDispatchRow {
  approval_id: string;
  device_id: string;
  message_id: string;
  payload_digest: string;
  payload_json: string;
  state: "pending" | "dispatching" | "offered" | "expired";
  attempt_count: number;
  next_attempt_at: string;
  lease_token: string | null;
  lease_expires_at: string | null;
  expires_at: string;
}

export interface DeviceRoomApproval {
  deviceId: string;
  messageId: string;
  correlationId: string;
  payloadDigest: string;
  payload: Record<string, unknown>;
  expiresAt: string;
}

export async function buildApprovalReceipt(
  env: ControlPlaneEnv,
  approvalId: string,
  decision: "approved" | "denied",
  now = new Date(),
): Promise<{ payload: Record<string, unknown>; payloadDigest: string; messageId: string; expiresAt: string; deviceId: string }> {
  const approval = await env.DB.prepare("SELECT operation_id,device_id,run_id,commitment_digest,revisions_json,expires_at FROM approvals WHERE id=?1 LIMIT 1")
    .bind(approvalId)
    .first<{ operation_id: string; device_id: string; run_id: string | null; commitment_digest: string; revisions_json: string; expires_at: string }>();
  if (approval === null || approval.run_id === null) throw new TypeError("approval dispatch target is incomplete");
  const revisions = JSON.parse(approval.revisions_json) as { controllerEpoch?: unknown };
  if (typeof revisions.controllerEpoch !== "string") throw new TypeError("approval controller epoch is missing");
  const expiresAt = new Date(Math.min(Date.parse(approval.expires_at), now.getTime() + 300_000)).toISOString();
  const validForMs = Math.max(1, Math.min(3_600_000, Date.parse(expiresAt) - now.getTime()));
  const commitment = {
    approvalId,
    operationId: approval.operation_id,
    runId: approval.run_id,
    operationDigest: approval.commitment_digest,
    decision,
    reuseScope: "once",
    controllerEpoch: revisions.controllerEpoch,
    issuedAt: now.toISOString(),
    expiresAt,
    validForMs,
  };
  const receiptDigest = await sha256Hex(canonicalJson(commitment));
  const payload = { ...commitment, receiptDigest };
  return {
    payload,
    payloadDigest: await sha256Hex(canonicalJson(payload)),
    messageId: `cmsg_xapproval_${approvalId.slice(6)}`,
    expiresAt,
    deviceId: approval.device_id,
  };
}

export async function attemptApprovalDispatch(
  env: ControlPlaneEnv,
  approvalId: string,
  now = new Date(),
  deliver: (frame: DeviceRoomApproval) => Promise<unknown> = (frame) => env.DEVICE_ROOMS.getByName(frame.deviceId).deliverApproval(frame),
): Promise<void> {
  const current = await env.DB.prepare("SELECT * FROM approval_dispatch_outbox WHERE approval_id=?1 LIMIT 1").bind(approvalId).first<ApprovalDispatchRow>();
  if (current === null || current.state === "offered" || current.state === "expired") return;
  if (Date.parse(current.expires_at) <= now.getTime()) {
    await env.DB.prepare("UPDATE approval_dispatch_outbox SET state='expired',lease_token=NULL,lease_expires_at=NULL,updated_at=?1 WHERE approval_id=?2 AND state IN ('pending','dispatching')").bind(now.toISOString(), approvalId).run();
    return;
  }
  const lease = crypto.randomUUID();
  const leaseExpires = new Date(now.getTime() + LEASE_MS).toISOString();
  const claimed = await env.DB.prepare("UPDATE approval_dispatch_outbox SET state='dispatching',lease_token=?1,lease_expires_at=?2,updated_at=?3 WHERE approval_id=?4 AND ((state='pending' AND next_attempt_at<=?3) OR (state='dispatching' AND lease_expires_at<=?3))")
    .bind(lease, leaseExpires, now.toISOString(), approvalId).run();
  if (claimed.meta.changes !== 1) return;
  const row = await env.DB.prepare("SELECT * FROM approval_dispatch_outbox WHERE approval_id=?1 AND lease_token=?2 LIMIT 1").bind(approvalId, lease).first<ApprovalDispatchRow>();
  if (row === null) return;
  try {
    await deliver({
      deviceId: row.device_id,
      messageId: row.message_id,
      correlationId: row.approval_id,
      payloadDigest: row.payload_digest,
      payload: JSON.parse(row.payload_json) as Record<string, unknown>,
      expiresAt: row.expires_at,
    });
    await env.DB.prepare("UPDATE approval_dispatch_outbox SET state='offered',attempt_count=attempt_count+1,lease_token=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=?1 WHERE approval_id=?2 AND lease_token=?3")
      .bind(now.toISOString(), approvalId, lease).run();
  } catch {
    const attempts = row.attempt_count + 1;
    const delay = Math.min(60_000, 2 ** Math.min(attempts, 6) * 1_000);
    const next = new Date(now.getTime() + delay).toISOString();
    await env.DB.prepare("UPDATE approval_dispatch_outbox SET state='pending',attempt_count=?1,next_attempt_at=?2,lease_token=NULL,lease_expires_at=NULL,last_error_code='device_room_delivery_failed',updated_at=?3 WHERE approval_id=?4 AND lease_token=?5")
      .bind(attempts, next, now.toISOString(), approvalId, lease).run();
  }
}

export async function reconcileApprovalDispatches(env: ControlPlaneEnv, now = new Date()): Promise<void> {
  const rows = await env.DB.prepare("SELECT approval_id FROM approval_dispatch_outbox WHERE (state='pending' AND (next_attempt_at<=?1 OR expires_at<=?1)) OR (state='dispatching' AND lease_expires_at<=?1) ORDER BY next_attempt_at LIMIT 32")
    .bind(now.toISOString()).all<{ approval_id: string }>();
  for (const row of rows.results) await attemptApprovalDispatch(env, row.approval_id, now);
}

export function approvalOutboxInsert(
  env: ControlPlaneEnv,
  approvalId: string,
  receipt: { payload: Record<string, unknown>; payloadDigest: string; messageId: string; expiresAt: string; deviceId: string },
  now = nowIso(),
): D1PreparedStatement {
  const decision = receipt.payload.decision;
  return env.DB.prepare("INSERT INTO approval_dispatch_outbox(approval_id,device_id,message_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) SELECT ?1,?2,?3,?4,?5,'pending',?6,?7,?6,?6 WHERE EXISTS (SELECT 1 FROM approvals WHERE id=?1 AND decision=?8 AND resolved_at=?6)")
    .bind(approvalId, receipt.deviceId, receipt.messageId, receipt.payloadDigest, canonicalJson(receipt.payload), now, receipt.expiresAt, decision);
}
