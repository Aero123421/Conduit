import { nowIso } from "./crypto.ts";
import { usageProfileForEnv } from "./usage-profile.ts";
import type { ControlPlaneEnv } from "./types.ts";

export interface RetentionCleanupResult {
  deletedRows: number;
  compactedRealtimeRows: number;
  hasMore: boolean;
  nextDueAt: string | null;
}

function changes(result: D1Result<unknown> | undefined): number {
  return result?.meta.changes ?? 0;
}

/** Idempotent bounded cleanup. D1 batch rollback keeps receipt compaction atomic. */
export async function cleanupHotData(env: ControlPlaneEnv, options: { now?: Date; limit?: number } = {}): Promise<RetentionCleanupResult> {
  const now = options.now ?? new Date();
  const profile = usageProfileForEnv(env);
  const limit = Math.max(100, Math.min(options.limit ?? profile.retentionBatchRows, 500));
  const at = now.toISOString();
  const dayAgo = new Date(now.getTime() - 86_400_000).toISOString();
  const weekAgo = new Date(now.getTime() - 7 * 86_400_000).toISOString();
  const realtimeReceiptExpiry = new Date(now.getTime() + 7 * 86_400_000).toISOString();
  const [realtimeReceipts, realtimeRows, projectionReceipts, challenges, codes, tokens, consent, clients, enrollments, effects, idempotency, deltas, deliveryReceipts, dispatchRows, approvalDispatchRows] = await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO realtime_delivery_receipts(event_id,session_id,record_id,revision,published_at,expires_at) SELECT event_id,session_id,record_id,revision,published_at,?1 FROM realtime_projection_outbox WHERE state='published' AND published_at<=?2 ORDER BY published_at,event_id LIMIT ?3").bind(realtimeReceiptExpiry, dayAgo, limit),
    env.DB.prepare("DELETE FROM realtime_projection_outbox WHERE event_id IN (SELECT outbox.event_id FROM realtime_projection_outbox AS outbox JOIN realtime_delivery_receipts AS receipt ON receipt.event_id=outbox.event_id WHERE outbox.state='published' AND outbox.published_at<=?1 ORDER BY outbox.published_at,outbox.event_id LIMIT ?2)").bind(dayAgo, limit),
    env.DB.prepare("DELETE FROM node_projection_receipts WHERE message_id IN (SELECT message_id FROM node_projection_receipts WHERE frame_type='device.health' AND created_at<=?1 ORDER BY created_at,message_id LIMIT ?2)").bind(dayAgo, limit),
    env.DB.prepare("DELETE FROM auth_challenges WHERE id IN (SELECT id FROM auth_challenges WHERE expires_at<=?1 OR (consumed_at IS NOT NULL AND consumed_at<=?2) ORDER BY expires_at,id LIMIT ?3)").bind(at, dayAgo, limit),
    env.DB.prepare("DELETE FROM oauth_authorization_codes WHERE id IN (SELECT id FROM oauth_authorization_codes WHERE expires_at<=?1 OR consumed_at<=?2 ORDER BY expires_at,id LIMIT ?3)").bind(at, dayAgo, limit),
    env.DB.prepare("DELETE FROM oauth_tokens WHERE id IN (SELECT id FROM oauth_tokens WHERE expires_at<=?1 OR consumed_at<=?2 OR revoked_at<=?2 ORDER BY expires_at,id LIMIT ?3)").bind(at, weekAgo, limit),
    env.DB.prepare("DELETE FROM oauth_consent_transactions WHERE id IN (SELECT id FROM oauth_consent_transactions WHERE expires_at<=?1 OR consumed_at<=?2 ORDER BY expires_at,id LIMIT ?3) AND NOT EXISTS (SELECT 1 FROM oauth_authorization_codes WHERE consent_transaction_id=oauth_consent_transactions.id)").bind(at, dayAgo, limit),
    env.DB.prepare("DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM oauth_clients WHERE registration_mechanism='dynamic' AND status='pending_owner' AND expires_at<=?1 ORDER BY expires_at,client_id LIMIT ?2) AND NOT EXISTS (SELECT 1 FROM oauth_grants WHERE client_id=oauth_clients.client_id) AND NOT EXISTS (SELECT 1 FROM connector_policies WHERE client_id=oauth_clients.client_id)").bind(at, limit),
    env.DB.prepare("DELETE FROM device_enrollments WHERE id IN (SELECT id FROM device_enrollments WHERE state IN ('denied','expired','cancelled') AND COALESCE(terminal_at,expires_at)<=?1 ORDER BY COALESCE(terminal_at,expires_at),id LIMIT ?2) AND assigned_device_id IS NULL").bind(dayAgo, limit),
    env.DB.prepare("DELETE FROM effect_idempotency_records WHERE rowid IN (SELECT rowid FROM effect_idempotency_records WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)").bind(at, limit),
    env.DB.prepare("DELETE FROM idempotency_records WHERE rowid IN (SELECT rowid FROM idempotency_records WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2) AND NOT EXISTS (SELECT 1 FROM operation_journal WHERE operation_journal.id=idempotency_records.operation_id AND operation_journal.state NOT IN ('completed','failed','cancelled','expired','rejected'))").bind(at, limit),
    env.DB.prepare("DELETE FROM normalized_events WHERE event_id IN (SELECT event_id FROM normalized_events WHERE retention_class='streaming_delta' AND expires_at<=?1 ORDER BY expires_at,event_id LIMIT ?2)").bind(at, limit),
    env.DB.prepare("DELETE FROM realtime_delivery_receipts WHERE event_id IN (SELECT event_id FROM realtime_delivery_receipts WHERE expires_at<=?1 ORDER BY expires_at,event_id LIMIT ?2)").bind(at, limit),
    env.DB.prepare("DELETE FROM operation_dispatch_outbox WHERE operation_id IN (SELECT operation_id FROM operation_dispatch_outbox WHERE state='expired' AND expires_at<=?1 ORDER BY expires_at,operation_id LIMIT ?2) AND EXISTS (SELECT 1 FROM operation_journal WHERE id=operation_dispatch_outbox.operation_id AND state='expired' AND concurrency_released_at IS NOT NULL)").bind(weekAgo, limit),
    env.DB.prepare("DELETE FROM approval_dispatch_outbox WHERE approval_id IN (SELECT approval_id FROM approval_dispatch_outbox WHERE state IN ('offered','expired') AND expires_at<=?1 ORDER BY expires_at,approval_id LIMIT ?2) AND EXISTS (SELECT 1 FROM approvals WHERE id=approval_dispatch_outbox.approval_id AND decision IS NOT NULL)").bind(weekAgo, limit),
  ]);
  const compactedRealtimeRows = changes(realtimeReceipts);
  const deletedRows = [realtimeRows, projectionReceipts, challenges, codes, tokens, consent, clients, enrollments, effects, idempotency, deltas, deliveryReceipts, dispatchRows, approvalDispatchRows].reduce((sum, result) => sum + changes(result), 0);
  const hasMore = [realtimeRows, projectionReceipts, challenges, codes, tokens, consent, clients, enrollments, effects, idempotency, deltas, deliveryReceipts, dispatchRows, approvalDispatchRows].some((result) => changes(result) >= limit);
  const nextDueAt = hasMore ? new Date(now.getTime() + 1_000).toISOString() : null;
  await env.DB.prepare("UPDATE retention_cleanup_state SET continuation_due_at=?1,last_started_at=?2,last_completed_at=?2,last_deleted_rows=?3 WHERE singleton=1").bind(nextDueAt, nowIso(), deletedRows).run();
  return { deletedRows, compactedRealtimeRows, hasMore, nextDueAt };
}

