import { nowIso } from "./crypto.ts";
import { PublicError } from "./errors.ts";

export interface EffectReservation {
  scope: string;
  key: string;
  digest: string;
}

export async function reserveEffect(db: D1Database, scope: string, key: string, digest: string): Promise<{ reservation?: EffectReservation; replay?: Record<string, unknown> }> {
  const existing = await db.prepare("SELECT payload_digest,state,response_json FROM effect_idempotency_records WHERE scope=?1 AND idempotency_key=?2 LIMIT 1").bind(scope, key).first<{ payload_digest: string; state: string; response_json: string | null }>();
  if (existing !== null) {
    if (existing.payload_digest !== digest) throw new PublicError("idempotency_conflict", 409, "Idempotency key is committed to different input");
    if (existing.state === "completed" && existing.response_json !== null) return { replay: { ...(JSON.parse(existing.response_json) as Record<string, unknown>), replay: true } };
    throw new PublicError("idempotency_conflict", 409, "Prior effect outcome is not safely replayable and will not be repeated automatically");
  }
  const now = nowIso();
  try {
    await db.prepare("INSERT INTO effect_idempotency_records(scope,idempotency_key,payload_digest,state,created_at,updated_at,expires_at) VALUES (?1,?2,?3,'reserved',?4,?4,?5)").bind(scope, key, digest, now, new Date(Date.now() + 86_400_000).toISOString()).run();
  } catch {
    return reserveEffect(db, scope, key, digest);
  }
  return { reservation: { scope, key, digest } };
}

export async function completeEffect(db: D1Database, reservation: EffectReservation, response: Record<string, unknown>): Promise<void> {
  const updated = await db.prepare("UPDATE effect_idempotency_records SET state='completed',response_json=?1,updated_at=?2 WHERE scope=?3 AND idempotency_key=?4 AND payload_digest=?5 AND state='reserved'").bind(JSON.stringify(response), nowIso(), reservation.scope, reservation.key, reservation.digest).run();
  if (updated.meta.changes !== 1) throw new PublicError("idempotency_conflict", 409, "Effect reservation changed before completion");
}
