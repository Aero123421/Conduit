import { DurableObject } from "cloudflare:workers";
import type { ControlPlaneEnv } from "../types.ts";

export interface LimitAdmission {
  operationId: string;
  idempotencyKey: string;
  payloadDigest: string;
  family: string;
  weight: number;
  requestLimit: number;
  windowSeconds: number;
  capacity: number;
  refillPerSecond: number;
  responseBytes: number;
  normalizedLogBytes: number;
  rawLogBytes: number;
  artifactUploadBytes: number;
  byteLimits: { response: number; normalizedDaily: number; rawDaily: number; artifactDaily: number };
  nowMs: number;
}

export type LimitDecision = { allowed: true; charged: boolean } | { allowed: false; code: "rate_limited" | "idempotency_conflict" | "resource_limit"; limitClass: string; retryAfterSeconds: number };

export class ConnectorLimiter extends DurableObject<ControlPlaneEnv> {
  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS idempotency(key TEXT PRIMARY KEY, operation_id TEXT NOT NULL, payload_digest TEXT NOT NULL, decision_json TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS request_windows(family TEXT NOT NULL, window_start INTEGER NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(family,window_start));
        CREATE TABLE IF NOT EXISTS token_bucket(singleton INTEGER PRIMARY KEY CHECK(singleton=1), tokens REAL NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS byte_usage(day TEXT PRIMARY KEY, response_bytes INTEGER NOT NULL, normalized_bytes INTEGER NOT NULL, raw_bytes INTEGER NOT NULL, artifact_bytes INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS concurrency(class TEXT PRIMARY KEY, active INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS concurrency_leases(operation_id TEXT PRIMARY KEY, class TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','released','expired')), expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS concurrency_leases_active_idx ON concurrency_leases(class,state,expires_at);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (2,datetime('now'));
      `);
    });
  }

  async admit(input: LimitAdmission): Promise<LimitDecision> {
    const existing = this.ctx.storage.sql.exec<{ payload_digest: string; decision_json: string }>("SELECT payload_digest,decision_json FROM idempotency WHERE key=?", input.idempotencyKey).toArray()[0];
    if (existing !== undefined) {
      if (existing.payload_digest !== input.payloadDigest) return { allowed: false, code: "idempotency_conflict", limitClass: "idempotency", retryAfterSeconds: 0 };
      return { ...(JSON.parse(existing.decision_json) as LimitDecision), ...(JSON.parse(existing.decision_json) as LimitDecision).allowed ? { charged: false } : {} } as LimitDecision;
    }
    const windowMs = input.windowSeconds * 1000;
    const windowStart = Math.floor(input.nowMs / windowMs) * windowMs;
    const window = this.ctx.storage.sql.exec<{ used: number }>("SELECT used FROM request_windows WHERE family=? AND window_start=?", input.family, windowStart).toArray()[0]?.used ?? 0;
    let decision: LimitDecision;
    if (window >= input.requestLimit) {
      decision = { allowed: false, code: "rate_limited", limitClass: `request.${input.family}`, retryAfterSeconds: Math.max(1, Math.ceil((windowStart + windowMs - input.nowMs) / 1000)) };
    } else {
      const bucket = this.ctx.storage.sql.exec<{ tokens: number; updated_at: number }>("SELECT tokens,updated_at FROM token_bucket WHERE singleton=1").toArray()[0];
      const available = Math.min(input.capacity, (bucket?.tokens ?? input.capacity) + Math.max(0, input.nowMs - (bucket?.updated_at ?? input.nowMs)) / 1000 * input.refillPerSecond);
      if (available < input.weight) decision = { allowed: false, code: "rate_limited", limitClass: "weighted_budget", retryAfterSeconds: input.refillPerSecond > 0 ? Math.max(1, Math.ceil((input.weight - available) / input.refillPerSecond)) : 3600 };
      else {
        const day = new Date(input.nowMs).toISOString().slice(0, 10);
        const usage = this.ctx.storage.sql.exec<{ response_bytes: number; normalized_bytes: number; raw_bytes: number; artifact_bytes: number }>("SELECT response_bytes,normalized_bytes,raw_bytes,artifact_bytes FROM byte_usage WHERE day=?", day).toArray()[0] ?? { response_bytes: 0, normalized_bytes: 0, raw_bytes: 0, artifact_bytes: 0 };
        const over = input.responseBytes > input.byteLimits.response ? "response_bytes" : usage.normalized_bytes + input.normalizedLogBytes > input.byteLimits.normalizedDaily ? "normalized_log_bytes" : usage.raw_bytes + input.rawLogBytes > input.byteLimits.rawDaily ? "raw_log_bytes" : usage.artifact_bytes + input.artifactUploadBytes > input.byteLimits.artifactDaily ? "artifact_upload_bytes" : null;
        if (over !== null) decision = { allowed: false, code: "resource_limit", limitClass: over, retryAfterSeconds: 86_400 };
        else {
          decision = { allowed: true, charged: true };
          this.ctx.storage.transactionSync(() => {
            this.ctx.storage.sql.exec("INSERT INTO request_windows(family,window_start,used) VALUES (?,?,1) ON CONFLICT(family,window_start) DO UPDATE SET used=used+1", input.family, windowStart);
            this.ctx.storage.sql.exec("INSERT INTO token_bucket(singleton,tokens,updated_at) VALUES (1,?,?) ON CONFLICT(singleton) DO UPDATE SET tokens=excluded.tokens,updated_at=excluded.updated_at", available - input.weight, input.nowMs);
            this.ctx.storage.sql.exec("INSERT INTO byte_usage(day,response_bytes,normalized_bytes,raw_bytes,artifact_bytes) VALUES (?,?,?,?,?) ON CONFLICT(day) DO UPDATE SET response_bytes=response_bytes+excluded.response_bytes,normalized_bytes=normalized_bytes+excluded.normalized_bytes,raw_bytes=raw_bytes+excluded.raw_bytes,artifact_bytes=artifact_bytes+excluded.artifact_bytes", day, input.responseBytes, input.normalizedLogBytes, input.rawLogBytes, input.artifactUploadBytes);
          });
        }
      }
    }
    this.ctx.storage.sql.exec("INSERT INTO idempotency(key,operation_id,payload_digest,decision_json,created_at) VALUES (?,?,?,?,?)", input.idempotencyKey, input.operationId, input.payloadDigest, JSON.stringify(decision), input.nowMs);
    return decision;
  }

  async acquire(operationId: string, className: "commands" | "agentRuns" | "runtimeStarts", limit: number, expiresAt: string): Promise<boolean> {
    const expiry = Date.parse(expiresAt);
    const now = Date.now();
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isFinite(expiry) || expiry <= now || operationId.length < 8 || operationId.length > 160) return false;
    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("UPDATE concurrency_leases SET state='expired',updated_at=? WHERE state='active' AND expires_at<=?", now, now);
      const existing = this.ctx.storage.sql.exec<{ class: string; state: string; expires_at: number }>("SELECT class,state,expires_at FROM concurrency_leases WHERE operation_id=?", operationId).toArray()[0];
      if (existing !== undefined) return existing.class === className && existing.state === "active" && existing.expires_at > now;
      const active = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM concurrency_leases WHERE class=? AND state='active' AND expires_at>?", className, now).one().count;
      if (active >= limit) return false;
      this.ctx.storage.sql.exec("INSERT INTO concurrency_leases(operation_id,class,state,expires_at,created_at,updated_at) VALUES (?,?,'active',?,?,?)", operationId, className, expiry, now, now);
      return true;
    });
  }

  async release(operationId: string, className: "commands" | "agentRuns" | "runtimeStarts"): Promise<boolean> {
    const changed = this.ctx.storage.sql.exec<{ operation_id: string }>("UPDATE concurrency_leases SET state='released',updated_at=? WHERE operation_id=? AND class=? AND state='active' RETURNING operation_id", Date.now(), operationId, className).toArray();
    return changed.length === 1;
  }
}
