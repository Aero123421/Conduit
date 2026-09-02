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
  effectful?: boolean;
  idempotencyExpiresAtMs?: number;
  concurrency?: { className: "commands" | "agentRuns" | "runtimeStarts"; limit: number; expiresAt: string };
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
        CREATE TABLE IF NOT EXISTS budget_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),windows_json TEXT NOT NULL,tokens REAL NOT NULL,updated_at INTEGER NOT NULL,day TEXT NOT NULL,normalized_bytes INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,artifact_bytes INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS maintenance(singleton INTEGER PRIMARY KEY CHECK(singleton=1),next_cleanup_at INTEGER NOT NULL);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (2,datetime('now'));
      `);
      const idempotencyColumns = new Set(this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(idempotency)").toArray().map((column) => column.name));
      if (!idempotencyColumns.has("expires_at")) this.ctx.storage.sql.exec("ALTER TABLE idempotency ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0");
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idempotency_expiry_idx ON idempotency(expires_at)");
      const now = Date.now();
      if (this.ctx.storage.sql.exec<{ singleton: number }>("SELECT singleton FROM budget_state WHERE singleton=1").toArray()[0] === undefined) {
        const windows = Object.fromEntries(this.ctx.storage.sql.exec<{ family: string; window_start: number; used: number }>("SELECT family,window_start,used FROM request_windows").toArray().map((row) => [row.family, { windowStart: row.window_start, used: row.used }]));
        const bucket = this.ctx.storage.sql.exec<{ tokens: number; updated_at: number }>("SELECT tokens,updated_at FROM token_bucket WHERE singleton=1").toArray()[0];
        const day = new Date(now).toISOString().slice(0, 10);
        const bytes = this.ctx.storage.sql.exec<{ normalized_bytes: number; raw_bytes: number; artifact_bytes: number }>("SELECT normalized_bytes,raw_bytes,artifact_bytes FROM byte_usage WHERE day=?", day).toArray()[0];
        this.ctx.storage.sql.exec("INSERT INTO budget_state(singleton,windows_json,tokens,updated_at,day,normalized_bytes,raw_bytes,artifact_bytes) VALUES (1,?,?,?,?,?,?,?)", JSON.stringify(windows), bucket?.tokens ?? -1, bucket?.updated_at ?? now, day, bytes?.normalized_bytes ?? 0, bytes?.raw_bytes ?? 0, bytes?.artifact_bytes ?? 0);
      }
      this.ctx.storage.sql.exec("DROP TABLE IF EXISTS concurrency");
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO maintenance(singleton,next_cleanup_at) VALUES (1,?)", now);
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (3,datetime('now'))");
    });
  }

  async admit(input: LimitAdmission): Promise<LimitDecision> {
    const effectful = input.effectful ?? input.family !== "read";
    this.prune(input.nowMs);
    if (input.concurrency !== undefined) this.ctx.storage.sql.exec("UPDATE concurrency_leases SET state='expired',updated_at=? WHERE state='active' AND expires_at<=?", input.nowMs, input.nowMs);
    const existing = effectful ? this.ctx.storage.sql.exec<{ payload_digest: string; decision_json: string }>("SELECT payload_digest,decision_json FROM idempotency WHERE key=? AND expires_at>?", input.idempotencyKey, input.nowMs).toArray()[0] : undefined;
    if (effectful && existing !== undefined) {
      if (existing.payload_digest !== input.payloadDigest) return { allowed: false, code: "idempotency_conflict", limitClass: "idempotency", retryAfterSeconds: 0 };
      return { ...(JSON.parse(existing.decision_json) as LimitDecision), ...(JSON.parse(existing.decision_json) as LimitDecision).allowed ? { charged: false } : {} } as LimitDecision;
    }
    const windowMs = input.windowSeconds * 1000;
    const windowStart = Math.floor(input.nowMs / windowMs) * windowMs;
    const budget = this.ctx.storage.sql.exec<{ windows_json: string; tokens: number; updated_at: number; day: string; normalized_bytes: number; raw_bytes: number; artifact_bytes: number }>("SELECT windows_json,tokens,updated_at,day,normalized_bytes,raw_bytes,artifact_bytes FROM budget_state WHERE singleton=1").one();
    const windows = JSON.parse(budget.windows_json) as Record<string, { windowStart: number; used: number }>;
    const currentWindow = windows[input.family];
    const window = currentWindow?.windowStart === windowStart ? currentWindow.used : 0;
    let decision: LimitDecision;
    if (window >= input.requestLimit) {
      decision = { allowed: false, code: "rate_limited", limitClass: `request.${input.family}`, retryAfterSeconds: Math.max(1, Math.ceil((windowStart + windowMs - input.nowMs) / 1000)) };
    } else {
      const startingTokens = budget.tokens < 0 ? input.capacity : budget.tokens;
      const available = Math.min(input.capacity, startingTokens + Math.max(0, input.nowMs - budget.updated_at) / 1000 * input.refillPerSecond);
      if (available < input.weight) decision = { allowed: false, code: "rate_limited", limitClass: "weighted_budget", retryAfterSeconds: input.refillPerSecond > 0 ? Math.max(1, Math.ceil((input.weight - available) / input.refillPerSecond)) : 3600 };
      else {
        const day = new Date(input.nowMs).toISOString().slice(0, 10);
        const usage = budget.day === day ? budget : { ...budget, normalized_bytes: 0, raw_bytes: 0, artifact_bytes: 0 };
        const over = input.responseBytes > input.byteLimits.response ? "response_bytes" : usage.normalized_bytes + input.normalizedLogBytes > input.byteLimits.normalizedDaily ? "normalized_log_bytes" : usage.raw_bytes + input.rawLogBytes > input.byteLimits.rawDaily ? "raw_log_bytes" : usage.artifact_bytes + input.artifactUploadBytes > input.byteLimits.artifactDaily ? "artifact_upload_bytes" : this.concurrencyDenial(input);
        if (over !== null) decision = { allowed: false, code: "resource_limit", limitClass: over, retryAfterSeconds: 86_400 };
        else {
          decision = { allowed: true, charged: true };
          this.ctx.storage.transactionSync(() => {
            windows[input.family] = { windowStart, used: window + 1 };
            this.ctx.storage.sql.exec("UPDATE budget_state SET windows_json=?,tokens=?,updated_at=?,day=?,normalized_bytes=?,raw_bytes=?,artifact_bytes=? WHERE singleton=1", JSON.stringify(windows), available - input.weight, input.nowMs, day, usage.normalized_bytes + input.normalizedLogBytes, usage.raw_bytes + input.rawLogBytes, usage.artifact_bytes + input.artifactUploadBytes);
            this.acquireInTransaction(input);
            if (effectful) this.ctx.storage.sql.exec("INSERT INTO idempotency(key,operation_id,payload_digest,decision_json,created_at,expires_at) VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET operation_id=excluded.operation_id,payload_digest=excluded.payload_digest,decision_json=excluded.decision_json,created_at=excluded.created_at,expires_at=excluded.expires_at", input.idempotencyKey, input.operationId, input.payloadDigest, JSON.stringify(decision), input.nowMs, input.idempotencyExpiresAtMs ?? input.nowMs + 86_400_000);
          });
        }
      }
    }
    if (effectful && !decision.allowed) this.ctx.storage.sql.exec("INSERT INTO idempotency(key,operation_id,payload_digest,decision_json,created_at,expires_at) VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET operation_id=excluded.operation_id,payload_digest=excluded.payload_digest,decision_json=excluded.decision_json,created_at=excluded.created_at,expires_at=excluded.expires_at", input.idempotencyKey, input.operationId, input.payloadDigest, JSON.stringify(decision), input.nowMs, input.idempotencyExpiresAtMs ?? input.nowMs + 86_400_000);
    return decision;
  }

  private concurrencyDenial(input: LimitAdmission): string | null {
    if (input.concurrency === undefined) return null;
    const { className, expiresAt, limit } = input.concurrency;
    const expiry = Date.parse(expiresAt);
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isFinite(expiry) || expiry <= input.nowMs) return `concurrency.${className}`;
    const existing = this.ctx.storage.sql.exec<{ class: string; state: string; expires_at: number }>("SELECT class,state,expires_at FROM concurrency_leases WHERE operation_id=?", input.operationId).toArray()[0];
    if (existing !== undefined) return existing.class === className && existing.state === "active" && existing.expires_at > input.nowMs ? null : `concurrency.${className}`;
    const active = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM concurrency_leases WHERE class=? AND state='active' AND expires_at>?", className, input.nowMs).one().count;
    return active >= limit ? `concurrency.${className}` : null;
  }

  private acquireInTransaction(input: LimitAdmission): void {
    if (input.concurrency === undefined) return;
    const existing = this.ctx.storage.sql.exec<{ operation_id: string }>("SELECT operation_id FROM concurrency_leases WHERE operation_id=? AND class=? AND state='active' AND expires_at>?", input.operationId, input.concurrency.className, input.nowMs).toArray()[0];
    if (existing !== undefined) return;
    this.ctx.storage.sql.exec("INSERT INTO concurrency_leases(operation_id,class,state,expires_at,created_at,updated_at) VALUES (?,?,'active',?,?,?)", input.operationId, input.concurrency.className, Date.parse(input.concurrency.expiresAt), input.nowMs, input.nowMs);
  }

  private prune(now: number): void {
    const maintenance = this.ctx.storage.sql.exec<{ next_cleanup_at: number }>("SELECT next_cleanup_at FROM maintenance WHERE singleton=1").one();
    if (maintenance.next_cleanup_at > now) return;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM idempotency WHERE key IN (SELECT key FROM idempotency WHERE expires_at<=? ORDER BY expires_at LIMIT 250)", now);
      this.ctx.storage.sql.exec("DELETE FROM concurrency_leases WHERE operation_id IN (SELECT operation_id FROM concurrency_leases WHERE state IN ('released','expired') OR expires_at<=? ORDER BY updated_at LIMIT 250)", now);
      this.ctx.storage.sql.exec("UPDATE maintenance SET next_cleanup_at=? WHERE singleton=1", now + 5 * 60_000);
    });
  }

  async acquire(operationId: string, className: "commands" | "agentRuns" | "runtimeStarts", limit: number, expiresAt: string): Promise<boolean> {
    const expiry = Date.parse(expiresAt);
    const now = Date.now();
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isFinite(expiry) || expiry <= now || operationId.length < 8 || operationId.length > 160) return false;
    this.prune(now);
    this.ctx.storage.sql.exec("UPDATE concurrency_leases SET state='expired',updated_at=? WHERE state='active' AND expires_at<=?", now, now);
    return this.ctx.storage.transactionSync(() => {
      const existing = this.ctx.storage.sql.exec<{ class: string; state: string; expires_at: number }>("SELECT class,state,expires_at FROM concurrency_leases WHERE operation_id=?", operationId).toArray()[0];
      if (existing !== undefined) return existing.class === className && existing.state === "active" && existing.expires_at > now;
      const active = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM concurrency_leases WHERE class=? AND state='active' AND expires_at>?", className, now).one().count;
      if (active >= limit) return false;
      this.ctx.storage.sql.exec("INSERT INTO concurrency_leases(operation_id,class,state,expires_at,created_at,updated_at) VALUES (?,?,'active',?,?,?)", operationId, className, expiry, now, now);
      return true;
    });
  }

  async release(operationId: string, className: "commands" | "agentRuns" | "runtimeStarts"): Promise<boolean> {
    const changed = this.ctx.storage.sql.exec<{ operation_id: string }>("DELETE FROM concurrency_leases WHERE operation_id=? AND class=? AND state='active' RETURNING operation_id", operationId, className).toArray();
    return changed.length === 1;
  }
}
