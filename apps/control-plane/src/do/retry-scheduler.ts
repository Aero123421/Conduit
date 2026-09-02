import { DurableObject } from "cloudflare:workers";
import { attemptApprovalDispatch } from "../approval-dispatch.ts";
import { attemptOperationDispatch } from "../dispatch.ts";
import { reconcileRealtimeProjections } from "../realtime-outbox.ts";
import { cleanupHotData } from "../retention.ts";
import type { RetryWork, RetryWorkKind } from "../retry-scheduler-client.ts";
import type { ControlPlaneEnv } from "../types.ts";

interface DueWorkRow extends Record<string, SqlStorageValue> {
  kind: RetryWorkKind;
  target_id: string;
  due_at: string;
}

const OUTER_D1_STATEMENT_BUDGET = 40;
// Dispatch/approval/realtime helpers may evolve independently. Reserve a
// conservative 32 statements for each external work item and spend that
// reservation before starting it. This makes the alarm stop after one item;
// remaining due rows cause armNext() to schedule an immediate continuation.
const D1_STATEMENT_RESERVATION_PER_WORK = 32;

export class RetryScheduler extends DurableObject<ControlPlaneEnv> {
  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS due_work(
          kind TEXT NOT NULL CHECK(kind IN ('operation','approval','realtime','retention')),
          target_id TEXT NOT NULL,
          due_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY(kind,target_id)
        );
        CREATE INDEX IF NOT EXISTS idx_due_work_due ON due_work(due_at,kind,target_id);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
      `);
      await this.armNext();
    });
  }

  async schedule(work: RetryWork): Promise<void> {
    if (!Number.isFinite(Date.parse(work.dueAt))) throw new TypeError("scheduler dueAt is invalid");
    const now = new Date().toISOString();
    this.ctx.storage.sql.exec(
      "INSERT INTO due_work(kind,target_id,due_at,created_at,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(kind,target_id) DO UPDATE SET due_at=excluded.due_at,updated_at=excluded.updated_at",
      work.kind,
      work.targetId,
      work.dueAt,
      now,
      now,
    );
    await this.armNext();
  }

  async clear(kind: RetryWorkKind, targetId: string): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM due_work WHERE kind=? AND target_id=?", kind, targetId);
    await this.armNext();
  }

  async backstop(nowValue: string): Promise<void> {
    if (!Number.isFinite(Date.parse(nowValue))) throw new TypeError("scheduler backstop time is invalid");
    const next = await this.discoverD1Due(new Date(nowValue));
    for (const work of next) {
      this.ctx.storage.sql.exec(
        "INSERT INTO due_work(kind,target_id,due_at,created_at,updated_at) VALUES (?,?,?,?,?) ON CONFLICT(kind,target_id) DO UPDATE SET due_at=MIN(due_work.due_at,excluded.due_at),updated_at=excluded.updated_at",
        work.kind,
        work.targetId,
        work.dueAt,
        nowValue,
        nowValue,
      );
    }
    await this.armNext();
  }

  async inspectBudget(): Promise<{ pending: number; alarmAt: number | null; nextDueAt: string | null }> {
    const row = this.ctx.storage.sql.exec<{ count: number; next_due_at: string | null }>("SELECT COUNT(*) AS count,MIN(due_at) AS next_due_at FROM due_work").one();
    return { pending: row.count, alarmAt: await this.ctx.storage.getAlarm(), nextDueAt: row.next_due_at };
  }

  async inspectTarget(kind: RetryWorkKind, targetId: string): Promise<{ dueAt: string } | null> {
    const row = this.ctx.storage.sql.exec<{ due_at: string }>("SELECT due_at FROM due_work WHERE kind=? AND target_id=? LIMIT 1", kind, targetId).toArray()[0];
    return row === undefined ? null : { dueAt: row.due_at };
  }

  override async alarm(): Promise<void> {
    const now = new Date();
    const rows = this.ctx.storage.sql.exec<DueWorkRow>(
      "SELECT kind,target_id,due_at FROM due_work WHERE due_at<=? ORDER BY due_at,kind,target_id LIMIT ?",
      now.toISOString(),
      32,
    ).toArray();
    let remainingD1Statements = OUTER_D1_STATEMENT_BUDGET;
    for (const row of rows) {
      if (remainingD1Statements < D1_STATEMENT_RESERVATION_PER_WORK) break;
      remainingD1Statements -= D1_STATEMENT_RESERVATION_PER_WORK;
      await this.runWork(row, now);
    }
    await this.armNext();
  }

  private async runWork(row: DueWorkRow, now: Date): Promise<void> {
    if (row.kind === "operation") {
      const result = await attemptOperationDispatch(this.env, row.target_id, { now, scheduleRetry: false });
      if (result?.state === "queued" && result.dispatch !== undefined) this.replaceDue(row, result.dispatch.nextAttemptAt, now);
      else this.deleteExact(row);
      return;
    }
    if (row.kind === "approval") {
      await attemptApprovalDispatch(this.env, row.target_id, now, undefined, false);
      const current = await this.env.DB.prepare("SELECT state,next_attempt_at FROM approval_dispatch_outbox WHERE approval_id=?1 LIMIT 1")
        .bind(row.target_id).first<{ state: string; next_attempt_at: string }>();
      if (current?.state === "pending" || current?.state === "dispatching") this.replaceDue(row, current.next_attempt_at, now);
      else this.deleteExact(row);
      return;
    }
    if (row.kind === "realtime") {
      const result = await reconcileRealtimeProjections(this.env, row.target_id, { now, scheduleRetry: false });
      if (result.nextAttemptAt === null) this.deleteExact(row);
      else this.replaceDue(row, result.nextAttemptAt, now);
      return;
    }
    const result = await cleanupHotData(this.env, { now });
    if (result.hasMore && result.nextDueAt !== null) this.replaceDue(row, result.nextDueAt, now);
    else this.deleteExact(row);
  }

  private replaceDue(row: DueWorkRow, dueAt: string, now: Date): void {
    this.ctx.storage.sql.exec(
      "UPDATE due_work SET due_at=?,updated_at=? WHERE kind=? AND target_id=? AND due_at=?",
      dueAt,
      now.toISOString(),
      row.kind,
      row.target_id,
      row.due_at,
    );
  }

  private deleteExact(row: DueWorkRow): void {
    this.ctx.storage.sql.exec("DELETE FROM due_work WHERE kind=? AND target_id=? AND due_at=?", row.kind, row.target_id, row.due_at);
  }

  private async armNext(): Promise<void> {
    const row = this.ctx.storage.sql.exec<{ due_at: string }>("SELECT due_at FROM due_work ORDER BY due_at,kind,target_id LIMIT 1").toArray()[0];
    if (row === undefined) {
      if (await this.ctx.storage.getAlarm() !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    // A one-second continuation is operationally immediate while preventing
    // a due backlog from collapsing several outer alarm invocations into one
    // platform turn and defeating the per-invocation D1 reservation.
    const due = Math.max(Date.now() + 1_000, Date.parse(row.due_at));
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || Math.abs(alarm - due) > 1_000) await this.ctx.storage.setAlarm(due);
  }

  private async discoverD1Due(now: Date): Promise<RetryWork[]> {
    const at = now.toISOString();
    const results = await this.env.DB.batch([
      this.env.DB.prepare("SELECT operation_id AS target_id,MIN(CASE WHEN state='dispatching' THEN lease_expires_at ELSE next_attempt_at END) AS due_at FROM operation_dispatch_outbox WHERE state IN ('pending','dispatching') GROUP BY operation_id ORDER BY due_at LIMIT 32"),
      this.env.DB.prepare("SELECT approval_id AS target_id,MIN(CASE WHEN state='dispatching' THEN lease_expires_at ELSE next_attempt_at END) AS due_at FROM approval_dispatch_outbox WHERE state IN ('pending','dispatching') GROUP BY approval_id ORDER BY due_at LIMIT 32"),
      this.env.DB.prepare("SELECT device_id AS target_id,MIN(CASE WHEN state='publishing' THEN lease_expires_at ELSE next_attempt_at END) AS due_at FROM realtime_projection_outbox WHERE state IN ('pending','publishing') GROUP BY device_id ORDER BY due_at LIMIT 32"),
      this.env.DB.prepare(`
        SELECT CASE WHEN
          EXISTS(SELECT 1 FROM retention_cleanup_state WHERE continuation_due_at<=?1)
          OR EXISTS(SELECT 1 FROM realtime_projection_outbox WHERE state='published' AND published_at<=?2)
          OR EXISTS(SELECT 1 FROM node_projection_receipts WHERE frame_type='device.health' AND created_at<=?2)
          OR EXISTS(SELECT 1 FROM auth_challenges WHERE expires_at<=?1 OR consumed_at<=?2)
          OR EXISTS(SELECT 1 FROM oauth_authorization_codes WHERE expires_at<=?1 OR consumed_at<=?2)
          OR EXISTS(SELECT 1 FROM oauth_tokens WHERE expires_at<=?1 OR consumed_at<=?2 OR revoked_at<=?2)
          OR EXISTS(SELECT 1 FROM oauth_consent_transactions WHERE expires_at<=?1 OR consumed_at<=?2)
          OR EXISTS(SELECT 1 FROM oauth_clients WHERE registration_mechanism='dynamic' AND status='pending_owner' AND expires_at<=?1)
          OR EXISTS(SELECT 1 FROM device_enrollments WHERE state IN ('denied','expired','cancelled') AND COALESCE(terminal_at,expires_at)<=?2 AND assigned_device_id IS NULL)
          OR EXISTS(SELECT 1 FROM effect_idempotency_records WHERE expires_at<=?1)
          OR EXISTS(SELECT 1 FROM idempotency_records WHERE expires_at<=?1)
          OR EXISTS(SELECT 1 FROM normalized_events WHERE retention_class='streaming_delta' AND expires_at<=?1)
          OR EXISTS(SELECT 1 FROM realtime_delivery_receipts WHERE expires_at<=?1)
          OR EXISTS(SELECT 1 FROM operation_dispatch_outbox WHERE state='expired' AND expires_at<=?3)
          OR EXISTS(SELECT 1 FROM approval_dispatch_outbox WHERE state IN ('offered','expired') AND expires_at<=?3)
          OR EXISTS(SELECT 1 FROM privilege_ticket_requests WHERE status IN ('denied','expired','conflict') AND COALESCE(terminal_at,expires_at)<=?3)
        THEN ?1 ELSE NULL END AS due_at
      `).bind(at, new Date(now.getTime() - 86_400_000).toISOString(), new Date(now.getTime() - 7 * 86_400_000).toISOString()),
    ]);
    const operations = results[0];
    const approvals = results[1];
    const realtime = results[2];
    const retention = results[3];
    if (operations === undefined || approvals === undefined || realtime === undefined || retention === undefined) throw new TypeError("scheduler backstop query result is incomplete");
    const work: RetryWork[] = [];
    for (const row of operations.results as Array<{ target_id: string; due_at: string }>) work.push({ kind: "operation", targetId: row.target_id, dueAt: row.due_at });
    for (const row of approvals.results as Array<{ target_id: string; due_at: string }>) work.push({ kind: "approval", targetId: row.target_id, dueAt: row.due_at });
    for (const row of realtime.results as Array<{ target_id: string; due_at: string }>) work.push({ kind: "realtime", targetId: row.target_id, dueAt: row.due_at });
    const retentionDue = (retention.results as Array<{ due_at: string | null }>)[0]?.due_at;
    if (retentionDue !== null && retentionDue !== undefined) work.push({ kind: "retention", targetId: "hot-data", dueAt: retentionDue });
    return work;
  }
}
