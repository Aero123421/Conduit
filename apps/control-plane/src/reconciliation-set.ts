import type { ControlPlaneEnv } from "./types.ts";

const U64 = /^(0|[1-9][0-9]{0,19})$/u;
const RUN_ID = /^(?:run|lrun)_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u;
const OPERATION_ID = /^op_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface ReconciliationEventRange {
  runId: string;
  fromSequence: string;
  throughSequence: string;
}

export interface ReconciliationRunSummary {
  runId: string;
  operationId: string;
  requestDigest: string;
}

export interface ReconciliationSetInput {
  retainedEventRanges: readonly ReconciliationEventRange[];
  runs: readonly ReconciliationRunSummary[];
}

export interface ReconciliationSetPlan {
  eventReplay: Array<{ runId: string; from: string; through: string }>;
  statusRunIds: string[];
  cancelOperationIds: string[];
  quarantineRunIds: string[];
  d1: {
    statements: number;
    bindingCalls: number;
    boundParameters: number;
    maxBoundParameters: number;
    rowsRead: number;
    rowsWritten: number;
  };
}

interface EventRangeRow {
  run_id: string;
  from_sequence: string;
  through_sequence: string;
  last_sequence: string | null;
}

interface RunSetRow {
  run_id: string;
  operation_id: string;
  request_digest: string;
  operation_run_id: string | null;
  payload_digest: string | null;
  operation_state: string | null;
}

function u64Less(left: string, right: string): boolean {
  return left.length < right.length || (left.length === right.length && left < right);
}

function u64Next(value: string): string {
  return (BigInt(value) + 1n).toString();
}

function addMeta(target: ReconciliationSetPlan["d1"], result: { meta?: { rows_read?: number; rows_written?: number } } | undefined): void {
  target.rowsRead += typeof result?.meta?.rows_read === "number" ? result.meta.rows_read : 0;
  target.rowsWritten += typeof result?.meta?.rows_written === "number" ? result.meta.rows_written : 0;
}

/**
 * Resolve all event ranges and run summaries with two json_each set queries.
 * This is intentionally independent of DeviceRoom so the DO can retain its
 * local custody/transport implementation while using a bounded D1 adapter.
 */
export async function planReconciliationSets(env: ControlPlaneEnv, input: ReconciliationSetInput): Promise<ReconciliationSetPlan> {
  if (!Array.isArray(input.retainedEventRanges) || !Array.isArray(input.runs)) throw new TypeError("reconciliation summary sets are invalid");
  const ranges = input.retainedEventRanges.slice(0, 512);
  const runs = input.runs.slice(0, 256);
  if (ranges.some((range) => !isReconciliationRange(range))) throw new TypeError("reconciliation event range is invalid");
  if (runs.some((run) => !isReconciliationRunSummary(run))) throw new TypeError("reconciliation run summary is invalid");
  const d1 = { statements: 0, bindingCalls: 0, boundParameters: 0, maxBoundParameters: 0, rowsRead: 0, rowsWritten: 0 };
  const eventRowsResult = await env.DB.prepare(`
    WITH requested AS (
      SELECT json_extract(value,'$.runId') AS run_id,
             json_extract(value,'$.fromSequence') AS from_sequence,
             json_extract(value,'$.throughSequence') AS through_sequence
      FROM json_each(?1)
    )
    SELECT requested.run_id,requested.from_sequence,requested.through_sequence,
           trace.last_sequence
    FROM requested
    LEFT JOIN trace_indexes AS trace ON trace.run_id=requested.run_id
  `).bind(JSON.stringify(ranges)).all<EventRangeRow>();
  d1.statements += 1;
  d1.bindingCalls += 1;
  d1.boundParameters += 1;
  d1.maxBoundParameters = Math.max(d1.maxBoundParameters, 1);
  addMeta(d1, eventRowsResult);

  const eventReplay: Array<{ runId: string; from: string; through: string }> = [];
  for (const row of eventRowsResult.results) {
    const floor = BigInt(row.from_sequence);
    const through = BigInt(row.through_sequence);
    const next = row.last_sequence === null ? floor : BigInt(row.last_sequence) + 1n;
    const from = next > floor ? next : floor;
    if (from <= through) eventReplay.push({ runId: row.run_id, from: from.toString(), through: row.through_sequence });
  }

  const runRowsResult = await env.DB.prepare(`
    WITH requested AS (
      SELECT json_extract(value,'$.runId') AS run_id,
             json_extract(value,'$.operationId') AS operation_id,
             json_extract(value,'$.requestDigest') AS request_digest
      FROM json_each(?1)
    )
    SELECT requested.run_id,requested.operation_id,requested.request_digest,
           operation.run_id AS operation_run_id,operation.payload_digest,operation.state AS operation_state
    FROM requested
    LEFT JOIN operation_journal AS operation ON operation.id=requested.operation_id
  `).bind(JSON.stringify(runs)).all<RunSetRow>();
  d1.statements += 1;
  d1.bindingCalls += 1;
  d1.boundParameters += 1;
  d1.maxBoundParameters = Math.max(d1.maxBoundParameters, 1);
  addMeta(d1, runRowsResult);

  const statusRunIds: string[] = [];
  const cancelOperationIds: string[] = [];
  const quarantineRunIds: string[] = [];
  for (const row of runRowsResult.results) {
    if (row.operation_run_id !== row.run_id || row.payload_digest === null || row.payload_digest !== row.request_digest) quarantineRunIds.push(row.run_id);
    else if (row.operation_state === "cancelled") cancelOperationIds.push(row.operation_id);
    else if (!["completed", "failed", "cancelled", "expired", "rejected"].includes(row.operation_state ?? "")) statusRunIds.push(row.run_id);
  }
  return {
    eventReplay,
    statusRunIds: [...new Set(statusRunIds)],
    cancelOperationIds: [...new Set(cancelOperationIds)],
    quarantineRunIds: [...new Set(quarantineRunIds)],
    d1,
  };
}

/** Type guard useful to adapters before passing untrusted summary JSON here. */
export function isReconciliationRange(value: unknown): value is ReconciliationEventRange {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.runId === "string" && RUN_ID.test(item.runId)
    && typeof item.fromSequence === "string" && U64.test(item.fromSequence)
    && typeof item.throughSequence === "string" && U64.test(item.throughSequence)
    && BigInt(item.fromSequence) <= BigInt(item.throughSequence);
}

export function isReconciliationRunSummary(value: unknown): value is ReconciliationRunSummary {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.runId === "string" && RUN_ID.test(item.runId)
    && typeof item.operationId === "string" && OPERATION_ID.test(item.operationId)
    && typeof item.requestDigest === "string" && SHA256.test(item.requestDigest);
}

/** Keep the sequence helpers available to tests without making SQL compare U64 as INTEGER. */
export const reconciliationSequence = { less: u64Less, next: u64Next };
