import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { planReconciliationSets } from "../src/reconciliation-set.ts";

describe("bounded reconciliation set queries", () => {
  it("handles the protocol maxima with two D1 statements", async () => {
    const ranges = Array.from({ length: 512 }, (_, index) => ({
      runId: `run_reconcile_range_${String(index).padStart(4, "0")}`,
      fromSequence: "1",
      throughSequence: "3",
    }));
    const runs = Array.from({ length: 256 }, (_, index) => ({
      runId: `run_reconcile_run_${String(index).padStart(4, "0")}`,
      operationId: `op_reconcile_run_${String(index).padStart(4, "0")}`,
      requestDigest: "a".repeat(64),
    }));

    const plan = await planReconciliationSets(env as never, { retainedEventRanges: ranges, runs });
    expect(plan.eventReplay).toHaveLength(512);
    expect(plan.quarantineRunIds).toHaveLength(256);
    expect(plan.statusRunIds).toHaveLength(0);
    expect(plan.cancelOperationIds).toHaveLength(0);
    expect(plan.d1).toMatchObject({ statements: 2, bindingCalls: 2, boundParameters: 2, maxBoundParameters: 1 });
    expect(plan.d1.rowsRead).toBeGreaterThanOrEqual(0);
    expect(plan.d1.rowsWritten).toBeGreaterThanOrEqual(0);
  });
});
