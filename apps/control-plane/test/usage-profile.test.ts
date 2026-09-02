import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { assertFreeD1Ceilings, instrumentD1, projectedObservabilityEvents, queueUsage } from "../src/usage-instrumentation.ts";
import { cloudflareUsageProfile, usageProfileForEnv } from "../src/usage-profile.ts";
import { projectCompositeSnapshot, sessionCompositeSnapshot } from "../src/snapshots.ts";

describe("Cloudflare usage profile and measurement harness", () => {
  it("defaults production templates and missing bindings to the Free profile", () => {
    expect(cloudflareUsageProfile(undefined)).toMatchObject({ name: "free", eventIngestionMode: "durable_inbox", eventBatchEvents: 32, eventBatchBytes: 60_000, cronBackstopMinutes: 5 });
    expect(usageProfileForEnv(env)).toMatchObject({ name: "free", logSamplingRate: 0.2, traceSamplingRate: 0.01 });
    expect(() => cloudflareUsageProfile("enterprise")).toThrow(/Unsupported/);
  });

  it("serves browser shells and JavaScript from the Static Assets binding", async () => {
    const [setup, login, device, dashboard, script, dashboardScript] = await Promise.all([
      env.ASSETS.fetch(new Request("https://conduit.example.com/setup")),
      env.ASSETS.fetch(new Request("https://conduit.example.com/login")),
      env.ASSETS.fetch(new Request("https://conduit.example.com/device")),
      env.ASSETS.fetch(new Request("https://conduit.example.com/dashboard")),
      env.ASSETS.fetch(new Request("https://conduit.example.com/static/auth-browser.js")),
      env.ASSETS.fetch(new Request("https://conduit.example.com/static/dashboard.js")),
    ]);
    expect([setup.status, login.status, device.status, dashboard.status, script.status, dashboardScript.status]).toEqual([200, 200, 200, 200, 200, 200]);
    expect(await setup.text()).toContain("passkey-setup");
    expect(await login.text()).toContain("passkey-sign-in");
    expect(await device.text()).toContain("device-enrollment-lookup");
    expect(await dashboard.text()).toContain("dashboard-session-form");
    expect(await dashboardScript.text()).toContain("buffered.splice");
    expect(script.headers.get("cache-control")).toContain("immutable");
  });

  it("measures real D1 result metadata and enforces per-invocation ceilings", async () => {
    const measured = instrumentD1(env.DB);
    const suffix = crypto.randomUUID().replaceAll("-", "");
    await measured.db.prepare("INSERT INTO schema_versions(component,version,applied_at) VALUES (?1,?2,?3)").bind(`budget_${suffix}`, 1, new Date().toISOString()).run();
    await measured.db.prepare("SELECT version FROM schema_versions WHERE component=?1").bind(`budget_${suffix}`).all();
    const snapshot = measured.snapshot();
    expect(snapshot).toMatchObject({ statements: 2, bindingCalls: 2, maxBoundParameters: 3 });
    expect(snapshot.rowsWritten).toBeGreaterThanOrEqual(1);
    expect(snapshot.rowsRead).toBeGreaterThanOrEqual(1);
    expect(() => assertFreeD1Ceilings(snapshot)).not.toThrow();
    expect(() => assertFreeD1Ceilings({ ...snapshot, statements: 41 })).toThrow(/statement budget/);
    expect(() => assertFreeD1Ceilings({ ...snapshot, bindingCalls: 41 })).toThrow(/binding-call budget/);
    expect(() => assertFreeD1Ceilings({ ...snapshot, maxBoundParameters: 91 })).toThrow(/parameter budget/);
  });

  it("counts Queue 64 KiB chunks, retries, and DLQ operations", () => {
    expect(queueUsage([60_000])).toMatchObject({ messages: 1, chunks: 1, totalOperations: 3 });
    expect(queueUsage([65_537])).toMatchObject({ messages: 1, chunks: 2, totalOperations: 6 });
    expect(queueUsage([60_000], { retries: 2 })).toMatchObject({ retryReadOperations: 2, totalOperations: 5 });
    expect(queueUsage([60_000], { retries: 5, deadLetter: true })).toMatchObject({ deadLetterOperations: 2, totalOperations: 9 });
  });

  it("keeps the Free production log and post-2026-10-01 trace projection below 25%", () => {
    const projection = projectedObservabilityEvents(100_000, { logSamplingRate: 0.2, traceSamplingRate: 0.01, spansPerTrace: 2 });
    expect(projection).toEqual({ logEvents: 20_000, traceSpans: 2_000, total: 22_000 });
    expect(projection.total).toBeLessThanOrEqual(50_000);
  });

  it("builds bounded dashboard snapshots in seven D1 statements", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const projectId = `prj_budget_${suffix}`;
    const sessionId = `csess_budget_${suffix}`;
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'Budget snapshot',?2,?2)").bind(projectId, now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'Budget snapshot',?3,?3)").bind(sessionId, projectId, now),
    ]);
    const sessionD1 = instrumentD1(env.DB);
    const session = await sessionCompositeSnapshot(sessionD1.db, sessionId);
    expect(session).toMatchObject({ kind: "session_snapshot", session: { id: sessionId, project_id: projectId } });
    expect(sessionD1.snapshot()).toMatchObject({ statements: 7, maxBoundParameters: 1 });
    assertFreeD1Ceilings(sessionD1.snapshot());
    const projectD1 = instrumentD1(env.DB);
    const project = await projectCompositeSnapshot(projectD1.db, projectId);
    expect(project).toMatchObject({ kind: "project_snapshot", project: { id: projectId } });
    expect(projectD1.snapshot()).toMatchObject({ statements: 7, maxBoundParameters: 1 });
    assertFreeD1Ceilings(projectD1.snapshot());
  });
});
