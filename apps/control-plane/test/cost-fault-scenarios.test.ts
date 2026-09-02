import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { handleApi } from "../src/api.ts";
import { AuthRepository } from "../src/repositories/auth.ts";
import { canonicalJson, keyedHash, sha256Hex } from "../src/crypto.ts";
import {
  buildEventBatch,
  consumeEvents,
  type EventBatchMessage,
} from "../src/ingestion.ts";
import {
  assertFreeD1Ceilings,
  instrumentD1,
  queueUsage,
  type D1UsageSnapshot,
} from "../src/usage-instrumentation.ts";
import type { ControlPlaneEnv, QueueEventMessage } from "../src/types.ts";

interface CostFixture {
  suffix: string;
  principalId: string;
  token: string;
  projectId: string;
  sessionId: string;
  agentId: string;
  deviceId: string;
  browserSession: { token: string; csrf: string };
}

interface CostSummary {
  invocations: number;
  totalStatements: number;
  maxStatements: number;
  totalBindingCalls: number;
  maxBindingCalls: number;
  maxBoundParameters: number;
  totalBoundParameters: number;
  totalRowsRead: number;
  totalRowsWritten: number;
}

function digestFor(index: number): string {
  return index.toString(16).padStart(64, "0");
}

function eventFor(runId: string, deviceId: string, suffix: string, sequence: number, eventId = `evt_${suffix}_${String(sequence).padStart(8, "0")}`): QueueEventMessage {
  return {
    schemaVersion: 1,
    kind: "normalized_event",
    eventId,
    runId,
    deviceId,
    sequence: String(sequence),
    eventType: "adapter.assistant_message_delta",
    source: "agent",
    observedAt: "2026-09-02T00:00:00.000Z",
    nodeBootId: `boot_${suffix}`,
    evidenceLevel: "observed",
    sensitivity: "metadata",
    retentionClass: "R1",
    payloadDigest: digestFor(10_000 + sequence),
    eventDigest: digestFor(sequence),
    previousChainHash: digestFor(sequence - 1),
    chainHash: digestFor(20_000 + sequence),
    payload: { text: `delta-${sequence}` },
  } as QueueEventMessage;
}

async function sourceDigest(runId: string, fromSequence: string, throughSequence: string, values: readonly unknown[]): Promise<string> {
  return sha256Hex(canonicalJson({
    runId,
    fromSequence,
    throughSequence,
    events: await Promise.all(values.map(async (value, index) => {
      const record = value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
      return {
        sequence: typeof record?.sequence === "string" ? record.sequence : String(BigInt(fromSequence) + BigInt(index)),
        eventDigest: typeof record?.eventDigest === "string" ? record.eventDigest : await sha256Hex(canonicalJson(value)),
      };
    })),
  }));
}

async function seedRun(runId: string, deviceId: string, suffix: string): Promise<void> {
  const now = new Date().toISOString();
  const enrollmentId = `enroll_${suffix}`;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8)")
      .bind(enrollmentId, `a${suffix}`, `b${suffix}`, `dkey_${suffix}`, `c${suffix}`, deviceId, now, new Date(Date.now() + 86_400_000).toISOString()),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Cost fault fixture','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)")
      .bind(deviceId, enrollmentId, now),
    env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,created_at,updated_at) VALUES (?1,?2,'native','project_full','always','queued',?3,?3)")
      .bind(runId, deviceId, now),
  ]);
}

function fakeBindings(): Pick<ControlPlaneEnv, "DEVICE_ROOMS" | "BOARD_ROOMS" | "RETRY_SCHEDULER"> {
  const deviceRoom = {
    offer: async (_frame: unknown) => ({ sequence: "1", delivered: true }),
    deliverApproval: async (_frame: unknown) => undefined,
  };
  const boardRoom = {
    publish: async (_event: unknown) => 1,
  };
  const retryScheduler = {
    schedule: async (_work: unknown) => undefined,
    clear: async (_kind: unknown, _targetId: unknown) => undefined,
    backstop: async (_now: unknown) => undefined,
  };

  // Miniflare's namespace stubs are RPC-branded and cannot be structurally
  // constructed in a unit test. The test only exercises the three methods
  // called by the production paths above, so keep the cast at this boundary.
  const deviceRooms = { getByName: (_name: string) => deviceRoom } as unknown as ControlPlaneEnv["DEVICE_ROOMS"];
  const boardRooms = { getByName: (_name: string) => boardRoom } as unknown as ControlPlaneEnv["BOARD_ROOMS"];
  const scheduler = { getByName: (_name: string) => retryScheduler } as unknown as ControlPlaneEnv["RETRY_SCHEDULER"];
  return { DEVICE_ROOMS: deviceRooms, BOARD_ROOMS: boardRooms, RETRY_SCHEDULER: scheduler };
}

function testEnv(database: D1Database): ControlPlaneEnv {
  return { ...env, DB: database, ...fakeBindings() } as ControlPlaneEnv;
}

function lostBatchResponse(database: D1Database, failOnBatch: number): { database: D1Database; batches: () => number } {
  let batches = 0;
  const databaseWithLoss = new Proxy(database, {
    get(target, property, receiver) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const batchNumber = batches + 1;
          const result = await target.batch(statements);
          batches = batchNumber;
          if (batchNumber === failOnBatch) throw new Error("simulated D1 response loss after commit");
          return result;
        };
      }
      return Reflect.get(target, property, receiver);
    },
  });
  return { database: databaseWithLoss, batches: () => batches };
}

function addSnapshot(summary: CostSummary, snapshot: D1UsageSnapshot): void {
  summary.invocations += 1;
  summary.totalStatements += snapshot.statements;
  summary.maxStatements = Math.max(summary.maxStatements, snapshot.statements);
  summary.totalBindingCalls += snapshot.bindingCalls;
  summary.maxBindingCalls = Math.max(summary.maxBindingCalls, snapshot.bindingCalls);
  summary.maxBoundParameters = Math.max(summary.maxBoundParameters, snapshot.maxBoundParameters);
  summary.totalBoundParameters += snapshot.boundParameters.reduce((sum, count) => sum + count, 0);
  summary.totalRowsRead += snapshot.rowsRead;
  summary.totalRowsWritten += snapshot.rowsWritten;
  assertFreeD1Ceilings(snapshot);
}

function newSummary(): CostSummary {
  return {
    invocations: 0,
    totalStatements: 0,
    maxStatements: 0,
    totalBindingCalls: 0,
    maxBindingCalls: 0,
    maxBoundParameters: 0,
    totalBoundParameters: 0,
    totalRowsRead: 0,
    totalRowsWritten: 0,
  };
}

async function seedCostFixture(): Promise<CostFixture> {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const principalId = `prin_cost_${suffix}`;
  const token = `conduit_owner_cost_${suffix}`;
  const projectId = `prj_cost_${suffix}`;
  const sessionId = `csess_cost_${suffix}`;
  const agentId = `pagent_cost_${suffix}`;
  const deviceId = `dev_cost_${suffix}`;
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 86_400_000).toISOString();
  const enrollmentId = `enroll_cost_${suffix}`;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES (?1,'Cost fixture owner','active',?2,?2)").bind(principalId, now),
    env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,created_at,last_used_at,expires_at) VALUES (?1,?2,?3,'Cost fixture','active',?4,?4,?5)").bind(`otk_cost_${suffix}`, principalId, await keyedHash(env.TOKEN_PEPPER, token), now, expires),
    env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8)").bind(enrollmentId, `a${suffix}`, `b${suffix}`, `dkey_${suffix}`, `c${suffix}`, deviceId, now, expires),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Cost fixture device','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now),
    env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'Cost fixture project',?2,?2)").bind(projectId, now),
    env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'Cost fixture session',?3,?3)").bind(sessionId, projectId, now),
    env.DB.prepare("INSERT INTO project_agents(id,project_id,name,adapter_id,role,configuration_json,status,created_at,updated_at) VALUES (?1,?2,'Builder','codex','implementer','{}','active',?3,?3)").bind(agentId, projectId, now),
  ]);
  const browserSession = await new AuthRepository(env.DB, env.TOKEN_PEPPER).createSession(principalId, "owner", true);
  return { suffix, principalId, token, projectId, sessionId, agentId, deviceId, browserSession };
}

async function seedApprovalRows(fixture: CostFixture, count: number): Promise<{ approvalIds: string[]; digests: string[] }> {
  const approvalIds: string[] = [];
  const digests: string[] = [];
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 86_400_000).toISOString();
  for (let start = 0; start < count; start += 16) {
    const statements: D1PreparedStatement[] = [];
    for (let index = start; index < Math.min(start + 16, count); index += 1) {
      const operationId = `op_cost_approval_${fixture.suffix}_${index}`;
      const runId = `run_cost_approval_${fixture.suffix}_${index}`;
      const approvalId = `approval_cost_${fixture.suffix}_${index}`;
      const digest = digestFor(40_000 + index);
      approvalIds.push(approvalId);
      digests.push(digest);
      statements.push(
        env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,created_at,updated_at) VALUES (?1,?2,'native','project_full','always','waiting_approval',?3,?3)").bind(runId, fixture.deviceId, now),
        env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,run_id,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,?2,?3,'cost.simulator',?4,?5,'agent.run.start',?6,'{}','queued',?7,?8,?8)").bind(operationId, `cost-approval-operation-${fixture.suffix}-${index}`, fixture.principalId, fixture.deviceId, runId, digestFor(50_000 + index), expires, now),
        env.DB.prepare("INSERT INTO approvals(id,operation_id,requester_principal_id,client_id,device_id,run_id,commitment_digest,operation_type,normalized_arguments_json,revisions_json,reuse_scope_json,expires_at,created_at) VALUES (?1,?2,?3,'cost.simulator',?4,?5,?6,'item/commandExecution/requestApproval','{}','{\"controllerEpoch\":\"1\"}','{\"kind\":\"once\"}',?7,?8)").bind(approvalId, operationId, fixture.principalId, fixture.deviceId, runId, digest, expires, now),
      );
    }
    await env.DB.batch(statements);
  }
  return { approvalIds, digests };
}

async function resolveApprovalRequest(fixture: CostFixture, database: D1Database, approvalId: string, digest: string, index: number): Promise<Response> {
  const request = new Request(`https://conduit.example.com/v1/approvals/${approvalId}/resolve`, {
    method: "POST",
    headers: {
      cookie: `__Host-conduit_session=${fixture.browserSession.token}`,
      origin: env.PUBLIC_ORIGIN,
      "x-csrf-token": fixture.browserSession.csrf,
      "content-type": "application/json",
      "idempotency-key": `cost-approval-resolve-${fixture.suffix}-${index}`,
    },
    body: JSON.stringify({ decision: "approved", commitmentDigest: digest }),
  });
  const response = await handleApi(request, testEnv(database), `/v1/approvals/${approvalId}/resolve`);
  if (response === null) throw new Error("approval route was not handled");
  return response;
}

describe.sequential("Required cost and fault scenarios", () => {
  it("retries a Queue message without quarantining valid siblings with its poison event", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const runId = `run_queue_fault_${suffix}`;
    const deviceId = `dev_queue_fault_${suffix}`;
    await seedRun(runId, deviceId, `queue_fault_${suffix}`);
    const validOne = eventFor(runId, deviceId, suffix, 1);
    const poison = { ...eventFor(runId, deviceId, suffix, 2), eventDigest: "not-a-digest" } as QueueEventMessage;
    const validTwo = eventFor(runId, deviceId, suffix, 3);
    const values = [validOne, poison, validTwo];
    const body: EventBatchMessage = {
      runId,
      fromSequence: "1",
      throughSequence: "3",
      sourceSequenceRange: { from: "1", through: "3" },
      sourceRangeDigest: await sourceDigest(runId, "1", "3", values),
      traceSchema: "conduit.trace/1",
      events: values,
      deviceId,
    };
    const loss = lostBatchResponse(env.DB, 2);
    const measured = instrumentD1(loss.database);
    const calls: string[] = [];
    const message = (attempts: number) => ({
      id: "queue-cost-poison-retry01",
      body,
      attempts,
      ack: () => calls.push("ack"),
      retry: (options?: { delaySeconds?: number }) => calls.push(`retry:${options?.delaySeconds ?? 0}`),
    });

    await consumeEvents({ messages: [message(1)] } as never, testEnv(measured.db));
    await consumeEvents({ messages: [message(2)] } as never, testEnv(measured.db));

    expect(calls).toEqual(["retry:5", "ack"]);
    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM normalized_events WHERE run_id=?1) AS events,(SELECT COUNT(*) FROM security_events WHERE event_type='event_ingestion.poison' AND json_extract(metadata_json,'$.messageId')=?2) AS poison_evidence").bind(runId, "queue-cost-poison-retry01").first<{ events: number; poison_evidence: number }>();
    expect(counts).toEqual({ events: 2, poison_evidence: 1 });
    const evidence = await env.DB.prepare("SELECT reason_code,metadata_json FROM security_events WHERE event_type='event_ingestion.poison' AND json_extract(metadata_json,'$.messageId')=?1").bind("queue-cost-poison-retry01").first<{ reason_code: string; metadata_json: string }>();
    expect(evidence?.reason_code).toBe("event_digest_invalid");
    expect(JSON.parse(evidence?.metadata_json ?? "{}")).toMatchObject({ eventId: poison.eventId, runId, sequence: "2" });

    const bytes = new TextEncoder().encode(JSON.stringify(body)).byteLength;
    expect(bytes).toBeLessThan(65_536);
    expect(queueUsage([bytes], { retries: 1 })).toMatchObject({ messages: 1, chunks: 1, retryReadOperations: 1, deadLetterOperations: 0, totalOperations: 4 });
    expect(loss.batches()).toBe(3);
    const snapshot = measured.snapshot();
    expect(snapshot).toMatchObject({ statements: 6, bindingCalls: 6, maxBoundParameters: 6 });
    assertFreeD1Ceilings(snapshot);
    console.log(`CONDUIT_QUEUE_POISON_RETRY=${JSON.stringify({ d1: snapshot, queue: queueUsage([bytes], { retries: 1 }), calls })}`);
  }, 120_000);

  it("replays an event.batch exactly once after a committed D1 response is lost", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const runId = `run_d1_replay_${suffix}`;
    const deviceId = `dev_d1_replay_${suffix}`;
    await seedRun(runId, deviceId, `d1_replay_${suffix}`);
    const events = [eventFor(runId, deviceId, suffix, 1), eventFor(runId, deviceId, suffix, 2)];
    const body = buildEventBatch(events);
    const loss = lostBatchResponse(env.DB, 1);
    const measured = instrumentD1(loss.database);
    const calls: string[] = [];
    const message = (attempts: number) => ({
      id: "queue-cost-response-loss01",
      body,
      attempts,
      ack: () => calls.push("ack"),
      retry: (options?: { delaySeconds?: number }) => calls.push(`retry:${options?.delaySeconds ?? 0}`),
    });

    await consumeEvents({ messages: [message(1)] } as never, testEnv(measured.db));
    await consumeEvents({ messages: [message(2)] } as never, testEnv(measured.db));

    expect(calls).toEqual(["retry:5", "ack"]);
    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM normalized_events WHERE run_id=?1) AS events,(SELECT first_sequence FROM trace_indexes WHERE run_id=?1) AS first_sequence,(SELECT last_sequence FROM trace_indexes WHERE run_id=?1) AS last_sequence").bind(runId).first<{ events: number; first_sequence: string; last_sequence: string }>();
    expect(counts).toEqual({ events: 2, first_sequence: "1", last_sequence: "2" });
    expect(loss.batches()).toBe(1);
    const snapshot = measured.snapshot();
    expect(snapshot).toMatchObject({ statements: 4, bindingCalls: 4, maxBoundParameters: 6 });
    assertFreeD1Ceilings(snapshot);
    console.log(`CONDUIT_D1_RESPONSE_REPLAY=${JSON.stringify({ d1: snapshot, calls })}`);
  }, 120_000);

  it("keeps 100 Board posts, 100 Assignment schedules, and 100 approvals within measured Free D1 ceilings", async () => {
    const fixture = await seedCostFixture();
    const summary = newSummary();
    const boardPosts = newSummary();
    const assignmentSchedules = newSummary();
    const approvals = newSummary();

    const measure = async (target: CostSummary, operation: (database: D1Database, index: number) => Promise<void>): Promise<void> => {
      const measured = instrumentD1(env.DB);
      for (let index = 0; index < 100; index += 1) {
        measured.reset();
        await operation(measured.db, index);
        addSnapshot(target, measured.snapshot());
        addSnapshot(summary, measured.snapshot());
      }
    };

    await measure(boardPosts, async (database, index) => {
      const request = new Request("https://conduit.example.com/v1/messages", {
        method: "POST",
        headers: { authorization: `Bearer ${fixture.token}`, "content-type": "application/json", "idempotency-key": `cost-board-post-${fixture.suffix}-${index}` },
        body: JSON.stringify({ sessionId: fixture.sessionId, body: `Board post ${index}`, mentions: [] }),
      });
      const response = await handleApi(request, testEnv(database), "/v1/messages");
      if (response === null) throw new Error("Board post route was not handled");
      expect(response.status).toBe(201);
    });

    await measure(assignmentSchedules, async (database, index) => {
      const body = {
        sessionId: fixture.sessionId,
        body: `@builder schedule ${index}`,
        mentions: [{
          type: "project_agent",
          targetId: fixture.agentId,
          startOffset: 0,
          endOffset: 8,
          assignment: {
            title: `Assignment ${index}`,
            body: `Schedule assignment ${index}`,
            schedule: {
              deviceId: fixture.deviceId,
              runtime: { kind: "native", providerId: "native.linux", configurationRevision: 1, networkMode: "restricted" },
              model: "gpt-5.6-codex",
              effort: "low",
              accessScope: "project_full",
              approvalMode: "always",
              sourceRevisions: [],
              verificationPolicy: {},
            },
          },
        }],
      };
      const request = new Request("https://conduit.example.com/v1/messages", {
        method: "POST",
        headers: { authorization: `Bearer ${fixture.token}`, "content-type": "application/json", "idempotency-key": `cost-assignment-${fixture.suffix}-${index}` },
        body: JSON.stringify(body),
      });
      const response = await handleApi(request, testEnv(database), "/v1/messages");
      if (response === null) throw new Error("Assignment schedule route was not handled");
      expect(response.status).toBe(202);
    });

    const seededApprovals = await seedApprovalRows(fixture, 100);
    await measure(approvals, async (database, index) => {
      const response = await resolveApprovalRequest(fixture, database, seededApprovals.approvalIds[index]!, seededApprovals.digests[index]!, index);
      expect(response.status).toBe(200);
    });

    expect(boardPosts.invocations).toBe(100);
    expect(assignmentSchedules.invocations).toBe(100);
    expect(approvals.invocations).toBe(100);
    expect(summary.invocations).toBe(300);
    expect(summary.maxStatements).toBeLessThanOrEqual(40);
    expect(summary.maxBindingCalls).toBeLessThanOrEqual(40);
    expect(summary.maxBoundParameters).toBeLessThanOrEqual(90);
    expect(boardPosts.totalStatements).toBeGreaterThan(0);
    expect(assignmentSchedules.totalStatements).toBeGreaterThan(0);
    expect(approvals.totalStatements).toBeGreaterThan(0);
    const resolved = await env.DB.prepare("SELECT COUNT(*) AS count FROM approvals WHERE id LIKE ?1 AND decision='approved'").bind(`approval_cost_${fixture.suffix}_%`).first<{ count: number }>();
    expect(resolved?.count).toBe(100);
    console.log(`CONDUIT_100_COST_SIMULATION=${JSON.stringify({ boardPosts, assignmentSchedules, approvals, aggregate: summary })}`);
  }, 180_000);
});
