import { env } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index.ts";
import { canonicalJson, sha256Hex } from "../src/crypto.ts";
import { MAX_QUEUE_MESSAGES_PER_INVOCATION, type EventBatchMessage } from "../src/ingestion.ts";
import type { DeviceRoom } from "../src/do/device-room.ts";
import type { RetryScheduler } from "../src/do/retry-scheduler.ts";
import { assertFreeD1Ceilings, instrumentD1, type D1UsageSnapshot } from "../src/usage-instrumentation.ts";
import type { ControlPlaneEnv, QueueEventMessage } from "../src/types.ts";

function digest(index: number): string {
  return index.toString(16).padStart(64, "0");
}

function normalizedEvent(runId: string, deviceId: string, index: number): QueueEventMessage {
  return {
    schemaVersion: 1,
    kind: "normalized_event",
    eventId: `evt_outer_budget_${index.toString().padStart(8, "0")}`,
    runId,
    deviceId,
    sequence: String(index),
    eventType: "adapter.assistant_message_delta",
    source: "agent",
    observedAt: "2026-09-02T00:00:00.000Z",
    nodeBootId: "node-boot-outer-budget-0001",
    evidenceLevel: "observed",
    sensitivity: "metadata",
    retentionClass: "R1",
    payloadDigest: digest(10_000 + index),
    eventDigest: digest(20_000 + index),
    previousChainHash: digest(30_000 + index),
    chainHash: digest(40_000 + index),
    payload: { text: `outer-${index}` },
  } as QueueEventMessage;
}

async function eventBatch(runId: string, deviceId: string, index: number): Promise<EventBatchMessage> {
  const event = normalizedEvent(runId, deviceId, index);
  const sourceSequenceRange = { from: event.sequence, through: event.sequence };
  const sourceRangeDigest = await sha256Hex(canonicalJson({
    runId,
    fromSequence: event.sequence,
    throughSequence: event.sequence,
    events: [{ sequence: event.sequence, eventDigest: event.eventDigest }],
  }));
  return { runId, fromSequence: event.sequence, throughSequence: event.sequence, sourceSequenceRange, sourceRangeDigest, traceSchema: "conduit.trace/1", events: [event], deviceId };
}

async function hostileEventBatch(runId: string, deviceId: string, index: number): Promise<EventBatchMessage> {
  const valid = normalizedEvent(runId, deviceId, index);
  const poison = {
    ...normalizedEvent(runId, deviceId, index + 10_000),
    eventId: `evt_outer_poison_${index.toString().padStart(8, "0")}`,
    eventType: "",
  };
  const fromSequence = valid.sequence;
  const throughSequence = poison.sequence;
  const sourceSequenceRange = { from: fromSequence, through: throughSequence };
  const sourceRangeDigest = await sha256Hex(canonicalJson({
    runId,
    fromSequence,
    throughSequence,
    events: [valid, poison].map((event) => ({ sequence: event.sequence, eventDigest: event.eventDigest })),
  }));
  return { runId, fromSequence, throughSequence, sourceSequenceRange, sourceRangeDigest, traceSchema: "conduit.trace/1", events: [valid, poison], deviceId };
}

async function seedRun(runId: string, deviceId: string, suffix: string): Promise<void> {
  const now = new Date().toISOString();
  const enrollmentId = `enroll_outer_${suffix}`;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8)")
      .bind(enrollmentId, `device-code-${suffix}`, `user-code-${suffix}`, `dkey_outer_${suffix}`, `fingerprint-${suffix}`, deviceId, now, new Date(Date.now() + 86_400_000).toISOString()),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Outer budget','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)")
      .bind(deviceId, enrollmentId, now),
    env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,created_at,updated_at) VALUES (?1,?2,'native','project_full','always','queued',?3,?3)")
      .bind(runId, deviceId, now),
  ]);
}

function envWithDatabase(database: D1Database): ControlPlaneEnv {
  return new Proxy(env as ControlPlaneEnv, {
    get(target, property, receiver) {
      return property === "DB" ? database : Reflect.get(target, property, receiver);
    },
  });
}

async function measureDurableAlarm<T extends DeviceRoom | RetryScheduler>(instance: T, run: () => Promise<void>): Promise<D1UsageSnapshot> {
  const holder = instance as unknown as { env: ControlPlaneEnv };
  const original = holder.env;
  const measured = instrumentD1(original.DB);
  Object.defineProperty(instance, "env", { value: envWithDatabase(measured.db), configurable: true });
  try {
    await run();
  } finally {
    Object.defineProperty(instance, "env", { value: original, configurable: true });
  }
  return measured.snapshot();
}

describe.sequential("outer invocation D1 budgets", () => {
  it("measures the configured maximum Queue batch through the actual exported queue handler", async () => {
    const measured = instrumentD1(env.DB);
    const calls: string[] = [];
    const messages: Array<Record<string, unknown>> = [];
    for (let index = 1; index <= MAX_QUEUE_MESSAGES_PER_INVOCATION; index += 1) {
      const suffix = `queue_${index.toString().padStart(4, "0")}`;
      const runId = `run_outer_${suffix}`;
      const deviceId = `dev_outer_${suffix}`;
      await seedRun(runId, deviceId, suffix);
      messages.push({
        id: `queue-outer-${index}`,
        // Each message exercises poison isolation plus a valid sibling commit,
        // the maximum statement shape of the consumer path.
        body: await hostileEventBatch(runId, deviceId, index),
        attempts: 1,
        timestamp: new Date(),
        ack: () => calls.push(`ack:${index}`),
        retry: () => calls.push(`retry:${index}`),
      });
    }
    await worker.queue!({ queue: "conduit-event-ingestion", messages } as never, envWithDatabase(measured.db));
    const snapshot = measured.snapshot();
    expect(calls).toEqual(Array.from({ length: MAX_QUEUE_MESSAGES_PER_INVOCATION }, (_, index) => `ack:${index + 1}`));
    expect(snapshot.statements).toBeGreaterThan(0);
    assertFreeD1Ceilings(snapshot);
    console.log(`CONDUIT_OUTER_QUEUE_BUDGET=${JSON.stringify(snapshot)}`);
  });

  it("limits a maximum DeviceRoom event backlog per actual alarm invocation", async () => {
    const suffix = "device_alarm_0001";
    const runId = `run_outer_${suffix}`;
    const deviceId = `dev_outer_${suffix}`;
    await seedRun(runId, deviceId, suffix);
    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const frames = await Promise.all(Array.from({ length: 32 }, async (_, offset) => {
      const sequence = offset + 1;
      const queuePayload = await eventBatch(runId, deviceId, sequence);
      const { deviceId: _queueRoutingDeviceId, ...payload } = queuePayload;
      return {
        protocol: "conduit.node/1",
        messageId: `nmsg_outer_alarm_${sequence.toString().padStart(8, "0")}`,
        deviceId,
        connectionEpoch: "1",
        direction: "node_to_control",
        sequence: String(sequence),
        type: "event.batch",
        payloadDigest: await sha256Hex(canonicalJson(payload)),
        payload,
      };
    }));
    const snapshot = await runInDurableObject(room, async (instance: DeviceRoom, state) => {
      const createdAt = new Date().toISOString();
      for (const [offset, frame] of frames.entries()) {
        state.storage.sql.exec(
          "INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,projected,projection_claimed_at,created_at,kind) VALUES (?,?,?,?,?,0,NULL,?,'app')",
          offset + 1,
          frame.messageId,
          null,
          frame.payloadDigest,
          JSON.stringify(frame),
          createdAt,
        );
      }
      state.storage.sql.exec("UPDATE transport_positions SET durable_sequence=32 WHERE direction='node_to_control'");
      state.storage.sql.exec("UPDATE room_work_marker SET pending=1,min_due_at=? WHERE singleton=1", Date.now());
      return measureDurableAlarm(instance, () => instance.alarm());
    });
    assertFreeD1Ceilings(snapshot);
    const remaining = await runInDurableObject(room, (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames WHERE projected=0").one().count);
    expect(remaining).toBe(28);
    expect(snapshot.statements).toBeGreaterThan(0);
    console.log(`CONDUIT_OUTER_DEVICE_ALARM_BUDGET=${JSON.stringify(snapshot)}`);
  });

  it("spends one bounded work reservation in the actual RetryScheduler alarm", async () => {
    const scheduler = env.RETRY_SCHEDULER.getByName("control-plane-outer-budget");
    let measured: ReturnType<typeof instrumentD1> | undefined;
    let originalEnv: ControlPlaneEnv | undefined;
    await runInDurableObject(scheduler, async (instance: RetryScheduler, state) => {
      const now = new Date().toISOString();
      state.storage.sql.exec("INSERT INTO due_work(kind,target_id,due_at,created_at,updated_at) VALUES ('retention','hot-data','1970-01-01T00:00:00.000Z',?,?)", now, now);
      for (let index = 0; index < 31; index += 1) {
        state.storage.sql.exec("INSERT INTO due_work(kind,target_id,due_at,created_at,updated_at) VALUES ('operation',?,?,?,?)", `op_outer_missing_${index.toString().padStart(8, "0")}`, "1970-01-02T00:00:00.000Z", now, now);
      }
      const holder = instance as unknown as { env: ControlPlaneEnv };
      originalEnv = holder.env;
      measured = instrumentD1(holder.env.DB);
      Object.defineProperty(instance, "env", { value: envWithDatabase(measured.db), configurable: true });
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(scheduler)).toBe(true);
    if (measured === undefined || originalEnv === undefined) throw new Error("RetryScheduler instrumentation was not installed");
    const snapshot = measured.snapshot();
    await runInDurableObject(scheduler, (instance: RetryScheduler) => {
      Object.defineProperty(instance, "env", { value: originalEnv, configurable: true });
    });
    assertFreeD1Ceilings(snapshot);
    const budget = await scheduler.inspectBudget();
    expect(budget.pending).toBe(31);
    expect(budget.nextDueAt).not.toBeNull();
    expect(snapshot.statements).toBeGreaterThanOrEqual(16);
    console.log(`CONDUIT_OUTER_RETRY_ALARM_BUDGET=${JSON.stringify(snapshot)}`);
  });

  it("keeps a completely empty 24-hour Cron backstop free of scheduler rows, alarms, and D1 writes", async () => {
    const scheduler = env.RETRY_SCHEDULER.getByName("control-plane-empty-day");
    const started = Date.parse("2026-09-02T00:00:00.000Z");
    const result = await runInDurableObject(scheduler, async (instance: RetryScheduler, state) => {
      const holder = instance as unknown as { env: ControlPlaneEnv };
      const original = holder.env;
      const measured = instrumentD1(original.DB);
      Object.defineProperty(instance, "env", { value: envWithDatabase(measured.db), configurable: true });
      let rowsWritten = 0;
      let maxStatements = 0;
      try {
        for (let tick = 0; tick < 24 * 12; tick += 1) {
          measured.reset();
          await instance.backstop(new Date(started + tick * 5 * 60_000).toISOString());
          const snapshot = measured.snapshot();
          assertFreeD1Ceilings(snapshot);
          rowsWritten += snapshot.rowsWritten;
          maxStatements = Math.max(maxStatements, snapshot.statements);
        }
      } finally {
        Object.defineProperty(instance, "env", { value: original, configurable: true });
      }
      return {
        rowsWritten,
        maxStatements,
        pending: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM due_work").one().count,
        alarm: await state.storage.getAlarm(),
      };
    });
    expect(result).toEqual({ rowsWritten: 0, maxStatements: 4, pending: 0, alarm: null });
  }, 20_000);
});
