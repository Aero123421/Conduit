import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { persistRealtimeProjection, reconcileRealtimeProjections, type RealtimeProjectionEvent } from "../src/realtime-outbox.ts";
import { sessionCompositeSnapshot } from "../src/snapshots.ts";
import { assertFreeD1Ceilings, instrumentD1 } from "../src/usage-instrumentation.ts";
import type { ControlPlaneEnv } from "../src/types.ts";

async function fixture(prefix: string) {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const projectId = `prj_${prefix}_${suffix}`;
  const sessionId = `csess_${prefix}_${suffix}`;
  const deviceId = `dev_${prefix}_${suffix}`;
  const enrollmentId = `enroll_${prefix}_${suffix}`;
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'Realtime budget',?2,?2)").bind(projectId, now),
    env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'Realtime budget',?3,?3)").bind(sessionId, projectId, now),
    env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8,?7)").bind(enrollmentId, `${suffix}a`.padEnd(64, "a").slice(0, 64), `${suffix}b`.padEnd(64, "b").slice(0, 64), `dkey_${prefix}_${suffix}`, `${suffix}c`.padEnd(64, "c").slice(0, 64), deviceId, now, new Date(Date.now() + 60_000).toISOString()),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Realtime budget','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now),
  ]);
  return { projectId, sessionId, deviceId, now };
}

function event(sessionId: string, index: number, type = "run.running"): RealtimeProjectionEvent {
  return { sessionId, eventId: `bevt_budget_${index}_${crypto.randomUUID().replaceAll("-", "")}`, type, recordId: `run_budget_${index}`, revision: index + 1 };
}

describe.sequential("realtime batch and fanout budget", () => {
  it("coalesces only pending non-critical status families", async () => {
    const { sessionId, deviceId } = await fixture("coalesce");
    const recordId = `run_coalesce_${crypto.randomUUID().replaceAll("-", "")}`;
    const statuses = [1, 2, 3].map((revision) => ({ sessionId, eventId: `bevt_status_${revision}_${crypto.randomUUID().replaceAll("-", "")}`, type: "run.running", recordId, revision }));
    for (const item of statuses) await persistRealtimeProjection(env, deviceId, item);
    const critical = ["message.created", "approval.decided", "run.completed", "change_set.created", "review.created", "baseline.accepted", "security.failure"].map((type, index) => ({ sessionId, eventId: `bevt_critical_${index}_${crypto.randomUUID().replaceAll("-", "")}`, type, recordId, revision: index + 4 }));
    for (const item of critical) await persistRealtimeProjection(env, deviceId, item);
    const rows = await env.DB.prepare("SELECT event_id FROM realtime_projection_outbox WHERE device_id=?1 AND record_id=?2 ORDER BY revision").bind(deviceId, recordId).all<{ event_id: string }>();
    expect(rows.results.map((row) => row.event_id)).toEqual([statuses[2]!.eventId, ...critical.map((item) => item.eventId)]);
  });

  it("claims 32 rows with UPDATE RETURNING and publishes one Session RPC within D1 ceilings", async () => {
    const { sessionId, deviceId, now } = await fixture("claim");
    const events = Array.from({ length: 32 }, (_, index) => event(sessionId, index, index % 8 === 0 ? "message.created" : `custom.event_${index}`));
    await env.DB.batch(events.map((item) => env.DB.prepare("INSERT INTO realtime_projection_outbox(event_id,device_id,session_id,event_type,record_id,revision,event_json,state,next_attempt_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',?8,?8,?8)").bind(item.eventId, deviceId, sessionId, item.type, item.recordId, item.revision, JSON.stringify(item), now)));
    const measured = instrumentD1(env.DB);
    const measuredEnv = { ...env, DB: measured.db } as ControlPlaneEnv;
    let batchCalls = 0;
    const result = await reconcileRealtimeProjections(measuredEnv, deviceId, {
      now: new Date(Date.parse(now) + 1),
      scheduleRetry: false,
      publisher: {
        async publish() { throw new Error("per-event publish must not be used"); },
        async publishBatch(items) { batchCalls += 1; expect(items).toHaveLength(32); return items.map((_, sequence) => ({ sequence: sequence + 1 })); },
      },
    });
    expect(result).toMatchObject({ attempted: 32, published: 32, pending: 0 });
    expect(batchCalls).toBe(1);
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot().maxBoundParameters).toBeLessThanOrEqual(90);
    console.log(`CLOUDFLARE_REALTIME_PROBE=${JSON.stringify({ events: 32, boardRoomRpc: batchCalls, d1: measured.snapshot() })}`);
  });

  it("sends one batch to each of five sockets and deduplicates replay", async () => {
    const { sessionId } = await fixture("sockets");
    const room = env.BOARD_ROOMS.getByName(sessionId);
    const sockets: WebSocket[] = [];
    const messages: Array<Promise<string>> = [];
    for (let index = 0; index < 5; index += 1) {
      const response = await room.fetch(new Request(`https://conduit.example.com/v1/sessions/${sessionId}/stream`, { headers: { upgrade: "websocket" } }));
      const socket = response.webSocket!;
      socket.accept();
      sockets.push(socket);
      messages.push(new Promise((resolve) => socket.addEventListener("message", (incoming) => resolve(String(incoming.data)), { once: true })));
    }
    const events = Array.from({ length: 32 }, (_, index) => event(sessionId, index, `message.created`));
    const first = await room.publishBatch(events);
    expect(first).toHaveLength(32);
    const delivered = await Promise.all(messages);
    for (const encoded of delivered) {
      const decoded = JSON.parse(encoded) as { type: string; events: unknown[] };
      expect(decoded.type).toBe("events.batch");
      expect(decoded.events).toHaveLength(32);
    }
    expect(await room.publishBatch(events)).toEqual(first);
    for (const socket of sockets) socket.close(1000, "complete");
  });

  it("converges zero, one, and five dashboard sockets on the same D1 snapshot", async () => {
    const finalStates: Array<{ body: string; origin: string; revision: number }> = [];
    for (const socketCount of [0, 1, 5]) {
      const { sessionId, now } = await fixture(`converge_${socketCount}`);
      const room = env.BOARD_ROOMS.getByName(sessionId);
      const sockets: WebSocket[] = [];
      const deliveries: Array<Promise<string>> = [];
      for (let index = 0; index < socketCount; index += 1) {
        const response = await room.fetch(new Request(`https://conduit.example.com/v1/sessions/${sessionId}/stream`, { headers: { upgrade: "websocket" } }));
        const socket = response.webSocket!;
        socket.accept();
        sockets.push(socket);
        deliveries.push(new Promise((resolve) => socket.addEventListener("message", (incoming) => resolve(String(incoming.data)), { once: true })));
      }

      const messageId = `msg_dashboard_${socketCount}_${crypto.randomUUID().replaceAll("-", "")}`;
      await env.DB.batch([
        env.DB.prepare("INSERT INTO messages(id,session_id,origin,body,revision,created_at) VALUES (?1,?2,'owner','authoritative dashboard state',7,?3)").bind(messageId, sessionId, now),
        env.DB.prepare("INSERT INTO message_revisions(message_id,revision,body,created_at) VALUES (?1,7,'authoritative dashboard state',?2)").bind(messageId, now),
      ]);
      await room.publishBatch([{ sessionId, eventId: `bevt_${messageId}`, type: "message.created", recordId: messageId, revision: 7 }]);

      for (const encoded of await Promise.all(deliveries)) {
        expect(JSON.parse(encoded)).toMatchObject({ type: "events.batch", events: [{ eventId: `bevt_${messageId}`, recordId: messageId, revision: 7 }] });
      }
      const snapshot = await sessionCompositeSnapshot(env.DB, sessionId);
      const messages = snapshot?.messages as Array<Record<string, unknown>> | undefined;
      expect(messages).toHaveLength(1);
      finalStates.push({ body: String(messages![0]!.body), origin: String(messages![0]!.origin), revision: Number(messages![0]!.revision) });
      for (const socket of sockets) socket.close(1000, "complete");
    }
    expect(finalStates).toEqual(Array.from({ length: 3 }, () => ({ body: "authoritative dashboard state", origin: "owner", revision: 7 })));
  });
});
