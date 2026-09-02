import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { queueRealtimeProjection, reconcileRealtimeProjections } from "../src/realtime-outbox.ts";

describe.sequential("realtime projection outbox", () => {
  it("retains a failed BoardRoom publication and deterministically retries it", async () => {
    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 300_000).toISOString();
    const deviceId = "dev_realtime_outbox01";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_realtime_outbox','Realtime','active',?1,?1)").bind(createdAt),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_realtime_outbox','completed',?1,?2,'{}','dkey_realtime_outbox','{}',?3,'challenge','signature',?4,?5,?6,?5)").bind("8".repeat(64), "9".repeat(64), "a".repeat(64), deviceId, createdAt, expiresAt),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,'enroll_realtime_outbox','Realtime','linux','x86_64','0.1.0','conduit.node/1','active',?2,?2)").bind(deviceId, createdAt),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_realtime_outbox','Realtime',?1,?1)").bind(createdAt),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_realtime_outbox','prj_realtime_outbox','Realtime',?1,?1)").bind(createdAt),
    ]);
    const event = { sessionId: "csess_realtime_outbox", eventId: "bevt_realtime_retry01", type: "run.working", recordId: "run_realtime_retry01", revision: 3 };
    let calls = 0;
    const failed = await queueRealtimeProjection(env, deviceId, event, {
      now,
      publisher: { publish: async () => { calls += 1; throw new Error("simulated BoardRoom failure"); } },
    });
    expect(failed).toMatchObject({ state: "pending", attemptCount: 1 });
    const durable = await env.DB.prepare("SELECT state,attempt_count,last_error_code FROM realtime_projection_outbox WHERE event_id=?1").bind(event.eventId).first<Record<string, unknown>>();
    expect(durable).toEqual({ state: "pending", attempt_count: 1, last_error_code: "board_room_publish_failed" });

    const published: unknown[] = [];
    const reconciled = await reconcileRealtimeProjections(env, deviceId, {
      now: new Date(Date.parse(failed.nextAttemptAt!) + 1),
      publisher: { publish: async (item) => { calls += 1; published.push(item); return 1; } },
    });
    expect(reconciled).toMatchObject({ attempted: 1, published: 1, pending: 0, nextAttemptAt: null });
    expect(calls).toBe(2);
    expect(published).toEqual([event]);
    const final = await env.DB.prepare("SELECT state,attempt_count,last_error_code,published_at FROM realtime_projection_outbox WHERE event_id=?1").bind(event.eventId).first<Record<string, unknown>>();
    expect(final).toMatchObject({ state: "published", attempt_count: 2, last_error_code: null, published_at: expect.any(String) });

    await expect(queueRealtimeProjection(env, deviceId, { ...event, recordId: "run_other_identity01" })).rejects.toThrow(/bound to another projection/);

    await env.DB.batch([
      env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,title,body,state,created_at,updated_at) VALUES ('asg_realtime_recovery','prj_realtime_outbox','csess_realtime_outbox','Recovery','Recovery','waiting_input',?1,?1)").bind(createdAt),
      env.DB.prepare("INSERT INTO runs(id,assignment_id,project_id,session_id,device_id,runtime_kind,access_scope,approval_mode,state,manifest_digest,manifest_json,created_at,updated_at) VALUES ('run_realtime_recovery','asg_realtime_recovery','prj_realtime_outbox','csess_realtime_outbox',?1,'native','project_full','always','waiting_input',?2,'{}',?3,?3)").bind(deviceId, "b".repeat(64), createdAt),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,capability,payload_digest,request_json,state,result_json,expires_at,created_at,updated_at,node_state_revision) VALUES ('op_realtime_recovery','realtime-recovery-key','prin_realtime_outbox','conduit.test',?1,'prj_realtime_outbox','csess_realtime_outbox','asg_realtime_recovery','run_realtime_recovery','agent.run.start',?2,'{}','claimed',?3,?4,?5,?5,4)").bind(deviceId, "c".repeat(64), JSON.stringify({ state: "waiting_input", revision: "4" }), expiresAt, createdAt),
      env.DB.prepare("INSERT INTO node_projection_receipts(message_id,device_id,connection_epoch,node_sequence,frame_type,correlation_id,operation_id,payload_digest,projection_state,result_json,created_at) VALUES ('nmsg_realtime_recovery',?1,'1','4','operation.status','op_realtime_recovery','op_realtime_recovery',?2,'applied',?3,?4)").bind(deviceId, "d".repeat(64), JSON.stringify({ state: "waiting_input", revision: 4 }), createdAt),
    ]);
    const recoveredEvents: unknown[] = [];
    const recovery = await reconcileRealtimeProjections(env, deviceId, {
      now: new Date(now.getTime() + 10_000),
      publisher: { publish: async (item) => { recoveredEvents.push(item); return 2; } },
    });
    expect(recovery).toMatchObject({ recovered: 1, attempted: 1, published: 1, pending: 0 });
    expect(recoveredEvents).toEqual([{ sessionId: "csess_realtime_outbox", eventId: "bevt_nmsg_realtime_recovery", type: "run.waiting_input", recordId: "run_realtime_recovery", revision: 4 }]);
  });
});
