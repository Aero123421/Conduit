import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { cleanupHotData } from "../src/retention.ts";
import { assertFreeD1Ceilings, instrumentD1 } from "../src/usage-instrumentation.ts";

describe.sequential("Free profile retention", () => {
  it("compacts published realtime custody and replays cleanup without deleting security evidence", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const eventId = `bevt_retention_${suffix}`;
    const securityId = `sevt_retention_${suffix}`;
    const challengeId = `chal_retention_${suffix}`;
    const projectId = `prj_retention_${suffix}`;
    const sessionId = `csess_retention_${suffix}`;
    const enrollmentId = `enroll_retention_${suffix}`;
    const deviceId = `dev_retention_${suffix}`;
    const old = "2026-08-01T00:00:00.000Z";
    const expired = "2026-08-01T00:05:00.000Z";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'Retention',?2,?2)").bind(projectId, old),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'Retention',?3,?3)").bind(sessionId, projectId, old),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8,?7)").bind(enrollmentId, "b".repeat(64), "c".repeat(64), `dkey_retention_${suffix}`, "d".repeat(64), deviceId, old, expired),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Retention','linux','x86_64','0.1','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, old),
      env.DB.prepare("INSERT INTO realtime_projection_outbox(event_id,device_id,session_id,event_type,record_id,revision,event_json,state,next_attempt_at,created_at,updated_at,published_at) VALUES (?1,?2,?3,'run.working','run_retention',1,'{}','published',?4,?4,?4,?4)").bind(eventId, deviceId, sessionId, old),
      env.DB.prepare("INSERT INTO security_events(id,event_type,metadata_json,created_at) VALUES (?1,'retention.must_remain','{}',?2)").bind(securityId, old),
      env.DB.prepare("INSERT INTO auth_challenges(id,kind,challenge_hash,expected_origin,expected_rp_id,state_json,expires_at,created_at) VALUES (?1,'authentication',?2,'https://conduit.example.com','conduit.example.com','{}',?3,?2)").bind(challengeId, "a".repeat(64), expired),
    ]);
    const measured = instrumentD1(env.DB);
    const first = await cleanupHotData({ ...env, DB: measured.db }, { now: new Date("2026-09-02T00:00:00.000Z"), limit: 100 });
    expect(first.deletedRows).toBeGreaterThanOrEqual(2);
    expect(first.compactedRealtimeRows).toBe(1);
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot()).toMatchObject({ statements: 17, maxBoundParameters: 3 });
    const compacted = await env.DB.prepare("SELECT event_id,session_id,record_id,revision FROM realtime_delivery_receipts WHERE event_id=?1").bind(eventId).first();
    expect(compacted).toMatchObject({ event_id: eventId, session_id: sessionId, record_id: "run_retention", revision: 1 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM realtime_projection_outbox WHERE event_id=?1").bind(eventId).first<{ count: number }>()).toEqual({ count: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM security_events WHERE id=?1").bind(securityId).first<{ count: number }>()).toEqual({ count: 1 });
    const replay = await cleanupHotData(env, { now: new Date("2026-09-02T00:00:01.000Z"), limit: 100 });
    expect(replay.compactedRealtimeRows).toBe(0);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM realtime_delivery_receipts WHERE event_id=?1").bind(eventId).first<{ count: number }>()).toEqual({ count: 1 });
  });

  it("resumes an interrupted receipt-first compaction without regeneration", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const eventId = `bevt_crash_${suffix}`;
    const projectId = `prj_crash_${suffix}`;
    const sessionId = `csess_crash_${suffix}`;
    const enrollmentId = `enroll_crash_${suffix}`;
    const deviceId = `dev_crash_${suffix}`;
    const old = "2026-08-01T00:00:00.000Z";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'Crash',?2,?2)").bind(projectId, old),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'Crash',?3,?3)").bind(sessionId, projectId, old),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,'2026-08-01T00:05:00.000Z',?7)").bind(enrollmentId, "e".repeat(64), "f".repeat(64), `dkey_crash_${suffix}`, "0".repeat(64), deviceId, old),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Crash','linux','x86_64','0.1','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, old),
      env.DB.prepare("INSERT INTO realtime_projection_outbox(event_id,device_id,session_id,event_type,record_id,revision,event_json,state,next_attempt_at,created_at,updated_at,published_at) VALUES (?1,?2,?3,'assignment.active','asg_crash',2,'{}','published',?4,?4,?4,?4)").bind(eventId, deviceId, sessionId, old),
      env.DB.prepare("INSERT INTO realtime_delivery_receipts(event_id,session_id,record_id,revision,published_at,expires_at) VALUES (?1,?2,'asg_crash',2,?3,'2026-09-09T00:00:00.000Z')").bind(eventId, sessionId, old),
    ]);
    await cleanupHotData(env, { now: new Date("2026-09-02T00:00:00.000Z"), limit: 100 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM realtime_projection_outbox WHERE event_id=?1").bind(eventId).first<{ count: number }>()).toEqual({ count: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM realtime_delivery_receipts WHERE event_id=?1").bind(eventId).first<{ count: number }>()).toEqual({ count: 1 });
  });
});
