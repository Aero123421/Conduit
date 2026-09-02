import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { attemptOperationDispatch } from "../src/dispatch.ts";

describe("demand-driven retry scheduler", () => {
  it("has no idle alarm and keeps one alarm at the minimum due time", async () => {
    const scheduler = env.RETRY_SCHEDULER.getByName(`budget-${crypto.randomUUID()}`);
    expect(await scheduler.inspectBudget()).toEqual({ pending: 0, alarmAt: null, nextDueAt: null });

    const later = new Date(Date.now() + 120_000).toISOString();
    const earlier = new Date(Date.now() + 60_000).toISOString();
    await scheduler.schedule({ kind: "operation", targetId: "op_budget_later", dueAt: later });
    await scheduler.schedule({ kind: "approval", targetId: "approval_budget_earlier", dueAt: earlier });
    const scheduled = await scheduler.inspectBudget();
    expect(scheduled.pending).toBe(2);
    expect(scheduled.nextDueAt).toBe(earlier);
    expect(scheduled.alarmAt).not.toBeNull();
    expect(Math.abs((scheduled.alarmAt ?? 0) - Date.parse(earlier))).toBeLessThanOrEqual(1_000);

    await scheduler.clear("approval", "approval_budget_earlier");
    const one = await scheduler.inspectBudget();
    expect(one.pending).toBe(1);
    expect(one.nextDueAt).toBe(later);
    await scheduler.clear("operation", "op_budget_later");
    expect(await scheduler.inspectBudget()).toEqual({ pending: 0, alarmAt: null, nextDueAt: null });
  });

  it("coalesces repeated scheduling for the exact work target", async () => {
    const scheduler = env.RETRY_SCHEDULER.getByName(`coalesce-${crypto.randomUUID()}`);
    const first = new Date(Date.now() + 30_000).toISOString();
    const replacement = new Date(Date.now() + 45_000).toISOString();
    await scheduler.schedule({ kind: "realtime", targetId: "device_budget", dueAt: first });
    await scheduler.schedule({ kind: "realtime", targetId: "device_budget", dueAt: replacement });
    expect(await scheduler.inspectBudget()).toMatchObject({ pending: 1, nextDueAt: replacement });
  });

  it("registers only a failed dispatch and clears it after exact-target success", async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const operationId = `op_scheduler_${suffix}`;
    const deviceId = `dev_scheduler_${suffix}`;
    const enrollmentId = `enroll_scheduler_${suffix}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60_000).toISOString();
    const digest = "a".repeat(64);
    const principalId = `prin_scheduler_${suffix}`;
    const clientId = `scheduler.client.${suffix}`;
    const rateId = `rate_scheduler_${suffix}`;
    const policyId = `cpol_scheduler_${suffix}`;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES (?1,'Scheduler','active',?2,?2)").bind(principalId, now.toISOString()),
      env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered','Scheduler','[]','none',?2,'active',?3,?3)").bind(clientId, digest, now.toISOString()),
      env.DB.prepare("INSERT INTO rate_limit_profiles(id,revision,status,name,profile_json,created_at,updated_at) VALUES (?1,1,'active','Scheduler','{}',?2,?2)").bind(rateId, now.toISOString()),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES (?1,?2,?3,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}','[\"command.start\"]','[\"native\"]','full_user','never','[]',0,0,?4,60,600,?5,?5)").bind(policyId, principalId, clientId, rateId, now.toISOString()),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8,?7)").bind(enrollmentId, `${suffix}a`.padEnd(64, "a").slice(0, 64), `${suffix}b`.padEnd(64, "b").slice(0, 64), `dkey_scheduler_${suffix}`, `${suffix}c`.padEnd(64, "c").slice(0, 64), deviceId, now.toISOString(), expiresAt),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'Scheduler','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now.toISOString()),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,1,'command.start',?7,'{}','queued',?8,?9,?9)").bind(operationId, `scheduler-idem-${suffix}`, principalId, clientId, deviceId, policyId, digest, expiresAt, now.toISOString()),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES ('scheduler',?1,?2,?3,'queued',202,NULL,?4,?5)").bind(`scheduler-idem-${suffix}`, digest, operationId, expiresAt, now.toISOString()),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?1,?4,'{}','pending',?5,?6,?5,?5)").bind(operationId, deviceId, `cmsg_scheduler_${suffix}`, digest, now.toISOString(), expiresAt),
    ]);
    const failed = await attemptOperationDispatch(env, operationId, { force: true, now, dispatcher: { async offer() { throw new Error("simulated failure"); } } });
    expect(failed).toMatchObject({ state: "queued", dispatch: { attemptCount: 1 } });
    const scheduler = env.RETRY_SCHEDULER.getByName("control-plane");
    expect(await scheduler.inspectTarget("operation", operationId)).toMatchObject({ dueAt: failed!.dispatch!.nextAttemptAt });

    const succeeded = await attemptOperationDispatch(env, operationId, { force: true, now: new Date(now.getTime() + 3_000), dispatcher: { async offer() { return { sequence: "1", delivered: true }; } } });
    expect(succeeded).toMatchObject({ state: "offered" });
    expect(await scheduler.inspectTarget("operation", operationId)).toBeNull();
  });
});
