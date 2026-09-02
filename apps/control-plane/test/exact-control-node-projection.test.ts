import { env, exports } from "cloudflare:workers";
import type { NodeV1PostAuthFrame } from "@conduit/schema";
import { beforeAll, describe, expect, it } from "vitest";
import { createExistingTargetControl } from "../src/controls.ts";
import { keyedHash } from "../src/crypto.ts";
import { projectNodeState } from "../src/node-projection.ts";

type ProjectedFrame = Extract<NodeV1PostAuthFrame, {
  type: "operation.admission" | "operation.status" | "runtime.control_result" | "device.health";
}>;

describe.sequential("exact existing-target controls and node projections", () => {
  const actor = { principalId: "prin_exact_control", clientId: "conduit.cli", scopes: ["owner"] };
  const ownerToken = "conduit_owner_exact_control_route_token_01";
  const deviceId = "dev_exact_control";
  const runId = "run_exact_control";
  const assignmentId = "asg_exact_control";
  const startOperationId = "op_exact_control_start";
  const runtimeId = "rt_exact_control";
  const runtimeDigest = "1".repeat(64);
  const runtimeHandleDigest = "2".repeat(64);
  const agentDigest = "3".repeat(64);
  const startDigest = "4".repeat(64);
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  const createdControls = new Map<string, string>();

  beforeAll(async () => {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES (?1,'Exact Control Owner','active',?2,?2)").bind(actor.principalId, now),
      env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,created_at,expires_at) VALUES ('otk_exact_control',?1,?2,'exact-control-route','active',?3,?4)").bind(actor.principalId, await keyedHash("test-only-token-pepper-with-at-least-32-bytes", ownerToken), now, expiresAt),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_exact_control','completed',?1,?2,'{}','dkey_exact_control','{}',?3,'challenge','signature',?4,?5,?6,?5)").bind("5".repeat(64), "6".repeat(64), "7".repeat(64), deviceId, now, expiresAt),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,connection_epoch,created_at,updated_at) VALUES (?1,'enroll_exact_control','Exact Linux','linux','x86_64','0.1.0','conduit.node/1','active','7',?2,?2)").bind(deviceId, now),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_exact_control','Exact Control',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_exact_control','prj_exact_control','Exact Control Session',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,title,body,state,revision,created_at,updated_at) VALUES (?1,'prj_exact_control','csess_exact_control','Control target','Control the admitted target','active',2,?2,?2)").bind(assignmentId, now),
      env.DB.prepare("INSERT INTO runs(id,assignment_id,project_id,session_id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,controller_epoch,created_at,updated_at) VALUES (?1,?2,'prj_exact_control','csess_exact_control',?3,'container','project_full','always','waiting_input',2,?4,'{}','11',?5,?5)").bind(runId, assignmentId, deviceId, "8".repeat(64), now),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,node_state_revision) VALUES (?1,'exact-control-start-key',?2,?3,?4,'prj_exact_control','csess_exact_control',?5,?6,'cpol_owner_first_party_v1',1,'agent.run.start',?7,?8,'claimed',?9,?10,?10,2)").bind(startOperationId, actor.principalId, actor.clientId, deviceId, assignmentId, runId, startDigest, JSON.stringify({ capability: "agent.run.start", arguments: { adapterId: "codex", settlementPolicy: "persistent" } }), expiresAt, now),
      env.DB.prepare("INSERT INTO runtime_custody(runtime_id,run_id,start_operation_id,device_id,provider_id,handle_digest,target_digest,controller_epoch,state,revision,created_at,updated_at) VALUES (?1,?2,?3,?4,'container.linux',?5,?6,'11','running',3,?7,?7)").bind(runtimeId, runId, startOperationId, deviceId, runtimeHandleDigest, runtimeDigest, now),
      env.DB.prepare("INSERT INTO agent_sessions(id,run_id,start_operation_id,device_id,adapter_id,native_session_id,target_digest,settlement_policy,state,controller_epoch,revision,last_activity_at,created_at,updated_at) VALUES ('ags_exact_control',?1,?2,?3,'codex','native-exact-control',?4,'waiting_input','waiting_input','11',2,?5,?5,?5)").bind(runId, startOperationId, deviceId, agentDigest, now),
      env.DB.prepare("UPDATE runs SET agent_session_id='ags_exact_control' WHERE id=?1").bind(runId),
    ]);
  });

  async function routeControl(collection: "assignments" | "runtimes", targetId: string, idempotencyKey: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/${collection}/${targetId}/controls`, {
      method: "POST",
      headers: { authorization: `Bearer ${ownerToken}`, "content-type": "application/json", "idempotency-key": idempotencyKey },
      body: JSON.stringify(body),
    }));
    expect(response.status, await response.clone().text()).toBe(202);
    return response.json<Record<string, unknown>>();
  }

  it("queues agent input, steer, close, and cancel against the exact admitted session", async () => {
    for (const command of ["input", "steer", "close", "cancel"] as const) {
      const result = await routeControl("assignments", assignmentId, `exact-agent-${command}-key`, { command, expectedState: "waiting_input", expectedRevision: 2, ...(command === "input" || command === "steer" ? { content: `${command} content` } : {}) });
      createdControls.set(`agent.${command}`, String(result.operationId));
    }

    const rows = await env.DB.prepare("SELECT journal.id,journal.operation_kind,journal.target_operation_id,journal.target_runtime_id,journal.target_digest,journal.target_controller_epoch,journal.expected_target_state,journal.expected_target_revision,journal.request_json,outbox.frame_type,outbox.payload_json FROM operation_journal AS journal JOIN operation_dispatch_outbox AS outbox ON outbox.operation_id=journal.id WHERE journal.target_operation_id=?1 ORDER BY journal.created_at,journal.id").bind(startOperationId).all<Record<string, unknown>>();
    const agentRows = rows.results.filter((row) => row.operation_kind === "agent_control");
    expect(agentRows).toHaveLength(4);
    expect(agentRows.map((row) => row.frame_type).sort()).toEqual(["operation.cancel", "operation.input", "operation.input", "operation.input"]);
    for (const row of agentRows) {
      expect(row).toMatchObject({ target_operation_id: startOperationId, target_runtime_id: null, target_digest: agentDigest, target_controller_epoch: "11", expected_target_state: "waiting_input", expected_target_revision: 2 });
      expect(JSON.parse(String(row.payload_json))).toMatchObject({ targetRunId: runId, targetControllerEpoch: "11", targetDigest: agentDigest, expectedState: "waiting_input", expectedRevision: "2" });
    }
  });

  it("queues every Runtime lifecycle control without creating another start or target representation", async () => {
    const bodies = {
      pause: {}, resume: {}, stop: {}, snapshot: { snapshotName: "reviewed" },
      restore: { snapshotName: "reviewed" }, destroy: { discardAuthorized: true, custodyComplete: true },
    } as const;
    for (const command of ["pause", "resume", "stop", "snapshot", "restore", "destroy"] as const) {
      const result = await routeControl("runtimes", runtimeId, `exact-runtime-${command}-key`, { command, expectedState: "running", expectedRevision: 3, ...bodies[command] });
      createdControls.set(`runtime.${command}`, String(result.operationId));
    }

    const rows = await env.DB.prepare("SELECT journal.id,journal.operation_kind,journal.target_operation_id,journal.target_runtime_id,journal.target_digest,journal.target_controller_epoch,journal.expected_target_state,journal.expected_target_revision,outbox.frame_type,outbox.payload_json FROM operation_journal AS journal JOIN operation_dispatch_outbox AS outbox ON outbox.operation_id=journal.id WHERE journal.operation_kind='runtime_control' AND journal.run_id=?1 ORDER BY journal.created_at,journal.id").bind(runId).all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(6);
    for (const row of rows.results) {
      expect(row).toMatchObject({ operation_kind: "runtime_control", target_operation_id: startOperationId, target_runtime_id: runtimeId, target_digest: runtimeDigest, target_controller_epoch: "11", expected_target_state: "running", expected_target_revision: 3, frame_type: "runtime.control" });
      expect(JSON.parse(String(row.payload_json))).toMatchObject({ targetRunId: runId, targetRuntimeId: runtimeId, targetHandleDigest: runtimeHandleDigest, targetControllerEpoch: "11", targetDigest: runtimeDigest, expectedState: "running", expectedRevision: "3" });
    }
    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM operation_journal WHERE run_id=?1 AND operation_kind='start') AS starts,(SELECT COUNT(*) FROM runs WHERE id=?1) AS runs,(SELECT COUNT(*) FROM runtime_custody WHERE run_id=?1) AS runtimes,(SELECT COUNT(*) FROM agent_sessions WHERE run_id=?1) AS sessions").bind(runId).first<Record<string, number>>();
    expect(counts).toEqual({ starts: 1, runs: 1, runtimes: 1, sessions: 1 });
  });

  it("replays an identical control idempotently and rejects key reuse with changed intent", async () => {
    const replay = await createExistingTargetControl(env, actor, {
      targetKind: "agent", targetId: assignmentId, idempotencyKey: "exact-agent-input-key",
      body: { command: "input", expectedState: "waiting_input", expectedRevision: 2, content: "input content" },
    }, "owner");
    expect(replay).toMatchObject({ operationId: createdControls.get("agent.input"), replay: true });
    await expect(createExistingTargetControl(env, actor, {
      targetKind: "agent", targetId: assignmentId, idempotencyKey: "exact-agent-input-key",
      body: { command: "input", expectedState: "waiting_input", expectedRevision: 2, content: "different content" },
    }, "owner")).rejects.toMatchObject({ code: "idempotency_conflict", status: 409 });
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM operation_journal WHERE idempotency_key='exact-agent-input-key'").first<{ count: number }>();
    expect(count?.count).toBe(1);
  });

  it("projects admission and ordered status while rejecting duplicates, reordered revisions, stale epochs, and digest mismatches", async () => {
    const now = new Date().toISOString();
    const projectionAssignment = "asg_exact_projection";
    const projectionRun = "run_exact_projection";
    const projectionOperation = "op_exact_projection";
    const requestDigest = "9".repeat(64);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,title,body,state,revision,created_at,updated_at) VALUES (?1,'prj_exact_control','csess_exact_control','Projection','Projection target','queued',1,?2,?2)").bind(projectionAssignment, now),
      env.DB.prepare("INSERT INTO runs(id,assignment_id,project_id,session_id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES (?1,?2,'prj_exact_control','csess_exact_control',?3,'native','project_full','always','queued',1,?4,'{}',?5,?5)").bind(projectionRun, projectionAssignment, deviceId, "a".repeat(64), now),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,connector_policy_id,connector_policy_revision,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'exact-projection-key',?2,?3,?4,'prj_exact_control','csess_exact_control',?5,?6,'cpol_owner_first_party_v1',1,'agentRuns','agent.run.start',?7,?8,'offered',?9,?10,?10)").bind(projectionOperation, actor.principalId, actor.clientId, deviceId, projectionAssignment, projectionRun, requestDigest, JSON.stringify({ capability: "agent.run.start", arguments: { adapterId: "codex", settlementPolicy: "persistent" } }), expiresAt, now),
    ]);

    const admission = frame("msg_exact_admission", "100", "operation.admission", projectionOperation, {
      operationId: projectionOperation, idempotencyKey: "exact-projection-key", requestDigest, decision: "duplicate_replay", journalState: "admitted", localPolicyRevision: 1, receiptDigest: "b".repeat(64),
    });
    expect(await projectNodeState(env, admission)).toEqual([{ sessionId: "csess_exact_control", eventId: "bevt_msg_exact_admission", type: "operation.admitted", recordId: projectionRun, revision: 1 }]);
    expect(await projectNodeState(env, admission)).toEqual([]);

    const running = frame("msg_exact_status_3", "101", "operation.status", projectionOperation, {
      operationId: projectionOperation, runId: projectionRun, requestDigest, state: "running", controllerEpoch: "2", revision: "3", targetDigest: "c".repeat(64), observedAt: now,
    });
    await projectNodeState(env, running);
    await projectNodeState(env, frame("msg_exact_status_duplicate", "102", "operation.status", projectionOperation, { ...running.payload, revision: "3" }));
    await projectNodeState(env, frame("msg_exact_status_reordered", "103", "operation.status", projectionOperation, { ...running.payload, revision: "2" }));
    await projectNodeState(env, frame("msg_exact_status_digest", "104", "operation.status", projectionOperation, { ...running.payload, revision: "4", requestDigest: "d".repeat(64) }));
    await projectNodeState(env, frame("msg_exact_status_epoch", "105", "operation.status", projectionOperation, { ...running.payload, revision: "4" }, "6"));

    const receipts = await env.DB.prepare("SELECT message_id,projection_state,result_json FROM node_projection_receipts WHERE operation_id=?1 ORDER BY node_sequence").bind(projectionOperation).all<{ message_id: string; projection_state: string; result_json: string }>();
    expect(receipts.results.map(({ message_id, projection_state }) => [message_id, projection_state])).toEqual([
      ["msg_exact_admission", "applied"], ["msg_exact_status_3", "applied"], ["msg_exact_status_duplicate", "duplicate"],
      ["msg_exact_status_reordered", "rejected"], ["msg_exact_status_digest", "rejected"], ["msg_exact_status_epoch", "rejected"],
    ]);
    expect(receipts.results.slice(3).map((row) => JSON.parse(row.result_json).reason)).toEqual(["status_revision_reordered", "status_custody_mismatch", "stale_connection_epoch"]);
  });

  it("releases terminal admission concurrency and projects monotonic Device health", async () => {
    const now = new Date().toISOString();
    const rejectedOperation = "op_exact_rejected";
    const rejectedDigest = "e".repeat(64);
    await env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'exact-rejected-key',?2,?3,?4,'cpol_owner_first_party_v1',1,'commands','command.start',?5,'{}','offered',?6,?7,?7)").bind(rejectedOperation, actor.principalId, actor.clientId, deviceId, rejectedDigest, expiresAt, now).run();
    await projectNodeState(env, frame("msg_exact_rejected", "110", "operation.admission", rejectedOperation, { operationId: rejectedOperation, idempotencyKey: "exact-rejected-key", requestDigest: rejectedDigest, decision: "rejected", journalState: "rejected", localPolicyRevision: 1, receiptDigest: "f".repeat(64) }));
    const released = await env.DB.prepare("SELECT state,concurrency_released_at FROM operation_journal WHERE id=?1").bind(rejectedOperation).first<{ state: string; concurrency_released_at: string | null }>();
    expect(released?.state).toBe("rejected");
    expect(released?.concurrency_released_at).not.toBeNull();

    await projectNodeState(env, frame("msg_exact_health", "200", "device.health", undefined, { observedAt: now, nodeState: "busy", journalState: "healthy", storageState: "healthy", activeCommands: 2, activeAgentRuns: 3, activeRuntimes: 1 }));
    await projectNodeState(env, frame("msg_exact_health_reordered", "199", "device.health", undefined, { observedAt: now, nodeState: "ready", journalState: "healthy", storageState: "healthy", activeAgentRuns: 0 }));
    await projectNodeState(env, frame("msg_exact_health_epoch", "201", "device.health", undefined, { observedAt: now, nodeState: "ready", journalState: "healthy", storageState: "healthy", activeAgentRuns: 0 }, "6"));
    const health = await env.DB.prepare("SELECT health_sequence,active_run_count,health_json FROM devices WHERE id=?1").bind(deviceId).first<{ health_sequence: string; active_run_count: number; health_json: string }>();
    expect(health).toMatchObject({ health_sequence: "200", active_run_count: 3 });
    expect(JSON.parse(health!.health_json)).toMatchObject({ nodeState: "busy", activeAgentRuns: 3 });
  });

  it("projects a Runtime control result once without creating a process representation", async () => {
    const operationId = createdControls.get("runtime.pause")!;
    const now = new Date().toISOString();
    const result = frame("msg_exact_runtime_pause", "300", "runtime.control_result", operationId, {
      operationId, targetRunId: runId, targetRuntimeId: runtimeId, targetDigest: runtimeDigest, control: "pause", state: "paused", revision: "4", processCountDelta: 0, result: { signal: "pause" }, receiptDigest: "0".repeat(64), observedAt: now,
    });
    await projectNodeState(env, result);
    await projectNodeState(env, result);
    const projected = await env.DB.prepare("SELECT journal.state AS operation_state,journal.node_state_revision,custody.state AS runtime_state,custody.revision,(SELECT COUNT(*) FROM operation_journal WHERE run_id=?1 AND operation_kind='start') AS starts,(SELECT COUNT(*) FROM runtime_custody WHERE run_id=?1) AS runtimes FROM operation_journal AS journal JOIN runtime_custody AS custody ON custody.runtime_id=journal.target_runtime_id WHERE journal.id=?2").bind(runId, operationId).first<Record<string, unknown>>();
    expect(projected).toMatchObject({ operation_state: "completed", node_state_revision: 4, runtime_state: "paused", revision: 4, starts: 1, runtimes: 1 });
  });
});

function frame<Type extends ProjectedFrame["type"]>(
  messageId: string,
  sequence: string,
  type: Type,
  correlationId: string | undefined,
  payload: Extract<ProjectedFrame, { type: Type }>["payload"],
  connectionEpoch = "7",
): Extract<ProjectedFrame, { type: Type }> {
  return {
    protocol: "conduit.node/1",
    messageId,
    deviceId: "dev_exact_control",
    connectionEpoch,
    direction: "node_to_control",
    sequence,
    type,
    ...(correlationId === undefined ? {} : { correlationId }),
    payloadDigest: "a".repeat(64),
    payload,
  } as Extract<ProjectedFrame, { type: Type }>;
}
