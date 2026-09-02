import type { NodeV1PostAuthFrame } from "@conduit/schema";
import { canonicalJson, newId, nowIso } from "./crypto.ts";
import { ensureOperationConcurrencyReleased } from "./dispatch.ts";
import type { ControlPlaneEnv } from "./types.ts";
import { requireVerifiedPrivilegeReceipt } from "./privilege.ts";

type ProjectedType = "operation.admission" | "operation.status" | "runtime.control_result" | "device.health";
type ProjectableFrame = Extract<NodeV1PostAuthFrame, { type: ProjectedType }>;

interface OperationProjectionRow {
  id: string;
  device_id: string;
  payload_digest: string;
  run_id: string | null;
  assignment_id: string | null;
  session_id: string | null;
  state: string;
  node_state_revision: number;
  request_json: string;
  operation_kind: string;
  target_runtime_id: string | null;
  target_digest: string | null;
  expected_target_revision: number | null;
  target_controller_epoch: string | null;
  expected_target_state: string | null;
  result_json: string | null;
}

export interface NodeProjectionEvent {
  sessionId: string;
  eventId: string;
  type: string;
  recordId: string;
  revision: number;
}

function payload(frame: ProjectableFrame): Record<string, unknown> {
  return frame.payload as unknown as Record<string, unknown>;
}

function safeRevision(value: unknown): number | null {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return null;
  const revision = Number(value);
  return Number.isSafeInteger(revision) ? revision : null;
}

async function existingReceipt(env: ControlPlaneEnv, frame: ProjectableFrame): Promise<boolean> {
  const prior = await env.DB.prepare("SELECT device_id,connection_epoch,node_sequence,frame_type,payload_digest FROM node_projection_receipts WHERE message_id=?1 LIMIT 1")
    .bind(frame.messageId).first<{ device_id: string; connection_epoch: string; node_sequence: string; frame_type: string; payload_digest: string }>();
  if (prior === null) return false;
  if (prior.device_id !== frame.deviceId || prior.connection_epoch !== frame.connectionEpoch || prior.node_sequence !== frame.sequence || prior.frame_type !== frame.type || prior.payload_digest !== frame.payloadDigest) throw new TypeError("node projection message identity conflict");
  return true;
}

async function rejectProjection(env: ControlPlaneEnv, frame: ProjectableFrame, operationId: string | null, reason: string): Promise<void> {
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO node_projection_receipts(message_id,device_id,connection_epoch,node_sequence,frame_type,correlation_id,operation_id,payload_digest,projection_state,result_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'rejected',?9,?10)")
      .bind(frame.messageId, frame.deviceId, frame.connectionEpoch, frame.sequence, frame.type, frame.correlationId ?? null, operationId, frame.payloadDigest, canonicalJson({ reason }), now),
    env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'node_projection.rejected',?2,?3,?4)")
      .bind(newId("sevt"), frame.deviceId, canonicalJson({ messageId: frame.messageId, sequence: frame.sequence, type: frame.type, operationId, reason }), now),
  ]);
}

async function operationFor(env: ControlPlaneEnv, operationId: string): Promise<OperationProjectionRow | null> {
  return env.DB.prepare("SELECT id,device_id,payload_digest,run_id,assignment_id,session_id,state,node_state_revision,request_json,operation_kind,target_runtime_id,target_digest,expected_target_revision,target_controller_epoch,expected_target_state,result_json FROM operation_journal WHERE id=?1 LIMIT 1")
    .bind(operationId).first<OperationProjectionRow>();
}

function receipt(env: ControlPlaneEnv, frame: ProjectableFrame, operationId: string | null, result: unknown): D1PreparedStatement {
  return env.DB.prepare("INSERT INTO node_projection_receipts(message_id,device_id,connection_epoch,node_sequence,frame_type,correlation_id,operation_id,payload_digest,projection_state,result_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'applied',?9,?10)")
    .bind(frame.messageId, frame.deviceId, frame.connectionEpoch, frame.sequence, frame.type, frame.correlationId ?? null, operationId, frame.payloadDigest, canonicalJson(result), nowIso());
}

function projectionResult(frame: ProjectableFrame, data: Record<string, unknown>): string {
  return canonicalJson({ ...data, projectionMessageId: frame.messageId });
}

function conditionalReceipt(env: ControlPlaneEnv, frame: ProjectableFrame, operationId: string, operationResultJson: string, result: unknown): D1PreparedStatement {
  return env.DB.prepare("INSERT INTO node_projection_receipts(message_id,device_id,connection_epoch,node_sequence,frame_type,correlation_id,operation_id,payload_digest,projection_state,result_json,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,'applied',?9,?10 WHERE EXISTS (SELECT 1 FROM operation_journal WHERE id=?7 AND result_json=?11)")
    .bind(frame.messageId, frame.deviceId, frame.connectionEpoch, frame.sequence, frame.type, frame.correlationId ?? null, operationId, frame.payloadDigest, canonicalJson(result), nowIso(), operationResultJson);
}

function operationSharedState(nodeState: string): string {
  if (nodeState === "reserved" || nodeState === "admitted") return "admitted";
  if (["starting", "running", "waiting_input", "waiting_approval", "finishing"].includes(nodeState)) return "claimed";
  if (["completed", "failed", "cancelled", "expired", "rejected", "uncertain"].includes(nodeState)) return nodeState;
  if (["timed_out", "lost", "recovery_required"].includes(nodeState)) return "uncertain";
  throw new TypeError("unsupported node operation state");
}

function runState(nodeState: string): string {
  if (nodeState === "reserved" || nodeState === "admitted") return "admitted";
  if (nodeState === "starting") return "starting_agent";
  if (nodeState === "running") return "working";
  if (["waiting_input", "waiting_approval", "finishing", "completed", "failed", "cancelled", "lost", "uncertain"].includes(nodeState)) return nodeState;
  if (nodeState === "timed_out" || nodeState === "recovery_required") return "uncertain";
  if (nodeState === "rejected" || nodeState === "expired") return "failed";
  throw new TypeError("unsupported Run projection state");
}

function statusCanAdvance(previous: string | null, next: string): boolean {
  if (previous === null || previous === next) return true;
  const allowed: Record<string, readonly string[]> = {
    reserved: ["admitted", "starting", "running", "failed", "cancelled", "rejected", "expired", "uncertain"],
    admitted: ["starting", "running", "failed", "cancelled", "rejected", "expired", "uncertain"],
    starting: ["running", "waiting_input", "waiting_approval", "failed", "cancelled", "lost", "uncertain", "recovery_required"],
    running: ["waiting_input", "waiting_approval", "finishing", "completed", "failed", "cancelled", "timed_out", "lost", "uncertain", "recovery_required"],
    waiting_input: ["running", "waiting_approval", "finishing", "completed", "failed", "cancelled", "timed_out", "lost", "uncertain", "recovery_required"],
    waiting_approval: ["running", "waiting_input", "finishing", "completed", "failed", "cancelled", "timed_out", "lost", "uncertain", "recovery_required"],
    finishing: ["completed", "failed", "cancelled", "timed_out", "lost", "uncertain", "recovery_required"],
  };
  return allowed[previous]?.includes(next) === true;
}

function assignmentState(nodeState: string): string | null {
  if (["admitted", "starting", "running", "finishing"].includes(nodeState)) return "active";
  if (nodeState === "waiting_input") return "waiting_input";
  if (nodeState === "waiting_approval") return "waiting_approval";
  if (nodeState === "cancelled") return "cancelled";
  if (["failed", "timed_out", "lost", "uncertain", "recovery_required", "rejected", "expired"].includes(nodeState)) return "failed";
  return null;
}

function sessionState(nodeState: string): string {
  if (nodeState === "waiting_input") return "waiting_input";
  if (nodeState === "waiting_approval") return "waiting_approval";
  if (nodeState === "finishing") return "closing";
  if (nodeState === "completed") return "closed";
  if (["failed", "lost", "uncertain", "recovery_required"].includes(nodeState)) return "recovery_required";
  if (nodeState === "cancelled") return "cancelled";
  return "running";
}

function realtime(frame: ProjectableFrame, operation: OperationProjectionRow, type: string, revision: number): NodeProjectionEvent[] {
  return operation.session_id === null || operation.run_id === null ? [] : [{ sessionId: operation.session_id, eventId: `bevt_${frame.messageId}`, type, recordId: operation.run_id, revision }];
}

async function projectAdmission(env: ControlPlaneEnv, frame: Extract<ProjectableFrame, { type: "operation.admission" }>): Promise<NodeProjectionEvent[]> {
  const data = payload(frame);
  const operationId = typeof data.operationId === "string" ? data.operationId : "";
  const operation = operationId === "" ? null : await operationFor(env, operationId);
  if (operation === null || frame.correlationId !== operationId || operation.device_id !== frame.deviceId || data.requestDigest !== operation.payload_digest) {
    await rejectProjection(env, frame, operation?.id ?? null, "admission_custody_mismatch");
    return [];
  }
  const device = await env.DB.prepare("SELECT connection_epoch FROM devices WHERE id=?1 AND status='active' LIMIT 1").bind(frame.deviceId).first<{ connection_epoch: string }>();
  if (device?.connection_epoch !== frame.connectionEpoch) {
    await rejectProjection(env, frame, operation.id, "stale_connection_epoch");
    return [];
  }
  const decision = String(data.decision ?? "");
  const next = decision === "admitted" || decision === "duplicate_replay" ? "admitted" : decision === "rejected" ? "rejected" : decision === "expired" ? "expired" : decision === "uncertain" ? "uncertain" : null;
  if (next === null) {
    await rejectProjection(env, frame, operation.id, "admission_decision_invalid");
    return [];
  }
  if (next === "admitted") await requireVerifiedPrivilegeReceipt(env, { operationId: operation.id, deviceId: frame.deviceId, runId: operation.run_id, requestDigest: operation.payload_digest, receiptDigest: data.privilegeReceiptDigest, transition: "admission", runtimeId: data.targetRuntimeId, controllerEpoch: data.controllerEpoch });
  const currentAllowed = next === "admitted" ? ["queued", "offered", "admitted"] : ["queued", "offered", "admitted", "claimed"];
  if (!currentAllowed.includes(operation.state) && operation.state !== next) {
    await rejectProjection(env, frame, operation.id, "admission_transition_reordered");
    return [];
  }
  const now = nowIso();
  const resultJson = projectionResult(frame, data);
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("UPDATE operation_journal SET state=?1,result_json=?2,updated_at=?3 WHERE id=?4 AND state=?5 AND node_state_revision=?6 AND result_json IS ?7")
      .bind(next, resultJson, now, operation.id, operation.state, operation.node_state_revision, operation.result_json),
    env.DB.prepare("UPDATE idempotency_records SET state=?1,response_json=?2 WHERE operation_id=?3 AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?3 AND result_json=?4)").bind(next, canonicalJson({ operationId: operation.id, state: next, admission: data }), operation.id, resultJson),
    conditionalReceipt(env, frame, operation.id, resultJson, { state: next }),
  ];
  const assignmentNext = assignmentState(next);
  if (operation.run_id !== null) statements.push(env.DB.prepare("UPDATE runs SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND state NOT IN ('completed','cancelled','failed','ready_for_review','accepted') AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?4 AND result_json=?5)").bind(runState(next), now, operation.run_id, operation.id, resultJson));
  if (operation.assignment_id !== null && assignmentNext !== null) statements.push(env.DB.prepare("UPDATE assignments SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND state IN ('queued','active','waiting_input','waiting_approval') AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?4 AND result_json=?5)").bind(assignmentNext, now, operation.assignment_id, operation.id, resultJson));
  const results = await env.DB.batch(statements);
  if (results[0]?.meta.changes !== 1) {
    await rejectProjection(env, frame, operation.id, "admission_projection_lost_race");
    return [];
  }
  if (["rejected", "expired", "uncertain"].includes(next)) await ensureOperationConcurrencyReleased(env, operation.id);
  return realtime(frame, operation, `operation.${next}`, 1);
}

async function projectStatus(env: ControlPlaneEnv, frame: Extract<ProjectableFrame, { type: "operation.status" }>): Promise<NodeProjectionEvent[]> {
  const data = payload(frame);
  const operationId = typeof data.operationId === "string" ? data.operationId : "";
  const operation = operationId === "" ? null : await operationFor(env, operationId);
  const revision = safeRevision(data.revision);
  const controllerEpoch = safeRevision(data.controllerEpoch);
  if (operation === null || frame.correlationId !== operationId || operation.device_id !== frame.deviceId || data.requestDigest !== operation.payload_digest || revision === null || controllerEpoch === null || (operation.run_id !== null && data.runId !== operation.run_id)) {
    await rejectProjection(env, frame, operation?.id ?? null, "status_custody_mismatch");
    return [];
  }
  const device = await env.DB.prepare("SELECT connection_epoch FROM devices WHERE id=?1 AND status='active' LIMIT 1").bind(frame.deviceId).first<{ connection_epoch: string }>();
  if (device?.connection_epoch !== frame.connectionEpoch) {
    await rejectProjection(env, frame, operation.id, "stale_connection_epoch");
    return [];
  }
  const state = typeof data.state === "string" ? data.state : "";
  let shared: string;
  try { shared = operationSharedState(state); } catch {
    await rejectProjection(env, frame, operation.id, "status_state_invalid");
    return [];
  }
  if (revision < operation.node_state_revision) {
    await rejectProjection(env, frame, operation.id, "status_revision_reordered");
    return [];
  }
  if (revision === operation.node_state_revision) {
    let previousState: unknown;
    try { previousState = operation.result_json === null ? undefined : (JSON.parse(operation.result_json) as Record<string, unknown>).state; } catch { previousState = undefined; }
    if (previousState !== state) {
      await rejectProjection(env, frame, operation.id, "status_revision_identity_mismatch");
      return [];
    }
    await env.DB.prepare("INSERT INTO node_projection_receipts(message_id,device_id,connection_epoch,node_sequence,frame_type,correlation_id,operation_id,payload_digest,projection_state,result_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'duplicate',?9,?10)")
      .bind(frame.messageId, frame.deviceId, frame.connectionEpoch, frame.sequence, frame.type, frame.correlationId ?? null, operation.id, frame.payloadDigest, canonicalJson({ state, revision }), nowIso()).run();
    return [];
  }
  let previousState: string | null = null;
  try {
    const prior = operation.result_json === null ? null : JSON.parse(operation.result_json) as Record<string, unknown>;
    previousState = typeof prior?.state === "string" ? prior.state : null;
  } catch { previousState = null; }
  if (!statusCanAdvance(previousState, state)) {
    await rejectProjection(env, frame, operation.id, "status_transition_reordered");
    return [];
  }
  const privilegeTransition = ["completed", "failed", "cancelled", "timed_out", "lost", "uncertain", "recovery_required"].includes(state) ? "terminal" : ["starting", "reserved", "admitted"].includes(state) ? "admission" : "running";
  await requireVerifiedPrivilegeReceipt(env, { operationId: operation.id, deviceId: frame.deviceId, runId: operation.run_id, requestDigest: operation.payload_digest, receiptDigest: data.privilegeReceiptDigest, transition: privilegeTransition, runtimeId: data.targetRuntimeId, controllerEpoch });
  const now = nowIso();
  const resultJson = projectionResult(frame, data);
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("UPDATE operation_journal SET state=?1,node_state_revision=?2,result_json=?3,updated_at=?4 WHERE id=?5 AND node_state_revision=?6 AND state=?7 AND result_json IS ?8 AND state NOT IN ('completed','failed','cancelled','expired','rejected','uncertain')").bind(shared, revision, resultJson, now, operation.id, operation.node_state_revision, operation.state, operation.result_json),
    conditionalReceipt(env, frame, operation.id, resultJson, { state, revision }),
  ];
  if (operation.run_id !== null) statements.push(env.DB.prepare("UPDATE runs SET state=?1,revision=revision+1,controller_epoch=?2,updated_at=?3 WHERE id=?4 AND state NOT IN ('completed','cancelled','failed','ready_for_review','accepted') AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?5 AND result_json=?6)").bind(runState(state), String(controllerEpoch), now, operation.run_id, operation.id, resultJson));
  const assignmentNext = assignmentState(state);
  if (operation.assignment_id !== null && assignmentNext !== null) statements.push(env.DB.prepare("UPDATE assignments SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND state IN ('queued','active','waiting_input','waiting_approval') AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?4 AND result_json=?5)").bind(assignmentNext, now, operation.assignment_id, operation.id, resultJson));

  const request = JSON.parse(operation.request_json) as { capability?: unknown; arguments?: Record<string, unknown> };
  const runtimeId = typeof data.targetRuntimeId === "string" ? data.targetRuntimeId : null;
  const handleDigest = typeof data.runtimeHandleDigest === "string" ? data.runtimeHandleDigest : null;
  const runtimeTargetDigest = typeof data.runtimeTargetDigest === "string" ? data.runtimeTargetDigest : typeof data.targetDigest === "string" && request.capability !== "agent.run.start" ? data.targetDigest : null;
  if (runtimeId !== null && handleDigest !== null && runtimeTargetDigest !== null && operation.run_id !== null) {
    const currentRuntime = await env.DB.prepare("SELECT start_operation_id,handle_digest,target_digest,controller_epoch FROM runtime_custody WHERE runtime_id=?1 OR run_id=?2 LIMIT 1").bind(runtimeId, operation.run_id).first<{ start_operation_id: string; handle_digest: string; target_digest: string; controller_epoch: string }>();
    if (currentRuntime !== null && (currentRuntime.start_operation_id !== operation.id || currentRuntime.handle_digest !== handleDigest || currentRuntime.target_digest !== runtimeTargetDigest || currentRuntime.controller_epoch !== String(controllerEpoch))) {
      await rejectProjection(env, frame, operation.id, "runtime_custody_identity_mismatch");
      return [];
    }
    statements.push(env.DB.prepare("INSERT INTO runtime_custody(runtime_id,run_id,start_operation_id,device_id,provider_id,handle_digest,target_digest,controller_epoch,state,revision,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'running',?9,?10,?10) ON CONFLICT(runtime_id) DO UPDATE SET handle_digest=excluded.handle_digest,target_digest=excluded.target_digest,controller_epoch=excluded.controller_epoch,state=excluded.state,revision=excluded.revision,updated_at=excluded.updated_at WHERE runtime_custody.start_operation_id=excluded.start_operation_id AND runtime_custody.revision<excluded.revision")
      .bind(runtimeId, operation.run_id, operation.id, frame.deviceId, String(data.selectedRuntimeProvider ?? "unknown"), handleDigest, runtimeTargetDigest, String(controllerEpoch), revision, now));
  }
  if (request.capability === "agent.run.start" && operation.run_id !== null && typeof data.targetDigest === "string") {
    const args = request.arguments ?? {};
    const policy = args.settlementPolicy === "persistent" ? "waiting_input" : "close_on_settle";
    const leaseMs = typeof args.sessionLeaseMs === "number" && Number.isSafeInteger(args.sessionLeaseMs) ? args.sessionLeaseMs : null;
    const lease = leaseMs === null ? null : new Date(Date.parse(String(data.observedAt)) + leaseMs).toISOString();
    const agentSessionId = `ags_${operation.run_id.replace(/^run_/, "")}`;
    const currentSession = await env.DB.prepare("SELECT start_operation_id,target_digest,controller_epoch FROM agent_sessions WHERE run_id=?1 LIMIT 1").bind(operation.run_id).first<{ start_operation_id: string; target_digest: string; controller_epoch: string }>();
    if (currentSession !== null && (currentSession.start_operation_id !== operation.id || currentSession.target_digest !== data.targetDigest || currentSession.controller_epoch !== String(controllerEpoch))) {
      await rejectProjection(env, frame, operation.id, "agent_session_identity_mismatch");
      return [];
    }
    statements.push(
      env.DB.prepare("INSERT INTO agent_sessions(id,run_id,start_operation_id,device_id,adapter_id,native_session_id,target_digest,settlement_policy,state,controller_epoch,revision,lease_expires_at,last_activity_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,NULL,?6,?7,?8,?9,?10,?11,?12,?12,?12) ON CONFLICT(run_id) DO UPDATE SET target_digest=excluded.target_digest,state=excluded.state,controller_epoch=excluded.controller_epoch,revision=excluded.revision,lease_expires_at=excluded.lease_expires_at,last_activity_at=excluded.last_activity_at,updated_at=excluded.updated_at WHERE agent_sessions.start_operation_id=excluded.start_operation_id AND agent_sessions.revision<excluded.revision")
        .bind(agentSessionId, operation.run_id, operation.id, frame.deviceId, String(args.adapterId ?? "unknown"), data.targetDigest, policy, sessionState(state), String(controllerEpoch), revision, lease, now),
      env.DB.prepare("UPDATE runs SET agent_session_id=?1 WHERE id=?2 AND (agent_session_id IS NULL OR agent_session_id=?1)").bind(agentSessionId, operation.run_id),
    );
  }
  const results = await env.DB.batch(statements);
  if (results[0]?.meta.changes !== 1) {
    await rejectProjection(env, frame, operation.id, "status_projection_lost_race");
    return [];
  }
  return realtime(frame, operation, `run.${state}`, revision);
}

async function projectRuntimeControl(env: ControlPlaneEnv, frame: Extract<ProjectableFrame, { type: "runtime.control_result" }>): Promise<NodeProjectionEvent[]> {
  const data = payload(frame);
  const operationId = typeof data.operationId === "string" ? data.operationId : "";
  const operation = operationId === "" ? null : await operationFor(env, operationId);
  const revision = safeRevision(data.revision);
  const expectedRevision = safeRevision(data.expectedRevision);
  let request: Record<string, unknown> | null = null;
  try { request = operation === null ? null : JSON.parse(operation.request_json) as Record<string, unknown>; } catch { request = null; }
  if (operation === null
    || operation.operation_kind !== "runtime_control"
    || frame.correlationId !== operationId
    || operation.device_id !== frame.deviceId
    || data.requestDigest !== operation.payload_digest
    || data.targetRunId !== operation.run_id
    || data.targetRuntimeId !== operation.target_runtime_id
    || data.targetControllerEpoch !== operation.target_controller_epoch
    || data.targetDigest !== operation.target_digest
    || data.expectedState !== operation.expected_target_state
    || expectedRevision === null
    || expectedRevision !== operation.expected_target_revision
    || revision === null
    || operation.expected_target_revision === null
    || revision !== operation.expected_target_revision + 1
    || request === null
    || request.operationId !== operation.id
    || request.targetRunId !== data.targetRunId
    || request.targetRuntimeId !== data.targetRuntimeId
    || request.targetControllerEpoch !== data.targetControllerEpoch
    || request.targetDigest !== data.targetDigest
    || request.expectedState !== data.expectedState
    || request.expectedRevision !== data.expectedRevision
    || request.control !== data.control) {
    await rejectProjection(env, frame, operation?.id ?? null, "runtime_control_custody_mismatch");
    return [];
  }
  const device = await env.DB.prepare("SELECT connection_epoch FROM devices WHERE id=?1 AND status='active' LIMIT 1").bind(frame.deviceId).first<{ connection_epoch: string }>();
  if (device?.connection_epoch !== frame.connectionEpoch) {
    await rejectProjection(env, frame, operation.id, "stale_connection_epoch");
    return [];
  }
  await requireVerifiedPrivilegeReceipt(env, { operationId: operation.id, deviceId: frame.deviceId, runId: operation.run_id, requestDigest: operation.payload_digest, receiptDigest: data.privilegeReceiptDigest, transition: "control", runtimeId: data.targetRuntimeId, controllerEpoch: data.targetControllerEpoch });
  const now = nowIso();
  const state = String(data.state ?? "uncertain");
  const resultJson = projectionResult(frame, data);
  const results = await env.DB.batch([
    env.DB.prepare("UPDATE operation_journal SET state='completed',node_state_revision=?1,result_json=?2,updated_at=?3 WHERE id=?4 AND state=?5 AND node_state_revision=?6 AND result_json IS ?7 AND state IN ('queued','offered','admitted','claimed') AND EXISTS (SELECT 1 FROM runtime_custody WHERE runtime_id=?8 AND run_id=?9 AND device_id=?10 AND target_digest=?11 AND controller_epoch=?12 AND state=?13 AND revision=?14)")
      .bind(revision, resultJson, now, operation.id, operation.state, operation.node_state_revision, operation.result_json, operation.target_runtime_id, operation.run_id, operation.device_id, operation.target_digest, operation.target_controller_epoch, operation.expected_target_state, operation.expected_target_revision),
    env.DB.prepare("UPDATE runtime_custody SET state=?1,revision=?2,updated_at=?3 WHERE runtime_id=?4 AND run_id=?5 AND device_id=?6 AND target_digest=?7 AND controller_epoch=?8 AND state=?9 AND revision=?10 AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?11 AND result_json=?12)")
      .bind(state, revision, now, operation.target_runtime_id, operation.run_id, operation.device_id, operation.target_digest, operation.target_controller_epoch, operation.expected_target_state, operation.expected_target_revision, operation.id, resultJson),
    env.DB.prepare("UPDATE idempotency_records SET state='completed',response_json=?1 WHERE operation_id=?2 AND EXISTS (SELECT 1 FROM operation_journal WHERE id=?2 AND result_json=?3)").bind(canonicalJson({ operationId: operation.id, state: "completed", result: data }), operation.id, resultJson),
    conditionalReceipt(env, frame, operation.id, resultJson, { state, revision }),
  ]);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) {
    await rejectProjection(env, frame, operation.id, "runtime_control_projection_lost_race");
    return [];
  }
  return realtime(frame, operation, `runtime.${String(data.control ?? "control")}.${state}`, revision);
}

async function projectHealth(env: ControlPlaneEnv, frame: Extract<ProjectableFrame, { type: "device.health" }>): Promise<NodeProjectionEvent[]> {
  const device = await env.DB.prepare("SELECT connection_epoch,health_sequence FROM devices WHERE id=?1 AND status='active' LIMIT 1").bind(frame.deviceId).first<{ connection_epoch: string; health_sequence: string }>();
  if (device === null || device.connection_epoch !== frame.connectionEpoch) {
    await rejectProjection(env, frame, null, "stale_connection_epoch");
    return [];
  }
  if (BigInt(frame.sequence) <= BigInt(device.health_sequence)) {
    await rejectProjection(env, frame, null, "health_sequence_reordered");
    return [];
  }
  const data = payload(frame);
  const activeRuns = typeof data.activeAgentRuns === "number" && Number.isSafeInteger(data.activeAgentRuns) && data.activeAgentRuns >= 0 ? data.activeAgentRuns : 0;
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("UPDATE devices SET health_sequence=?1,health_json=?2,health_observed_at=?3,last_observed_at=?4,active_run_count=?5,updated_at=?4 WHERE id=?6 AND connection_epoch=?7").bind(frame.sequence, canonicalJson(data), String(data.observedAt), now, activeRuns, frame.deviceId, frame.connectionEpoch),
    receipt(env, frame, null, { healthSequence: frame.sequence }),
  ]);
  return [];
}

export async function projectNodeState(env: ControlPlaneEnv, frame: ProjectableFrame): Promise<NodeProjectionEvent[]> {
  if (await existingReceipt(env, frame)) return [];
  if (frame.type === "operation.admission") return projectAdmission(env, frame);
  if (frame.type === "operation.status") return projectStatus(env, frame);
  if (frame.type === "runtime.control_result") return projectRuntimeControl(env, frame);
  return projectHealth(env, frame);
}
