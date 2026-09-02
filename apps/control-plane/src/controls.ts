import { parseWireDocument, schemaIds } from "@conduit/schema";
import { z } from "zod";
import { attemptOperationDispatch } from "./dispatch.ts";
import { canonicalJson, newId, nowIso, operationDigest, sha256Hex } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { authorizeConnector } from "./policy.ts";
import type { AuthActor, ControlPlaneEnv, RuntimeKind } from "./types.ts";

const OWNER_POLICY_ID = "cpol_owner_first_party_v1";
const OWNER_POLICY_REVISION = 1;

const controlSchema = z.strictObject({
  command: z.enum(["input", "steer", "follow_up", "close", "cancel", "pause", "resume", "stop", "snapshot", "restore", "destroy"]),
  expectedState: z.string().min(1).max(64),
  expectedRevision: z.number().int().min(1),
  content: z.string().max(32_768).optional(),
  snapshotName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/).optional(),
  discardAuthorized: z.boolean().optional(),
  custodyComplete: z.boolean().optional(),
  expiresInSeconds: z.number().int().min(30).max(3600).optional(),
});

export interface ExistingTargetControlInput {
  targetKind: "agent" | "runtime";
  targetId: string;
  idempotencyKey: string;
  body: unknown;
}

interface AgentTarget {
  session_id: string;
  run_id: string;
  start_operation_id: string;
  device_id: string;
  project_id: string | null;
  collaboration_session_id: string | null;
  assignment_id: string | null;
  adapter_id: string;
  target_digest: string;
  controller_epoch: string;
  state: string;
  revision: number;
  request_digest: string;
}

interface RuntimeTarget {
  runtime_id: string;
  run_id: string;
  start_operation_id: string;
  device_id: string;
  provider_id: string;
  handle_digest: string;
  target_digest: string;
  controller_epoch: string;
  state: string;
  revision: number;
  project_id: string | null;
  collaboration_session_id: string | null;
  assignment_id: string | null;
  runtime_kind: RuntimeKind;
  request_digest: string;
}

function assertCommand(kind: "agent" | "runtime", command: string): void {
  const allowed = kind === "agent"
    ? new Set(["input", "steer", "follow_up", "close", "cancel"])
    : new Set(["pause", "resume", "stop", "snapshot", "restore", "destroy"]);
  if (!allowed.has(command)) throw new PublicError("invalid_request", 400, `${command} is not a ${kind} control`);
}

function runtimeKind(value: string): RuntimeKind {
  if (value === "native" || value === "restricted_native" || value === "container" || value === "vm") return value;
  throw new TypeError("Stored Runtime kind is invalid");
}

export async function createExistingTargetControl(
  env: ControlPlaneEnv,
  actor: AuthActor,
  input: ExistingTargetControlInput,
  authorization: "owner" | "connector",
): Promise<Record<string, unknown>> {
  const parsed = controlSchema.safeParse(input.body);
  if (!parsed.success) throw new PublicError("invalid_request", 400, `Control input is invalid: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  const body = parsed.data;
  assertCommand(input.targetKind, body.command);

  const agent = input.targetKind === "agent"
    ? await env.DB.prepare("SELECT session.id AS session_id,session.run_id,session.start_operation_id,session.device_id,run.project_id,run.session_id AS collaboration_session_id,run.assignment_id,session.adapter_id,session.target_digest,session.controller_epoch,session.state,session.revision,operation.payload_digest AS request_digest FROM agent_sessions AS session JOIN runs AS run ON run.id=session.run_id JOIN operation_journal AS operation ON operation.id=session.start_operation_id WHERE session.run_id=?1 OR run.assignment_id=?1 ORDER BY run.created_at DESC LIMIT 1")
      .bind(input.targetId).first<AgentTarget>()
    : null;
  const runtime = input.targetKind === "runtime"
    ? await env.DB.prepare("SELECT custody.runtime_id,custody.run_id,custody.start_operation_id,custody.device_id,custody.provider_id,custody.handle_digest,custody.target_digest,custody.controller_epoch,custody.state,custody.revision,run.project_id,run.session_id AS collaboration_session_id,run.assignment_id,run.runtime_kind,operation.payload_digest AS request_digest FROM runtime_custody AS custody JOIN runs AS run ON run.id=custody.run_id JOIN operation_journal AS operation ON operation.id=custody.start_operation_id WHERE custody.runtime_id=?1 OR custody.run_id=?1 LIMIT 1")
      .bind(input.targetId).first<Omit<RuntimeTarget, "runtime_kind"> & { runtime_kind: string }>()
    : null;
  if (agent === null && runtime === null) throw new PublicError("not_found", 404, `${input.targetKind === "agent" ? "Run Agent Session" : "Runtime"} not found`);
  const target = agent ?? runtime!;
  if (target.state !== body.expectedState || target.revision !== body.expectedRevision) throw new PublicError("revision_conflict", 409, `Target changed: state=${target.state}, revision=${target.revision}`);

  const effectiveActor: AuthActor = authorization === "owner"
    ? { ...actor, policyId: OWNER_POLICY_ID, policyRevision: OWNER_POLICY_REVISION }
    : actor;
  const stableDigest = await operationDigest({
    actorPrincipalId: effectiveActor.principalId,
    clientId: effectiveActor.clientId,
    targetKind: input.targetKind,
    targetRunId: target.run_id,
    targetStartOperationId: target.start_operation_id,
    targetDigest: target.target_digest,
    targetControllerEpoch: target.controller_epoch,
    body,
  });
  const idempotencyScope = effectiveActor.grantId ?? `owner:${effectiveActor.principalId}:${effectiveActor.clientId}`;
  const existing = await env.DB.prepare("SELECT operation_id,payload_digest,response_json,state FROM idempotency_records WHERE scope=?1 AND idempotency_key=?2 LIMIT 1")
    .bind(idempotencyScope, input.idempotencyKey).first<{ operation_id: string; payload_digest: string; response_json: string | null; state: string }>();
  if (existing !== null) {
    if (existing.payload_digest !== stableDigest) throw new PublicError("idempotency_conflict", 409, "Idempotency key is bound to another control");
    const retried = await attemptOperationDispatch(env, existing.operation_id, { force: true });
    return retried === null ? { operationId: existing.operation_id, state: existing.state, replay: true } : { ...retried, replay: true };
  }

  const operationId = newId("op");
  const frameType = input.targetKind === "runtime" ? "runtime.control" : body.command === "cancel" ? "operation.cancel" : "operation.input";
  const payload: Record<string, unknown> = input.targetKind === "runtime"
    ? {
        operationId,
        idempotencyKey: input.idempotencyKey,
        targetRunId: target.run_id,
        targetRuntimeId: (runtime as RuntimeTarget).runtime_id,
        targetHandleDigest: (runtime as RuntimeTarget).handle_digest,
        targetControllerEpoch: target.controller_epoch,
        targetDigest: target.target_digest,
        expectedState: body.expectedState,
        expectedRevision: String(body.expectedRevision),
        control: body.command,
        ...(body.content === undefined ? {} : { content: body.content }),
        ...(body.snapshotName === undefined ? {} : { snapshotName: body.snapshotName }),
        ...(body.discardAuthorized === undefined ? {} : { discardAuthorized: body.discardAuthorized }),
        ...(body.custodyComplete === undefined ? {} : { custodyComplete: body.custodyComplete }),
      }
    : {
        operationId,
        idempotencyKey: input.idempotencyKey,
        targetRunId: target.run_id,
        targetControllerEpoch: target.controller_epoch,
        targetDigest: target.target_digest,
        expectedState: body.expectedState,
        expectedRevision: String(body.expectedRevision),
        mode: body.command,
        ...(body.content === undefined ? {} : { content: body.content }),
      };
  const payloadDigest = await sha256Hex(canonicalJson(payload));
  if (authorization === "connector") {
    await authorizeConnector(env, effectiveActor, {
      operation: input.targetKind === "runtime" ? "runtime.control" : "run.control",
      deviceId: target.device_id,
      ...(target.project_id === null ? {} : { projectId: target.project_id }),
      ...(runtime === null ? {} : { runtimeKind: runtimeKind(runtime.runtime_kind) }),
      idempotencyKey: input.idempotencyKey,
      operationId,
      payloadDigest: stableDigest,
    });
  }

  const now = new Date();
  const createdAt = nowIso();
  const expiresAt = new Date(now.getTime() + (body.expiresInSeconds ?? 600) * 1000).toISOString();
  const messageId = newId("cmsg");
  parseWireDocument(schemaIds.nodeV1, { protocol: "conduit.node/1", messageId, deviceId: target.device_id, connectionEpoch: "0", direction: "control_to_node", sequence: "1", type: frameType, correlationId: operationId, payloadDigest, payload });
  const response = { operationId, state: "queued", payloadDigest, expiresAt, targetRunId: target.run_id, ...(runtime === null ? {} : { targetRuntimeId: runtime.runtime_id }) };
  await env.DB.batch([
    env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,connector_policy_id,connector_policy_revision,connector_grant_id,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,target_operation_id,target_runtime_id,target_digest,target_controller_epoch,expected_target_state,expected_target_revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,?13,?14,?15,'queued',?16,?17,?17,?18,?19,?20,?21,?22,?23,?24)")
      .bind(operationId, input.idempotencyKey, effectiveActor.principalId, effectiveActor.clientId, target.device_id, target.project_id, target.collaboration_session_id, target.assignment_id, target.run_id, effectiveActor.policyId ?? null, effectiveActor.policyRevision ?? null, effectiveActor.grantId ?? null, input.targetKind === "runtime" ? "runtime.control" : "run.control", payloadDigest, canonicalJson(payload), expiresAt, createdAt, input.targetKind === "runtime" ? "runtime_control" : "agent_control", target.start_operation_id, runtime?.runtime_id ?? null, target.target_digest, target.controller_epoch, body.expectedState, body.expectedRevision),
    env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES (?1,?2,?3,?4,'queued',202,?5,?6,?7)")
      .bind(idempotencyScope, input.idempotencyKey, stableDigest, operationId, JSON.stringify(response), expiresAt, createdAt),
    env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at,frame_type) VALUES (?1,?2,?3,?1,?4,?5,'pending',?6,?7,?6,?6,?8)")
      .bind(operationId, target.device_id, messageId, payloadDigest, canonicalJson(payload), createdAt, expiresAt, frameType),
  ]);
  const dispatched = await attemptOperationDispatch(env, operationId, { force: true });
  return dispatched === null ? response : { ...dispatched };
}
