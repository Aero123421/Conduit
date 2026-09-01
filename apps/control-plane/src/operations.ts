import { parseWireDocument, schemaIds } from "@conduit/schema";
import { canonicalJson, newId, nowIso, operationDigest, sha256Hex } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { authorizeConnector, type PolicyRequest } from "./policy.ts";
import type { ApprovalMode, AuthActor, ControlPlaneEnv, OperationRequest, RuntimeRequest, SourceRevision, AccessScope } from "./types.ts";

export interface StartOperationInput {
  idempotencyKey: string;
  deviceId: string;
  capability: string;
  projectId?: string;
  sessionId?: string;
  assignmentId?: string;
  runId?: string;
  runtime: RuntimeRequest;
  accessScope: AccessScope;
  approvalMode: ApprovalMode;
  sourceRevisions: SourceRevision[];
  arguments: Record<string, unknown>;
  expiresInSeconds?: number;
}

function operationPermission(capability: string): string {
  if (capability === "command.start") return "command.start";
  if (capability === "agent.run.start") return "run.start";
  if (capability.startsWith("runtime.")) return capability === "runtime.create" ? "runtime.create" : "runtime.control";
  if (capability.startsWith("run.")) return "run.control";
  if (capability === "approval.resolve") return "approval.resolve";
  return capability;
}

function concurrencyClass(capability: string): "commands" | "agentRuns" | "runtimeStarts" | undefined {
  if (capability === "command.start") return "commands";
  if (capability === "agent.run.start") return "agentRuns";
  if (capability === "runtime.create") return "runtimeStarts";
  return undefined;
}

export async function createOperation(env: ControlPlaneEnv, actor: AuthActor, input: StartOperationInput): Promise<Record<string, unknown>> {
  if (input.idempotencyKey.length < 16 || input.idempotencyKey.length > 256) throw new PublicError("invalid_request", 400, "idempotencyKey must be 16-256 characters");
  if (input.sourceRevisions.length > 128 || Object.keys(input.arguments).length > 128) throw new PublicError("invalid_request", 400, "Operation input exceeds structural bounds");
  if (actor.policyId === undefined || actor.policyRevision === undefined) throw new PublicError("grant_required", 403, "Operation requires an exact connector policy revision");
  const stableDigest = await operationDigest({ actorPrincipalId: actor.principalId, clientId: actor.clientId, connectorPolicyId: actor.policyId, connectorPolicyRevision: actor.policyRevision, ...input });
  const operationId = newId("op");
  const now = new Date();
  const expiresInSeconds = Math.min(Math.max(input.expiresInSeconds ?? 600, 30), 3600);
  const requestWithoutDigest: Omit<OperationRequest, "payloadDigest"> = {
    schemaVersion: 1,
    operationId,
    idempotencyKey: input.idempotencyKey,
    actorPrincipalId: actor.principalId,
    clientId: actor.clientId,
    deviceId: input.deviceId,
    ...(input.projectId !== undefined ? { projectId: input.projectId } : {}),
    ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
    ...(input.assignmentId !== undefined ? { assignmentId: input.assignmentId } : {}),
    ...(input.runId !== undefined ? { runId: input.runId } : {}),
    connectorPolicyId: actor.policyId,
    connectorPolicyRevision: actor.policyRevision,
    capability: input.capability,
    accessScope: input.accessScope,
    approvalMode: input.approvalMode,
    runtime: input.runtime,
    sourceRevisions: input.sourceRevisions,
    arguments: input.arguments,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + expiresInSeconds * 1000).toISOString(),
    validForMs: expiresInSeconds * 1000,
  };
  const digest = await operationDigest(requestWithoutDigest);
  const request: OperationRequest = { ...requestWithoutDigest, payloadDigest: digest };
  parseWireDocument(schemaIds.nodeV1, { protocol: "conduit.node/1", messageId: "cmsg_contract0001", deviceId: input.deviceId, connectionEpoch: "0", direction: "control_to_node", sequence: "1", type: "operation.offer", correlationId: operationId, payloadDigest: await sha256Hex(canonicalJson({ operation: request })), payload: { operation: request } });
  const permission = operationPermission(input.capability);
  const policyRequest: PolicyRequest = { operation: permission, deviceId: input.deviceId, runtimeKind: input.runtime.kind, accessScope: input.accessScope, approvalMode: input.approvalMode, idempotencyKey: input.idempotencyKey, operationId, payloadDigest: stableDigest };
  if (input.projectId !== undefined) policyRequest.projectId = input.projectId;
  const authorized = await authorizeConnector(env, actor, policyRequest);
  const existing = await env.DB.prepare("SELECT operation_id,payload_digest,response_json,state FROM idempotency_records WHERE scope=?1 AND idempotency_key=?2 LIMIT 1").bind(actor.grantId ?? actor.clientId, input.idempotencyKey).first<{ operation_id: string; payload_digest: string; response_json: string | null; state: string }>();
  if (existing !== null) {
    if (existing.payload_digest !== stableDigest) throw new PublicError("idempotency_conflict", 409, "Idempotency key is bound to another payload");
    return existing.response_json === null ? { operationId: existing.operation_id, state: existing.state, replay: true } : { ...(JSON.parse(existing.response_json) as Record<string, unknown>), replay: true };
  }
  const limitClass = concurrencyClass(input.capability);
  if (limitClass !== undefined) {
    const profile = JSON.parse(authorized.rate.profile_json) as Record<string, unknown>;
    const configured = profile.concurrency;
    const limit = configured !== null && typeof configured === "object" && !Array.isArray(configured) ? Number((configured as Record<string, unknown>)[limitClass] ?? 0) : 0;
    if (!Number.isSafeInteger(limit) || limit < 1 || !await env.CONNECTOR_LIMITERS.getByName(actor.grantId!).acquire(limitClass, limit)) throw new PublicError("resource_limit", 429, `Connector concurrency limit denied: ${limitClass}`);
  }
  const row = { operationId, state: "queued", payloadDigest: digest, expiresAt: request.expiresAt };
  const createdAt = nowIso();
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,connector_policy_id,connector_policy_revision,connector_grant_id,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'queued',?17,?18,?18)").bind(operationId, input.idempotencyKey, actor.principalId, actor.clientId, input.deviceId, input.projectId ?? null, input.sessionId ?? null, input.assignmentId ?? null, input.runId ?? null, actor.policyId, actor.policyRevision, actor.grantId ?? null, limitClass ?? null, input.capability, digest, canonicalJson(request), request.expiresAt, createdAt),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES (?1,?2,?3,?4,'queued',202,?5,?6,?7)").bind(actor.grantId ?? actor.clientId, input.idempotencyKey, stableDigest, operationId, JSON.stringify(row), request.expiresAt, createdAt),
    ]);
  } catch (error) {
    if (limitClass !== undefined) await env.CONNECTOR_LIMITERS.getByName(actor.grantId!).release(limitClass);
    throw error;
  }
  const delivery = await env.DEVICE_ROOMS.getByName(input.deviceId).offer({ messageId: newId("cmsg"), correlationId: operationId, payloadDigest: await sha256Hex(canonicalJson({ operation: { ...request, payloadDigest: digest } })), payload: { operation: { ...request, payloadDigest: digest } }, expiresAt: request.expiresAt });
  await env.DB.prepare("UPDATE operation_journal SET state='offered',updated_at=?1,result_json=?2 WHERE id=?3 AND state='queued'").bind(nowIso(), JSON.stringify(delivery), operationId).run();
  return { ...row, state: "offered", delivery };
}
