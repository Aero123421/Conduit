import { parseWireDocument, schemaIds } from "@conduit/schema";
import { z } from "zod";
import { canonicalJson, newId, nowIso, operationDigest, sha256Hex } from "./crypto.ts";
import { attemptOperationDispatch, durableObjectOperationDispatcher, type OperationDispatcher } from "./dispatch.ts";
import { PublicError } from "./errors.ts";
import { ALL_APPROVAL_RISK_CLASSES, authorizeConnector, type ConnectorPolicyAuthoritySnapshot, type PolicyRequest } from "./policy.ts";
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

export type OperationAuthorization =
  | { kind: "connector" }
  | { kind: "owner" };

export interface OperationTransactionContext {
  operationId: string;
  request: OperationRequest;
  createdAt: string;
}

export interface CreateOperationOptions {
  dispatcher?: OperationDispatcher;
  /** Reserve an ID so related immutable records can commit with the operation. */
  operationId?: string;
  /**
   * Statements returned here are committed in the same D1 batch as operation
   * custody, idempotency, and the dispatch outbox, before dispatch is attempted.
   */
  transactionStatements?: (context: OperationTransactionContext) => D1PreparedStatement[] | Promise<D1PreparedStatement[]>;
}

const OWNER_FIRST_PARTY_POLICY_ID = "cpol_owner_first_party_v1";
const OWNER_FIRST_PARTY_POLICY_REVISION = 1;

const boundedId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`));
const startOperationSchema = z.strictObject({
  idempotencyKey: z.string().min(16).max(256),
  deviceId: boundedId("dev"),
  capability: z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/),
  projectId: boundedId("prj").optional(),
  sessionId: boundedId("csess").optional(),
  assignmentId: boundedId("asg").optional(),
  runId: boundedId("run").optional(),
  runtime: z.strictObject({
    kind: z.enum(["native", "restricted_native", "container", "vm"]),
    providerId: z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/),
    configurationRevision: z.number().int().min(1),
    cpuLimit: z.number().gt(0).max(1024).optional(),
    memoryBytes: z.number().int().nonnegative().optional(),
    storageBytes: z.number().int().nonnegative().optional(),
    gpuCount: z.number().int().nonnegative().max(64).optional(),
    networkMode: z.enum(["open", "restricted", "offline", "lan_explicit"]).optional(),
  }),
  accessScope: z.enum(["read_only", "selected_sources", "project_full", "full_user", "full_device", "custom"]),
  approvalMode: z.enum(["always", "outside_scope", "risk_classes", "never"]),
  sourceRevisions: z.array(z.strictObject({
    sourceId: boundedId("src"),
    locationId: boundedId("loc"),
    locationRevision: z.number().int().min(1),
    mode: z.enum(["read_only", "direct", "worktree", "managed_copy"]),
    baseCommit: z.string().regex(/^[A-Fa-f0-9]{7,64}$/).optional(),
    dirtyDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  })).max(128),
  arguments: z.record(z.string(), z.unknown()).refine((value) => Object.keys(value).length <= 128, "arguments has more than 128 properties"),
  expiresInSeconds: z.number().int().min(30).max(3600).optional(),
});

function parseStartOperationInput(input: unknown): StartOperationInput {
  const result = startOperationSchema.safeParse(input);
  if (!result.success) throw new PublicError("invalid_request", 400, `Operation input is invalid: ${result.error.issues[0]?.message ?? "schema mismatch"}`);
  return result.data as StartOperationInput;
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

export async function createOperation(
  env: ControlPlaneEnv,
  actor: AuthActor,
  rawInput: StartOperationInput,
  authorization: OperationAuthorization = { kind: "connector" },
  dispatcherOrOptions: OperationDispatcher | CreateOperationOptions = durableObjectOperationDispatcher,
): Promise<Record<string, unknown>> {
  const options: CreateOperationOptions = "offer" in dispatcherOrOptions ? { dispatcher: dispatcherOrOptions } : dispatcherOrOptions;
  const dispatcher = options.dispatcher ?? durableObjectOperationDispatcher;
  const input = parseStartOperationInput(rawInput);
  const effectiveActor: AuthActor = authorization.kind === "owner"
    ? { ...actor, policyId: OWNER_FIRST_PARTY_POLICY_ID, policyRevision: OWNER_FIRST_PARTY_POLICY_REVISION }
    : actor;
  if (effectiveActor.policyId === undefined || effectiveActor.policyRevision === undefined) throw new PublicError("grant_required", 403, "Operation requires an exact connector policy revision");
  const operationId = options.operationId ?? newId("op");
  const now = new Date();
  const expiresInSeconds = Math.min(Math.max(input.expiresInSeconds ?? 600, 30), 3600);
  const operationExpiresAt = new Date(now.getTime() + expiresInSeconds * 1000).toISOString();
  const limitClass = authorization.kind === "connector" ? concurrencyClass(input.capability) : undefined;
  const snapshottedRiskClasses = (snapshot: ConnectorPolicyAuthoritySnapshot | undefined) => {
    const authoritative = snapshot?.requiredApprovalRiskClasses ?? [];
    return input.approvalMode === "risk_classes" && authoritative.length === 0
      ? [...ALL_APPROVAL_RISK_CLASSES]
      : [...authoritative];
  };
  const permission = operationPermission(input.capability);
  const policyRequest: PolicyRequest = {
    operation: permission,
    deviceId: input.deviceId,
    runtimeKind: input.runtime.kind,
    accessScope: input.accessScope,
    approvalMode: input.approvalMode,
    idempotencyKey: input.idempotencyKey,
    operationId,
    payloadDigest: async (snapshot) => operationDigest({
      actorPrincipalId: effectiveActor.principalId,
      clientId: effectiveActor.clientId,
      connectorPolicyId: effectiveActor.policyId,
      connectorPolicyRevision: effectiveActor.policyRevision,
      ...input,
      requiredApprovalRiskClasses: snapshottedRiskClasses(snapshot),
    }),
    ...(limitClass === undefined ? {} : { concurrencyClass: limitClass, concurrencyExpiresAt: operationExpiresAt }),
  };
  if (input.projectId !== undefined) policyRequest.projectId = input.projectId;
  const authorized = authorization.kind === "connector" ? await authorizeConnector(env, effectiveActor, policyRequest) : undefined;
  const requiredApprovalRiskClasses = snapshottedRiskClasses(authorized?.authoritySnapshot);
  const stableDigest = authorized?.payloadDigest ?? await operationDigest({
    actorPrincipalId: effectiveActor.principalId,
    clientId: effectiveActor.clientId,
    connectorPolicyId: effectiveActor.policyId,
    connectorPolicyRevision: effectiveActor.policyRevision,
    ...input,
    requiredApprovalRiskClasses,
  });
  const requestWithoutDigest: Omit<OperationRequest, "payloadDigest"> = {
    schemaVersion: 1,
    operationId,
    idempotencyKey: input.idempotencyKey,
    actorPrincipalId: effectiveActor.principalId,
    clientId: effectiveActor.clientId,
    deviceId: input.deviceId,
    ...(input.projectId !== undefined ? { projectId: input.projectId } : {}),
    ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
    ...(input.assignmentId !== undefined ? { assignmentId: input.assignmentId } : {}),
    ...(input.runId !== undefined ? { runId: input.runId } : {}),
    connectorPolicyId: effectiveActor.policyId,
    connectorPolicyRevision: effectiveActor.policyRevision,
    capability: input.capability,
    accessScope: input.accessScope,
    approvalMode: input.approvalMode,
    requiredApprovalRiskClasses,
    runtime: input.runtime,
    sourceRevisions: input.sourceRevisions,
    arguments: input.arguments,
    issuedAt: now.toISOString(),
    expiresAt: operationExpiresAt,
    validForMs: expiresInSeconds * 1000,
  };
  const digest = await operationDigest(requestWithoutDigest);
  const request: OperationRequest = { ...requestWithoutDigest, payloadDigest: digest };
  parseWireDocument(schemaIds.nodeV1, { protocol: "conduit.node/1", messageId: "cmsg_contract0001", deviceId: input.deviceId, connectionEpoch: "0", direction: "control_to_node", sequence: "1", type: "operation.offer", correlationId: operationId, payloadDigest: await sha256Hex(canonicalJson({ operation: request })), payload: { operation: request } });
  const idempotencyScope = effectiveActor.grantId ?? `owner:${effectiveActor.principalId}:${effectiveActor.clientId}`;
  const existing = await env.DB.prepare("SELECT operation_id,payload_digest,response_json,state FROM idempotency_records WHERE scope=?1 AND idempotency_key=?2 LIMIT 1").bind(idempotencyScope, input.idempotencyKey).first<{ operation_id: string; payload_digest: string; response_json: string | null; state: string }>();
  if (existing !== null) {
    if (existing.payload_digest !== stableDigest) throw new PublicError("idempotency_conflict", 409, "Idempotency key is bound to another payload");
    const retried = await attemptOperationDispatch(env, existing.operation_id, { force: true, dispatcher });
    if (retried !== null) return { ...retried, replay: true };
    return existing.response_json === null ? { operationId: existing.operation_id, state: existing.state, replay: true } : { ...(JSON.parse(existing.response_json) as Record<string, unknown>), replay: true };
  }
  const row = { operationId, state: "queued", payloadDigest: digest, expiresAt: request.expiresAt };
  const createdAt = nowIso();
  const dispatchMessageId = newId("cmsg");
  const dispatchPayload = { operation: request };
  const dispatchPayloadDigest = await sha256Hex(canonicalJson(dispatchPayload));
  try {
    const transactionStatements = options.transactionStatements === undefined
      ? []
      : await options.transactionStatements({ operationId, request, createdAt });
    await env.DB.batch([
      ...transactionStatements,
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,connector_policy_id,connector_policy_revision,connector_grant_id,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'queued',?17,?18,?18)").bind(operationId, input.idempotencyKey, effectiveActor.principalId, effectiveActor.clientId, input.deviceId, input.projectId ?? null, input.sessionId ?? null, input.assignmentId ?? null, input.runId ?? null, effectiveActor.policyId, effectiveActor.policyRevision, effectiveActor.grantId ?? null, limitClass ?? null, input.capability, digest, canonicalJson(request), request.expiresAt, createdAt),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES (?1,?2,?3,?4,'queued',202,?5,?6,?7)").bind(idempotencyScope, input.idempotencyKey, stableDigest, operationId, JSON.stringify(row), request.expiresAt, createdAt),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?1,?4,?5,'pending',?6,?7,?6,?6)").bind(operationId, input.deviceId, dispatchMessageId, dispatchPayloadDigest, canonicalJson(dispatchPayload), createdAt, request.expiresAt),
    ]);
  } catch (error) {
    if (limitClass !== undefined && effectiveActor.grantId !== undefined) await env.CONNECTOR_LIMITERS.getByName(effectiveActor.grantId).release(operationId, limitClass);
    throw error;
  }
  return await attemptOperationDispatch(env, operationId, { force: true, dispatcher }) ?? row;
}
