import { boundedString, boundedStringArray, readJsonBounded, record } from "./bounds.ts";
import { canonicalJson, newId, nowIso, operationDigest } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { completeEffect, reserveEffect } from "./idempotency.ts";
import type { AccessScope, ApprovalMode, ApprovalRiskClass, AuthActor, ControlPlaneEnv, RuntimeKind } from "./types.ts";
import type { LimitAdmission } from "./do/connector-limiter.ts";
import { requireBrowserSession } from "./auth/browser.ts";

interface PolicyRow {
  id: string;
  principal_id: string;
  client_id: string;
  revision: number;
  status: string;
  device_selector_json: string;
  project_selector_json: string;
  allowed_operations_json: string;
  allowed_runtimes_json: string;
  max_access_scope: AccessScope;
  most_permissive_approval_mode: ApprovalMode;
  required_risk_classes_json: string;
  allow_raw_content: number;
  allow_artifact_upload: number;
  rate_limit_profile_id: string;
  max_command_seconds: number;
  max_run_seconds: number;
}

interface RateProfileRow { id: string; revision: number; status: string; profile_json: string; }
interface Selector { mode: "all" | "ids"; ids?: string[]; }

const scopeRank: Record<Exclude<AccessScope, "custom">, number> = { read_only: 0, selected_sources: 1, project_full: 2, full_user: 3, full_device: 4 };
const approvalRank: Record<ApprovalMode, number> = { always: 0, outside_scope: 1, risk_classes: 2, never: 3 };
export const ALL_APPROVAL_RISK_CLASSES: readonly ApprovalRiskClass[] = Object.freeze([
  "external_publish",
  "secret_access",
  "destructive_delete",
  "elevation",
  "production_deploy",
  "device_admin",
  "raw_log_export",
  "lan_access",
  "credential_export",
  "runtime_management",
]);
const approvalRiskClasses = new Set<ApprovalRiskClass>(ALL_APPROVAL_RISK_CLASSES);
const scopeForOperation: Record<string, string> = {
  "project.read": "conduit.read", "session.read": "conduit.read", "board.read": "conduit.read", "run.read": "conduit.read",
  "board.write": "conduit.board.write", "assignment.create": "conduit.board.write", "run.start": "conduit.run.start", "command.start": "conduit.run.start",
  "run.control": "conduit.run.control", "runtime.create": "conduit.runtime.manage", "runtime.control": "conduit.runtime.manage",
  "logs.summary.read": "conduit.logs.read", "logs.normalized.read": "conduit.logs.read", "logs.raw.read": "conduit.logs.raw",
  "artifact.read": "conduit.read", "artifact.upload": "conduit.run.start", "approval.resolve": "conduit.approval.resolve",
  "config.write": "conduit.config.write", "device.manage": "conduit.admin", "connector.manage": "conduit.admin", "security.audit.read": "conduit.admin",
};

function parseSelector(json: string): Selector { return JSON.parse(json) as Selector; }
function includesSelector(selector: Selector, id: string | undefined): boolean { return selector.mode === "all" || (id !== undefined && selector.ids?.includes(id) === true); }

export interface PolicyRequest {
  operation: string;
  deviceId?: string;
  projectId?: string;
  runtimeKind?: RuntimeKind;
  accessScope?: AccessScope;
  approvalMode?: ApprovalMode;
  rawContent?: boolean;
  artifactUploadBytes?: number;
  commandSeconds?: number;
  runSeconds?: number;
  idempotencyKey: string;
  operationId: string;
  payloadDigest: string | ((snapshot: ConnectorPolicyAuthoritySnapshot) => Promise<string>);
  responseBytes?: number;
  normalizedLogBytes?: number;
  rawLogBytes?: number;
  concurrencyClass?: "commands" | "agentRuns" | "runtimeStarts";
  concurrencyExpiresAt?: string;
}

export interface ConnectorPolicyAuthoritySnapshot {
  connectorPolicyId: string;
  connectorPolicyRevision: number;
  requiredApprovalRiskClasses: readonly ApprovalRiskClass[];
}

export interface AuthorizedPolicy {
  policy: PolicyRow;
  rate: RateProfileRow;
  authoritySnapshot: Readonly<ConnectorPolicyAuthoritySnapshot>;
  payloadDigest: string;
}

function deny(code: ConstructorParameters<typeof PublicError>[0], message: string): never { throw new PublicError(code, code === "rate_limited" ? 429 : 403, message); }

function parseApprovalRiskClasses(value: unknown, code: "invalid_request" | "grant_reauthorization_required"): ApprovalRiskClass[] {
  if (!Array.isArray(value) || value.length > 32 || value.some((item) => typeof item !== "string" || !approvalRiskClasses.has(item as ApprovalRiskClass))) {
    throw new PublicError(code, code === "invalid_request" ? 400 : 403, "requiredApprovalRiskClasses is invalid");
  }
  if (new Set(value).size !== value.length) throw new PublicError(code, code === "invalid_request" ? 400 : 403, "requiredApprovalRiskClasses must be unique");
  return value as ApprovalRiskClass[];
}

function parseStoredApprovalRiskClasses(json: string): ApprovalRiskClass[] {
  try {
    return parseApprovalRiskClasses(JSON.parse(json), "grant_reauthorization_required");
  } catch (error) {
    if (error instanceof PublicError) throw error;
    throw new PublicError("grant_reauthorization_required", 403, "Connector policy risk-class snapshot is invalid");
  }
}

export async function authorizeConnector(env: ControlPlaneEnv, actor: AuthActor, request: PolicyRequest): Promise<AuthorizedPolicy> {
  const requiredScope = scopeForOperation[request.operation];
  if (requiredScope === undefined || !actor.scopes.includes(requiredScope)) deny("scope_insufficient", "OAuth scope does not permit this operation");
  if (actor.policyId === undefined || actor.policyRevision === undefined || actor.grantId === undefined) deny("grant_required", "OAuth grant policy binding is missing");
  const joined = await env.DB.prepare("SELECT p.*,r.id AS rate_id,r.revision AS rate_revision,r.status AS rate_status,r.profile_json AS rate_profile_json FROM connector_policies p LEFT JOIN rate_limit_profiles r ON r.id=p.rate_limit_profile_id WHERE p.id=?1 AND p.revision=?2 LIMIT 1").bind(actor.policyId, actor.policyRevision).first<PolicyRow & { rate_id: string | null; rate_revision: number | null; rate_status: string | null; rate_profile_json: string | null }>();
  if (joined === null || joined.status !== "active" || joined.client_id !== actor.clientId || joined.principal_id !== actor.principalId) deny("grant_reauthorization_required", "Connector policy is no longer active");
  const policy: PolicyRow = joined;
  const allowedOperations = JSON.parse(policy.allowed_operations_json) as string[];
  if (!allowedOperations.includes(request.operation)) deny("operation_not_allowed", "Connector policy does not permit this operation");
  if (!includesSelector(parseSelector(policy.device_selector_json), request.deviceId)) deny("device_not_allowed", "Connector policy does not permit this Device");
  if (!includesSelector(parseSelector(policy.project_selector_json), request.projectId)) deny("project_not_allowed", "Connector policy does not permit this Project");
  if (request.runtimeKind !== undefined && !(JSON.parse(policy.allowed_runtimes_json) as string[]).includes(request.runtimeKind)) deny("runtime_not_allowed", "Connector policy does not permit this Runtime kind");
  if (request.accessScope !== undefined) {
    if (request.accessScope === "custom" || policy.max_access_scope === "custom") deny("connector_ceiling_exceeded", "Custom scope requires a typed capability-subset authorization path");
    if (scopeRank[request.accessScope] > scopeRank[policy.max_access_scope]) deny("connector_ceiling_exceeded", "Requested Access Scope exceeds connector ceiling");
  }
  if (request.approvalMode !== undefined && approvalRank[request.approvalMode] > approvalRank[policy.most_permissive_approval_mode]) deny("connector_ceiling_exceeded", "Requested Approval Policy exceeds connector ceiling");
  if (request.rawContent && policy.allow_raw_content !== 1) deny("connector_ceiling_exceeded", "Raw content is not permitted by connector policy");
  if ((request.artifactUploadBytes ?? 0) > 0 && policy.allow_artifact_upload !== 1) deny("connector_ceiling_exceeded", "Artifact upload is not permitted by connector policy");
  if ((request.commandSeconds ?? 0) > policy.max_command_seconds || (request.runSeconds ?? 0) > policy.max_run_seconds) deny("connector_ceiling_exceeded", "Requested duration exceeds connector ceiling");
  const authoritySnapshot: Readonly<ConnectorPolicyAuthoritySnapshot> = Object.freeze({
    connectorPolicyId: policy.id,
    connectorPolicyRevision: policy.revision,
    requiredApprovalRiskClasses: Object.freeze(parseStoredApprovalRiskClasses(policy.required_risk_classes_json)),
  });
  const payloadDigest = typeof request.payloadDigest === "string" ? request.payloadDigest : await request.payloadDigest(authoritySnapshot);
  if (!/^[a-f0-9]{64}$/.test(payloadDigest)) throw new TypeError("Connector admission payload digest must be SHA-256 hex");
  if (joined.rate_id === null || joined.rate_revision === null || joined.rate_status !== "active" || joined.rate_profile_json === null) deny("rate_limited", "Connector rate profile is unavailable");
  const rate: RateProfileRow = { id: joined.rate_id, revision: joined.rate_revision, status: joined.rate_status, profile_json: joined.rate_profile_json };
  const profile = JSON.parse(rate.profile_json) as Record<string, unknown>;
  const requestWindows = record(profile.requestWindows, "requestWindows");
  const family = operationFamily(request.operation);
  const window = record(requestWindows[family] ?? requestWindows.read, "requestWindow");
  const weighted = record(profile.weightedBudget, "weightedBudget");
  const weights = record(weighted.weights, "weights");
  const bytes = record(profile.bytes, "bytes");
  const concurrency = record(profile.concurrency, "concurrency");
  const concurrencyLimit = request.concurrencyClass === undefined ? undefined : Number(concurrency[request.concurrencyClass] ?? 0);
  if (request.concurrencyClass !== undefined && (!Number.isSafeInteger(concurrencyLimit) || concurrencyLimit! < 1 || request.concurrencyExpiresAt === undefined)) deny("rate_limited", "Connector concurrency profile is unavailable");
  const admission: LimitAdmission = {
    operationId: request.operationId,
    idempotencyKey: request.idempotencyKey,
    payloadDigest,
    family,
    weight: Number(weights[request.operation] ?? 1),
    requestLimit: Number(window.limit ?? 0),
    windowSeconds: Number(window.windowSeconds ?? 60),
    capacity: Number(weighted.capacity ?? 0),
    refillPerSecond: Number(weighted.refillPerSecond ?? 0),
    responseBytes: request.responseBytes ?? 0,
    normalizedLogBytes: request.normalizedLogBytes ?? 0,
    rawLogBytes: request.rawLogBytes ?? 0,
    artifactUploadBytes: request.artifactUploadBytes ?? 0,
    byteLimits: { response: Number(bytes.responseBytes ?? 0), normalizedDaily: Number(bytes.normalizedLogBytesPerDay ?? 0), rawDaily: Number(bytes.rawLogBytesPerDay ?? 0), artifactDaily: Number(bytes.artifactUploadBytesPerDay ?? 0) },
    nowMs: Date.now(),
    effectful: !request.operation.endsWith(".read"),
    ...(request.concurrencyClass === undefined ? {} : { concurrency: { className: request.concurrencyClass, limit: concurrencyLimit!, expiresAt: request.concurrencyExpiresAt! }, idempotencyExpiresAtMs: Date.parse(request.concurrencyExpiresAt!) }),
  };
  const decision = await env.CONNECTOR_LIMITERS.getByName(actor.grantId).admit(admission);
  if (!decision.allowed) throw new PublicError(decision.code === "idempotency_conflict" ? "idempotency_conflict" : decision.code, decision.code === "idempotency_conflict" ? 409 : 429, `Connector limit denied: ${decision.limitClass}`, decision.retryAfterSeconds);
  return { policy, rate, authoritySnapshot, payloadDigest };
}

function operationFamily(operation: string): string {
  if (operation === "board.write") return "boardWrite";
  if (operation === "command.start") return "commandStart";
  if (operation === "run.start") return "agentRunStart";
  if (operation === "runtime.create") return "runtimeStart";
  if (operation === "approval.resolve") return "approvalResolve";
  if (operation === "logs.raw.read") return "rawLogRead";
  return "read";
}

async function createRateProfile(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const body = record(await readJsonBounded(request));
  const id = body.id === undefined ? newId("rate") : boundedString(body.id, "id", 128);
  const name = boundedString(body.name, "name", 128);
  const profile = record(body.profile, "profile");
  // Structural bounds are revalidated when every admission reads the profile.
  if (Object.keys(profile).length > 16) throw new PublicError("invalid_request", 400, "Rate profile has too many sections");
  const now = nowIso();
  await env.DB.prepare("INSERT INTO rate_limit_profiles(id,revision,status,name,profile_json,created_at,updated_at) VALUES (?1,1,'active',?2,?3,?4,?4)").bind(id, name, JSON.stringify(profile), now).run();
  await repo.audit("rate_limit_profile.created", { id }, session.principal_id);
  return Response.json({ id, revision: 1, status: "active", name, profile }, { status: 201 });
}

async function createPolicy(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const body = record(await readJsonBounded(request));
  const idempotencyKey = boundedString(request.headers.get("idempotency-key"), "Idempotency-Key", 256, 16);
  const reserved = await reserveEffect(env.DB, `connector-policy:${session.principal_id}`, idempotencyKey, await operationDigest({ create: body }));
  if (reserved.replay !== undefined) return Response.json(reserved.replay);
  const clientId = boundedString(body.clientId, "clientId", 2048);
  const client = await env.DB.prepare("SELECT status FROM oauth_clients WHERE client_id=?1 LIMIT 1").bind(clientId).first<{ status: string }>();
  if (client?.status !== "active") throw new PublicError("client_not_registered", 400, "OAuth client is not active");
  const id = body.id === undefined ? newId("cpol") : boundedString(body.id, "id", 128);
  const maxScope = boundedString(body.maxAccessScope, "maxAccessScope", 32) as AccessScope;
  const approval = boundedString(body.mostPermissiveApprovalMode, "mostPermissiveApprovalMode", 32) as ApprovalMode;
  if (!(maxScope in scopeRank) && maxScope !== "custom") throw new PublicError("invalid_request", 400, "maxAccessScope is invalid");
  if (!(approval in approvalRank)) throw new PublicError("invalid_request", 400, "mostPermissiveApprovalMode is invalid");
  const deviceSelector = record(body.deviceSelector, "deviceSelector");
  const projectSelector = record(body.projectSelector, "projectSelector");
  const operations = boundedStringArray(body.allowedOperations, "allowedOperations", 128, 128);
  const runtimes = boundedStringArray(body.allowedRuntimes, "allowedRuntimes", 4, 32);
  const requiredApprovalRiskClasses = parseApprovalRiskClasses(body.requiredApprovalRiskClasses ?? [], "invalid_request");
  const rateId = boundedString(body.rateLimitProfileId, "rateLimitProfileId", 128);
  const snapshot = { ...body, requiredApprovalRiskClasses, id, principalId: session.principal_id, revision: 1 };
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,expires_at,created_at,updated_at) VALUES (?1,?2,?3,1,'active',?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)").bind(id, session.principal_id, clientId, JSON.stringify(deviceSelector), JSON.stringify(projectSelector), JSON.stringify(operations), JSON.stringify(runtimes), maxScope, approval, JSON.stringify(requiredApprovalRiskClasses), body.allowRawContent === true ? 1 : 0, body.allowArtifactUpload === true ? 1 : 0, rateId, Number(body.maxCommandSeconds ?? 1800), Number(body.maxRunSeconds ?? 86400), body.expiresAt ?? null, now),
    env.DB.prepare("INSERT INTO connector_policy_history(policy_id,revision,snapshot_json,changed_by_principal_id,change_reason,created_at) VALUES (?1,1,?2,?3,'created',?4)").bind(id, canonicalJson(snapshot), session.principal_id, now),
  ]);
  await repo.audit("connector_policy.created", { id, clientId, maxScope, approval }, session.principal_id, clientId);
  await completeEffect(env.DB, reserved.reservation!, snapshot);
  return Response.json(snapshot, { status: 201 });
}

async function registerFirstPartyClient(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const body = record(await readJsonBounded(request));
  const clientId = boundedString(body.clientId, "clientId", 2048);
  const redirectUris = boundedStringArray(body.redirectUris, "redirectUris", 64, 2048);
  const metadata = { clientId, clientName: boundedString(body.clientName, "clientName", 256), redirectUris, tokenEndpointAuthMethod: "none" };
  const now = nowIso();
  await env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered',?2,?3,'none',?4,'active',?5,?5)").bind(clientId, metadata.clientName, JSON.stringify(redirectUris), await operationDigest(metadata), now).run();
  await repo.audit("oauth_client.registered", { clientId, mechanism: "pre_registered" }, session.principal_id, clientId);
  return Response.json(metadata, { status: 201 });
}

function policyIfMatch(request: Request): number {
  const match = request.headers.get("if-match")?.match(/^"([1-9][0-9]*)"$/);
  if (match?.[1] === undefined) throw new PublicError("invalid_request", 428, "If-Match must contain one quoted policy revision ETag");
  const value = Number(match[1]);
  if (!Number.isSafeInteger(value)) throw new PublicError("invalid_request", 400, "Policy revision is out of range");
  return value;
}

async function updatePolicy(request: Request, env: ControlPlaneEnv, id: string): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true });
  const idempotencyKey = boundedString(request.headers.get("idempotency-key"), "Idempotency-Key", 256, 16);
  const expected = policyIfMatch(request);
  const body = record(await readJsonBounded(request));
  const reserved = await reserveEffect(env.DB, `connector-policy:${session.principal_id}`, idempotencyKey, await operationDigest({ id, expected, body }));
  if (reserved.replay !== undefined) return Response.json(reserved.replay, { headers: typeof reserved.replay.revision === "number" ? { etag: `"${reserved.replay.revision}"` } : {} });
  const current = await env.DB.prepare("SELECT * FROM connector_policies WHERE id=?1 AND principal_id=?2 LIMIT 1").bind(id, session.principal_id).first<PolicyRow>();
  if (current === null) throw new PublicError("not_found", 404, "Connector policy not found");
  if (current.revision !== expected) throw new PublicError("revision_conflict", 409, "Connector policy revision is stale");
  const maxScope = body.maxAccessScope === undefined ? current.max_access_scope : boundedString(body.maxAccessScope, "maxAccessScope", 32) as AccessScope;
  const approval = body.mostPermissiveApprovalMode === undefined ? current.most_permissive_approval_mode : boundedString(body.mostPermissiveApprovalMode, "mostPermissiveApprovalMode", 32) as ApprovalMode;
  if ((maxScope !== "custom" && !(maxScope in scopeRank)) || !(approval in approvalRank)) throw new PublicError("invalid_request", 400, "Policy ceiling is invalid");
  const deviceSelector = body.deviceSelector === undefined ? JSON.parse(current.device_selector_json) : record(body.deviceSelector, "deviceSelector");
  const projectSelector = body.projectSelector === undefined ? JSON.parse(current.project_selector_json) : record(body.projectSelector, "projectSelector");
  const operations = body.allowedOperations === undefined ? JSON.parse(current.allowed_operations_json) as string[] : boundedStringArray(body.allowedOperations, "allowedOperations", 128, 128);
  const runtimes = body.allowedRuntimes === undefined ? JSON.parse(current.allowed_runtimes_json) as string[] : boundedStringArray(body.allowedRuntimes, "allowedRuntimes", 4, 32);
  const currentRequiredApprovalRiskClasses = parseStoredApprovalRiskClasses(current.required_risk_classes_json);
  const requiredApprovalRiskClasses = body.requiredApprovalRiskClasses === undefined ? currentRequiredApprovalRiskClasses : parseApprovalRiskClasses(body.requiredApprovalRiskClasses, "invalid_request");
  const allowRaw = body.allowRawContent === undefined ? current.allow_raw_content === 1 : body.allowRawContent === true;
  const allowArtifact = body.allowArtifactUpload === undefined ? current.allow_artifact_upload === 1 : body.allowArtifactUpload === true;
  const broadening = (maxScope !== "custom" && current.max_access_scope !== "custom" && scopeRank[maxScope] > scopeRank[current.max_access_scope]) || approvalRank[approval] > approvalRank[current.most_permissive_approval_mode] || currentRequiredApprovalRiskClasses.some((item) => !requiredApprovalRiskClasses.includes(item)) || (!current.allow_raw_content && allowRaw) || (!current.allow_artifact_upload && allowArtifact) || operations.some((item) => !(JSON.parse(current.allowed_operations_json) as string[]).includes(item)) || runtimes.some((item) => !(JSON.parse(current.allowed_runtimes_json) as string[]).includes(item));
  if (broadening) repo.requireFresh(session);
  const revision = expected + 1;
  const snapshot = { id, revision, maxAccessScope: maxScope, mostPermissiveApprovalMode: approval, requiredApprovalRiskClasses, deviceSelector, projectSelector, allowedOperations: operations, allowedRuntimes: runtimes, allowRawContent: allowRaw, allowArtifactUpload: allowArtifact };
  const now = nowIso();
  const results = await env.DB.batch([
    env.DB.prepare("UPDATE connector_policies SET revision=?1,device_selector_json=?2,project_selector_json=?3,allowed_operations_json=?4,allowed_runtimes_json=?5,max_access_scope=?6,most_permissive_approval_mode=?7,required_risk_classes_json=?8,allow_raw_content=?9,allow_artifact_upload=?10,updated_at=?11 WHERE id=?12 AND principal_id=?13 AND revision=?14").bind(revision, JSON.stringify(deviceSelector), JSON.stringify(projectSelector), JSON.stringify(operations), JSON.stringify(runtimes), maxScope, approval, JSON.stringify(requiredApprovalRiskClasses), allowRaw ? 1 : 0, allowArtifact ? 1 : 0, now, id, session.principal_id, expected),
    env.DB.prepare("INSERT INTO connector_policy_history(policy_id,revision,snapshot_json,changed_by_principal_id,change_reason,created_at) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS (SELECT 1 FROM connector_policies WHERE id=?1 AND revision=?2)").bind(id, revision, canonicalJson(snapshot), session.principal_id, broadening ? "broadened" : "updated", now),
    env.DB.prepare("UPDATE oauth_grants SET status='reauthorization_required' WHERE connector_policy_id=?1 AND connector_policy_revision=?2 AND status IN ('active','paused')").bind(id, expected),
    env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE grant_id IN (SELECT id FROM oauth_grants WHERE connector_policy_id=?2 AND status='reauthorization_required') AND revoked_at IS NULL").bind(now, id),
  ]);
  if (results[0]?.meta.changes !== 1 || results[1]?.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Connector policy changed concurrently");
  await repo.audit("connector_policy.updated", { id, previousRevision: expected, revision, broadening }, session.principal_id, current.client_id);
  await completeEffect(env.DB, reserved.reservation!, snapshot);
  return Response.json(snapshot, { headers: { etag: `"${revision}"` } });
}

export async function handlePolicyAdmin(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "POST" && path === "/v1/rate-limit-profiles") return createRateProfile(request, env);
  if (request.method === "POST" && path === "/v1/connector-policies") return createPolicy(request, env);
  if (request.method === "POST" && path === "/v1/oauth/clients") return registerFirstPartyClient(request, env);
  const policy = path.match(/^\/v1\/connector-policies\/([^/]+)$/);
  if (request.method === "PATCH" && policy?.[1] !== undefined) return updatePolicy(request, env, decodeURIComponent(policy[1]));
  return null;
}
