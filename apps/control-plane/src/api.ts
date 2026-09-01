import { boundedString, readJsonBounded, record } from "./bounds.ts";
import { authenticateBearer } from "./auth/oauth.ts";
import { authenticateOwnerCli, requireBrowserSession } from "./auth/browser.ts";
import { uploadArtifact } from "./artifacts.ts";
import { newId, nowIso, operationDigest } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { completeEffect, reserveEffect } from "./idempotency.ts";
import { createOperation, type StartOperationInput } from "./operations.ts";
import { authorizeConnector } from "./policy.ts";
import { DomainRepository, resourceSpecs, type ResourceName } from "./repositories/domain.ts";
import type { AuthActor, ControlPlaneEnv } from "./types.ts";

const readPermissions: Partial<Record<ResourceName, string>> = {
  projects: "project.read", sources: "project.read", locations: "project.read", sessions: "session.read", messages: "board.read",
  project_agents: "project.read", assignments: "session.read", runs: "run.read", approvals: "run.read", tasks: "session.read",
  artifacts: "artifact.read", devices: "project.read", traces: "logs.summary.read", evidence: "logs.summary.read", operations: "run.read",
};
const writePermissions: Partial<Record<ResourceName, string>> = { projects: "config.write", sources: "config.write", locations: "config.write", sessions: "board.write", messages: "board.write", project_agents: "config.write", assignments: "assignment.create", runs: "run.start", tasks: "board.write", artifacts: "artifact.upload" };

export const CLI_CONTROL_PLANE_ROUTE_MANIFEST = [
  ["POST", "/v1/auth/setup/options"], ["POST", "/v1/auth/setup/verify"], ["POST", "/v1/auth/login/options"], ["POST", "/v1/auth/login/verify"], ["POST", "/v1/auth/passkeys/options"], ["POST", "/v1/auth/passkeys/verify"], ["POST", "/v1/auth/recovery"], ["POST", "/v1/auth/passkeys/passkey_contract01/revoke"],
  ["GET", "/v1/devices"], ["GET", "/v1/devices/dev_contract01"], ["POST", "/v1/devices/dev_contract01/revoke"],
  ["POST", "/v1/projects"], ["GET", "/v1/projects"], ["GET", "/v1/projects/prj_contract01"], ["PATCH", "/v1/projects/prj_contract01"], ["POST", "/v1/sources"],
  ["POST", "/v1/sessions"], ["GET", "/v1/sessions"], ["GET", "/v1/sessions/csess_contract01"], ["PATCH", "/v1/sessions/csess_contract01"],
  ["POST", "/v1/messages"], ["GET", "/v1/messages/msg_contract01"], ["GET", "/v1/messages"], ["PATCH", "/v1/messages/msg_contract01"],
  ["POST", "/v1/project_agents"], ["GET", "/v1/project_agents"], ["GET", "/v1/project_agents/pagent_contract01"], ["PATCH", "/v1/project_agents/pagent_contract01"],
  ["POST", "/v1/assignments"], ["GET", "/v1/assignments/asg_contract01"], ["POST", "/v1/assignments/asg_contract01/transitions"],
  ["GET", "/v1/runs"], ["GET", "/v1/runs/run_contract01"], ["GET", "/v1/runs/run_contract01/events"], ["POST", "/v1/operations"],
  ["POST", "/v1/tasks"], ["GET", "/v1/tasks"], ["GET", "/v1/tasks/task_contract01"], ["PATCH", "/v1/tasks/task_contract01"],
  ["GET", "/v1/evidence/evid_contract01"], ["GET", "/v1/evidence"],
  ["POST", "/v1/connector-policies"], ["PATCH", "/v1/connector-policies/cpol_contract01"],
  ["POST", "/v1/oauth/grants/grant_contract01/pause"], ["POST", "/v1/oauth/grants/grant_contract01/resume"], ["POST", "/v1/oauth/grants/grant_contract01/revoke"], ["POST", "/v1/oauth/grants/grant_contract01/reauthorize"],
  ["POST", "/v1/artifacts"], ["GET", "/v1/artifacts"], ["GET", "/v1/artifacts/art_contract01"], ["PUT", "/v1/artifacts/art_contract01/content"],
] as const;

const legacyCompatibilityPaths = new Set([
  "POST /v1/auth/logout", "GET /v1/auth/status", "DELETE /v1/auth/passkeys/revoke", "DELETE /v1/devices/revoke", "PATCH /v1/projects", "POST /v1/sessions/accept", "GET /v1/board/search", "PATCH /v1/messages", "DELETE /v1/project_agents",
  "POST /v1/assignments/cancel", "POST /v1/assignments/input", "POST /v1/assignments/steer", "POST /v1/runs/pause", "POST /v1/runs/resume", "POST /v1/runs/cancel", "POST /v1/runs/recover",
  "POST /v1/quick/command", "POST /v1/quick/agent", "POST /v1/quick/vm", "PATCH /v1/tasks", "POST /v1/tasks/link", "POST /v1/evaluations", "GET /v1/evaluations/compare",
  "POST /v1/connectors", "GET /v1/connectors", "POST /v1/connectors/pause", "POST /v1/connectors/resume", "DELETE /v1/connectors", "PATCH /v1/connectors/policy",
]);

async function actorFor(request: Request, env: ControlPlaneEnv, mutation: boolean): Promise<{ actor: AuthActor; connector: boolean }> {
  if (request.headers.get("authorization")?.startsWith("Bearer conduit_owner_")) return { actor: await authenticateOwnerCli(request, env), connector: false };
  if (request.headers.has("authorization")) return { actor: await authenticateBearer(request, env), connector: true };
  const auth = await requireBrowserSession(request, env, { csrf: mutation });
  return { actor: { principalId: auth.session.principal_id, clientId: "conduit.browser", scopes: ["conduit.admin"], sessionKind: auth.session.kind }, connector: false };
}

function idempotencyKey(request: Request): string {
  return boundedString(request.headers.get("idempotency-key"), "Idempotency-Key", 256, 16);
}

function parseIfMatch(request: Request): number {
  const value = request.headers.get("if-match");
  const match = value?.match(/^"([1-9][0-9]*)"$/);
  if (match?.[1] === undefined) throw new PublicError("invalid_request", 428, "If-Match must contain one quoted revision ETag");
  const revision = Number(match[1]);
  if (!Number.isSafeInteger(revision)) throw new PublicError("invalid_request", 400, "If-Match revision is out of range");
  return revision;
}

async function authorizeResource(request: Request, env: ControlPlaneEnv, actor: AuthActor, connector: boolean, resource: ResourceName, mutation: boolean, url: URL, body?: unknown): Promise<void> {
  if (!connector) return;
  const operation = (mutation ? writePermissions : readPermissions)[resource];
  if (operation === undefined) throw new PublicError("operation_not_allowed", 403, "Resource operation is not available to connectors");
  const input = body === undefined ? {} : record(body);
  const operationId = newId("op");
  const digest = await operationDigest({ resource, mutation, id: url.pathname.split("/").at(-1), body: input });
  const key = mutation ? idempotencyKey(request) : `read:${operationId}`;
  await authorizeConnector(env, actor, { operation, ...(typeof input.device_id === "string" ? { deviceId: input.device_id } : {}), ...(typeof input.project_id === "string" ? { projectId: input.project_id } : {}), artifactUploadBytes: resource === "artifacts" ? Number(input.bytes ?? 0) : 0, idempotencyKey: key, operationId, payloadDigest: digest });
}

async function resolveApproval(request: Request, env: ControlPlaneEnv, approvalId: string): Promise<Response> {
  const auth = await actorFor(request, env, true);
  const key = idempotencyKey(request);
  const body = record(await readJsonBounded(request));
  const decision = boundedString(body.decision, "decision", 16);
  if (!['approved', 'denied'].includes(decision)) throw new PublicError("invalid_request", 400, "decision is invalid");
  const approval = await env.DB.prepare("SELECT operation_id,commitment_digest,expires_at,decision FROM approvals WHERE id=?1 LIMIT 1").bind(approvalId).first<{ operation_id: string; commitment_digest: string; expires_at: string; decision: string | null }>();
  if (approval === null) throw new PublicError("not_found", 404, "Approval not found");
  if (approval.decision !== null || Date.parse(approval.expires_at) <= Date.now()) throw new PublicError("approval_expired", 409, "Approval is resolved or expired");
  if (boundedString(body.commitmentDigest, "commitmentDigest", 64, 64) !== approval.commitment_digest) throw new PublicError("approval_digest_mismatch", 409, "Approval commitment does not match");
  if (auth.connector) await authorizeConnector(env, auth.actor, { operation: "approval.resolve", idempotencyKey: key, operationId: newId("op"), payloadDigest: approval.commitment_digest });
  else await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const reserved = await reserveEffect(env.DB, auth.actor.grantId ?? `${auth.actor.clientId}:${auth.actor.principalId}`, key, await operationDigest({ approvalId, decision, commitmentDigest: approval.commitment_digest }));
  if (reserved.replay !== undefined) return Response.json(reserved.replay);
  const result = await env.DB.prepare("UPDATE approvals SET decision=?1,resolved_at=?2 WHERE id=?3 AND decision IS NULL AND expires_at>?2").bind(decision, nowIso(), approvalId).run();
  if (result.meta.changes !== 1) throw new PublicError("approval_expired", 409, "Approval changed before resolution");
  const response = { approvalId, decision, commitmentDigest: approval.commitment_digest };
  await completeEffect(env.DB, reserved.reservation!, response);
  return Response.json(response);
}

async function transition(request: Request, env: ControlPlaneEnv, kind: "assignment" | "run", id: string): Promise<Response> {
  const auth = await actorFor(request, env, true);
  if (auth.connector) throw new PublicError("operation_not_allowed", 403, "Direct state transitions are owner-only");
  const key = idempotencyKey(request);
  const body = record(await readJsonBounded(request));
  const table = kind === "assignment" ? "assignments" : "runs";
  const transitions = kind === "assignment" ? "assignment_transitions" : "run_transitions";
  const current = await env.DB.prepare(`SELECT state,revision FROM ${table} WHERE id=?1 LIMIT 1`).bind(id).first<{ state: string; revision: number }>();
  if (current === null) throw new PublicError("not_found", 404, `${kind} not found`);
  const expectedRevision = parseIfMatch(request);
  const toState = boundedString(body.toState, "toState", 64);
  const assignmentTransitions: Record<string, readonly string[]> = {
    draft: ["queued", "cancelled"], queued: ["active", "cancelled", "failed"], active: ["waiting_input", "waiting_approval", "ready_for_review", "cancelled", "failed"],
    waiting_input: ["active", "cancelled", "failed"], waiting_approval: ["active", "cancelled", "failed"], ready_for_review: ["accepted", "rejected", "active"], rejected: ["active", "cancelled"], accepted: [], cancelled: [], failed: [],
  };
  const runTransitions: Record<string, readonly string[]> = {
    created: ["admitted", "cancelled", "failed"], admitted: ["queued", "cancelled", "failed"], queued: ["offered", "cancelled", "failed"], offered: ["claimed", "cancelled", "failed", "lost", "uncertain"],
    claimed: ["preparing_workspace", "cancelled", "failed", "lost", "uncertain"], preparing_workspace: ["provisioning_runtime", "cancelled", "failed", "lost", "uncertain"], provisioning_runtime: ["starting_agent", "cancelled", "failed", "lost", "uncertain"],
    starting_agent: ["prompt_accepted", "cancelled", "failed", "lost", "uncertain"], prompt_accepted: ["working", "cancelled", "failed", "lost", "uncertain"], working: ["waiting_input", "waiting_approval", "finishing", "paused", "cancelled", "failed", "lost", "uncertain"],
    waiting_input: ["working", "cancelled", "failed", "lost", "uncertain"], waiting_approval: ["working", "cancelled", "failed", "lost", "uncertain"], paused: ["working", "cancelled", "failed", "lost", "uncertain"], finishing: ["ready_for_review", "completed", "failed", "lost", "uncertain"], ready_for_review: ["completed", "working", "cancelled", "failed"], completed: [], cancelled: [], failed: [], lost: ["uncertain"], uncertain: [],
  };
  if (!(kind === "assignment" ? assignmentTransitions : runTransitions)[current.state]?.includes(toState)) throw new PublicError("invalid_request", 409, `Invalid ${kind} transition ${current.state} -> ${toState}`);
  const receiptKind = boundedString(body.receiptKind ?? body.reasonCode, "receiptKind", 128);
  if (kind === "assignment" && receiptKind === "agent_claim") throw new PublicError("invalid_request", 400, "Agent claims cannot directly transition Assignment state");
  const reserved = await reserveEffect(env.DB, `${auth.actor.clientId}:${auth.actor.principalId}`, key, await operationDigest({ kind, id, expectedRevision, toState, receiptKind, evidenceRef: body.evidenceRef ?? null, receiptDigest: body.receiptDigest ?? null }));
  if (reserved.replay !== undefined) return Response.json(reserved.replay, { headers: typeof reserved.replay.revision === "number" ? { etag: `"${reserved.replay.revision}"` } : {} });
  const now = nowIso();
  const transitionId = newId(kind === "assignment" ? "asgt" : "runt");
  const statements = [env.DB.prepare(`UPDATE ${table} SET state=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND revision=?4 AND state=?5`).bind(toState, now, id, expectedRevision, current.state)];
  if (kind === "assignment") statements.push(env.DB.prepare(`INSERT INTO ${transitions}(id,assignment_id,from_state,to_state,reason_code,evidence_ref,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE EXISTS (SELECT 1 FROM assignments WHERE id=?2 AND state=?4 AND revision=?8)`).bind(transitionId, id, current.state, toState, receiptKind, body.evidenceRef ?? null, now, expectedRevision + 1));
  else statements.push(env.DB.prepare(`INSERT INTO ${transitions}(id,run_id,from_state,to_state,receipt_kind,receipt_digest,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE EXISTS (SELECT 1 FROM runs WHERE id=?2 AND state=?4 AND revision=?8)`).bind(transitionId, id, current.state, toState, receiptKind, body.receiptDigest ?? null, now, expectedRevision + 1));
  const [updated, inserted] = await env.DB.batch(statements);
  if (updated?.meta.changes !== 1 || inserted?.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Target revision is stale");
  const response = { id, state: toState, revision: expectedRevision + 1, transitionId };
  await completeEffect(env.DB, reserved.reservation!, response);
  return Response.json(response, { headers: { etag: `"${expectedRevision + 1}"` } });
}

async function postBoardMessage(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const body = record(await readJsonBounded(request));
  const auth = await actorFor(request, env, true);
  const url = new URL(request.url);
  await authorizeResource(request, env, auth.actor, auth.connector, "messages", true, url, body);
  const key = idempotencyKey(request);
  const sessionId = boundedString(body.session_id ?? body.sessionId, "sessionId", 128);
  const text = boundedString(body.body, "body", 32_768);
  const rawMentions = body.mentions === undefined ? [] : body.mentions;
  if (!Array.isArray(rawMentions) || rawMentions.length > 64) throw new PublicError("invalid_request", 400, "mentions must be an array with at most 64 entries");
  const digest = await operationDigest({ sessionId, body: text, mentions: rawMentions });
  const reserved = await reserveEffect(env.DB, auth.actor.grantId ?? `${auth.actor.clientId}:${auth.actor.principalId}`, key, digest);
  if (reserved.replay !== undefined) return Response.json(reserved.replay);
  const session = await env.DB.prepare("SELECT project_id FROM collaboration_sessions WHERE id=?1 LIMIT 1").bind(sessionId).first<{ project_id: string | null }>();
  if (session === null) throw new PublicError("not_found", 404, "Collaboration Session not found");
  const messageId = newId("msg");
  const now = nowIso();
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("INSERT INTO messages(id,session_id,author_principal_id,origin,body,revision,attachments_json,created_at) VALUES (?1,?2,?3,?4,?5,1,?6,?7)").bind(messageId, sessionId, auth.actor.principalId, auth.connector ? `mcp:${auth.actor.clientId}` : auth.actor.clientId, text, JSON.stringify(body.attachments ?? []), now),
    env.DB.prepare("INSERT INTO message_revisions(message_id,revision,body,editor_principal_id,created_at) VALUES (?1,1,?2,?3,?4)").bind(messageId, text, auth.actor.principalId, now),
  ];
  const assignmentIds: string[] = [];
  for (const [index, value] of rawMentions.entries()) {
    const mention = record(value, `mentions[${index}]`);
    const mentionType = boundedString(mention.type, `mentions[${index}].type`, 64);
    if (!["project_agent", "principal", "assignment_proposal"].includes(mentionType)) throw new PublicError("invalid_request", 400, "Structured mention type is invalid");
    const targetId = boundedString(mention.targetId, `mentions[${index}].targetId`, 128);
    const startOffset = Number(mention.startOffset);
    const endOffset = Number(mention.endOffset);
    if (!Number.isSafeInteger(startOffset) || !Number.isSafeInteger(endOffset) || startOffset < 0 || endOffset <= startOffset || endOffset > text.length) throw new PublicError("invalid_request", 400, "Structured mention offsets are invalid");
    statements.push(env.DB.prepare("INSERT INTO structured_mentions(id,message_id,mention_type,target_id,start_offset,end_offset,payload_json) VALUES (?1,?2,?3,?4,?5,?6,?7)").bind(newId("mnt"), messageId, mentionType, targetId, startOffset, endOffset, JSON.stringify(mention.payload ?? {})));
    if (mention.assignment !== undefined) {
      const assignment = record(mention.assignment, `mentions[${index}].assignment`);
      const assignmentId = newId("asg");
      assignmentIds.push(assignmentId);
      statements.push(env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,source_message_id,title,body,state,revision,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,'draft',1,?7,?7)").bind(assignmentId, session.project_id, sessionId, messageId, boundedString(assignment.title, "assignment.title", 256), boundedString(assignment.body ?? text, "assignment.body", 32_768), now));
    }
  }
  await env.DB.batch(statements);
  const response = { id: messageId, session_id: sessionId, author_principal_id: auth.actor.principalId, origin: auth.actor.clientId, body: text, revision: 1, assignmentIds, created_at: now };
  await completeEffect(env.DB, reserved.reservation!, response);
  await env.BOARD_ROOMS.getByName(sessionId).publish({ eventId: newId("bevt"), sessionId, type: "message.created", recordId: messageId, revision: 1 });
  return Response.json(response, { status: 201, headers: { etag: '"1"' } });
}

export async function handleApi(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "POST" && path === "/v1/messages") return postBoardMessage(request, env);
  const artifactUpload = path.match(/^\/v1\/artifacts\/([^/]+)\/content$/);
  if (request.method === "PUT" && artifactUpload?.[1] !== undefined) return uploadArtifact(request, env, artifactUpload[1]);
  const approval = path.match(/^\/v1\/approvals\/([^/]+)\/resolve$/);
  if (request.method === "POST" && approval?.[1] !== undefined) return resolveApproval(request, env, approval[1]);
  const assignmentTransition = path.match(/^\/v1\/assignments\/([^/]+)\/transitions$/);
  if (request.method === "POST" && assignmentTransition?.[1] !== undefined) return transition(request, env, "assignment", assignmentTransition[1]);
  const runTransition = path.match(/^\/v1\/runs\/([^/]+)\/transitions$/);
  if (request.method === "POST" && runTransition?.[1] !== undefined) return transition(request, env, "run", runTransition[1]);
  if (request.method === "POST" && path === "/v1/operations") {
    const auth = await actorFor(request, env, true);
    const body = record(await readJsonBounded(request)) as unknown as StartOperationInput;
    const key = idempotencyKey(request);
    if (body.idempotencyKey !== undefined && body.idempotencyKey !== key) throw new PublicError("idempotency_conflict", 409, "Body and Idempotency-Key header differ");
    body.idempotencyKey = key;
    return Response.json(await createOperation(env, auth.actor, body, { kind: auth.connector ? "connector" : "owner" }), { status: 202 });
  }
  const stream = path.match(/^\/v1\/sessions\/([^/]+)\/stream$/);
  if (request.method === "GET" && stream?.[1] !== undefined && request.headers.get("upgrade")?.toLowerCase() === "websocket") {
    await actorFor(request, env, false);
    return env.BOARD_ROOMS.getByName(stream[1]).fetch(request);
  }
  const runEvents = path.match(/^\/v1\/runs\/([^/]+)\/events$/);
  if (request.method === "GET" && runEvents?.[1] !== undefined) {
    await actorFor(request, env, false);
    const rows = await env.DB.prepare("SELECT * FROM normalized_events WHERE run_id=?1 ORDER BY CAST(sequence AS INTEGER) LIMIT 500").bind(runEvents[1]).all<Record<string, unknown>>();
    return Response.json({ items: rows.results });
  }
  if (legacyCompatibilityPaths.has(`${request.method} ${path}`) || (request.method === "GET" && /^\/v1\/connectors\/[^/]+$/.test(path))) {
    await actorFor(request, env, request.method !== "GET");
    throw new PublicError("invalid_request", 400, "This CLI route requires a targetId and typed payload; use the canonical resource URL documented by the control plane");
  }
  const match = path.match(/^\/v1\/([a-z_]+)(?:\/([^/]+))?$/);
  if (match?.[1] === undefined || !(match[1] in resourceSpecs)) return null;
  const resource = match[1] as ResourceName;
  const id = match[2];
  const repo = new DomainRepository(env.DB);
  const url = new URL(request.url);
  if (request.method === "GET") {
    const auth = await actorFor(request, env, false);
    await authorizeResource(request, env, auth.actor, auth.connector, resource, false, url);
    if (id === undefined) return Response.json({ items: await repo.list(resource, url) });
    const item = await repo.get(resource, id);
    return typeof item.revision === "number" ? Response.json(item, { headers: { etag: `"${item.revision}"` } }) : Response.json(item);
  }
  if (request.method === "POST" && id === undefined) {
    const body = await readJsonBounded(request);
    const auth = await actorFor(request, env, true);
    idempotencyKey(request);
    await authorizeResource(request, env, auth.actor, auth.connector, resource, true, url, body);
    if (resource === "approvals") throw new PublicError("invalid_request", 405, "Approvals are created by operation admission");
    const key = idempotencyKey(request);
    const reserved = await reserveEffect(env.DB, auth.actor.grantId ?? `${auth.actor.clientId}:${auth.actor.principalId}`, key, await operationDigest({ method: "POST", resource, body }));
    if (reserved.replay !== undefined) return Response.json(reserved.replay);
    const created = await repo.create(resource, body);
    await completeEffect(env.DB, reserved.reservation!, created);
    if (resource === "messages" && typeof created.session_id === "string") await env.BOARD_ROOMS.getByName(created.session_id).publish({ eventId: newId("bevt"), sessionId: created.session_id, type: "message.created", recordId: String(created.id), revision: Number(created.revision) });
    return Response.json(created, { status: 201 });
  }
  if (request.method === "PATCH" && id !== undefined) {
    const body = await readJsonBounded(request);
    const auth = await actorFor(request, env, true);
    const key = idempotencyKey(request);
    await authorizeResource(request, env, auth.actor, auth.connector, resource, true, url, body);
    const expected = parseIfMatch(request);
    const reserved = await reserveEffect(env.DB, auth.actor.grantId ?? `${auth.actor.clientId}:${auth.actor.principalId}`, key, await operationDigest({ method: "PATCH", resource, id, expected, body }));
    if (reserved.replay !== undefined) return Response.json(reserved.replay, { headers: typeof reserved.replay.revision === "number" ? { etag: `"${reserved.replay.revision}"` } : {} });
    const updated = await repo.update(resource, id, expected, body);
    await completeEffect(env.DB, reserved.reservation!, updated);
    return Response.json(updated, { headers: { etag: `"${String(updated.revision)}"` } });
  }
  return new Response(null, { status: 405, headers: { allow: "GET, POST, PATCH" } });
}
