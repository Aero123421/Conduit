import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { approvalOutboxInsert, attemptApprovalDispatch, buildApprovalReceipt } from "../approval-dispatch.ts";
import { newId, nowIso, operationDigest } from "../crypto.ts";
import { PublicError } from "../errors.ts";
import { completeEffect, reserveEffect } from "../idempotency.ts";
import { createOperation, type StartOperationInput } from "../operations.ts";
import { authorizeConnector } from "../policy.ts";
import { DomainRepository, type ResourceName } from "../repositories/domain.ts";
import { combineResourceAuthorities, resolveInputAuthority, resolveResourceAuthority, type ResourceAuthority } from "../repositories/resource-authority.ts";
import type { AccessScope, ApprovalMode, AuthActor, ControlPlaneEnv } from "../types.ts";

const id = z.string().min(8).max(128);
const requestKey = z.string().min(16).max(256);
const jsonObject = z.record(z.string().max(128), z.unknown()).refine((value) => Object.keys(value).length <= 128, "object has too many fields");

function result(value: Record<string, unknown>) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }], structuredContent: value };
}

function toolFailure(error: unknown) {
  const message = error instanceof PublicError ? `${error.code}: ${error.message}` : "internal_error: tool invocation failed";
  return { isError: true, content: [{ type: "text" as const, text: message }] };
}

async function readOne(env: ControlPlaneEnv, actor: AuthActor, resource: ResourceName, recordId: string, operation: string, requestIdempotency: string): Promise<Record<string, unknown>> {
  const digest = await operationDigest({ resource, recordId, operation });
  const target = await resolveResourceAuthority(env.DB, resource, recordId);
  await authorizeConnector(env, actor, { operation, ...target, idempotencyKey: requestIdempotency, operationId: newId("op"), payloadDigest: digest });
  return new DomainRepository(env.DB).get(resource, recordId);
}

async function authorityForSession(env: ControlPlaneEnv, sessionId: string): Promise<ResourceAuthority> {
  return resolveResourceAuthority(env.DB, "sessions", sessionId);
}

async function authorityForRun(env: ControlPlaneEnv, runId: string): Promise<ResourceAuthority> {
  return resolveResourceAuthority(env.DB, "runs", runId);
}

export function createConduitMcpServer(env: ControlPlaneEnv, actor: AuthActor): McpServer {
  const server = new McpServer({ name: "conduit-control-plane", version: "0.1.0" });

  server.registerTool("device_health_get", { title: "Get Device health", description: "Read bounded health and last-observed metadata for one allowed Device.", inputSchema: z.object({ deviceId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ deviceId, requestKey: key }) => {
    try { return result(await readOne(env, actor, "devices", deviceId, "project.read", key)); } catch (error) { return toolFailure(error); }
  });

  server.registerTool("project_get", { title: "Get Project", description: "Read one allowed Project and its current revision.", inputSchema: z.object({ projectId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ projectId, requestKey: key }) => {
    try { return result(await readOne(env, actor, "projects", projectId, "project.read", key)); } catch (error) { return toolFailure(error); }
  });

  server.registerTool("source_location_get", { title: "Get Source Location", description: "Read opaque Source/Location metadata. Project and Device authority are resolved from the stored Location and Source.", inputSchema: z.object({ locationId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ locationId, requestKey: key }) => {
    try { return result(await readOne(env, actor, "locations", locationId, "project.read", key)); } catch (error) { return toolFailure(error); }
  });

  server.registerTool("session_board_read", { title: "Read Session board", description: "Read a bounded page of immutable board Messages for one Collaboration Session.", inputSchema: z.object({ sessionId: id, afterId: z.string().max(128).default(""), limit: z.number().int().min(1).max(100).default(50), requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ sessionId, afterId, limit, requestKey: key }) => {
    try {
      const target = await authorityForSession(env, sessionId);
      await authorizeConnector(env, actor, { operation: "board.read", ...target, idempotencyKey: key, operationId: newId("op"), payloadDigest: await operationDigest({ sessionId, afterId, limit }) });
      const rows = await env.DB.prepare("SELECT * FROM messages WHERE session_id=?1 AND id>?2 ORDER BY id LIMIT ?3").bind(sessionId, afterId, limit).all<Record<string, unknown>>();
      return result({ items: rows.results, nextCursor: rows.results.at(-1)?.id ?? null });
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("board_message_post", { title: "Post board Message", description: "Create one bounded board Message in an allowed Collaboration Session.", inputSchema: z.object({ sessionId: id, body: z.string().min(1).max(32768), idempotencyKey: requestKey }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }, async ({ sessionId, body, idempotencyKey }) => {
    try {
      const target = await authorityForSession(env, sessionId);
      const digest = await operationDigest({ sessionId, body });
      await authorizeConnector(env, actor, { operation: "board.write", ...target, idempotencyKey, operationId: newId("op"), payloadDigest: digest });
      const reserved = await reserveEffect(env.DB, actor.grantId!, idempotencyKey, digest);
      if (reserved.replay !== undefined) return result(reserved.replay);
      const message = await new DomainRepository(env.DB).create("messages", { session_id: sessionId, author_principal_id: actor.principalId, origin: `mcp:${actor.clientId}`, body, attachments_json: [] });
      await completeEffect(env.DB, reserved.reservation!, message);
      await env.BOARD_ROOMS.getByName(sessionId).publish({ eventId: newId("bevt"), sessionId, type: "message.created", recordId: String(message.id), revision: 1 });
      return result(message);
    } catch (error) { return toolFailure(error); }
  });

  const entityReads: Array<{ name: string; title: string; resource: ResourceName; idName: string; permission: string }> = [
    { name: "project_agent_get", title: "Get Project Agent", resource: "project_agents", idName: "recordId", permission: "project.read" },
    { name: "assignment_get", title: "Get Assignment", resource: "assignments", idName: "recordId", permission: "session.read" },
    { name: "run_get", title: "Get Run", resource: "runs", idName: "recordId", permission: "run.read" },
    { name: "task_get", title: "Get Task", resource: "tasks", idName: "recordId", permission: "session.read" },
    { name: "artifact_get", title: "Get Artifact metadata", resource: "artifacts", idName: "recordId", permission: "artifact.read" },
  ];
  for (const item of entityReads) {
    server.registerTool(item.name, { title: item.title, description: `Read one bounded ${item.resource} record. Project authority is resolved from the stored record.`, inputSchema: z.object({ recordId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ recordId, requestKey: key }) => {
      try { return result(await readOne(env, actor, item.resource, recordId, item.permission, key)); } catch (error) { return toolFailure(error); }
    });
  }

  server.registerTool("assignment_create", { title: "Create Assignment", description: "Create a durable Assignment proposal; this does not itself start a Run.", inputSchema: z.object({ projectId: id.optional(), sessionId: id.optional(), title: z.string().min(1).max(256), body: z.string().min(1).max(32768), idempotencyKey: requestKey }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }, async ({ projectId, sessionId, title, body, idempotencyKey }) => {
    try {
      const digest = await operationDigest({ projectId, sessionId, title, body });
      const target = await resolveInputAuthority(env.DB, "assignments", { ...(projectId === undefined ? {} : { project_id: projectId }), ...(sessionId === undefined ? {} : { session_id: sessionId }) });
      await authorizeConnector(env, actor, { operation: "assignment.create", ...target, idempotencyKey, operationId: newId("op"), payloadDigest: digest });
      const reserved = await reserveEffect(env.DB, actor.grantId!, idempotencyKey, digest);
      if (reserved.replay !== undefined) return result(reserved.replay);
      const assignment = await new DomainRepository(env.DB).create("assignments", { project_id: target.projectId, session_id: sessionId, title, body, state: "draft" });
      await completeEffect(env.DB, reserved.reservation!, assignment);
      return result(assignment);
    } catch (error) { return toolFailure(error); }
  });

  const sourceRevision = z.object({ sourceId: id, locationId: id, locationRevision: z.number().int().min(1), mode: z.enum(["read_only", "direct", "worktree", "managed_copy"]), baseCommit: z.string().regex(/^[A-Fa-f0-9]{7,64}$/).optional(), dirtyDigest: z.string().regex(/^[a-f0-9]{64}$/).optional() });
  const runtimeRequest = z.object({ kind: z.enum(["native", "restricted_native", "container", "vm"]), providerId: z.string().regex(/^[a-z][a-z0-9_.-]{0,127}$/), configurationRevision: z.number().int().min(1), cpuLimit: z.number().positive().max(1024).optional(), memoryBytes: z.number().int().nonnegative().optional(), storageBytes: z.number().int().nonnegative().optional(), gpuCount: z.number().int().min(0).max(64).optional(), networkMode: z.enum(["open", "restricted", "offline", "lan_explicit"]).optional() });
  const startSchema = z.object({ idempotencyKey: requestKey, deviceId: id, projectId: id.optional(), sessionId: id.optional(), assignmentId: id.optional(), runId: id.optional(), runtime: runtimeRequest, accessScope: z.enum(["read_only", "selected_sources", "project_full", "full_user", "full_device"]), approvalMode: z.enum(["always", "outside_scope", "risk_classes", "never"]), sourceRevisions: z.array(sourceRevision).max(128).default([]), arguments: jsonObject, maxDurationSeconds: z.number().int().min(1).max(3600).optional() });
  const registerStart = (name: string, title: string, capability: string, description: string) => server.registerTool(name, { title, description, inputSchema: startSchema, annotations: { readOnlyHint: false, destructiveHint: capability.includes("destroy") || capability.includes("stop"), idempotentHint: true } }, async (input) => {
    try {
      let target = await resolveInputAuthority(env.DB, "operations", { device_id: input.deviceId, ...(input.projectId === undefined ? {} : { project_id: input.projectId }), ...(input.sessionId === undefined ? {} : { session_id: input.sessionId }), ...(input.assignmentId === undefined ? {} : { assignment_id: input.assignmentId }), ...(input.runId === undefined ? {} : { run_id: input.runId }) });
      for (const revision of input.sourceRevisions) {
        const location = await env.DB.prepare("SELECT source_id,revision FROM locations WHERE id=?1 LIMIT 1").bind(revision.locationId).first<{ source_id: string; revision: number }>();
        if (location === null) throw new PublicError("not_found", 404, "Source Location not found");
        if (location.source_id !== revision.sourceId || location.revision !== revision.locationRevision) throw new PublicError("revision_conflict", 409, "Source Location binding or revision is stale");
        target = combineResourceAuthorities(target, await resolveResourceAuthority(env.DB, "locations", revision.locationId));
      }
      const argumentsFromClient = { ...input.arguments };
      delete argumentsFromClient.role;
      let effectiveAccessScope = input.accessScope as AccessScope;
      if (capability === "agent.run.start" && typeof argumentsFromClient.projectAgentId === "string") {
        const agent = await env.DB.prepare("SELECT project_id,adapter_id,role,status FROM project_agents WHERE id=?1 LIMIT 1").bind(argumentsFromClient.projectAgentId).first<{ project_id: string; adapter_id: string; role: string; status: string }>();
        if (agent === null || agent.status !== "active") throw new PublicError("not_found", 404, "Project Agent not found");
        target = combineResourceAuthorities(target, { projectId: agent.project_id });
        argumentsFromClient.adapterId = agent.adapter_id;
        argumentsFromClient.role = agent.role;
        if (agent.role === "reviewer") effectiveAccessScope = "read_only";
      }
      const operationInput: StartOperationInput = { idempotencyKey: input.idempotencyKey, deviceId: input.deviceId, capability, runtime: JSON.parse(JSON.stringify(input.runtime)) as StartOperationInput["runtime"], accessScope: effectiveAccessScope, approvalMode: input.approvalMode as ApprovalMode, sourceRevisions: JSON.parse(JSON.stringify(input.sourceRevisions)) as StartOperationInput["sourceRevisions"], arguments: { ...argumentsFromClient, ...(input.maxDurationSeconds !== undefined ? { maxDurationSeconds: input.maxDurationSeconds } : {}) }, ...(input.maxDurationSeconds !== undefined ? { expiresInSeconds: input.maxDurationSeconds } : {}) };
      if (target.projectId !== undefined) operationInput.projectId = target.projectId;
      if (input.sessionId !== undefined) operationInput.sessionId = input.sessionId;
      if (input.assignmentId !== undefined) operationInput.assignmentId = input.assignmentId;
      if (input.runId !== undefined) operationInput.runId = input.runId;
      return result(await createOperation(env, actor, operationInput));
    } catch (error) { return toolFailure(error); }
  });
  registerStart("run_start", "Start Assignment Run", "agent.run.start", "Start an allowed Assignment Run and return a durable operation handle immediately.");
  registerStart("quick_command_start", "Start Quick Command", "command.start", "Start a projectless or Project-bound Quick Command and return immediately.");
  registerStart("quick_agent_session_start", "Start Quick Agent Session", "agent.run.start", "Start a projectless or Project-bound Quick Agent Session and return immediately.");
  registerStart("runtime_vm_lifecycle", "Control Runtime or VM", "runtime.create", "Create or control an allowed Runtime/VM through a typed durable operation.");
  registerStart("run_control", "Control Run", "run.control", "Pause, resume, stop, or send typed input to one exact Run.");

  server.registerTool("approval_resolve", { title: "Resolve Approval", description: "Resolve one typed approval using its exact commitment digest.", inputSchema: z.object({ approvalId: id, commitmentDigest: z.string().regex(/^[a-f0-9]{64}$/), decision: z.enum(["approved", "denied"]), idempotencyKey: requestKey }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }, async ({ approvalId, commitmentDigest, decision, idempotencyKey }) => {
    try {
      const approval = await env.DB.prepare("SELECT commitment_digest,expires_at,decision FROM approvals WHERE id=?1 LIMIT 1").bind(approvalId).first<{ commitment_digest: string; expires_at: string; decision: string | null }>();
      if (approval === null || approval.commitment_digest !== commitmentDigest) throw new PublicError("approval_digest_mismatch", 409, "Approval commitment does not match");
      const target = await resolveResourceAuthority(env.DB, "approvals", approvalId);
      await authorizeConnector(env, actor, { operation: "approval.resolve", ...target, idempotencyKey, operationId: newId("op"), payloadDigest: commitmentDigest });
      const reserved = await reserveEffect(env.DB, actor.grantId!, idempotencyKey, await operationDigest({ approvalId, commitmentDigest, decision }));
      if (reserved.replay !== undefined) return result(reserved.replay);
      if (approval.decision !== null || Date.parse(approval.expires_at) <= Date.now()) throw new PublicError("approval_expired", 409, "Approval is resolved or expired");
      const resolvedAt = nowIso();
      const receipt = await buildApprovalReceipt(env, approvalId, decision, new Date(resolvedAt));
      const response = { approvalId, commitmentDigest, decision };
      const reservation = reserved.reservation!;
      const [updated, outbox, completed] = await env.DB.batch([
        env.DB.prepare("UPDATE approvals SET decision=?1,resolved_at=?2 WHERE id=?3 AND decision IS NULL AND expires_at>?2").bind(decision, resolvedAt, approvalId),
        approvalOutboxInsert(env, approvalId, receipt, resolvedAt),
        env.DB.prepare("UPDATE effect_idempotency_records SET state='completed',response_json=?1,updated_at=?2 WHERE scope=?3 AND idempotency_key=?4 AND payload_digest=?5 AND state='reserved' AND EXISTS (SELECT 1 FROM approvals WHERE id=?6 AND decision=?7 AND resolved_at=?2)").bind(JSON.stringify(response), resolvedAt, reservation.scope, reservation.key, reservation.digest, approvalId, decision),
      ]);
      if (updated?.meta.changes !== 1 || outbox?.meta.changes !== 1 || completed?.meta.changes !== 1) throw new PublicError("approval_expired", 409, "Approval changed before resolution");
      await attemptApprovalDispatch(env, approvalId);
      return result(response);
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("task_create", { title: "Create Task", description: "Create a Kanban Task linked to ordinary execution records without replacing them.", inputSchema: z.object({ projectId: id.optional(), sessionId: id.optional(), assignmentId: id.optional(), title: z.string().min(1).max(256), description: z.string().max(32768).default(""), idempotencyKey: requestKey }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }, async ({ projectId, sessionId, assignmentId, title, description, idempotencyKey }) => {
    try {
      const target = await resolveInputAuthority(env.DB, "tasks", { ...(projectId === undefined ? {} : { project_id: projectId }), ...(sessionId === undefined ? {} : { session_id: sessionId }), ...(assignmentId === undefined ? {} : { assignment_id: assignmentId }) });
      await authorizeConnector(env, actor, { operation: "board.write", ...target, idempotencyKey, operationId: newId("op"), payloadDigest: await operationDigest({ projectId, sessionId, assignmentId, title, description }) });
      const digest = await operationDigest({ projectId, sessionId, assignmentId, title, description });
      const reserved = await reserveEffect(env.DB, actor.grantId!, idempotencyKey, digest);
      if (reserved.replay !== undefined) return result(reserved.replay);
      const task = await new DomainRepository(env.DB).create("tasks", { project_id: target.projectId, session_id: sessionId, assignment_id: assignmentId, title, description, status: "todo" });
      await completeEffect(env.DB, reserved.reservation!, task);
      return result(task);
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("artifact_register", { title: "Register Artifact upload", description: "Commit bounded artifact metadata before a separately authorized streaming upload.", inputSchema: z.object({ projectId: id.optional(), runId: id.optional(), artifactKind: z.string().min(1).max(128), contentDigest: z.string().regex(/^[a-f0-9]{64}$/), bytes: z.number().int().min(0).max(67_108_864), sensitivity: z.string().min(1).max(64), retentionClass: z.string().min(1).max(32), idempotencyKey: requestKey }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }, async ({ projectId, runId, artifactKind, contentDigest, bytes, sensitivity, retentionClass, idempotencyKey }) => {
    try {
      const digest = await operationDigest({ projectId, runId, artifactKind, contentDigest, bytes, sensitivity, retentionClass });
      const target = await resolveInputAuthority(env.DB, "artifacts", { ...(projectId === undefined ? {} : { project_id: projectId }), ...(runId === undefined ? {} : { run_id: runId }) });
      await authorizeConnector(env, actor, { operation: "artifact.upload", ...target, artifactUploadBytes: bytes, idempotencyKey, operationId: newId("op"), payloadDigest: digest });
      const reserved = await reserveEffect(env.DB, actor.grantId!, idempotencyKey, digest);
      if (reserved.replay !== undefined) return result(reserved.replay);
      const artifact = await new DomainRepository(env.DB).create("artifacts", { project_id: target.projectId, run_id: runId, artifact_kind: artifactKind, content_digest: contentDigest, bytes, sensitivity, retention_class: retentionClass, custody: "upload_pending", upload_policy_json: { connectorPolicyId: actor.policyId, connectorPolicyRevision: actor.policyRevision }, status: "pending" });
      const response = { ...artifact, uploadMethod: "PUT", uploadPath: `/api/v1/artifacts/${String(artifact.id)}/content`, requiredDigestHeader: "X-Conduit-Content-SHA256" };
      await completeEffect(env.DB, reserved.reservation!, response);
      return result(response);
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("trace_log_summary", { title: "Read trace/log summary", description: "Read bounded normalized trace indexes and evidence summaries; raw logs require a separate tool and budget.", inputSchema: z.object({ runId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ runId, requestKey: key }) => {
    try {
      const target = await authorityForRun(env, runId);
      await authorizeConnector(env, actor, { operation: "logs.summary.read", ...target, idempotencyKey: key, operationId: newId("op"), payloadDigest: await operationDigest({ runId }) });
      const [trace, evidence] = await Promise.all([env.DB.prepare("SELECT * FROM trace_indexes WHERE run_id=?1 LIMIT 1").bind(runId).first<Record<string, unknown>>(), env.DB.prepare("SELECT * FROM evidence_summaries WHERE run_id=?1 ORDER BY created_at DESC LIMIT 100").bind(runId).all<Record<string, unknown>>()]);
      return result({ trace, evidence: evidence.results });
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("skill_instruction_report", { title: "Read Skill and instruction report", description: "Read evidence-labelled Skill and instruction summaries without claiming inferred use as explicit invocation.", inputSchema: z.object({ runId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ runId, requestKey: key }) => {
    try {
      const target = await authorityForRun(env, runId);
      await authorizeConnector(env, actor, { operation: "logs.summary.read", ...target, idempotencyKey: key, operationId: newId("op"), payloadDigest: await operationDigest({ runId, kinds: ["skill", "instruction"] }) });
      const rows = await env.DB.prepare("SELECT * FROM evidence_summaries WHERE run_id=?1 AND (evidence_kind LIKE 'skill.%' OR evidence_kind LIKE 'instruction.%') ORDER BY created_at LIMIT 200").bind(runId).all<Record<string, unknown>>();
      return result({ items: rows.results });
    } catch (error) { return toolFailure(error); }
  });

  server.registerTool("comparison_evaluation_get", { title: "Read comparison or evaluation", description: "Read one evidence-backed comparison/evaluation summary with retained confounders. Project authority is resolved from its Run.", inputSchema: z.object({ summaryId: id, requestKey }), annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }, async ({ summaryId, requestKey: key }) => {
    try {
      const target = await resolveResourceAuthority(env.DB, "evidence", summaryId);
      await authorizeConnector(env, actor, { operation: "logs.summary.read", ...target, idempotencyKey: key, operationId: newId("op"), payloadDigest: await operationDigest({ summaryId }) });
      const row = await env.DB.prepare("SELECT * FROM evidence_summaries WHERE id=?1 AND evidence_kind IN ('comparison','evaluation') LIMIT 1").bind(summaryId).first<Record<string, unknown>>();
      if (row === null) throw new PublicError("not_found", 404, "Comparison or evaluation not found");
      return result(row);
    } catch (error) { return toolFailure(error); }
  });

  return server;
}
