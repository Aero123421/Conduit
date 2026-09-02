import { z } from "zod";
import { canonicalJson, newId, nowIso, sha256Hex } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { createOperation, type OperationAuthorization, type StartOperationInput } from "./operations.ts";
import { attemptOperationDispatch } from "./dispatch.ts";
import type { AuthActor, ControlPlaneEnv } from "./types.ts";

const id = (prefix: string) => z.string().regex(new RegExp(`^${prefix}_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`));
const sourceBindingSchema = z.strictObject({
  sourceId: id("src"),
  sourceRevision: z.number().int().min(1),
  locationId: id("loc"),
  locationRevision: z.number().int().min(1),
  mode: z.enum(["read_only", "direct", "worktree", "managed_copy"]),
  baseCommit: z.string().regex(/^[A-Fa-f0-9]{7,64}$/).optional(),
  dirtyDigest: z.string().regex(/^[a-f0-9]{64}$/).optional(),
});

const boardScheduleSchema = z.strictObject({
  deviceId: id("dev"),
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
  model: z.string().min(1).max(256),
  effort: z.string().min(1).max(64),
  accessScope: z.enum(["read_only", "selected_sources", "project_full", "full_user", "full_device", "custom"]),
  approvalMode: z.enum(["always", "outside_scope", "risk_classes", "never"]),
  sourceRevisions: z.array(sourceBindingSchema).max(128),
  verificationPolicy: z.record(z.string(), z.unknown()).default({}),
  expiresInSeconds: z.number().int().min(30).max(3600).optional(),
});

interface SessionRow { project_id: string; revision: number; project_revision: number; accepted_baseline_id: string | null; }
interface AgentRow { project_id: string; revision: number; adapter_id: string; role: string; configuration_json: string; status: string; }
interface ScheduledReplayRow {
  operation_id: string;
  request_json: string;
  request_digest: string;
  source_message_id: string;
  assignment_id: string;
  run_id: string;
  context_snapshot_id: string;
  session_id: string;
  body: string;
  created_at: string;
}

interface SourceAuthorityRow {
  source_index: number;
  source_project_id: string | null;
  source_revision: number | null;
  source_id: string | null;
  location_source_id: string | null;
  location_device_id: string | null;
  location_revision: number | null;
  location_status: string | null;
}

export interface ScheduledBoardMention {
  targetId: string;
  startOffset: number;
  endOffset: number;
  title: string;
  body: string;
  payload: Record<string, unknown>;
  schedule: unknown;
}

export interface ScheduledBoardResult {
  id: string;
  session_id: string;
  body: string;
  revision: number;
  assignmentIds: string[];
  runIds: string[];
  contextSnapshotIds: string[];
  operationIds: string[];
  created_at: string;
  replay?: true;
}

async function digest(domain: string, value: unknown): Promise<string> {
  return sha256Hex(`${domain}\n${canonicalJson(value)}`);
}

function parseJsonRecord(value: string, label: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new PublicError("invalid_request", 409, `${label} is not an object`);
  return parsed as Record<string, unknown>;
}

function projectAgentCredentialProjections(configuration: Record<string, unknown>): Array<{ profileId: string; revision: number; targetName: string }> {
  const value = configuration.credentialProjections;
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) throw new PublicError("invalid_request", 409, "Project Agent credentialProjections is invalid");
  const profiles = new Set<string>();
  const targets = new Set<string>();
  return value.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw new PublicError("invalid_request", 409, "Project Agent credential projection is invalid");
    const projection = item as Record<string, unknown>;
    if (Object.keys(projection).some((key) => !["profileId", "revision", "targetName"].includes(key))) throw new PublicError("invalid_request", 409, "Project Agent credential projection contains an unknown field");
    const profileId = projection.profileId;
    const revision = projection.revision;
    const targetName = projection.targetName;
    if (typeof profileId !== "string" || !/^cred_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(profileId) || !Number.isSafeInteger(revision) || (revision as number) < 1 || typeof targetName !== "string" || targetName.length > 256 || targetName.startsWith("/") || targetName.includes("\\") || targetName.split("/").some((part) => part.length === 0 || part === "." || part === ".." || !/^[A-Za-z0-9_.-]+$/.test(part)) || !profiles.add(profileId) || !targets.add(targetName)) {
      throw new PublicError("invalid_request", 409, "Project Agent credential projection is invalid");
    }
    return { profileId, revision: revision as number, targetName };
  });
}

async function replayScheduledBoard(
  env: ControlPlaneEnv,
  actor: AuthActor,
  idempotencyKey: string,
  requestDigest: string,
): Promise<ScheduledBoardResult | null> {
  const scope = actor.grantId ?? `owner:${actor.principalId}:${actor.clientId}`;
  const existing = await env.DB.prepare(`
    SELECT o.id AS operation_id,o.request_json,b.request_digest,a.source_message_id,a.id AS assignment_id,
           r.id AS run_id,c.id AS context_snapshot_id,m.session_id,m.body,m.created_at
    FROM idempotency_records i
    JOIN operation_journal o ON o.id=i.operation_id
    JOIN assignments a ON a.id=o.assignment_id
    JOIN assignment_run_bindings b ON b.assignment_id=a.id
    JOIN runs r ON r.id=o.run_id
    JOIN context_snapshots c ON c.run_id=r.id AND c.mode='initial'
    JOIN messages m ON m.id=a.source_message_id
    WHERE i.scope=?1 AND i.idempotency_key=?2 LIMIT 1
  `).bind(scope, idempotencyKey).first<ScheduledReplayRow>();
  if (existing === null) return null;
  if (existing.request_digest !== requestDigest) throw new PublicError("idempotency_conflict", 409, "Idempotency key is bound to another Board assignment");
  await attemptOperationDispatch(env, existing.operation_id, { force: true });
  return {
    id: existing.source_message_id,
    session_id: existing.session_id,
    body: existing.body,
    revision: 1,
    assignmentIds: [existing.assignment_id],
    runIds: [existing.run_id],
    contextSnapshotIds: [existing.context_snapshot_id],
    operationIds: [existing.operation_id],
    created_at: existing.created_at,
    replay: true,
  };
}

export async function scheduleBoardAssignment(
  env: ControlPlaneEnv,
  actor: AuthActor,
  authorization: OperationAuthorization,
  idempotencyKey: string,
  sessionId: string,
  boardBody: string,
  mention: ScheduledBoardMention,
): Promise<ScheduledBoardResult> {
  const parsed = boardScheduleSchema.safeParse(mention.schedule);
  if (!parsed.success) throw new PublicError("invalid_request", 400, `Board run schedule is invalid: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  const schedule = parsed.data;
  const requestDigest = await digest("conduit.board-assignment-request.v1", { sessionId, boardBody, mention, schedule });
  const replay = await replayScheduledBoard(env, actor, idempotencyKey, requestDigest);
  if (replay !== null) return replay;

  const [session, agent, device] = await Promise.all([
    env.DB.prepare("SELECT s.project_id,s.revision,s.accepted_baseline_id,p.revision AS project_revision FROM collaboration_sessions s JOIN projects p ON p.id=s.project_id WHERE s.id=?1 AND s.status='active' AND p.status='active' LIMIT 1").bind(sessionId).first<SessionRow>(),
    env.DB.prepare("SELECT project_id,revision,adapter_id,role,configuration_json,status FROM project_agents WHERE id=?1 LIMIT 1").bind(mention.targetId).first<AgentRow>(),
    env.DB.prepare("SELECT id,revision,status FROM devices WHERE id=?1 LIMIT 1").bind(schedule.deviceId).first<{ id: string; revision: number; status: string }>(),
  ]);
  if (session === null) throw new PublicError("not_found", 404, "Active Collaboration Session not found");
  if (agent === null || agent.status !== "active") throw new PublicError("not_found", 404, "Active Project Agent not found");
  if (agent.project_id !== session.project_id) throw new PublicError("project_not_allowed", 403, "Project Agent does not belong to the Session Project");
  if (device === null || device.status !== "active") throw new PublicError("not_found", 404, "Active Device not found");
  if (agent.role === "reviewer" && schedule.accessScope !== "read_only") throw new PublicError("invalid_request", 409, "Reviewer Project Agents require read_only access");
  if (agent.role === "reviewer" && schedule.sourceRevisions.some((source) => source.mode !== "read_only")) throw new PublicError("invalid_request", 409, "Reviewer Project Agents require read_only Source bindings");

  // Validate all Source/Location pairs in one json_each set query. The
  // max-size schedule (128 Sources) therefore costs one D1 statement rather
  // than 128 round trips, while the exact revision/device checks below remain
  // part of the atomic INSERT ... SELECT authority predicate.
  const sourceAuthorityRows = await env.DB.prepare(`
    WITH requested AS (
      SELECT CAST(key AS INTEGER) AS source_index,
             json_extract(value,'$.sourceId') AS source_id,
             CAST(json_extract(value,'$.sourceRevision') AS INTEGER) AS source_revision,
             json_extract(value,'$.locationId') AS location_id,
             CAST(json_extract(value,'$.locationRevision') AS INTEGER) AS location_revision
      FROM json_each(?1)
    )
    SELECT requested.source_index,source.project_id AS source_project_id,source.revision AS source_revision,
           source.id AS source_id,location.source_id AS location_source_id,
           location.device_id AS location_device_id,location.revision AS location_revision,
           location.status AS location_status
    FROM requested
    LEFT JOIN sources AS source ON source.id=requested.source_id
    LEFT JOIN locations AS location ON location.id=requested.location_id AND location.source_id=requested.source_id
  `).bind(canonicalJson(schedule.sourceRevisions)).all<SourceAuthorityRow>();
  for (const [index, source] of schedule.sourceRevisions.entries()) {
    const row = sourceAuthorityRows.results.find((candidate) => candidate.source_index === index);
    if (row === undefined || row.source_id === null || row.location_status !== "active") throw new PublicError("not_found", 404, "Active Source Location not found");
    if (row.source_project_id !== session.project_id || row.location_source_id !== source.sourceId || row.location_device_id !== schedule.deviceId) throw new PublicError("invalid_request", 409, "Source Location authority does not match the scheduled Project and Device");
    if (row.source_revision !== source.sourceRevision || row.location_revision !== source.locationRevision) throw new PublicError("revision_conflict", 409, "Source or Location revision is stale");
  }
  const sourceBaselineRevisions = session.accepted_baseline_id === null
    ? {}
    : JSON.parse((await env.DB.prepare("SELECT vector_json FROM baseline_revisions WHERE id=?1 AND session_id=?2 LIMIT 1").bind(session.accepted_baseline_id, sessionId).first<{ vector_json: string }>())?.vector_json ?? "null") as Record<string, unknown> | null;
  if (sourceBaselineRevisions === null) throw new PublicError("revision_conflict", 409, "Session accepted Baseline record is missing");
  const scheduledSourceIds = new Set(schedule.sourceRevisions.map((source) => source.sourceId));
  if (Object.keys(sourceBaselineRevisions).some((sourceId) => !scheduledSourceIds.has(sourceId))) throw new PublicError("invalid_request", 409, "Run schedule omits a Source from the accepted Baseline vector");
  for (const source of schedule.sourceRevisions) {
    const baseline = sourceBaselineRevisions[source.sourceId];
    if (baseline !== null && typeof baseline === "object" && !Array.isArray(baseline)) {
      const commit = (baseline as Record<string, unknown>).commit;
      if (typeof commit === "string" && source.baseCommit !== commit) throw new PublicError("revision_conflict", 409, "Scheduled Git base does not match the accepted Baseline vector");
    }
  }

  const messageId = newId("msg");
  const mentionId = newId("mnt");
  const assignmentId = newId("asg");
  const runId = newId("run");
  const operationId = newId("op");
  const snapshotId = newId("ctx");
  const createdAt = nowIso();
  const agentConfiguration = parseJsonRecord(agent.configuration_json, "Project Agent configuration");
  const credentialProjections = projectAgentCredentialProjections(agentConfiguration);
  const runtime: StartOperationInput["runtime"] = {
    kind: schedule.runtime.kind,
    providerId: schedule.runtime.providerId,
    configurationRevision: schedule.runtime.configurationRevision,
    ...(schedule.runtime.cpuLimit === undefined ? {} : { cpuLimit: schedule.runtime.cpuLimit }),
    ...(schedule.runtime.memoryBytes === undefined ? {} : { memoryBytes: schedule.runtime.memoryBytes }),
    ...(schedule.runtime.storageBytes === undefined ? {} : { storageBytes: schedule.runtime.storageBytes }),
    ...(schedule.runtime.gpuCount === undefined ? {} : { gpuCount: schedule.runtime.gpuCount }),
    ...(schedule.runtime.networkMode === undefined ? {} : { networkMode: schedule.runtime.networkMode }),
  };
  const sourceRevisions: StartOperationInput["sourceRevisions"] = schedule.sourceRevisions.map((source) => ({
    sourceId: source.sourceId,
    locationId: source.locationId,
    locationRevision: source.locationRevision,
    mode: source.mode,
    ...(source.baseCommit === undefined ? {} : { baseCommit: source.baseCommit }),
    ...(source.dirtyDigest === undefined ? {} : { dirtyDigest: source.dirtyDigest }),
  }));
  const binding = {
    assignmentId, projectId: session.project_id, projectRevision: session.project_revision,
    sessionId, sessionRevision: session.revision, messageId, messageRevision: 1,
    projectAgentId: mention.targetId, projectAgentRevision: agent.revision,
    adapterId: agent.adapter_id, role: agent.role, agentConfiguration,
        deviceId: schedule.deviceId, deviceRevision: device.revision, runtime: schedule.runtime, model: schedule.model, effort: schedule.effort,
    accessScope: schedule.accessScope, approvalMode: schedule.approvalMode,
    sourceRevisions: schedule.sourceRevisions, verificationPolicy: schedule.verificationPolicy,
  };
  const bindingDigest = await digest("conduit.assignment-binding.v1", binding);
  const compiledContentDigest = await digest("conduit.compiled-context.v1", boardBody);
  const itemManifest = [{ type: "board_message", recordId: messageId, revision: 1, precedence: 100, contentDigest: compiledContentDigest, bytes: new TextEncoder().encode(boardBody).byteLength, disposition: "included" }];
  const snapshot = { id: snapshotId, runId, operationId, mode: "initial", projectRevision: session.project_revision, sessionRevision: session.revision, messageId, messageRevision: 1, compilerVersion: "control-plane-board/v1", itemManifest, compiledContentDigest };
  const snapshotDigest = await digest("conduit.context-snapshot.v1", snapshot);
  const sourceRevisionJson = canonicalJson(schedule.sourceRevisions);
  // Keep this statement's bound parameter count constant (19), independent
  // of the number of Source bindings. SQLite's JSON table expansion supplies
  // the per-Source revision/device predicates inside the same atomic insert.
  const authorityValues: Array<string | number> = [
    assignmentId, session.project_id, sessionId, messageId, mention.title, mention.body, createdAt,
    session.project_id, session.project_revision,
    sessionId, session.project_id, session.revision,
    mention.targetId, session.project_id, agent.revision,
    schedule.deviceId, device.revision,
    sourceRevisionJson, schedule.sourceRevisions.length,
  ];
  const exactAuthorities = `
    EXISTS (SELECT 1 FROM projects WHERE id=?8 AND revision=?9 AND status='active')
    AND EXISTS (SELECT 1 FROM collaboration_sessions WHERE id=?10 AND project_id=?11 AND revision=?12 AND status='active')
    AND EXISTS (SELECT 1 FROM project_agents WHERE id=?13 AND project_id=?14 AND revision=?15 AND status='active')
    AND EXISTS (SELECT 1 FROM devices WHERE id=?16 AND revision=?17 AND status='active')
    AND (SELECT COUNT(*) FROM requested_sources)=?19
    AND (SELECT COUNT(*) FROM valid_sources)=?19
  `;
  const exactAuthorityCte = `
    WITH requested_sources AS (
      SELECT json_extract(value,'$.sourceId') AS source_id,
             CAST(json_extract(value,'$.sourceRevision') AS INTEGER) AS source_revision,
             json_extract(value,'$.locationId') AS location_id,
             CAST(json_extract(value,'$.locationRevision') AS INTEGER) AS location_revision
      FROM json_each(?18)
    ), valid_sources AS (
      SELECT requested.source_id
      FROM requested_sources AS requested
      JOIN sources AS source ON source.id=requested.source_id AND source.revision=requested.source_revision AND source.project_id=?8
      JOIN locations AS location ON location.id=requested.location_id
        AND location.source_id=source.id AND location.device_id=?16
        AND location.revision=requested.location_revision AND location.status='active'
    )
  `;

  const operationInput: StartOperationInput = {
    idempotencyKey,
    deviceId: schedule.deviceId,
    capability: "agent.run.start",
    projectId: session.project_id,
    sessionId,
    assignmentId,
    runId,
    runtime,
    accessScope: schedule.accessScope,
    approvalMode: schedule.approvalMode,
    sourceRevisions,
    arguments: {
      projectAgentId: mention.targetId, projectAgentRevision: agent.revision, adapterId: agent.adapter_id, role: agent.role,
      model: schedule.model, effort: schedule.effort, prompt: boardBody,
      contextSnapshotId: snapshotId, contextSnapshotDigest: snapshotDigest, contextCompilerVersion: "control-plane-board/v1",
      contextSnapshotContentDigest: compiledContentDigest, contextSnapshotBytes: new TextEncoder().encode(boardBody).byteLength,
      parentBaselineId: session.accepted_baseline_id, sourceBaselineRevisions,
      expectedNodeRevision: 0, verificationPolicy: schedule.verificationPolicy, settlementPolicy: "close_on_settle",
      ...(credentialProjections.length === 0 ? {} : { credentialProjections }),
    },
    ...(schedule.expiresInSeconds === undefined ? {} : { expiresInSeconds: schedule.expiresInSeconds }),
  };

  const operation = await createOperation(env, actor, operationInput, authorization, {
    operationId,
    transactionStatements: async ({ request }) => {
      const manifest = {
        schemaVersion: 1, runId, assignmentId, projectId: session.project_id, sessionId,
        operationId, operationRequestDigest: request.payloadDigest, actorPrincipalId: actor.principalId,
        clientId: actor.clientId, projectAgentId: mention.targetId, projectAgentRevision: agent.revision,
        projectRevision: session.project_revision, deviceId: schedule.deviceId, runtime: schedule.runtime,
        adapter: { id: agent.adapter_id, role: agent.role, model: schedule.model, effort: schedule.effort },
        authority: { accessScope: schedule.accessScope, approvalMode: schedule.approvalMode, connectorPolicyId: request.connectorPolicyId, connectorPolicyRevision: request.connectorPolicyRevision },
        sourceRevisions: schedule.sourceRevisions, parentBaselineId: session.accepted_baseline_id, sourceBaselineRevisions,
        settlementPolicy: "close_on_settle", assignmentBindingDigest: bindingDigest,
        initialContextSnapshotId: snapshotId, initialContextSnapshotDigest: snapshotDigest,
      };
      const manifestJson = canonicalJson(manifest);
      const manifestDigest = await digest("conduit.run-manifest.v1", manifest);
      return { runManifestDigest: manifestDigest, statements: [
        env.DB.prepare("INSERT INTO messages(id,session_id,author_principal_id,origin,body,revision,attachments_json,created_at) VALUES (?1,?2,?3,?4,?5,1,'[]',?6)").bind(messageId, sessionId, actor.principalId, actor.clientId, boardBody, createdAt),
        env.DB.prepare("INSERT INTO message_revisions(message_id,revision,body,editor_principal_id,created_at) VALUES (?1,1,?2,?3,?4)").bind(messageId, boardBody, actor.principalId, createdAt),
        env.DB.prepare("INSERT INTO structured_mentions(id,message_id,mention_type,target_id,start_offset,end_offset,payload_json) VALUES (?1,?2,'project_agent',?3,?4,?5,?6)").bind(mentionId, messageId, mention.targetId, mention.startOffset, mention.endOffset, canonicalJson(mention.payload)),
        env.DB.prepare(`${exactAuthorityCte} INSERT INTO assignments(id,project_id,session_id,source_message_id,title,body,state,revision,created_at,updated_at) SELECT ?1,?2,?3,?4,?5,?6,'queued',1,?7,?7 WHERE ${exactAuthorities}`).bind(...authorityValues),
        env.DB.prepare("INSERT INTO assignment_run_bindings(assignment_id,project_agent_id,project_agent_revision,project_revision,session_revision,message_revision,device_id,device_revision,runtime_kind,runtime_provider_id,runtime_configuration_revision,adapter_id,role,model,effort,access_scope,approval_mode,source_revisions_json,agent_configuration_json,verification_policy_json,request_digest,binding_digest,created_at) VALUES (?1,?2,?3,?4,?5,1,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)").bind(assignmentId, mention.targetId, agent.revision, session.project_revision, session.revision, schedule.deviceId, device.revision, schedule.runtime.kind, schedule.runtime.providerId, schedule.runtime.configurationRevision, agent.adapter_id, agent.role, schedule.model, schedule.effort, schedule.accessScope, schedule.approvalMode, canonicalJson(schedule.sourceRevisions), canonicalJson(agentConfiguration), canonicalJson(schedule.verificationPolicy), requestDigest, bindingDigest, createdAt),
        env.DB.prepare("INSERT INTO assignment_transitions(id,assignment_id,from_state,to_state,reason_code,evidence_ref,created_at) VALUES (?1,?2,NULL,'queued','board_schedule',?3,?4)").bind(newId("asgt"), assignmentId, bindingDigest, createdAt),
        env.DB.prepare("INSERT INTO runs(id,assignment_id,project_id,session_id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued',1,?9,?10,?11,?11)").bind(runId, assignmentId, session.project_id, sessionId, schedule.deviceId, schedule.runtime.kind, schedule.accessScope, schedule.approvalMode, manifestDigest, manifestJson, createdAt),
        env.DB.prepare("INSERT INTO run_transitions(id,run_id,from_state,to_state,receipt_kind,receipt_digest,created_at) VALUES (?1,?2,NULL,'queued','control_plane_schedule',?3,?4)").bind(newId("runt"), runId, request.payloadDigest, createdAt),
        env.DB.prepare("INSERT INTO context_snapshots(id,run_id,operation_id,mode,project_revision,session_revision,message_id,message_revision,compiler_version,item_manifest_json,compiled_content_digest,snapshot_digest,created_at) VALUES (?1,?2,?3,'initial',?4,?5,?6,1,'control-plane-board/v1',?7,?8,?9,?10)").bind(snapshotId, runId, operationId, session.project_revision, session.revision, messageId, canonicalJson(itemManifest), compiledContentDigest, snapshotDigest, createdAt),
      ] };
    },
  });
  const persistedOperationId = String(operation.operationId ?? operationId);
  return { id: messageId, session_id: sessionId, body: boardBody, revision: 1, assignmentIds: [assignmentId], runIds: [runId], contextSnapshotIds: [snapshotId], operationIds: [persistedOperationId], created_at: createdAt };
}
