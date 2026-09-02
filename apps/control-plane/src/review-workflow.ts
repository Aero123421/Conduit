import { z } from "zod";
import { canonicalJson, newId, nowIso, operationDigest, sha256Hex } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { completeEffect, reserveEffect } from "./idempotency.ts";
import type { AuthActor, ControlPlaneEnv } from "./types.ts";

const digest64 = z.string().regex(/^[a-f0-9]{64}$/);
const id = z.string().min(9).max(128);
const verificationSchema = z.strictObject({
  checkId: z.string().min(1).max(128),
  status: z.enum(["passed", "failed", "skipped", "unavailable"]),
  evidenceRefs: z.array(id).max(128),
  observedDigest: digest64,
});
const sourceChangeSchema = z.strictObject({
  sourceId: id,
  sourceDigest: digest64,
  baseRevision: z.record(z.string(), z.unknown()),
  resultRevision: z.record(z.string(), z.unknown()),
  state: z.enum(["clean", "draft", "conflicted"]),
  custody: z.enum(["healthy", "degraded", "missing"]),
});
const unchangedSourceSchema = z.strictObject({ sourceId: id, revision: z.record(z.string(), z.unknown()) });
const terminalSubmissionSchema = z.strictObject({
  expectedRunRevision: z.number().int().min(1),
  terminalReceiptDigest: digest64,
  parentBaselineId: id.nullable(),
  supersedesChangeSetId: id.optional(),
  sourceChanges: z.array(sourceChangeSchema).max(128),
  unchangedSources: z.array(unchangedSourceSchema).max(128),
  applicationOrder: z.array(id).max(128),
  artifactCommitments: z.array(z.record(z.string(), z.unknown())).max(256),
  provenance: z.record(z.string(), z.unknown()),
  custody: z.record(z.string(), z.unknown()),
  verification: z.array(verificationSchema).max(128),
});
const reviewSchema = z.strictObject({
  changeSetDigest: digest64,
  reviewerProjectAgentId: id.optional(),
  sourceChangeDigests: z.array(digest64).max(128),
  verificationStateDigest: digest64,
  findings: z.array(z.record(z.string(), z.unknown())).max(256),
  evidenceRefs: z.array(id).max(256),
  verdict: z.enum(["approved", "changes_requested", "rejected", "unable_to_review"]),
});
const acceptanceSchema = z.strictObject({
  changeSetDigest: digest64,
  expectedBaselineId: id.nullable(),
  preparedReceiptDigest: digest64,
});

interface ChangeSetRow {
  id: string;
  session_id: string;
  assignment_id: string;
  run_id: string;
  parent_baseline_id: string | null;
  source_changes_json: string;
  unchanged_sources_json: string;
  custody_json: string;
  verification_policy_json: string;
  change_set_digest: string;
  state: string;
  state_revision: number;
}

async function domainDigest(domain: string, value: unknown): Promise<string> {
  return sha256Hex(`${domain}\n${canonicalJson(value)}`);
}

function effectScope(actor: AuthActor): string {
  return actor.grantId ?? `${actor.clientId}:${actor.principalId}`;
}

function requiredChecks(policyJson: string): string[] {
  const parsed: unknown = JSON.parse(policyJson);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const checks = (parsed as Record<string, unknown>).requiredChecks;
  if (!Array.isArray(checks)) return [];
  return checks.filter((value): value is string => typeof value === "string");
}

export async function projectTerminalSubmission(
  env: ControlPlaneEnv,
  actor: AuthActor,
  idempotencyKey: string,
  runId: string,
  input: unknown,
): Promise<Record<string, unknown>> {
  const parsed = terminalSubmissionSchema.safeParse(input);
  if (!parsed.success) throw new PublicError("invalid_request", 400, `Terminal submission is invalid: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  const submission = parsed.data;
  const reserved = await reserveEffect(env.DB, effectScope(actor), idempotencyKey, await operationDigest({ runId, submission }));
  if (reserved.replay !== undefined) return { ...reserved.replay, replay: true };
  const run = await env.DB.prepare(`
    SELECT r.assignment_id,r.session_id,r.state,r.revision,r.manifest_digest,r.device_id,
           a.state AS assignment_state,a.revision AS assignment_revision,
           b.verification_policy_json,b.source_revisions_json,s.accepted_baseline_id
    FROM runs r JOIN assignments a ON a.id=r.assignment_id
    JOIN assignment_run_bindings b ON b.assignment_id=a.id
    JOIN collaboration_sessions s ON s.id=r.session_id
    WHERE r.id=?1 LIMIT 1
  `).bind(runId).first<{ assignment_id: string; session_id: string; state: string; revision: number; manifest_digest: string | null; device_id: string; assignment_state: string; assignment_revision: number; verification_policy_json: string; source_revisions_json: string; accepted_baseline_id: string | null }>();
  if (run === null) throw new PublicError("not_found", 404, "Run not found");
  if (run.revision !== submission.expectedRunRevision) throw new PublicError("revision_conflict", 409, "Run revision is stale");
  if (run.state !== "finishing") throw new PublicError("invalid_request", 409, "Only a finishing Run can submit a Change Set");
  if (run.assignment_state !== "active") throw new PublicError("invalid_request", 409, "Run Assignment is not active");
  if (run.manifest_digest === null) throw new PublicError("invalid_request", 409, "Run Manifest was not committed");
  if (submission.parentBaselineId !== run.accepted_baseline_id) throw new PublicError("revision_conflict", 409, "Change Set parent is not the current Session Baseline");
  const snapshot = await env.DB.prepare("SELECT snapshot_digest FROM context_snapshots WHERE run_id=?1 AND mode='initial' LIMIT 1").bind(runId).first<{ snapshot_digest: string }>();
  if (snapshot === null) throw new PublicError("invalid_request", 409, "Initial Context Snapshot is missing");
  const boundSourceIds = new Set((JSON.parse(run.source_revisions_json) as Array<{ sourceId: string }>).map((source) => source.sourceId));
  const changedSourceIds = submission.sourceChanges.map((change) => change.sourceId);
  if (new Set(changedSourceIds).size !== changedSourceIds.length || changedSourceIds.some((sourceId) => !boundSourceIds.has(sourceId))) throw new PublicError("invalid_request", 409, "Change Set contains duplicate or unbound Sources");
  const unchangedSourceIds = submission.unchangedSources.map((source) => source.sourceId);
  const representedSourceIds = new Set([...changedSourceIds, ...unchangedSourceIds]);
  if (new Set(unchangedSourceIds).size !== unchangedSourceIds.length || changedSourceIds.some((sourceId) => unchangedSourceIds.includes(sourceId)) || representedSourceIds.size !== boundSourceIds.size || [...boundSourceIds].some((sourceId) => !representedSourceIds.has(sourceId))) throw new PublicError("invalid_request", 409, "Change Set must represent every bound Source exactly once");
  if (submission.applicationOrder.length !== changedSourceIds.length || new Set(submission.applicationOrder).size !== submission.applicationOrder.length || changedSourceIds.some((sourceId) => !submission.applicationOrder.includes(sourceId))) throw new PublicError("invalid_request", 409, "Change Set application order must contain each changed Source exactly once");
  if (run.accepted_baseline_id !== null) {
    const baseline = await env.DB.prepare("SELECT vector_json FROM baseline_revisions WHERE id=?1 AND session_id=?2 LIMIT 1").bind(run.accepted_baseline_id, run.session_id).first<{ vector_json: string }>();
    if (baseline === null) throw new PublicError("revision_conflict", 409, "Run parent Baseline record is missing");
    const vector = JSON.parse(baseline.vector_json) as Record<string, unknown>;
    if (submission.sourceChanges.some((change) => canonicalJson(change.baseRevision) !== canonicalJson(vector[change.sourceId]))) throw new PublicError("revision_conflict", 409, "Source Change base does not match the parent Baseline vector");
  }
  const seenChecks = new Map(submission.verification.map((check) => [check.checkId, check.status]));
  const required = requiredChecks(run.verification_policy_json);
  const requiredPassed = required.every((check) => seenChecks.get(check) === "passed");
  const sourceEligible = submission.sourceChanges.every((change) => change.state === "clean" && change.custody === "healthy");
  const proposed = requiredPassed && sourceEligible;
  const changeSetId = newId("cset");
  const immutable = {
    id: changeSetId, sessionId: run.session_id, assignmentId: run.assignment_id, runId,
    parentBaselineId: submission.parentBaselineId, supersedesChangeSetId: submission.supersedesChangeSetId ?? null,
    sourceChanges: submission.sourceChanges, unchangedSources: submission.unchangedSources,
    applicationOrder: submission.applicationOrder, artifactCommitments: submission.artifactCommitments,
    provenance: { ...submission.provenance, manifestDigest: run.manifest_digest, contextSnapshotDigest: snapshot.snapshot_digest, terminalReceiptDigest: submission.terminalReceiptDigest, deviceId: run.device_id },
    custody: submission.custody, verificationPolicy: JSON.parse(run.verification_policy_json) as unknown,
  };
  const changeSetDigest = await domainDigest("conduit.change-set.v1", immutable);
  const now = nowIso();
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("INSERT INTO change_sets(id,session_id,assignment_id,run_id,parent_baseline_id,supersedes_change_set_id,source_changes_json,unchanged_sources_json,application_order_json,artifact_commitments_json,provenance_json,custody_json,verification_policy_json,change_set_digest,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)").bind(changeSetId, run.session_id, run.assignment_id, runId, submission.parentBaselineId, submission.supersedesChangeSetId ?? null, canonicalJson(submission.sourceChanges), canonicalJson(submission.unchangedSources), canonicalJson(submission.applicationOrder), canonicalJson(submission.artifactCommitments), canonicalJson(immutable.provenance), canonicalJson(submission.custody), run.verification_policy_json, changeSetDigest, now),
    env.DB.prepare("INSERT INTO change_set_state(change_set_id,state,revision,updated_at) VALUES (?1,?2,1,?3)").bind(changeSetId, proposed ? "proposed" : "draft", now),
  ];
  for (const verification of submission.verification) {
    statements.push(env.DB.prepare("INSERT INTO verification_records(id,change_set_id,check_id,status,evidence_refs_json,observed_digest,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)").bind(newId("verify"), changeSetId, verification.checkId, verification.status, canonicalJson(verification.evidenceRefs), verification.observedDigest, now));
  }
  if (proposed) {
    statements.push(
      env.DB.prepare("UPDATE runs SET state='ready_for_review',revision=revision+1,updated_at=?1 WHERE id=?2 AND revision=?3 AND state='finishing'").bind(now, runId, run.revision),
      env.DB.prepare("INSERT INTO run_transitions(id,run_id,from_state,to_state,receipt_kind,receipt_digest,created_at) SELECT ?1,?2,'finishing','ready_for_review','terminal_submission',?3,?4 WHERE EXISTS (SELECT 1 FROM runs WHERE id=?2 AND revision=?5 AND state='ready_for_review')").bind(newId("runt"), runId, submission.terminalReceiptDigest, now, run.revision + 1),
      env.DB.prepare("UPDATE assignments SET state='ready_for_review',revision=revision+1,updated_at=?1 WHERE id=?2 AND revision=?3 AND state='active'").bind(now, run.assignment_id, run.assignment_revision),
      env.DB.prepare("INSERT INTO assignment_transitions(id,assignment_id,from_state,to_state,reason_code,evidence_ref,created_at) SELECT ?1,?2,'active','ready_for_review','verified_change_set',?3,?4 WHERE EXISTS (SELECT 1 FROM assignments WHERE id=?2 AND revision=?5 AND state='ready_for_review')").bind(newId("asgt"), run.assignment_id, changeSetDigest, now, run.assignment_revision + 1),
    );
  }
  const results = await env.DB.batch(statements);
  if (results.some((result) => result.meta.changes !== 1)) throw new PublicError("revision_conflict", 409, "Run changed before terminal submission committed");
  const response = { changeSetId, changeSetDigest, state: proposed ? "proposed" : "draft", runId, runState: proposed ? "ready_for_review" : "finishing", assignmentId: run.assignment_id, assignmentState: proposed ? "ready_for_review" : "active" };
  await completeEffect(env.DB, reserved.reservation!, response);
  return response;
}

export interface DeviceTerminalSubmissionInput {
  operationId: string;
  runId: string;
  deviceId: string;
  submission: unknown;
}

/**
 * DeviceRoom calls this only after authenticating and validating the terminal
 * frame. The projection independently rebinds that frame to durable operation
 * custody so a valid Device cannot submit against another Run or operation.
 */
export async function projectDeviceTerminalSubmission(
  env: ControlPlaneEnv,
  input: DeviceTerminalSubmissionInput,
): Promise<Record<string, unknown>> {
  const operation = await env.DB.prepare(`
    SELECT actor_principal_id,client_id,connector_grant_id,run_id,device_id,payload_digest,capability,node_state_revision
    FROM operation_journal WHERE id=?1 LIMIT 1
  `).bind(input.operationId).first<{ actor_principal_id: string; client_id: string; connector_grant_id: string | null; run_id: string | null; device_id: string; payload_digest: string; capability: string; node_state_revision: number }>();
  if (operation === null) throw new PublicError("not_found", 404, "Terminal operation custody not found");
  if (operation.run_id !== input.runId || operation.device_id !== input.deviceId || operation.capability !== "agent.run.start") throw new PublicError("invalid_request", 409, "Terminal submission does not match operation custody");
  if (input.submission === null || typeof input.submission !== "object" || Array.isArray(input.submission)) throw new PublicError("invalid_request", 400, "Terminal submission must be an object");
  const submitted = input.submission as Record<string, unknown>;
  if (!Number.isSafeInteger(submitted.expectedNodeRevision) || submitted.expectedNodeRevision !== operation.node_state_revision) throw new PublicError("revision_conflict", 409, "Terminal submission Node revision is stale");
  const currentRun = await env.DB.prepare("SELECT revision FROM runs WHERE id=?1 AND device_id=?2 LIMIT 1").bind(input.runId, input.deviceId).first<{ revision: number }>();
  if (currentRun === null) throw new PublicError("not_found", 404, "Terminal Run not found");
  const provenance = submitted.provenance;
  if (provenance === null || typeof provenance !== "object" || Array.isArray(provenance)) throw new PublicError("invalid_request", 400, "Terminal submission provenance must be an object");
  const terminalReceiptDigest = typeof submitted.terminalReceiptDigest === "string" ? submitted.terminalReceiptDigest : "";
  const actor: AuthActor = {
    principalId: operation.actor_principal_id,
    clientId: operation.client_id,
    ...(operation.connector_grant_id === null ? {} : { grantId: operation.connector_grant_id }),
    scopes: [],
  };
  const { expectedNodeRevision: _expectedNodeRevision, ...terminalSubmission } = submitted;
  return projectTerminalSubmission(env, actor, `terminal:${input.operationId}:${terminalReceiptDigest}`, input.runId, {
    ...terminalSubmission,
    expectedRunRevision: currentRun.revision,
    provenance: { ...(provenance as Record<string, unknown>), operationId: input.operationId, operationRequestDigest: operation.payload_digest },
  });
}

export async function createReview(
  env: ControlPlaneEnv,
  actor: AuthActor,
  idempotencyKey: string,
  changeSetId: string,
  expectedStateRevision: number,
  input: unknown,
): Promise<Record<string, unknown>> {
  const parsed = reviewSchema.safeParse(input);
  if (!parsed.success) throw new PublicError("invalid_request", 400, `Review is invalid: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  const review = parsed.data;
  const reserved = await reserveEffect(env.DB, effectScope(actor), idempotencyKey, await operationDigest({ changeSetId, expectedStateRevision, review }));
  if (reserved.replay !== undefined) return { ...reserved.replay, replay: true };
  const changeSet = await loadChangeSet(env.DB, changeSetId);
  if (changeSet.change_set_digest !== review.changeSetDigest) throw new PublicError("revision_conflict", 409, "Review digest does not match the immutable Change Set");
  if (changeSet.state_revision !== expectedStateRevision || !["proposed", "under_review"].includes(changeSet.state)) throw new PublicError("revision_conflict", 409, "Change Set review state is stale");
  if (review.reviewerProjectAgentId !== undefined) {
    const reviewer = await env.DB.prepare("SELECT project_id,role,status FROM project_agents WHERE id=?1 LIMIT 1").bind(review.reviewerProjectAgentId).first<{ project_id: string; role: string; status: string }>();
    const session = await env.DB.prepare("SELECT project_id FROM collaboration_sessions WHERE id=?1").bind(changeSet.session_id).first<{ project_id: string }>();
    if (reviewer === null || reviewer.status !== "active" || reviewer.role !== "reviewer" || reviewer.project_id !== session?.project_id) throw new PublicError("invalid_request", 409, "Reviewer Project Agent is not active for this Project");
  }
  const reviewId = newId("review");
  const nextState = review.verdict === "approved" ? "approved" : review.verdict === "changes_requested" ? "changes_requested" : "rejected";
  const now = nowIso();
  const [inserted, updated] = await env.DB.batch([
    env.DB.prepare("INSERT INTO reviews(id,change_set_id,change_set_digest,reviewer_principal_id,reviewer_project_agent_id,source_change_digests_json,verification_state_digest,findings_json,evidence_refs_json,verdict,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)").bind(reviewId, changeSetId, review.changeSetDigest, actor.principalId, review.reviewerProjectAgentId ?? null, canonicalJson(review.sourceChangeDigests), review.verificationStateDigest, canonicalJson(review.findings), canonicalJson(review.evidenceRefs), review.verdict, now),
    env.DB.prepare("UPDATE change_set_state SET state=?1,revision=revision+1,updated_at=?2 WHERE change_set_id=?3 AND revision=?4 AND state IN ('proposed','under_review')").bind(nextState, now, changeSetId, expectedStateRevision),
  ]);
  if (inserted?.meta.changes !== 1 || updated?.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Change Set changed before Review commit");
  const response = { reviewId, changeSetId, changeSetDigest: review.changeSetDigest, verdict: review.verdict, state: nextState, revision: expectedStateRevision + 1 };
  await completeEffect(env.DB, reserved.reservation!, response);
  return response;
}

async function loadChangeSet(db: D1Database, changeSetId: string): Promise<ChangeSetRow> {
  const row = await db.prepare("SELECT c.*,s.state,s.revision AS state_revision FROM change_sets c JOIN change_set_state s ON s.change_set_id=c.id WHERE c.id=?1 LIMIT 1").bind(changeSetId).first<ChangeSetRow>();
  if (row === null) throw new PublicError("not_found", 404, "Change Set not found");
  return row;
}

export async function acceptChangeSet(
  env: ControlPlaneEnv,
  actor: AuthActor,
  idempotencyKey: string,
  sessionId: string,
  expectedSessionRevision: number,
  input: unknown,
): Promise<Record<string, unknown>> {
  const parsed = acceptanceSchema.safeParse(input);
  if (!parsed.success) throw new PublicError("invalid_request", 400, `Acceptance is invalid: ${parsed.error.issues[0]?.message ?? "schema mismatch"}`);
  const acceptance = parsed.data;
  const reserved = await reserveEffect(env.DB, effectScope(actor), idempotencyKey, await operationDigest({ sessionId, expectedSessionRevision, acceptance }));
  if (reserved.replay !== undefined) return { ...reserved.replay, replay: true };
  const changeSet = await env.DB.prepare("SELECT c.*,st.state,st.revision AS state_revision,a.revision AS assignment_revision,a.state AS assignment_state FROM change_sets c JOIN change_set_state st ON st.change_set_id=c.id JOIN assignments a ON a.id=c.assignment_id WHERE c.session_id=?1 AND c.change_set_digest=?2 LIMIT 1").bind(sessionId, acceptance.changeSetDigest).first<ChangeSetRow & { assignment_revision: number; assignment_state: string }>();
  if (changeSet === null) throw new PublicError("not_found", 404, "Change Set not found");
  if (changeSet.state !== "approved") throw new PublicError("invalid_request", 409, "Change Set does not have a current approved Review");
  if (changeSet.parent_baseline_id !== acceptance.expectedBaselineId) throw new PublicError("revision_conflict", 409, "Change Set parent does not match expected Baseline");
  const session = await env.DB.prepare("SELECT revision,accepted_baseline_id FROM collaboration_sessions WHERE id=?1 AND status='active' LIMIT 1").bind(sessionId).first<{ revision: number; accepted_baseline_id: string | null }>();
  if (session === null) throw new PublicError("not_found", 404, "Active Collaboration Session not found");
  if (session.revision !== expectedSessionRevision || session.accepted_baseline_id !== acceptance.expectedBaselineId) throw new PublicError("revision_conflict", 409, "Session Baseline compare-and-swap failed");
  const currentReview = await env.DB.prepare("SELECT id FROM reviews WHERE change_set_id=?1 AND change_set_digest=?2 AND verdict='approved' ORDER BY created_at DESC LIMIT 1").bind(changeSet.id, changeSet.change_set_digest).first<{ id: string }>();
  if (currentReview === null) throw new PublicError("invalid_request", 409, "Current approved Review is missing");
  const failedVerification = await env.DB.prepare("SELECT id FROM verification_records WHERE change_set_id=?1 AND status<>'passed' LIMIT 1").bind(changeSet.id).first<{ id: string }>();
  if (failedVerification !== null) throw new PublicError("invalid_request", 409, "Change Set verification is not fully passing");
  const sourceChanges = JSON.parse(changeSet.source_changes_json) as Array<{ sourceId: string; resultRevision: Record<string, unknown> }>;
  const priorVector = acceptance.expectedBaselineId === null ? {} : JSON.parse((await env.DB.prepare("SELECT vector_json FROM baseline_revisions WHERE id=?1 AND session_id=?2 LIMIT 1").bind(acceptance.expectedBaselineId, sessionId).first<{ vector_json: string }>())?.vector_json ?? "null") as Record<string, unknown> | null;
  if (priorVector === null) throw new PublicError("revision_conflict", 409, "Expected Baseline is not part of this Session");
  const vector: Record<string, unknown> = { ...priorVector };
  for (const change of sourceChanges) vector[change.sourceId] = change.resultRevision;
  for (const unchanged of JSON.parse(changeSet.unchanged_sources_json) as Array<Record<string, unknown>>) if (typeof unchanged.sourceId === "string" && unchanged.revision !== undefined) vector[unchanged.sourceId] = unchanged.revision;
  const vectorDigest = await domainDigest("conduit.baseline-vector.v1", vector);
  const nextBaselineId = newId("base");
  const acceptanceId = newId("bacc");
  const nextBaselineRevision = acceptance.expectedBaselineId === null ? 1 : ((await env.DB.prepare("SELECT revision FROM baseline_revisions WHERE id=?1").bind(acceptance.expectedBaselineId).first<{ revision: number }>())?.revision ?? 0) + 1;
  const now = nowIso();
  const expectedNull = acceptance.expectedBaselineId === null ? 1 : 0;
  const statements = [
    env.DB.prepare("INSERT INTO baseline_revisions(id,session_id,revision,predecessor_id,accepted_change_set_id,vector_json,vector_digest,accepting_principal_id,accepting_client_id,prepared_receipt_digest,materialization_state,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending',?11 WHERE EXISTS (SELECT 1 FROM collaboration_sessions WHERE id=?2 AND revision=?12 AND ((?13=1 AND accepted_baseline_id IS NULL) OR accepted_baseline_id=?4))").bind(nextBaselineId, sessionId, nextBaselineRevision, acceptance.expectedBaselineId, changeSet.id, canonicalJson(vector), vectorDigest, actor.principalId, actor.clientId, acceptance.preparedReceiptDigest, now, expectedSessionRevision, expectedNull),
    env.DB.prepare("UPDATE collaboration_sessions SET accepted_baseline_id=?1,revision=revision+1,updated_at=?2 WHERE id=?3 AND revision=?4 AND ((?5=1 AND accepted_baseline_id IS NULL) OR accepted_baseline_id=?6)").bind(nextBaselineId, now, sessionId, expectedSessionRevision, expectedNull, acceptance.expectedBaselineId),
    env.DB.prepare("INSERT INTO baseline_acceptances(id,session_id,change_set_id,expected_baseline_id,committed_baseline_id,prepared_receipt_digest,accepted_by_principal_id,accepted_by_client_id,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)").bind(acceptanceId, sessionId, changeSet.id, acceptance.expectedBaselineId, nextBaselineId, acceptance.preparedReceiptDigest, actor.principalId, actor.clientId, now),
    env.DB.prepare("UPDATE change_set_state SET state='accepted',revision=revision+1,updated_at=?1 WHERE change_set_id=?2 AND revision=?3 AND state='approved'").bind(now, changeSet.id, changeSet.state_revision),
    env.DB.prepare("UPDATE assignments SET state='accepted',revision=revision+1,updated_at=?1 WHERE id=?2 AND revision=?3 AND state='ready_for_review'").bind(now, changeSet.assignment_id, changeSet.assignment_revision),
    env.DB.prepare("INSERT INTO assignment_transitions(id,assignment_id,from_state,to_state,reason_code,evidence_ref,created_at) VALUES (?1,?2,'ready_for_review','accepted','baseline_acceptance',?3,?4)").bind(newId("asgt"), changeSet.assignment_id, nextBaselineId, now),
    env.DB.prepare("UPDATE change_set_state SET state='stale',revision=revision+1,updated_at=?1 WHERE change_set_id IN (SELECT id FROM change_sets WHERE session_id=?2 AND id<>?3 AND parent_baseline_id IS ?4) AND state IN ('proposed','under_review','approved')").bind(now, sessionId, changeSet.id, acceptance.expectedBaselineId),
  ];
  const results = await env.DB.batch(statements);
  if (results.slice(0, 6).some((result) => result.meta.changes !== 1)) throw new PublicError("revision_conflict", 409, "Session Baseline changed before acceptance commit");
  const response = { acceptanceId, sessionId, changeSetId: changeSet.id, baselineId: nextBaselineId, baselineRevision: nextBaselineRevision, vectorDigest, materializationState: "pending", sessionRevision: expectedSessionRevision + 1 };
  await completeEffect(env.DB, reserved.reservation!, response);
  return response;
}
