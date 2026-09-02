import { env, exports } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { canonicalJson, keyedHash, sha256Hex } from "../src/crypto.ts";
import { projectDeviceTerminalSubmission } from "../src/review-workflow.ts";

describe.sequential("Board assignment to accepted Session Baseline", () => {
  const token = "conduit_owner_board_baseline_token_00000001";
  const authHeaders = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  const sourceDigest = "a".repeat(64);
  let assignmentId = "";
  let runId = "";
  let contextSnapshotId = "";
  let operationId = "";
  let changeSetId = "";
  let changeSetDigest = "";
  let baselineId = "";

  beforeAll(async () => {
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 60_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_board_baseline','Owner','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,created_at,expires_at) VALUES ('otk_board_baseline','prin_board_baseline',?1,'test','active',?2,?3)").bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", token), now, expires),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_board_baseline','completed',?1,?2,'{}','dkey_board_baseline','{}',?3,'challenge','signature','dev_board_baseline',?4,?5,?4)").bind("b".repeat(64), "c".repeat(64), "d".repeat(64), now, expires),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES ('dev_board_baseline','enroll_board_baseline','Linux','linux','x86_64','0.1.0','conduit.node/1','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_board_baseline','Board Baseline',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_board_baseline','prj_board_baseline','Session',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO project_agents(id,project_id,name,adapter_id,role,configuration_json,status,created_at,updated_at) VALUES ('pagent_board_builder','prj_board_baseline','Builder','codex','implementer',?1,'active',?2,?2)").bind(JSON.stringify({ instructionRevision: 3, credentialProjections: [{ profileId: "cred_board_local", revision: 2, targetName: ".codex/auth.json" }] }), now),
      env.DB.prepare("INSERT INTO sources(id,project_id,display_name,source_kind,repository_identity,created_at,updated_at) VALUES ('src_board_baseline','prj_board_baseline','Repository','git','repo-digest',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO locations(id,source_id,device_id,opaque_local_id,display_label,observed_state_json,status,created_at,updated_at) VALUES ('loc_board_baseline','src_board_baseline','dev_board_baseline','opaque-location-01','Checkout','{}','active',?1,?1)").bind(now),
    ]);
  });

  it("atomically binds an @Project Agent Board assignment and durable Run dispatch", async () => {
    const body = {
      sessionId: "csess_board_baseline",
      body: "@builder implement the requested change",
      mentions: [{
        type: "project_agent", targetId: "pagent_board_builder", startOffset: 0, endOffset: 8,
        assignment: {
          title: "Implement change", body: "Implement the requested change",
          schedule: {
            deviceId: "dev_board_baseline",
            runtime: { kind: "native", providerId: "native.linux", configurationRevision: 4, networkMode: "restricted" },
            model: "gpt-5.6-codex", effort: "high", accessScope: "project_full", approvalMode: "always",
            sourceRevisions: [{ sourceId: "src_board_baseline", sourceRevision: 1, locationId: "loc_board_baseline", locationRevision: 1, mode: "worktree", baseCommit: "1".repeat(40) }],
            verificationPolicy: { requiredChecks: ["workspace_clean"] },
          },
        },
      }],
    };
    const headers = { ...authHeaders, "idempotency-key": "board-baseline-schedule-0001" };
    const response = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers, body: JSON.stringify(body) }));
    expect(response.status).toBe(202);
    const scheduled = await response.json() as { assignmentIds: string[]; runIds: string[]; contextSnapshotIds: string[]; operationIds: string[] };
    assignmentId = scheduled.assignmentIds[0]!;
    runId = scheduled.runIds[0]!;
    contextSnapshotId = scheduled.contextSnapshotIds[0]!;
    operationId = scheduled.operationIds[0]!;
    const persisted = await env.DB.prepare(`
      SELECT a.state AS assignment_state,r.state AS run_state,r.manifest_digest,b.project_agent_revision,b.device_revision,
             b.runtime_configuration_revision,b.model,b.effort,b.access_scope,b.approval_mode,
             c.snapshot_digest,o.state AS operation_state,o.request_json,x.state AS outbox_state
      FROM assignments a JOIN assignment_run_bindings b ON b.assignment_id=a.id
      JOIN runs r ON r.assignment_id=a.id JOIN context_snapshots c ON c.run_id=r.id
      JOIN operation_journal o ON o.run_id=r.id JOIN operation_dispatch_outbox x ON x.operation_id=o.id
      WHERE a.id=?1
    `).bind(assignmentId).first<Record<string, unknown>>();
    expect(persisted).toMatchObject({ assignment_state: "queued", run_state: "queued", project_agent_revision: 1, device_revision: 1, runtime_configuration_revision: 4, model: "gpt-5.6-codex", effort: "high", access_scope: "project_full", approval_mode: "always" });
    expect(String(persisted?.manifest_digest)).toHaveLength(64);
    expect(String(persisted?.snapshot_digest)).toHaveLength(64);
    expect(["queued", "offered"]).toContain(persisted?.operation_state);
    expect(["pending", "offered"]).toContain(persisted?.outbox_state);
    expect(JSON.parse(String(persisted?.request_json))).toMatchObject({ arguments: { parentBaselineId: null, sourceBaselineRevisions: {}, expectedNodeRevision: 0, verificationPolicy: { requiredChecks: ["workspace_clean"] }, settlementPolicy: "close_on_settle", credentialProjections: [{ profileId: "cred_board_local", revision: 2, targetName: ".codex/auth.json" }] } });

    const replay = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers, body: JSON.stringify(body) }));
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toMatchObject({ replay: true, assignmentIds: [assignmentId], runIds: [runId], operationIds: [operationId] });
    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM assignments WHERE id=?1) AS assignments,(SELECT COUNT(*) FROM runs WHERE id=?2) AS runs,(SELECT COUNT(*) FROM context_snapshots WHERE id=?3) AS snapshots").bind(assignmentId, runId, contextSnapshotId).first<{ assignments: number; runs: number; snapshots: number }>();
    expect(counts).toEqual({ assignments: 1, runs: 1, snapshots: 1 });
  });

  it("projects observed terminal verification into an immutable proposed Change Set", async () => {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE assignments SET state='active',revision=2,updated_at=?1 WHERE id=?2").bind(now, assignmentId),
      env.DB.prepare("UPDATE runs SET state='finishing',revision=2,updated_at=?1 WHERE id=?2").bind(now, runId),
    ]);
    const projected = await projectDeviceTerminalSubmission(env, {
      operationId, runId, deviceId: "dev_board_baseline", submission: {
        expectedNodeRevision: 0, terminalReceiptDigest: "2".repeat(64), parentBaselineId: null,
        sourceChanges: [{ sourceId: "src_board_baseline", sourceDigest, baseRevision: { kind: "git", commit: "1".repeat(40) }, resultRevision: { kind: "git", commit: "3".repeat(40), treeDigest: "4".repeat(64) }, state: "clean", custody: "healthy" }],
        unchangedSources: [], applicationOrder: ["src_board_baseline"], artifactCommitments: [{ artifactId: "art_test_report01", digest: "5".repeat(64) }],
        provenance: { adapterId: "codex" }, custody: { deviceRef: true, localArchive: true },
        verification: [{ checkId: "workspace_clean", status: "passed", evidenceRefs: ["evid_test_report01"], observedDigest: "6".repeat(64) }],
      },
    }) as { changeSetId: string; changeSetDigest: string; state: string; runState: string; assignmentState: string };
    changeSetId = projected.changeSetId;
    changeSetDigest = projected.changeSetDigest;
    expect(projected).toMatchObject({ state: "proposed", runState: "ready_for_review", assignmentState: "ready_for_review" });
    const verification = await env.DB.prepare("SELECT status,evidence_refs_json FROM verification_records WHERE change_set_id=?1 AND check_id='workspace_clean'").bind(changeSetId).first<{ status: string; evidence_refs_json: string }>();
    expect(verification).toMatchObject({ status: "passed" });
    await expect(env.DB.prepare("UPDATE change_sets SET custody_json='{}' WHERE id=?1").bind(changeSetId).run()).rejects.toThrow(/immutable/);
    await expect(env.DB.prepare("UPDATE context_snapshots SET compiler_version='changed' WHERE id=?1").bind(contextSnapshotId).run()).rejects.toThrow(/immutable/);
  });

  it("binds Review to the exact digest and advances the Baseline with compare-and-swap", async () => {
    const verificationStateDigest = await sha256Hex(`conduit.verification-state.v1\n${canonicalJson([{ checkId: "workspace_clean", status: "passed", evidenceRefs: ["evid_test_report01"], observedDigest: "6".repeat(64) }])}`);
    const wrongSourceEvidence = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/change_sets/${changeSetId}/reviews`, {
      method: "POST", headers: { ...authHeaders, "idempotency-key": "board-baseline-review-wrong-source", "if-match": '"1"' },
      body: JSON.stringify({ changeSetDigest, sourceChangeDigests: ["f".repeat(64)], verificationStateDigest, findings: [], evidenceRefs: [], verdict: "approved" }),
    }));
    expect(wrongSourceEvidence.status).toBe(409);
    const wrongVerificationEvidence = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/change_sets/${changeSetId}/reviews`, {
      method: "POST", headers: { ...authHeaders, "idempotency-key": "board-baseline-review-wrong-verification", "if-match": '"1"' },
      body: JSON.stringify({ changeSetDigest, sourceChangeDigests: [sourceDigest], verificationStateDigest: "7".repeat(64), findings: [], evidenceRefs: [], verdict: "approved" }),
    }));
    expect(wrongVerificationEvidence.status).toBe(409);
    const review = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/change_sets/${changeSetId}/reviews`, {
      method: "POST", headers: { ...authHeaders, "idempotency-key": "board-baseline-review-0001", "if-match": '"1"' },
      body: JSON.stringify({ changeSetDigest, sourceChangeDigests: [sourceDigest], verificationStateDigest, findings: [], evidenceRefs: ["evid_test_report01"], verdict: "approved" }),
    }));
    expect(review.status).toBe(201);
    await expect(review.json()).resolves.toMatchObject({ changeSetId, changeSetDigest, verdict: "approved", state: "approved", revision: 2 });

    const staleDigestReview = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/change_sets/${changeSetId}/reviews`, {
      method: "POST", headers: { ...authHeaders, "idempotency-key": "board-baseline-review-0002", "if-match": '"2"' },
      body: JSON.stringify({ changeSetDigest: "8".repeat(64), sourceChangeDigests: [sourceDigest], verificationStateDigest, findings: [], evidenceRefs: [], verdict: "approved" }),
    }));
    expect(staleDigestReview.status).toBe(409);

    const acceptanceHeaders = { ...authHeaders, "idempotency-key": "board-baseline-accept-0001", "if-match": '"1"' };
    const acceptanceBody = { changeSetDigest, expectedBaselineId: null, preparedReceiptDigest: "9".repeat(64) };
    const accepted = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/sessions/csess_board_baseline/acceptances", { method: "POST", headers: acceptanceHeaders, body: JSON.stringify(acceptanceBody) }));
    expect(accepted.status).toBe(201);
    const baseline = await accepted.json() as { baselineId: string; vectorDigest: string };
    baselineId = baseline.baselineId;
    expect(baseline).toMatchObject({ changeSetId, baselineRevision: 1, materializationState: "pending", sessionRevision: 2 });
    expect(baseline.vectorDigest).toHaveLength(64);
    const committed = await env.DB.prepare("SELECT s.accepted_baseline_id,s.revision,b.accepted_change_set_id,b.vector_json,cs.state,a.state AS assignment_state FROM collaboration_sessions s JOIN baseline_revisions b ON b.id=s.accepted_baseline_id JOIN change_set_state cs ON cs.change_set_id=b.accepted_change_set_id JOIN assignments a ON a.id=?1 WHERE s.id='csess_board_baseline'").bind(assignmentId).first<Record<string, unknown>>();
    expect(committed).toMatchObject({ accepted_baseline_id: baseline.baselineId, revision: 2, accepted_change_set_id: changeSetId, state: "accepted", assignment_state: "accepted" });
    expect(JSON.parse(String(committed?.vector_json))).toMatchObject({ src_board_baseline: { kind: "git", commit: "3".repeat(40) } });

    const replay = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/sessions/csess_board_baseline/acceptances", { method: "POST", headers: acceptanceHeaders, body: JSON.stringify(acceptanceBody) }));
    expect(replay.status).toBe(201);
    await expect(replay.json()).resolves.toMatchObject({ replay: true, baselineId: baseline.baselineId });
    const stale = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/sessions/csess_board_baseline/acceptances", { method: "POST", headers: { ...acceptanceHeaders, "idempotency-key": "board-baseline-accept-0002" }, body: JSON.stringify(acceptanceBody) }));
    expect(stale.status).toBe(409);
  });

  it("maps the Device Node revision to the current D1 Run revision during terminal projection", async () => {
    const board = {
      sessionId: "csess_board_baseline", body: "@builder follow up",
      mentions: [{ type: "project_agent", targetId: "pagent_board_builder", startOffset: 0, endOffset: 8, assignment: {
        title: "Follow up", body: "Follow up",
        schedule: {
          deviceId: "dev_board_baseline", runtime: { kind: "native", providerId: "native.linux", configurationRevision: 4 },
          model: "gpt-5.6-codex", effort: "high", accessScope: "project_full", approvalMode: "always",
          sourceRevisions: [{ sourceId: "src_board_baseline", sourceRevision: 1, locationId: "loc_board_baseline", locationRevision: 1, mode: "worktree", baseCommit: "3".repeat(40) }],
          verificationPolicy: { requiredChecks: ["workspace_clean"] },
        },
      }}],
    };
    const scheduledResponse = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers: { ...authHeaders, "idempotency-key": "board-baseline-schedule-0002" }, body: JSON.stringify(board) }));
    expect(scheduledResponse.status).toBe(202);
    const scheduled = await scheduledResponse.json() as { assignmentIds: string[]; runIds: string[]; operationIds: string[] };
    const nextAssignmentId = scheduled.assignmentIds[0]!;
    const nextRunId = scheduled.runIds[0]!;
    const nextOperationId = scheduled.operationIds[0]!;
    const operation = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1").bind(nextOperationId).first<{ request_json: string }>();
    expect(JSON.parse(operation!.request_json)).toMatchObject({ arguments: { parentBaselineId: baselineId, sourceBaselineRevisions: { src_board_baseline: { commit: "3".repeat(40) } }, expectedNodeRevision: 0 } });
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE assignments SET state='active',revision=2,updated_at=?1 WHERE id=?2").bind(now, nextAssignmentId),
      env.DB.prepare("UPDATE runs SET state='finishing',revision=5,updated_at=?1 WHERE id=?2").bind(now, nextRunId),
      env.DB.prepare("UPDATE operation_journal SET node_state_revision=3 WHERE id=?1").bind(nextOperationId),
    ]);
    const projected = await projectDeviceTerminalSubmission(env, {
      operationId: nextOperationId, runId: nextRunId, deviceId: "dev_board_baseline",
      submission: {
        expectedNodeRevision: 3, terminalReceiptDigest: "b".repeat(64), parentBaselineId: baselineId,
        sourceChanges: [{ sourceId: "src_board_baseline", sourceDigest: "c".repeat(64), baseRevision: { kind: "git", commit: "3".repeat(40), treeDigest: "4".repeat(64) }, resultRevision: { kind: "git", commit: "d".repeat(40) }, state: "clean", custody: "healthy" }],
        unchangedSources: [], applicationOrder: ["src_board_baseline"], artifactCommitments: [],
        provenance: { adapterId: "codex" }, custody: { deviceRef: true, localArchive: true },
        verification: [{ checkId: "workspace_clean", status: "passed", evidenceRefs: ["evid_followup_test"], observedDigest: "e".repeat(64) }],
      },
    });
    expect(projected).toMatchObject({ runId: nextRunId, state: "proposed", runState: "ready_for_review" });
    await expect(projectDeviceTerminalSubmission(env, {
      operationId: nextOperationId, runId: nextRunId, deviceId: "dev_board_baseline",
      submission: { expectedNodeRevision: 2, provenance: {} },
    })).rejects.toMatchObject({ code: "revision_conflict" });
  });

  it("schedules the maximum 128 Source bindings through the bounded set query", async () => {
    const now = new Date().toISOString();
    const projectId = "prj_board_batch128";
    const sessionId = "csess_board_batch128";
    const agentId = "pagent_board_batch128";
    const sourceRevisions = Array.from({ length: 128 }, (_, index) => {
      const suffix = String(index).padStart(4, "0");
      return { sourceId: `src_board_batch_${suffix}`, sourceRevision: 1, locationId: `loc_board_batch_${suffix}`, locationRevision: 1, mode: "worktree" as const, baseCommit: "1".repeat(40) };
    });
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES (?1,'128 Source project',?2,?2)").bind(projectId, now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES (?1,?2,'128 Source session',?3,?3)").bind(sessionId, projectId, now),
      env.DB.prepare("INSERT INTO project_agents(id,project_id,name,adapter_id,role,configuration_json,status,created_at,updated_at) VALUES (?1,?2,'Builder','codex','implementer','{}','active',?3,?3)").bind(agentId, projectId, now),
    ]);
    // Keep fixture setup itself within D1 batch-size limits; the production
    // schedule path remains a single set query regardless of this count.
    for (let offset = 0; offset < sourceRevisions.length; offset += 32) await env.DB.batch(sourceRevisions.slice(offset, offset + 32).flatMap((source) => [
        env.DB.prepare("INSERT INTO sources(id,project_id,display_name,source_kind,repository_identity,created_at,updated_at) VALUES (?1,?2,?1,'git','batch-128',?3,?3)").bind(source.sourceId, projectId, now),
        env.DB.prepare("INSERT INTO locations(id,source_id,device_id,opaque_local_id,display_label,observed_state_json,status,created_at,updated_at) VALUES (?1,?2,'dev_board_baseline',?1,'Batch location','{}','active',?3,?3)").bind(source.locationId, source.sourceId, now),
      ]));
    const response = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", {
      method: "POST",
      headers: { ...authHeaders, "idempotency-key": "board-baseline-schedule-128" },
      body: JSON.stringify({
        sessionId,
        body: "@builder run across all sources",
        mentions: [{
          type: "project_agent", targetId: agentId, startOffset: 0, endOffset: 8,
          assignment: {
            title: "128 Source assignment", body: "Run across all sources",
            schedule: {
              deviceId: "dev_board_baseline",
              runtime: { kind: "native", providerId: "native.linux", configurationRevision: 1 },
              model: "gpt-5.6-codex", effort: "high", accessScope: "project_full", approvalMode: "always",
              sourceRevisions,
              verificationPolicy: { requiredChecks: ["workspace_clean"] },
            },
          },
        }],
      }),
    }));
    expect(response.status).toBe(202);
    const scheduled = await response.json() as { assignmentIds: string[] };
    expect(scheduled.assignmentIds).toHaveLength(1);
    const bindings = await env.DB.prepare("SELECT source_revisions_json FROM assignment_run_bindings WHERE assignment_id=?1").bind(scheduled.assignmentIds[0]).first<{ source_revisions_json: string }>();
    expect(JSON.parse(bindings!.source_revisions_json)).toHaveLength(128);
  });
});
