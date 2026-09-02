import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { base64url, canonicalJson, keyedHash, sha256Hex } from "../src/crypto.ts";

describe.sequential("Board assignment through the authenticated Device route", () => {
  it("projects Node custody and an immutable Change Set before Review and Baseline acceptance", async () => {
    const token = "conduit_owner_board_device_route_token_01";
    const deviceId = "dev_board_device_route01";
    const keyId = "dkey_board_device_route01";
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 300_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_board_device_route','Owner','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,created_at,expires_at) VALUES ('otk_board_device_route','prin_board_device_route',?1,'test','active',?2,?3)").bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", token), now, expires),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_board_device_route','completed',?1,?2,'{}',?3,?4,?5,'challenge','signature',?6,?7,?8,?7)").bind("1".repeat(64), "2".repeat(64), keyId, JSON.stringify(publicJwk), "3".repeat(64), deviceId, now, expires),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,'enroll_board_device_route','Linux','linux','x86_64','0.1.0','conduit.node/1','active',?2,?2)").bind(deviceId, now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(keyId, deviceId, JSON.stringify(publicJwk), "3".repeat(64), now),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_board_device_route','Board Device',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_board_device_route','prj_board_device_route','Session',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO project_agents(id,project_id,name,adapter_id,role,configuration_json,status,created_at,updated_at) VALUES ('pagent_board_device_builder','prj_board_device_route','Builder','codex','implementer','{}','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO sources(id,project_id,display_name,source_kind,repository_identity,created_at,updated_at) VALUES ('src_board_device_route','prj_board_device_route','Repository','git','repo-device-route',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO locations(id,source_id,device_id,opaque_local_id,display_label,observed_state_json,status,created_at,updated_at) VALUES ('loc_board_device_route','src_board_device_route',?1,'opaque-device-route','Checkout','{}','active',?2,?2)").bind(deviceId, now),
    ]);

    const upgraded = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
    expect(upgraded.status).toBe(101);
    const socket = upgraded.webSocket!;
    socket.accept();
    const queued: string[] = [];
    const waiters: Array<(message: string) => void> = [];
    socket.addEventListener("message", (event) => {
      const waiter = waiters.shift();
      if (waiter === undefined) queued.push(String(event.data)); else waiter(String(event.data));
    });
    const next = () => queued.length > 0 ? Promise.resolve(queued.shift()!) : new Promise<string>((resolve) => waiters.push(resolve));
    const nonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const challengePending = next();
    socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "4".repeat(64), clientNonce: nonce, nodeBootId: "node-boot-board-device-route01" }));
    const challenge = parseWireDocumentText(schemaIds.nodeV1, await challengePending);
    if (challenge.type !== "device.challenge") throw new Error("expected device.challenge");
    const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce: nonce, connectionId: challenge.connectionId, deviceId, keyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime });
    const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(transcript))));
    const acceptedPending = next();
    socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId, signature }));
    const accepted = parseWireDocumentText(schemaIds.nodeV1, await acceptedPending);
    if (accepted.type !== "transport.accepted") throw new Error("expected transport.accepted");
    let nodeSequence = 0;
    const send = async (type: string, payload: Record<string, unknown>, correlationId?: string) => {
      nodeSequence += 1;
      socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_board_device_route_${nodeSequence.toString().padStart(2, "0")}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(nodeSequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
    };
    await send("reconcile.summary", { nodeBootId: "node-boot-board-device-route01", journalGeneration: "1", capabilityDigest: "4".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, accepted.connectionId);
    const reconcileMessages = [parseWireDocumentText(schemaIds.nodeV1, await next()), parseWireDocumentText(schemaIds.nodeV1, await next())];
    const plan = reconcileMessages.find((frame) => frame.type === "reconcile.plan");
    if (plan?.type !== "reconcile.plan") throw new Error("expected reconcile.plan");
    await send("reconcile.complete", { reconciliationId: plan.payload.reconciliationId, lastControlSequenceApplied: "2", lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, plan.payload.reconciliationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    await send("transport.ack", { direction: "control_to_node", throughSequence: "3" });

    const auth = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    const scheduledResponse = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", {
      method: "POST",
      headers: { ...auth, "idempotency-key": "board-device-route-schedule-0001" },
      body: JSON.stringify({
        sessionId: "csess_board_device_route",
        body: "@builder commit the verified change",
        mentions: [{ type: "project_agent", targetId: "pagent_board_device_builder", startOffset: 0, endOffset: 8, assignment: {
          title: "Commit verified change", body: "Commit the verified change",
          schedule: {
            deviceId, runtime: { kind: "restricted_native", providerId: "restricted-native.linux", configurationRevision: 1, networkMode: "restricted" },
            model: "gpt-5.6-codex", effort: "high", accessScope: "project_full", approvalMode: "always",
            sourceRevisions: [{ sourceId: "src_board_device_route", sourceRevision: 1, locationId: "loc_board_device_route", locationRevision: 1, mode: "worktree", baseCommit: "1".repeat(40) }],
            verificationPolicy: { requiredChecks: ["workspace_clean"] },
          },
        } }],
      }),
    }));
    expect(scheduledResponse.status, await scheduledResponse.clone().text()).toBe(202);
    const scheduled = await scheduledResponse.json<{ assignmentIds: string[]; runIds: string[]; operationIds: string[] }>();
    const assignmentId = scheduled.assignmentIds[0]!;
    const runId = scheduled.runIds[0]!;
    const operationId = scheduled.operationIds[0]!;
    const offer = parseWireDocumentText(schemaIds.nodeV1, await next());
    expect(offer).toMatchObject({ type: "operation.offer", correlationId: operationId, payload: { operation: { operationId, assignmentId, runId, arguments: { prompt: "@builder commit the verified change", contextSnapshotId: expect.stringMatching(/^ctx_/), contextSnapshotDigest: expect.stringMatching(/^[a-f0-9]{64}$/) } } } });
    if (offer.type !== "operation.offer") throw new Error("expected operation.offer");
    const requestDigest = offer.payload.operation.payloadDigest;
    const idempotencyKey = offer.payload.operation.idempotencyKey;
    await send("operation.admission", { operationId, idempotencyKey, requestDigest, decision: "admitted", journalState: "admitted", selectedRuntimeProvider: "restricted-native.linux", effectiveAccessScope: "project_full", effectiveApprovalMode: "always", localPolicyRevision: 1, receiptDigest: "5".repeat(64) }, operationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    const runtimeId = "rt_board_device_route01";
    const agentDigest = "6".repeat(64);
    const runtimeDigest = "7".repeat(64);
    const handleDigest = "8".repeat(64);
    await send("operation.status", { operationId, runId, requestDigest, state: "running", controllerEpoch: "1", revision: "1", phase: "adapter_started", targetRuntimeId: runtimeId, targetDigest: agentDigest, runtimeTargetDigest: runtimeDigest, selectedRuntimeProvider: "restricted-native.linux", runtimeHandleDigest: handleDigest, observedAt: new Date().toISOString() }, operationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    await send("operation.status", { operationId, runId, requestDigest, state: "finishing", controllerEpoch: "1", revision: "2", phase: "workspace_capture", targetRuntimeId: runtimeId, targetDigest: agentDigest, runtimeTargetDigest: runtimeDigest, selectedRuntimeProvider: "restricted-native.linux", runtimeHandleDigest: handleDigest, observedAt: new Date().toISOString() }, operationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    const sourceDigest = "9".repeat(64);
    const terminalReceiptDigest = "a".repeat(64);
    await send("operation.terminal", {
      operationId, runId, state: "completed", requestDigest, receiptDigest: "b".repeat(64), lastRunEventSequence: "0", observedAt: new Date().toISOString(),
      resultSummary: { submission: {
        expectedNodeRevision: 2, terminalReceiptDigest, parentBaselineId: null,
        sourceChanges: [{ sourceId: "src_board_device_route", sourceDigest, baseRevision: { kind: "git", commit: "1".repeat(40) }, resultRevision: { kind: "git", commit: "2".repeat(40), treeDigest: "c".repeat(64) }, state: "clean", custody: "healthy" }],
        unchangedSources: [], applicationOrder: ["src_board_device_route"], artifactCommitments: [],
        provenance: { adapterId: "codex", evidenceLevel: "observed" }, custody: { deviceRef: true, localArchive: false },
        verification: [{ checkId: "workspace_clean", status: "passed", evidenceRefs: [], observedDigest: "d".repeat(64) }],
      } },
    }, operationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");

    await expect.poll(async () => env.DB.prepare("SELECT s.state FROM change_sets c JOIN change_set_state s ON s.change_set_id=c.id WHERE c.run_id=?1").bind(runId).first<{ state: string }>()).toMatchObject({ state: "proposed" });
    const changeSet = await env.DB.prepare("SELECT c.id,c.change_set_digest,s.state FROM change_sets c JOIN change_set_state s ON s.change_set_id=c.id WHERE c.run_id=?1").bind(runId).first<{ id: string; change_set_digest: string; state: string }>();
    expect(changeSet).toMatchObject({ state: "proposed" });
    const projected = await env.DB.prepare("SELECT r.state AS run_state,a.state AS assignment_state,o.state AS operation_state FROM runs r JOIN assignments a ON a.id=r.assignment_id JOIN operation_journal o ON o.run_id=r.id WHERE r.id=?1").bind(runId).first<Record<string, unknown>>();
    expect(projected).toMatchObject({ run_state: "ready_for_review", assignment_state: "ready_for_review", operation_state: "completed" });

    const verificationStateDigest = await sha256Hex(`conduit.verification-state.v1\n${canonicalJson([{ checkId: "workspace_clean", status: "passed", evidenceRefs: [], observedDigest: "d".repeat(64) }])}`);
    const review = await exports.default.fetch(new Request(`https://conduit.example.com/api/v1/change_sets/${changeSet!.id}/reviews`, { method: "POST", headers: { ...auth, "idempotency-key": "board-device-route-review-0001", "if-match": '"1"' }, body: JSON.stringify({ changeSetDigest: changeSet!.change_set_digest, sourceChangeDigests: [sourceDigest], verificationStateDigest, findings: [], evidenceRefs: [], verdict: "approved" }) }));
    expect(review.status, await review.clone().text()).toBe(201);
    const baselineAcceptance = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/sessions/csess_board_device_route/acceptances", { method: "POST", headers: { ...auth, "idempotency-key": "board-device-route-accept-0001", "if-match": '"1"' }, body: JSON.stringify({ changeSetDigest: changeSet!.change_set_digest, expectedBaselineId: null, preparedReceiptDigest: "f".repeat(64) }) }));
    expect(baselineAcceptance.status, await baselineAcceptance.clone().text()).toBe(201);
    const baseline = await baselineAcceptance.json<{ baselineId: string }>();
    const session = await env.DB.prepare("SELECT accepted_baseline_id FROM collaboration_sessions WHERE id='csess_board_device_route'").first<{ accepted_baseline_id: string }>();
    expect(session?.accepted_baseline_id).toBe(baseline.baselineId);
    socket.close(1000, "complete");
  });
});
