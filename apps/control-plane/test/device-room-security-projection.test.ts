import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { base64url, canonicalJson, sha256Hex } from "../src/crypto.ts";

describe.sequential("DeviceRoom terminal and exact-control security projections", () => {
  it("rejects non-completed or invalid submissions, keeps missing submissions out of review, and terminalizes correlated control errors", async () => {
    const deviceId = "dev_terminal_security01";
    const keyId = "dkey_terminal_security01";
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 300_000).toISOString();
    const scenarios = [
      { suffix: "failed_submission", terminal: "failed", submission: {} },
      { suffix: "cancelled_submission", terminal: "cancelled", submission: {} },
      { suffix: "completed_missing", terminal: "completed", submission: undefined },
      { suffix: "completed_invalid", terminal: "completed", submission: {} },
    ] as const;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_terminal_security','Terminal Security','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_terminal_security','completed',?1,?2,'{}',?3,?4,?5,'challenge','signature',?6,?7,?8,?7)").bind("1".repeat(64), "2".repeat(64), keyId, JSON.stringify(publicJwk), "3".repeat(64), deviceId, now, expires),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,'enroll_terminal_security','Linux','linux','x86_64','0.1.0','conduit.node/1','active',?2,?2)").bind(deviceId, now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(keyId, deviceId, JSON.stringify(publicJwk), "3".repeat(64), now),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_terminal_security','Terminal Security',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_terminal_security','prj_terminal_security','Terminal Security',?1,?1)").bind(now),
    ]);
    for (const scenario of scenarios) {
      const assignmentId = `asg_${scenario.suffix}`;
      const runId = `run_${scenario.suffix}`;
      const operationId = `op_${scenario.suffix}`;
      const digest = await sha256Hex(operationId);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,title,body,state,revision,created_at,updated_at) VALUES (?1,'prj_terminal_security','csess_terminal_security',?2,?2,'active',2,?3,?3)").bind(assignmentId, scenario.suffix, now),
        env.DB.prepare("INSERT INTO runs(id,assignment_id,project_id,session_id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES (?1,?2,'prj_terminal_security','csess_terminal_security',?3,'native','project_full','always','finishing',2,?4,'{}',?5,?5)").bind(runId, assignmentId, deviceId, "4".repeat(64), now),
        env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,node_state_revision) VALUES (?1,?2,'prin_terminal_security','conduit.test',?3,'prj_terminal_security','csess_terminal_security',?4,?5,'agent.run.start',?6,'{}','claimed',?7,?8,?8,2)").bind(operationId, `terminal-${scenario.suffix}-key`, deviceId, assignmentId, runId, digest, expires, now),
        env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,expires_at,created_at) VALUES ('terminal-security',?1,?2,?3,'claimed',?4,?5)").bind(`terminal-${scenario.suffix}-key`, digest, operationId, expires, now),
      ]);
    }

    const controlOperationId = "op_transport_error_control";
    const controlDigest = await sha256Hex(controlOperationId);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,project_id,session_id,assignment_id,run_id,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,target_operation_id,target_digest,target_controller_epoch,expected_target_state,expected_target_revision) VALUES (?1,'transport-error-control-key','prin_terminal_security','conduit.test',?2,'prj_terminal_security','csess_terminal_security','asg_completed_invalid','run_completed_invalid','run.control',?3,'{}','offered',?4,?5,?5,'agent_control','op_completed_invalid',?6,'1','waiting_input',2)").bind(controlOperationId, deviceId, controlDigest, expires, now, "5".repeat(64)),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,expires_at,created_at) VALUES ('terminal-security','transport-error-control-key',?1,?2,'offered',?3,?4)").bind(controlDigest, controlOperationId, expires, now),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at,frame_type) VALUES (?1,?2,'cmsg_transport_error_control',?1,?3,'{}','offered',?4,?5,?4,?4,'operation.input')").bind(controlOperationId, deviceId, "6".repeat(64), now, expires),
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
    socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "7".repeat(64), clientNonce: nonce, nodeBootId: "node-boot-terminal-security01" }));
    const challenge = parseWireDocumentText(schemaIds.nodeV1, await challengePending);
    if (challenge.type !== "device.challenge") throw new Error("expected device.challenge");
    const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce: nonce, connectionId: challenge.connectionId, deviceId, keyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime });
    const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(transcript))));
    const acceptedPending = next();
    socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId, signature }));
    const accepted = parseWireDocumentText(schemaIds.nodeV1, await acceptedPending);
    if (accepted.type !== "transport.accepted") throw new Error("expected transport.accepted");
    let sequence = 0;
    const send = async (type: string, payload: Record<string, unknown>, correlationId?: string) => {
      sequence += 1;
      socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_terminal_security_${sequence}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
    };
    await send("reconcile.summary", { nodeBootId: "node-boot-terminal-security01", journalGeneration: "1", capabilityDigest: "7".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, accepted.connectionId);
    const reconcileMessages = [parseWireDocumentText(schemaIds.nodeV1, await next()), parseWireDocumentText(schemaIds.nodeV1, await next())];
    const plan = reconcileMessages.find((frame) => frame.type === "reconcile.plan");
    if (plan?.type !== "reconcile.plan") throw new Error("expected reconcile.plan");
    await send("reconcile.complete", { reconciliationId: plan.payload.reconciliationId, lastControlSequenceApplied: "2", lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, plan.payload.reconciliationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    await send("transport.ack", { direction: "control_to_node", throughSequence: "3" });

    for (const scenario of scenarios) {
      const operationId = `op_${scenario.suffix}`;
      const runId = `run_${scenario.suffix}`;
      const payload = {
        operationId,
        runId,
        state: scenario.terminal,
        requestDigest: await sha256Hex(operationId),
        receiptDigest: await sha256Hex(`receipt-${scenario.suffix}`),
        lastRunEventSequence: "0",
        ...(scenario.submission === undefined ? {} : { resultSummary: { submission: scenario.submission } }),
        observedAt: new Date().toISOString(),
      };
      await send("operation.terminal", payload, operationId);
      expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    }
    await send("transport.error", { code: "capability_unavailable", retryable: false, details: { messageType: "operation.input", reason: "target session unavailable" } }, controlOperationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");

    await expect.poll(async () => env.DB.prepare("SELECT state FROM operation_journal WHERE id=?1").bind(controlOperationId).first<{ state: string }>()).toEqual({ state: "failed" });
    const states = await env.DB.prepare("SELECT r.id,r.state AS run_state,a.state AS assignment_state,(SELECT COUNT(*) FROM change_sets c WHERE c.run_id=r.id) AS change_sets FROM runs r JOIN assignments a ON a.id=r.assignment_id WHERE r.id IN ('run_failed_submission','run_cancelled_submission','run_completed_missing','run_completed_invalid') ORDER BY r.id").all<Record<string, unknown>>();
    expect(states.results).toEqual([
      { id: "run_cancelled_submission", run_state: "cancelled", assignment_state: "cancelled", change_sets: 0 },
      { id: "run_completed_invalid", run_state: "failed", assignment_state: "failed", change_sets: 0 },
      { id: "run_completed_missing", run_state: "completed", assignment_state: "failed", change_sets: 0 },
      { id: "run_failed_submission", run_state: "failed", assignment_state: "failed", change_sets: 0 },
    ]);
    const evidence = await env.DB.prepare("SELECT event_type,reason_code FROM security_events WHERE device_id=?1 AND event_type IN ('device_terminal.submission_rejected','device_terminal.submission_missing','device_control.transport_error') ORDER BY event_type,reason_code").bind(deviceId).all<Record<string, unknown>>();
    expect(evidence.results).toEqual([
      { event_type: "device_control.transport_error", reason_code: "capability_unavailable" },
      { event_type: "device_terminal.submission_missing", reason_code: "completed_without_submission" },
      { event_type: "device_terminal.submission_rejected", reason_code: "submission_invalid" },
      { event_type: "device_terminal.submission_rejected", reason_code: "terminal_state_not_completed" },
      { event_type: "device_terminal.submission_rejected", reason_code: "terminal_state_not_completed" },
    ]);
    const idempotency = await env.DB.prepare("SELECT state FROM idempotency_records WHERE operation_id=?1").bind(controlOperationId).first<{ state: string }>();
    expect(idempotency?.state).toBe("failed");
    socket.close(1000, "complete");
  });
});
