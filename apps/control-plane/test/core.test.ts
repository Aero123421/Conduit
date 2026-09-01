import { env, exports } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, keyedHash, operationDigest, sha256Hex } from "../src/crypto.ts";
import { readJsonBounded } from "../src/bounds.ts";
import { CLI_CONTROL_PLANE_ROUTE_MANIFEST } from "../src/api.ts";
import { durableObjectOperationDispatcher, reconcileOperationDispatches, type OperationDispatcher } from "../src/dispatch.ts";
import { createOperation } from "../src/operations.ts";
import { attemptApprovalDispatch, buildApprovalReceipt } from "../src/approval-dispatch.ts";
import { ALL_APPROVAL_RISK_CLASSES } from "../src/policy.ts";

function derEcdsaSignature(signature: Uint8Array): Uint8Array {
  if (signature[0] === 0x30) return signature;
  if (signature.length !== 64) throw new Error("unexpected WebCrypto ECDSA signature length");
  const integer = (bytes: Uint8Array): Uint8Array => {
    let offset = 0;
    while (offset < bytes.length - 1 && bytes[offset] === 0) offset += 1;
    const value = bytes.slice(offset);
    return value[0]! >= 0x80 ? Uint8Array.from([0, ...value]) : value;
  };
  const r = integer(signature.slice(0, 32));
  const s = integer(signature.slice(32));
  return Uint8Array.from([0x30, 4 + r.length + s.length, 0x02, r.length, ...r, 0x02, s.length, ...s]);
}

describe.sequential("control-plane contracts", () => {
  beforeAll(async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    if (version === null) throw new Error("D1 migrations were not applied by the Workers test runtime");
  });

  it("applies forward D1 migrations", async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    expect(version?.version).toBe(9);
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>();
    const names = new Set(tables.results.map((row) => row.name));
    for (const required of ["owner_principals", "oauth_grants", "connector_policies", "devices", "projects", "collaboration_sessions", "runs", "operation_journal", "operation_dispatch_outbox", "approval_dispatch_outbox", "artifacts", "normalized_events", "security_events"]) expect(names.has(required)).toBe(true);
  });

  it("keeps security events immutable", async () => {
    await env.DB.prepare("INSERT INTO security_events(id,event_type,metadata_json,created_at) VALUES ('sevt_test_immutable','test.event','{}','2026-09-01T00:00:00.000Z')").run();
    await expect(env.DB.prepare("UPDATE security_events SET event_type='changed' WHERE id='sevt_test_immutable'").run()).rejects.toThrow(/immutable/);
    await expect(env.DB.prepare("DELETE FROM security_events WHERE id='sevt_test_immutable'").run()).rejects.toThrow(/immutable/);
  });

  it("canonicalizes operation commitments deterministically", async () => {
    expect(canonicalJson({ z: 1, a: [true, "x"] })).toBe('{"a":[true,"x"],"z":1}');
    expect(await operationDigest({ b: 2, a: 1 })).toBe(await operationDigest({ a: 1, b: 2 }));
  });

  it("rejects oversized JSON before parsing", async () => {
    const request = new Request("https://conduit.example.com/test", { method: "POST", headers: { "content-length": "70000" }, body: "{}" });
    await expect(readJsonBounded(request)).rejects.toMatchObject({ code: "invalid_request", status: 413 });
  });

  it("publishes OAuth resource and server metadata", async () => {
    const protectedResource = await exports.default.fetch(new Request("https://conduit.example.com/.well-known/oauth-protected-resource"));
    expect(protectedResource.status).toBe(200);
    await expect(protectedResource.json()).resolves.toMatchObject({ resource: "https://conduit.example.com/mcp", authorization_servers: ["https://conduit.example.com"] });
    const server = await exports.default.fetch(new Request("https://conduit.example.com/.well-known/oauth-authorization-server"));
    await expect(server.json()).resolves.toMatchObject({ code_challenge_methods_supported: ["S256"], grant_types_supported: ["authorization_code", "refresh_token"] });
  });

  it("does not accept a browser or anonymous identity at MCP", async () => {
    const response = await exports.default.fetch(new Request("https://conduit.example.com/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) }));
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "authentication_required" } });
  });

  it("routes /api/v1 with the same authorization boundary as /v1", async () => {
    const [canonical, cli] = await Promise.all([
      exports.default.fetch(new Request("https://conduit.example.com/v1/projects")),
      exports.default.fetch(new Request("https://conduit.example.com/api/v1/projects")),
    ]);
    expect(canonical.status).toBe(401);
    expect(cli.status).toBe(401);
    await expect(cli.json()).resolves.toMatchObject({ error: { code: "authentication_required" } });
  });

  it("routes every CLI control-plane method/path into authentication or typed validation", async () => {
    for (const [method, path] of CLI_CONTROL_PLANE_ROUTE_MANIFEST) {
      const headers = new Headers({ accept: "application/json" });
      const init: RequestInit = { method, headers };
      if (method !== "GET") { headers.set("content-type", "application/json"); init.body = "{}"; }
      const response = await exports.default.fetch(new Request(`https://conduit.example.com/api${path}`, init));
      expect([404, 405], `${method} ${path}`).not.toContain(response.status);
    }
  });

  it("commits structured Message mentions and Assignments atomically while ordinary posts stay non-starting", async () => {
    const token = "conduit_owner_board_contract_token_00000001";
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_board_contract','Owner','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,created_at,expires_at) VALUES ('otk_board_contract','prin_board_contract',?1,'test','active',?2,?3)").bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", token), now, new Date(Date.now() + 60_000).toISOString()),
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_board_contract','Board',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_board_contract','prj_board_contract','Session',?1,?1)").bind(now),
    ]);
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": "board-contract-key-000001" };
    const structured = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers, body: JSON.stringify({ sessionId: "csess_board_contract", body: "@builder fix it", mentions: [{ type: "project_agent", targetId: "pagent_builder01", startOffset: 0, endOffset: 8, assignment: { title: "Fix it", body: "fix it" } }] }) }));
    expect(structured.status).toBe(201);
    await expect(structured.json()).resolves.toMatchObject({ assignmentIds: [expect.stringMatching(/^asg_/)] });
    const replay = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers, body: JSON.stringify({ sessionId: "csess_board_contract", body: "@builder fix it", mentions: [{ type: "project_agent", targetId: "pagent_builder01", startOffset: 0, endOffset: 8, assignment: { title: "Fix it", body: "fix it" } }] }) }));
    await expect(replay.json()).resolves.toMatchObject({ replay: true });
    const ordinary = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/board/messages", { method: "POST", headers: { ...headers, "idempotency-key": "board-contract-key-000002" }, body: JSON.stringify({ sessionId: "csess_board_contract", body: "quoted @builder text", mentions: [] }) }));
    expect(ordinary.status).toBe(201);
    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM messages WHERE session_id='csess_board_contract') AS messages,(SELECT COUNT(*) FROM structured_mentions WHERE message_id IN (SELECT id FROM messages WHERE session_id='csess_board_contract')) AS mentions,(SELECT COUNT(*) FROM assignments WHERE session_id='csess_board_contract') AS assignments").first<{ messages: number; mentions: number; assignments: number }>();
    expect(counts).toEqual({ messages: 2, mentions: 1, assignments: 1 });
    const mcp = await exports.default.fetch(new Request("https://conduit.example.com/mcp", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) }));
    expect(mcp.status).toBe(401);
  });

  it("completes the schema-defined Device handshake with a signed node transcript", async () => {
    const deviceId = "dev_handshake01";
    const keyId = "dkey_handshake01";
    const enrollmentId = "enroll_handshake01";
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,?5,?6,'challenge','signature',?7,?8,?9,?8)").bind(enrollmentId, "a".repeat(64), "b".repeat(64), keyId, JSON.stringify(publicJwk), "c".repeat(64), deviceId, now, new Date(Date.now() + 60_000).toISOString()),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'test','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(keyId, deviceId, JSON.stringify(publicJwk), "c".repeat(64), now),
    ]);
    const response = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
    expect(response.status).toBe(101);
    const socket = response.webSocket!;
    socket.accept();
    const queuedMessages: string[] = [];
    const messageWaiters: Array<(message: string) => void> = [];
    socket.addEventListener("message", (event) => { const waiter = messageWaiters.shift(); if (waiter === undefined) queuedMessages.push(String(event.data)); else waiter(String(event.data)); });
    const nextMessage = () => queuedMessages.length > 0 ? Promise.resolve(queuedMessages.shift()!) : new Promise<string>((resolve) => messageWaiters.push(resolve));
    const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    const challengeMessage = nextMessage();
    socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "d".repeat(64), clientNonce, nodeBootId: "node-boot-handshake-0001" }));
    const challenge = parseWireDocumentText(schemaIds.nodeV1, await challengeMessage);
    expect(challenge.type).toBe("device.challenge");
    if (challenge.type !== "device.challenge") throw new Error("expected device.challenge");
    const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce, connectionId: challenge.connectionId, deviceId, keyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime });
    const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(transcript))));
    const acceptedMessage = nextMessage();
    socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId, signature }));
    const accepted = parseWireDocumentText(schemaIds.nodeV1, await acceptedMessage);
    expect(accepted).toMatchObject({ type: "transport.accepted", deviceId, selectedProtocol: "conduit.node/1", controlNextSequence: "1", nodeStoredThroughSequence: "0", reconciliationRequired: true });
    if (accepted.type !== "transport.accepted") throw new Error("expected transport.accepted");
    await evictDurableObject(env.DEVICE_ROOMS.getByName(deviceId));
    const sendNodeFrame = async (sequence: number, type: string, payload: Record<string, unknown>, correlationId?: string) => {
      socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_handshake${sequence.toString().padStart(2, "0")}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
    };
    await sendNodeFrame(1, "reconcile.summary", { nodeBootId: "node-boot-handshake-0001", journalGeneration: "1", capabilityDigest: "d".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, accepted.connectionId);
    const plan = parseWireDocumentText(schemaIds.nodeV1, await nextMessage());
    const summaryAck = parseWireDocumentText(schemaIds.nodeV1, await nextMessage());
    expect(plan).toMatchObject({ type: "reconcile.plan", direction: "control_to_node", sequence: "1", payload: { controlReplay: [], nodeReplay: [], eventReplay: [], statusRunIds: [], cancelOperationIds: [], quarantineRunIds: [] } });
    expect(summaryAck).toMatchObject({ type: "transport.ack", direction: "control_to_node", sequence: "2", payload: { direction: "node_to_control", throughSequence: "1" } });
    if (plan.type !== "reconcile.plan") throw new Error("expected reconcile.plan");
    await sendNodeFrame(2, "reconcile.complete", { reconciliationId: plan.payload.reconciliationId, lastControlSequenceApplied: "2", lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, plan.payload.reconciliationId);
    const completeAck = parseWireDocumentText(schemaIds.nodeV1, await nextMessage());
    expect(completeAck).toMatchObject({ type: "transport.ack", direction: "control_to_node", sequence: "3", payload: { throughSequence: "2" } });
    await sendNodeFrame(3, "transport.ack", { direction: "control_to_node", throughSequence: "3" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const transportState = await runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), (_instance, state) => ({
      outbound: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames").one().count,
      acknowledged: state.storage.sql.exec<{ acknowledged_sequence: number }>("SELECT acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one().acknowledged_sequence,
      reconciliation: state.storage.sql.exec<{ reconciliation_state: string }>("SELECT reconciliation_state FROM connection_state WHERE singleton=1").one().reconciliation_state,
    }));
    expect(transportState).toEqual({ outbound: 0, acknowledged: 3, reconciliation: "complete" });
    socket.close(1000, "test_complete");
  });

  it("replays an unacknowledged control offer with the same identity after reconnect", async () => {
    const deviceId = "dev_control_replay01";
    const keyId = "dkey_control_replay01";
    const enrollmentId = "enroll_control_replay01";
    const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed',?2,?3,'{}',?4,?5,?6,'challenge','signature',?7,?8,?9,?8)").bind(enrollmentId, "1".repeat(64), "2".repeat(64), keyId, JSON.stringify(publicJwk), "3".repeat(64), deviceId, now, new Date(Date.now() + 300_000).toISOString()),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,'replay-test','linux','x86_64','0.1.0','conduit.node/1','active',?3,?3)").bind(deviceId, enrollmentId, now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(keyId, deviceId, JSON.stringify(publicJwk), "3".repeat(64), now),
    ]);

    const connect = async (bootId: string) => {
      const response = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
      expect(response.status).toBe(101);
      expect(response.webSocket).not.toBeNull();
      const socket = response.webSocket!;
      socket.accept();
      const queued: string[] = [];
      const waiters: Array<(message: string) => void> = [];
      socket.addEventListener("message", (event) => { const waiter = waiters.shift(); if (waiter === undefined) queued.push(String(event.data)); else waiter(String(event.data)); });
      const next = () => queued.length > 0 ? Promise.resolve(queued.shift()!) : new Promise<string>((resolve) => waiters.push(resolve));
      const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
      const challengePending = next();
      socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "4".repeat(64), clientNonce, nodeBootId: bootId }));
      const challenge = parseWireDocumentText(schemaIds.nodeV1, await challengePending);
      if (challenge.type !== "device.challenge") throw new Error("expected device.challenge");
      const transcript = canonicalJson({ domain: "conduit.device-auth.v1", origin: "https://conduit.example.com", clientNonce, connectionId: challenge.connectionId, deviceId, keyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime });
      const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", keyPair.privateKey, new TextEncoder().encode(transcript))));
      const acceptedPending = next();
      socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId, signature }));
      const accepted = parseWireDocumentText(schemaIds.nodeV1, await acceptedPending);
      if (accepted.type !== "transport.accepted") throw new Error("expected transport.accepted");
      const send = async (sequence: number, type: string, payload: Record<string, unknown>, correlationId?: string) => {
        socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_control_replay_${sequence.toString().padStart(2, "0")}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(sequence), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
      };
      return { socket, next, send, accepted };
    };

    const first = await connect("node-boot-control-replay-0001");
    expect(first.accepted).toMatchObject({ controlNextSequence: "1", nodeStoredThroughSequence: "0" });
    await first.send(1, "reconcile.summary", { nodeBootId: "node-boot-control-replay-0001", journalGeneration: "1", capabilityDigest: "4".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, first.accepted.connectionId);
    const initialPlan = parseWireDocumentText(schemaIds.nodeV1, await first.next());
    const initialSummaryAck = parseWireDocumentText(schemaIds.nodeV1, await first.next());
    if (initialPlan.type !== "reconcile.plan") throw new Error("expected initial reconcile.plan");
    expect(initialSummaryAck).toMatchObject({ type: "transport.ack", sequence: "2" });
    await first.send(2, "reconcile.complete", { reconciliationId: initialPlan.payload.reconciliationId, lastControlSequenceApplied: "2", lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, initialPlan.payload.reconciliationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await first.next())).toMatchObject({ type: "transport.ack", sequence: "3" });
    await first.send(3, "transport.ack", { direction: "control_to_node", throughSequence: "3" });
    await expect.poll(async () => runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), (_instance, state) => state.storage.sql.exec<{ acknowledged_sequence: number }>("SELECT acknowledged_sequence FROM transport_positions WHERE direction='control_to_node'").one().acknowledged_sequence)).toBe(3);

    const issuedAt = new Date();
    const originalOffers = [];
    for (let index = 0; index < 40; index += 1) {
      const suffix = index.toString().padStart(4, "0");
      const operation = {
        schemaVersion: 1,
        operationId: `op_control_replay${suffix}`,
        idempotencyKey: `control-replay-idempotency-${suffix}`,
        actorPrincipalId: "prin_control_replay01",
        clientId: "conduit.test",
        deviceId,
        capability: "command.start",
        sourceRevisions: [],
        runtime: { kind: "native", providerId: "native.linux", configurationRevision: 1 },
        accessScope: "full_user",
        approvalMode: "never",
        requiredApprovalRiskClasses: [],
        connectorPolicyId: "cpol_control_replay01",
        connectorPolicyRevision: 1,
        arguments: { argv: ["true"] },
        payloadDigest: "5".repeat(64),
        issuedAt: issuedAt.toISOString(),
        expiresAt: new Date(issuedAt.getTime() + 300_000).toISOString(),
        validForMs: 300_000,
      };
      const offerPayload = { operation };
      const messageId = `cmsg_control_replay_${suffix}`;
      const delivery = await env.DEVICE_ROOMS.getByName(deviceId).offer({ deviceId, messageId, correlationId: operation.operationId, payloadDigest: await sha256Hex(canonicalJson(offerPayload)), payload: offerPayload, expiresAt: operation.expiresAt });
      expect(delivery).toEqual({ sequence: String(index + 4), delivered: true });
      const offered = parseWireDocumentText(schemaIds.nodeV1, await first.next());
      expect(offered).toMatchObject({ type: "operation.offer", sequence: String(index + 4), messageId, payload: offerPayload });
      originalOffers.push(offered);
    }
    const originalOffer = originalOffers[0]!;
    if (originalOffer.type !== "operation.offer") throw new Error("expected operation.offer");
    const messageId = originalOffer.messageId;
    first.socket.close(1000, "fault_disconnect_before_ack");
    await evictDurableObject(env.DEVICE_ROOMS.getByName(deviceId));

    const second = await connect("node-boot-control-replay-0002");
    expect(second.accepted).toMatchObject({ controlNextSequence: "44", nodeStoredThroughSequence: "3" });
    const concurrentOperation = {
      ...originalOffer.payload.operation,
      operationId: "op_control_replay_concurrent",
      idempotencyKey: "control-replay-concurrent-idempotency",
    };
    const concurrentPayload = { operation: concurrentOperation };
    const deferredError = await runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), async (instance) => {
      try {
        await instance.offer({
          deviceId,
          messageId: "cmsg_control_replay_concurrent",
          correlationId: concurrentOperation.operationId,
          payloadDigest: await sha256Hex(canonicalJson(concurrentPayload)),
          payload: concurrentPayload,
          expiresAt: concurrentOperation.expiresAt,
        });
        return "allocated";
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    });
    expect(deferredError).toBe("effectful control delivery waits for reconciliation completion");
    expect(await runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), (_instance, state) => ({
      controlStored: state.storage.sql.exec<{ durable_sequence: number }>("SELECT durable_sequence FROM transport_positions WHERE direction='control_to_node'").one().durable_sequence,
      concurrentFrames: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id='cmsg_control_replay_concurrent'").one().count,
      concurrentReceipts: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_message_receipts WHERE message_id='cmsg_control_replay_concurrent'").one().count,
    }))).toEqual({ controlStored: 43, concurrentFrames: 0, concurrentReceipts: 0 });
    await second.send(4, "reconcile.summary", { nodeBootId: "node-boot-control-replay-0002", journalGeneration: "1", capabilityDigest: "4".repeat(64), lastControlSequenceApplied: "3", lastNodeSequenceAcknowledged: "3", lastNodeSequenceRetained: "4", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, second.accepted.connectionId);
    const reconnectMessages = [parseWireDocumentText(schemaIds.nodeV1, await second.next()), parseWireDocumentText(schemaIds.nodeV1, await second.next())];
    const replayPlan = reconnectMessages.find((frame) => frame.type === "reconcile.plan");
    expect(replayPlan).toMatchObject({ type: "reconcile.plan", sequence: "44", payload: { controlReplay: [{ from: "4", through: "43" }] } });
    const planFrame = reconnectMessages.find((frame) => frame.type === "reconcile.plan");
    if (planFrame?.type !== "reconcile.plan") throw new Error("expected reconnect reconcile.plan");
    const replayPayload = { direction: "control_to_node", expectedSequence: "4", receivedSequence: "44" };
    const replayRequest = { protocol: "conduit.node/1", messageId: "nmsg_control_replay_05", deviceId, connectionEpoch: second.accepted.connectionEpoch, direction: "node_to_control", sequence: "5", type: "transport.replay_required", payloadDigest: await sha256Hex(canonicalJson(replayPayload)), payload: replayPayload };
    await runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), async (_instance, state) => {
      await state.storage.setAlarm(Date.now() + 60_000);
      state.storage.transactionSync(() => {
        state.storage.sql.exec("INSERT INTO inbound_frames(sequence,message_id,correlation_id,payload_digest,frame_json,created_at) VALUES (5,?,NULL,?,?,?)", replayRequest.messageId, replayRequest.payloadDigest, JSON.stringify(replayRequest), now);
        state.storage.sql.exec("UPDATE transport_positions SET durable_sequence=5 WHERE direction='node_to_control'");
        state.storage.sql.exec("INSERT INTO control_replay_intents(request_sequence,request_message_id,from_sequence,through_sequence,next_attempt_at,created_at) VALUES (5,?,4,44,?,?)", replayRequest.messageId, now, now);
      });
    });
    await evictDurableObject(env.DEVICE_ROOMS.getByName(deviceId));
    await second.send(5, "transport.replay_required", replayPayload);
    const firstChunk = [];
    for (let index = 0; index < 34; index += 1) firstChunk.push(parseWireDocumentText(schemaIds.nodeV1, await second.next()));
    const replayedOffer = firstChunk[0]!;
    const replayedPlan = firstChunk[32]!;
    const replayRequestAck = firstChunk[33]!;
    expect(replayedOffer).toMatchObject({ type: "operation.offer", sequence: originalOffer.sequence, messageId: originalOffer.messageId, payloadDigest: originalOffer.payloadDigest, payload: originalOffer.payload, connectionEpoch: second.accepted.connectionEpoch });
    expect(replayedPlan).toMatchObject({ type: "reconcile.plan", sequence: planFrame.sequence, messageId: planFrame.messageId, payloadDigest: planFrame.payloadDigest });
    expect(replayRequestAck).toMatchObject({ type: "transport.ack", sequence: "46", payload: { direction: "node_to_control", throughSequence: "5" } });

    await second.send(6, "transport.replay_required", { direction: "control_to_node", expectedSequence: "36", receivedSequence: "44" });
    const secondChunk = [];
    for (let index = 0; index < 10; index += 1) secondChunk.push(parseWireDocumentText(schemaIds.nodeV1, await second.next()));
    expect(secondChunk.slice(0, 8).map((frame) => "sequence" in frame ? frame.sequence : null)).toEqual(["36", "37", "38", "39", "40", "41", "42", "43"]);
    expect(secondChunk[8]).toMatchObject({ type: "reconcile.plan", sequence: "44", messageId: planFrame.messageId, payloadDigest: planFrame.payloadDigest });
    expect(secondChunk[9]).toMatchObject({ type: "transport.ack", sequence: "47", payload: { throughSequence: "6" } });

    await second.send(7, "transport.ack", { direction: "control_to_node", throughSequence: "44" });
    await expect.poll(async () => runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), (_instance, state) => ({
      frameCount: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", messageId).one().count,
      receipt: state.storage.sql.exec<{ message_id: string; sequence: number; payload_digest: string; state: string }>("SELECT message_id,sequence,payload_digest,state FROM outbound_message_receipts WHERE message_id=?", messageId).toArray()[0],
      replayIntents: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM control_replay_intents").one().count,
    }))).toEqual({ frameCount: 0, receipt: { message_id: messageId, sequence: 4, payload_digest: originalOffer.payloadDigest, state: "acknowledged" }, replayIntents: 0 });

    const rejected = new Promise<{ code: number; reason: string }>((resolve) => second.socket.addEventListener("close", (event) => resolve({ code: event.code, reason: event.reason }), { once: true }));
    await second.send(8, "transport.replay_required", { direction: "control_to_node", expectedSequence: "4", receivedSequence: "4" });
    await expect(rejected).resolves.toEqual({ code: 1008, reason: "replay_range_acknowledged" });
    const invalidPersisted = await runInDurableObject(env.DEVICE_ROOMS.getByName(deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames WHERE sequence=8").one().count);
    expect(invalidPersisted).toBe(0);
  });

  it("admits owner CLI effects through the first-party policy boundary", async () => {
    const token = "conduit_owner_board_contract_token_00000001";
    const headers = {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "idempotency-key": "owner-operation-contract-0001",
    };
    const body = {
      deviceId: "dev_handshake01",
      capability: "command.start",
      runtime: { kind: "native", providerId: "native.linux", configurationRevision: 1 },
      accessScope: "full_user",
      approvalMode: "never",
      sourceRevisions: [],
      arguments: { argv: ["true"] },
    };
    const response = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers, body: JSON.stringify(body) }));
    expect(response.status).toBe(202);
    const accepted = await response.json<Record<string, unknown>>();
    expect(accepted).toMatchObject({ state: "offered", payloadDigest: expect.stringMatching(/^[a-f0-9]{64}$/) });
    const row = await env.DB.prepare("SELECT client_id,connector_policy_id,connector_policy_revision,connector_grant_id,request_json FROM operation_journal WHERE id=?1 LIMIT 1").bind(accepted.operationId).first<{ client_id: string; connector_policy_id: string; connector_policy_revision: number; connector_grant_id: string | null; request_json: string }>();
    expect(row).toMatchObject({ client_id: "conduit.cli", connector_policy_id: "cpol_owner_first_party_v1", connector_policy_revision: 1, connector_grant_id: null });
    expect(JSON.parse(row!.request_json)).toMatchObject({ actorPrincipalId: "prin_board_contract", accessScope: "full_user", approvalMode: "never", requiredApprovalRiskClasses: [] });
    const replay = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers, body: JSON.stringify(body) }));
    await expect(replay.json()).resolves.toMatchObject({ operationId: accepted.operationId, replay: true });
    const malformed = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers: { ...headers, "idempotency-key": "owner-operation-contract-0002" }, body: JSON.stringify({ deviceId: "dev_handshake01", capability: "command.start" }) }));
    expect(malformed.status).toBe(400);
    await expect(malformed.json()).resolves.toMatchObject({ error: { code: "invalid_request" } });
    const riskClasses = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers: { ...headers, "idempotency-key": "owner-operation-contract-0003" }, body: JSON.stringify({ ...body, approvalMode: "risk_classes" }) }));
    expect(riskClasses.status).toBe(202);
    const riskReceipt = await riskClasses.json<Record<string, unknown>>();
    const riskRow = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1").bind(riskReceipt.operationId).first<{ request_json: string }>();
    expect(JSON.parse(riskRow!.request_json)).toMatchObject({ approvalMode: "risk_classes", requiredApprovalRiskClasses: ALL_APPROVAL_RISK_CLASSES });
    const injected = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers: { ...headers, "idempotency-key": "owner-operation-contract-0004" }, body: JSON.stringify({ ...body, requiredApprovalRiskClasses: [] }) }));
    expect(injected.status).toBe(400);
    await expect(injected.json()).resolves.toMatchObject({ error: { code: "invalid_request" } });
  });

  it("recovers a DeviceRoom RPC throw from the durable dispatch row", async () => {
    const input = {
      idempotencyKey: "owner-operation-do-throw-0001",
      deviceId: "dev_handshake01",
      capability: "command.start",
      runtime: { kind: "native" as const, providerId: "native.linux", configurationRevision: 1 },
      accessScope: "full_user" as const,
      approvalMode: "never" as const,
      sourceRevisions: [],
      arguments: { argv: ["true"] },
    };
    const actor = { principalId: "prin_board_contract", clientId: "conduit.cli", scopes: ["owner"] };
    const throwBeforeCustody: OperationDispatcher = {
      async offer() {
        throw new Error("simulated DeviceRoom RPC failure before custody");
      },
    };
    const pending = await createOperation(env, actor, input, { kind: "owner" }, throwBeforeCustody);
    expect(pending).toMatchObject({ state: "queued", dispatch: { state: "pending", attemptCount: 1 } });
    const operationId = String(pending.operationId);
    const outbox = await env.DB.prepare("SELECT message_id,next_attempt_at FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1").bind(operationId).first<{ message_id: string; next_attempt_at: string }>();
    if (outbox === null) throw new Error("dispatch outbox row was not persisted");
    const absent = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(absent).toBe(0);
    const recovered = await reconcileOperationDispatches(env, { now: new Date(Date.parse(outbox.next_attempt_at) + 1) });
    expect(recovered).toEqual({ examined: 1, offered: 1, pending: 0, expired: 0 });
    const present = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(present).toBe(1);
  });

  it("retries a durably accepted DeviceRoom offer after response loss, hibernation, and Worker restart", async () => {
    const input = {
      idempotencyKey: "owner-operation-dispatch-restart-0001",
      deviceId: "dev_handshake01",
      capability: "command.start",
      runtime: { kind: "native" as const, providerId: "native.linux", configurationRevision: 1 },
      accessScope: "full_user" as const,
      approvalMode: "never" as const,
      sourceRevisions: [],
      arguments: { argv: ["true"] },
    };
    const actor = { principalId: "prin_board_contract", clientId: "conduit.cli", scopes: ["owner"] };
    const loseFirstResponse: OperationDispatcher = {
      async offer(environment, frame) {
        await durableObjectOperationDispatcher.offer(environment, frame);
        throw new Error("simulated DeviceRoom response loss after durable custody");
      },
    };

    const pending = await createOperation(env, actor, input, { kind: "owner" }, loseFirstResponse);
    expect(pending).toMatchObject({ state: "queued", dispatch: { state: "pending", attemptCount: 1 } });
    const operationId = String(pending.operationId);
    const outbox = await env.DB.prepare("SELECT message_id,payload_digest,payload_json,expires_at,state,attempt_count,next_attempt_at FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1")
      .bind(operationId)
      .first<{ message_id: string; payload_digest: string; payload_json: string; expires_at: string; state: string; attempt_count: number; next_attempt_at: string }>();
    expect(outbox).toMatchObject({ state: "pending", attempt_count: 1 });
    if (outbox === null) throw new Error("dispatch outbox row was not persisted");
    const beforeRestart = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(beforeRestart).toBe(1);
    expect(await runDurableObjectAlarm(env.DEVICE_ROOMS.getByName(input.deviceId))).toBe(true);
    const afterAlarm = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(afterAlarm).toBe(1);

    await evictDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId));
    const restartTime = new Date(Date.parse(outbox.next_attempt_at) + 1);
    const reconciled = await reconcileOperationDispatches(env, { now: restartTime });
    expect(reconciled).toEqual({ examined: 1, offered: 1, pending: 0, expired: 0 });

    const afterRestart = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => ({
      count: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count,
      sequence: state.storage.sql.exec<{ sequence: number }>("SELECT sequence FROM outbound_frames WHERE message_id=?", outbox.message_id).one().sequence,
    }));
    expect(afterRestart.count).toBe(1);
    expect(afterRestart.sequence).toBeGreaterThan(0);
    const durable = await env.DB.prepare("SELECT state,attempt_count,lease_token,last_error_code FROM operation_dispatch_outbox WHERE operation_id=?1 LIMIT 1")
      .bind(operationId)
      .first<{ state: string; attempt_count: number; lease_token: string | null; last_error_code: string | null }>();
    expect(durable).toEqual({ state: "offered", attempt_count: 2, lease_token: null, last_error_code: null });
    const journal = await env.DB.prepare("SELECT state FROM operation_journal WHERE id=?1 LIMIT 1").bind(operationId).first<{ state: string }>();
    expect(journal?.state).toBe("offered");

    const replay = await createOperation(env, actor, input, { kind: "owner" });
    expect(replay).toMatchObject({ operationId, state: "offered", replay: true });
    const noDuplicate = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(noDuplicate).toBe(1);

    await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => {
      state.storage.transactionSync(() => {
        state.storage.sql.exec("UPDATE outbound_message_receipts SET state='acknowledged' WHERE message_id=?", outbox.message_id);
        state.storage.sql.exec("DELETE FROM outbound_frames WHERE message_id=?", outbox.message_id);
      });
    });
    await evictDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId));
    const replayPayload: unknown = JSON.parse(outbox.payload_json);
    if (replayPayload === null || typeof replayPayload !== "object" || Array.isArray(replayPayload)) throw new Error("persisted replay payload is invalid");
    const acknowledgedReplay = await durableObjectOperationDispatcher.offer(env, {
      deviceId: input.deviceId,
      messageId: outbox.message_id,
      correlationId: operationId,
      payloadDigest: outbox.payload_digest,
      payload: replayPayload as Record<string, unknown>,
      expiresAt: outbox.expires_at,
    });
    expect(acknowledgedReplay).toEqual({ sequence: String(afterRestart.sequence), delivered: true });
    const compacted = await runInDurableObject(env.DEVICE_ROOMS.getByName(input.deviceId), (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames WHERE message_id=?", outbox.message_id).one().count);
    expect(compacted).toBe(0);
  });

  it("repairs the historical crash image where offered custody was not projected", async () => {
    const operationId = "op_dispatch_offered_crash01";
    const digest = "f".repeat(64);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60_000).toISOString();
    const createdAt = now.toISOString();
    const response = { operationId, state: "offered", payloadDigest: digest, expiresAt, delivery: { sequence: "91", delivered: false } };
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'dispatch-offered-crash-key-0001','prin_board_contract','conduit.cli','dev_handshake01','cpol_owner_first_party_v1',1,'command.start',?2,'{}','queued',?3,?4,?4)").bind(operationId, digest, expiresAt, createdAt),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES ('owner:prin_board_contract:conduit.cli','dispatch-offered-crash-key-0001',?1,?2,'queued',202,NULL,?3,?4)").bind(digest, operationId, expiresAt, createdAt),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,attempt_count,next_attempt_at,result_json,expires_at,created_at,updated_at) VALUES (?1,'dev_handshake01','cmsg_dispatch_offered_crash01',?1,?2,'{}','offered',1,?3,?4,?3,?5,?5)").bind(operationId, digest, expiresAt, JSON.stringify(response), createdAt),
    ]);
    expect(await reconcileOperationDispatches(env, { now })).toEqual({ examined: 1, offered: 1, pending: 0, expired: 0 });
    const invariant = await env.DB.prepare("SELECT (SELECT state FROM operation_dispatch_outbox WHERE operation_id=?1) AS outbox_state,(SELECT state FROM operation_journal WHERE id=?1) AS operation_state,(SELECT state FROM idempotency_records WHERE operation_id=?1) AS idempotency_state,(SELECT response_json FROM idempotency_records WHERE operation_id=?1) AS response_json").bind(operationId).first<{ outbox_state: string; operation_state: string; idempotency_state: string; response_json: string }>();
    expect(invariant).toMatchObject({ outbox_state: "offered", operation_state: "offered", idempotency_state: "offered" });
    expect(JSON.parse(invariant!.response_json)).toEqual(response);
  });

  it("retries a durably journaled approval after DeviceRoom delivery failure and worker restart", async () => {
    const approvalId = "appr_dispatch_retry0001";
    const operationId = "op_approval_dispatch_retry01";
    const digest = "a".repeat(64);
    const created = new Date();
    const createdAt = created.toISOString();
    const retryAt = new Date(Date.now() + 3_000);
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'approval-dispatch-retry-key01','prin_board_contract','conduit.cli','dev_handshake01','cpol_owner_first_party_v1',1,'agent.start',?2,'{}','claimed',?3,?4,?4)").bind(operationId, digest, expiresAt, createdAt),
      env.DB.prepare("INSERT INTO approvals(id,operation_id,requester_principal_id,client_id,device_id,run_id,commitment_digest,operation_type,normalized_arguments_json,revisions_json,decision,reuse_scope_json,expires_at,resolved_at,created_at) VALUES (?1,?2,'prin_board_contract','conduit.cli','dev_handshake01','run_approval_retry01',?3,'item/commandExecution/requestApproval','{}','{\"controllerEpoch\":\"1\"}','approved','{\"kind\":\"once\"}',?4,?5,?5)").bind(approvalId, operationId, digest, expiresAt, createdAt),
    ]);
    const receipt = await buildApprovalReceipt(env, approvalId, "approved", created);
    await env.DB.prepare("INSERT INTO approval_dispatch_outbox(approval_id,device_id,message_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'pending',?6,?7,?6,?6)")
      .bind(approvalId, receipt.deviceId, receipt.messageId, receipt.payloadDigest, canonicalJson(receipt.payload), createdAt, receipt.expiresAt).run();

    await attemptApprovalDispatch(env, approvalId, new Date(createdAt), async () => { throw new Error("DeviceRoom unavailable"); });
    const failed = await env.DB.prepare("SELECT state,attempt_count,last_error_code FROM approval_dispatch_outbox WHERE approval_id=?1").bind(approvalId).first<{ state: string; attempt_count: number; last_error_code: string | null }>();
    expect(failed).toEqual({ state: "pending", attempt_count: 1, last_error_code: "device_room_delivery_failed" });

    await attemptApprovalDispatch(env, approvalId, retryAt);
    const roomCustody = await runInDurableObject(env.DEVICE_ROOMS.getByName("dev_handshake01"), (_instance, state) => state.storage.sql.exec<{ payload_digest: string; frame_json: string }>("SELECT payload_digest,frame_json FROM outbound_frames WHERE message_id=?", receipt.messageId).one());
    expect(roomCustody.payload_digest).toBe(receipt.payloadDigest);
    expect(JSON.parse(roomCustody.frame_json)).toMatchObject({ type: "operation.approval", payload: receipt.payload });
    const retried = await env.DB.prepare("SELECT state,attempt_count,lease_token,last_error_code FROM approval_dispatch_outbox WHERE approval_id=?1").bind(approvalId).first<{ state: string; attempt_count: number; lease_token: string | null; last_error_code: string | null }>();
    expect(retried).toEqual({ state: "offered", attempt_count: 2, lease_token: null, last_error_code: null });
  });

  it("expires an undispatched operation and releases its Connector concurrency slot once", async () => {
    const operationId = "op_dispatch_expiry01";
    const grantId = "grant_dispatch_expiry01";
    const now = new Date();
    const expiredAt = new Date(now.getTime() - 1_000).toISOString();
    const createdAt = new Date(now.getTime() - 2_000).toISOString();
    const digest = "e".repeat(64);
    const payload = { operation: { deviceId: "dev_handshake01" } };
    const messageId = "cmsg_dispatch_expiry01";
    const limiter = env.CONNECTOR_LIMITERS.getByName(grantId);
    const leaseExpiresAt = new Date(now.getTime() + 60_000).toISOString();
    expect(await limiter.acquire(operationId, "commands", 1, leaseExpiresAt)).toBe(true);
    expect(await limiter.acquire(operationId, "commands", 1, leaseExpiresAt)).toBe(true);
    expect(await limiter.acquire(operationId, "agentRuns", 1, leaseExpiresAt)).toBe(false);
    expect(await limiter.acquire("op_dispatch_competing1", "commands", 1, leaseExpiresAt)).toBe(false);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,connector_grant_id,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'dispatch-expiry-idempotency-0001','prin_board_contract','connector.dispatch-expiry','dev_handshake01','cpol_dispatch_expiry01',1,?2,'commands','command.start',?3,'{}','queued',?4,?5,?5)").bind(operationId, grantId, digest, expiredAt, createdAt),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES ('scope_dispatch_expiry01','dispatch-expiry-idempotency-0001',?1,?2,'queued',202,NULL,?3,?4)").bind(digest, operationId, expiredAt, createdAt),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) VALUES (?1,'dev_handshake01',?2,?1,?3,?4,'pending',?5,?5,?6,?6)").bind(operationId, messageId, await sha256Hex(canonicalJson(payload)), canonicalJson(payload), expiredAt, createdAt),
    ]);
    const expiredResponse = { operationId, state: "expired", payloadDigest: digest, expiresAt: expiredAt };
    await env.DB.prepare("UPDATE operation_dispatch_outbox SET state='expired',result_json=?1 WHERE operation_id=?2").bind(JSON.stringify(expiredResponse), operationId).run();
    expect(await reconcileOperationDispatches(env, { now })).toEqual({ examined: 1, offered: 0, pending: 0, expired: 1 });
    expect(await reconcileOperationDispatches(env, { now: new Date(now.getTime() + 1_000) })).toEqual({ examined: 0, offered: 0, pending: 0, expired: 0 });
    const states = await env.DB.prepare("SELECT (SELECT state FROM operation_journal WHERE id=?1) AS operation_state,(SELECT state FROM operation_dispatch_outbox WHERE operation_id=?1) AS dispatch_state,(SELECT state FROM idempotency_records WHERE operation_id=?1) AS idempotency_state,(SELECT concurrency_released_at FROM operation_journal WHERE id=?1) AS concurrency_released_at").bind(operationId).first<{ operation_state: string; dispatch_state: string; idempotency_state: string; concurrency_released_at: string | null }>();
    expect(states).toMatchObject({ operation_state: "expired", dispatch_state: "expired", idempotency_state: "expired" });
    expect(states?.concurrency_released_at).not.toBeNull();
    expect(await limiter.acquire("op_dispatch_competing1", "commands", 1, leaseExpiresAt)).toBe(true);
    expect(await limiter.release(operationId, "commands")).toBe(false);
    const active = await runInDurableObject(limiter, (_instance, state) => state.storage.sql.exec<{ active: number }>("SELECT COUNT(*) AS active FROM concurrency_leases WHERE class='commands' AND state='active'").one().active);
    expect(active).toBe(1);
    expect(await limiter.release("op_dispatch_competing1", "commands")).toBe(true);
    expect(await limiter.release("op_dispatch_competing1", "commands")).toBe(false);
  });

  it("reclaims an orphaned concurrency lease after its operation expiry", async () => {
    const limiter = env.CONNECTOR_LIMITERS.getByName("grant_dispatch_orphan01");
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(await limiter.acquire("op_dispatch_orphan0001", "runtimeStarts", 1, future)).toBe(true);
    await runInDurableObject(limiter, (_instance, state) => {
      state.storage.sql.exec("UPDATE concurrency_leases SET expires_at=? WHERE operation_id='op_dispatch_orphan0001'", Date.now() - 1);
    });
    expect(await limiter.acquire("op_dispatch_after_orphan1", "runtimeStarts", 1, future)).toBe(true);
    const leases = await runInDurableObject(limiter, (_instance, state) => state.storage.sql.exec<{ operation_id: string; state: string }>("SELECT operation_id,state FROM concurrency_leases ORDER BY operation_id").toArray());
    expect(leases).toEqual([
      { operation_id: "op_dispatch_after_orphan1", state: "active" },
      { operation_id: "op_dispatch_orphan0001", state: "expired" },
    ]);
  });

  it("serves typed MCP tools through an OAuth policy and exact limiter", async () => {
    const token = "mcp_contract_access_token_00000000000001";
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 60_000).toISOString();
    const profile = {
      requestWindows: {
        read: { limit: 100, windowSeconds: 60 },
        boardWrite: { limit: 100, windowSeconds: 60 },
        commandStart: { limit: 100, windowSeconds: 60 },
        agentRunStart: { limit: 100, windowSeconds: 60 },
        runtimeStart: { limit: 100, windowSeconds: 60 },
        approvalResolve: { limit: 100, windowSeconds: 60 },
        rawLogRead: { limit: 100, windowSeconds: 60 },
      },
      weightedBudget: { capacity: 100, refillPerSecond: 10, weights: {} },
      bytes: { responseBytes: 1_048_576, normalizedLogBytesPerDay: 1_048_576, rawLogBytesPerDay: 0, artifactUploadBytesPerDay: 0 },
      concurrency: { commands: 2, agentRuns: 2, runtimeStarts: 1 },
    };
    const clientId = "https://client.example/mcp-contract";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered','MCP contract','[\"https://client.example/callback\"]','none',?2,'active',?3,?3)").bind(clientId, "a".repeat(64), now),
      env.DB.prepare("INSERT INTO rate_limit_profiles(id,revision,status,name,profile_json,created_at,updated_at) VALUES ('rate_mcp_contract01',1,'active','MCP contract',?1,?2,?2)").bind(JSON.stringify(profile), now),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_mcp_contract01','prin_board_contract',?1,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}',?2,'[\"native\",\"restricted_native\",\"container\",\"vm\"]','project_full','always','[]',0,0,'rate_mcp_contract01',60,600,?3,?3)").bind(clientId, JSON.stringify(["project.read", "session.read", "board.read", "run.read"]), now),
      env.DB.prepare("INSERT INTO oauth_grants(id,principal_id,client_id,resource,scopes_json,connector_policy_id,connector_policy_revision,token_family_id,status,created_at,expires_at) VALUES ('grant_mcp_contract01','prin_board_contract',?1,'https://conduit.example.com/mcp','[\"conduit.read\"]','cpol_mcp_contract01',1,'family_mcp_contract01','active',?2,?3)").bind(clientId, now, expires),
      env.DB.prepare("INSERT INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,resource,scopes_json,issued_at,expires_at) VALUES ('tok_mcp_contract01','grant_mcp_contract01','family_mcp_contract01','access',?1,'https://conduit.example.com/mcp','[\"conduit.read\"]',?2,?3)").bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", token), now, expires),
    ]);
    const call = async (id: number, method: string, params: Record<string, unknown>) => {
      const protocolVersion = "2026-07-28";
      const headers: Record<string, string> = {
        authorization: `Bearer ${token}`,
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": method,
      };
      if (method === "tools/call" && typeof params.name === "string") headers["Mcp-Name"] = params.name;
      const response = await exports.default.fetch(new Request("https://conduit.example.com/mcp", {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method,
          params: {
            ...params,
            _meta: {
              "io.modelcontextprotocol/protocolVersion": protocolVersion,
              "io.modelcontextprotocol/clientInfo": { name: "conduit-test", version: "1" },
              "io.modelcontextprotocol/clientCapabilities": {},
            },
          },
        }),
      }));
      const text = await response.text();
      expect(response.status, text).toBe(200);
      return JSON.parse(text) as Record<string, unknown>;
    };
    const discovered = await call(1, "server/discover", {});
    expect(discovered).toMatchObject({ jsonrpc: "2.0", id: 1, result: { supportedVersions: ["2026-07-28"] } });
    const tools = await call(2, "tools/list", {});
    expect(tools).toMatchObject({ result: { tools: expect.arrayContaining([expect.objectContaining({ name: "project_get" }), expect.objectContaining({ name: "quick_command_start" }), expect.objectContaining({ name: "runtime_vm_lifecycle" })]) } });
    expect(JSON.stringify(tools)).not.toContain("requiredApprovalRiskClasses");
    const project = await call(3, "tools/call", { name: "project_get", arguments: { projectId: "prj_board_contract", requestKey: "mcp-project-read-000001" } });
    expect(project).toMatchObject({ result: { structuredContent: { id: "prj_board_contract", name: "Board" } } });
    const injected = await call(4, "tools/call", { name: "quick_command_start", arguments: { idempotencyKey: "mcp-risk-injection-000001", deviceId: "dev_handshake01", runtime: { kind: "native", providerId: "native.linux", configurationRevision: 1 }, accessScope: "read_only", approvalMode: "always", sourceRevisions: [], arguments: {}, requiredApprovalRiskClasses: [] } });
    expect(JSON.stringify(injected)).toContain("Unrecognized key");
  });

  it("snapshots grant-bound required approval risks into immutable operation custody", async () => {
    const now = new Date().toISOString();
    const clientId = "https://client.example/risk-snapshot";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered','Risk snapshot','[\"https://client.example/risk-callback\"]','none',?2,'active',?3,?3)").bind(clientId, "e".repeat(64), now),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_risk_snapshot01','prin_board_contract',?1,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}','[\"command.start\"]','[\"native\"]','full_user','never','[\"secret_access\",\"runtime_management\"]',0,0,'rate_mcp_contract01',60,600,?2,?2)").bind(clientId, now),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_risk_empty0001','prin_board_contract',?1,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}','[\"command.start\"]','[\"native\"]','full_user','never','[]',0,0,'rate_mcp_contract01',60,600,?2,?2)").bind(clientId, now),
    ]);
    const base = {
      deviceId: "dev_handshake01",
      capability: "command.start",
      runtime: { kind: "native" as const, providerId: "native.linux", configurationRevision: 1 },
      accessScope: "full_user" as const,
      sourceRevisions: [],
      arguments: { argv: ["true"] },
    };
    const actor = { principalId: "prin_board_contract", clientId, grantId: "grant_risk_snapshot01", policyId: "cpol_risk_snapshot01", policyRevision: 1, scopes: ["conduit.run.start"] };
    const never = await createOperation(env, actor, { ...base, idempotencyKey: "risk-snapshot-never-0001", approvalMode: "never" });
    const riskClasses = await createOperation(env, actor, { ...base, idempotencyKey: "risk-snapshot-classes-001", approvalMode: "risk_classes" });
    const rows = await env.DB.prepare("SELECT id,request_json,payload_digest FROM operation_journal WHERE id IN (?1,?2) ORDER BY id").bind(never.operationId, riskClasses.operationId).all<{ id: string; request_json: string; payload_digest: string }>();
    expect(rows.results).toHaveLength(2);
    for (const row of rows.results) {
      const request = JSON.parse(row.request_json) as Record<string, unknown>;
      expect(request).toMatchObject({ connectorPolicyId: "cpol_risk_snapshot01", connectorPolicyRevision: 1, requiredApprovalRiskClasses: ["secret_access", "runtime_management"] });
      expect(row.payload_digest).toBe(request.payloadDigest);
      const outbox = await env.DB.prepare("SELECT payload_json FROM operation_dispatch_outbox WHERE operation_id=?1").bind(row.id).first<{ payload_json: string }>();
      expect(JSON.parse(outbox!.payload_json)).toMatchObject({ operation: { requiredApprovalRiskClasses: ["secret_access", "runtime_management"], payloadDigest: row.payload_digest } });
      const { payloadDigest: _payloadDigest, ...withoutDigest } = request;
      expect(await operationDigest({ ...withoutDigest, requiredApprovalRiskClasses: ["destructive_delete"] })).not.toBe(row.payload_digest);
    }

    const emptyActor = { ...actor, grantId: "grant_risk_empty0001", policyId: "cpol_risk_empty0001" };
    const conservative = await createOperation(env, emptyActor, { ...base, idempotencyKey: "risk-snapshot-empty-00001", approvalMode: "risk_classes" });
    const conservativeRow = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1").bind(conservative.operationId).first<{ request_json: string }>();
    expect(JSON.parse(conservativeRow!.request_json)).toMatchObject({ requiredApprovalRiskClasses: ALL_APPROVAL_RISK_CLASSES });

    const firstRequest = JSON.parse(rows.results[0]!.request_json) as Record<string, unknown>;
    await env.DB.prepare("UPDATE connector_policies SET revision=2,required_risk_classes_json='[\"destructive_delete\"]' WHERE id='cpol_risk_snapshot01'").run();
    const revisedActor = { ...actor, grantId: "grant_risk_snapshot02", policyRevision: 2 };
    const revised = await createOperation(env, revisedActor, { ...base, idempotencyKey: "risk-snapshot-revision-0001", approvalMode: "never" });
    const revisedRow = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1").bind(revised.operationId).first<{ request_json: string }>();
    expect(JSON.parse(revisedRow!.request_json)).toMatchObject({ connectorPolicyRevision: 2, requiredApprovalRiskClasses: ["destructive_delete"] });
    const retained = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1").bind(rows.results[0]!.id).first<{ request_json: string }>();
    expect(JSON.parse(retained!.request_json)).toEqual(firstRequest);

    await env.DB.prepare("UPDATE connector_policies SET required_risk_classes_json='[\"secret_access\",\"secret_access\"]' WHERE id='cpol_risk_snapshot01'").run();
    await expect(createOperation(env, revisedActor, { ...base, idempotencyKey: "risk-snapshot-tamper-00001", approvalMode: "never" })).rejects.toMatchObject({ code: "grant_reauthorization_required", status: 403 });
  });

  it("completes standard OAuth consent in a browser without connector_policy_id or custom headers", async () => {
    const sessionToken = "browser_oauth_session_token_00000000001";
    const csrfToken = "browser_oauth_csrf_token_00000000000001";
    const verifier = "chatgpt-compatible-pkce-verifier-000000000000000000000000";
    const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_oauth_browser01','prin_board_contract',?1,?2,'owner','active',?3,?3,?3,?4,1)")
      .bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", sessionToken), await keyedHash("test-only-token-pepper-with-at-least-32-bytes", csrfToken), now, new Date(Date.now() + 60_000).toISOString()).run();
    const authorize = new URL("https://conduit.example.com/authorize");
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: "https://client.example/mcp-contract",
      redirect_uri: "https://client.example/callback",
      resource: "https://conduit.example.com/mcp",
      scope: "conduit.read",
      state: "chatgpt-state-0001",
      code_challenge: challenge,
      code_challenge_method: "S256",
      prompt: "consent",
    }).toString();
    expect(authorize.searchParams.has("connector_policy_id")).toBe(false);
    const unauthenticated = await exports.default.fetch(new Request(authorize, { redirect: "manual" }));
    expect(unauthenticated.status).toBe(303);
    const loginRedirect = new URL(unauthenticated.headers.get("location")!);
    expect(loginRedirect.pathname).toBe("/login");
    expect(loginRedirect.searchParams.get("return_to")).toBe(`/authorize?${authorize.searchParams.toString()}`);
    const cookie = `__Host-conduit_session=${sessionToken}; __Host-conduit_csrf=${csrfToken}`;
    const page = await exports.default.fetch(new Request(authorize, { headers: { cookie } }));
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Connector Policy");
    expect(html).toContain("cpol_mcp_contract01");
    expect(html).not.toContain("X-CSRF-Token");
    const transactionId = html.match(/name=transaction_id value="([^"]+)"/)?.[1];
    expect(transactionId).toMatch(/^consent_/);
    const consent = await exports.default.fetch(new Request("https://conduit.example.com/authorize", {
      method: "POST",
      headers: { cookie, origin: "https://conduit.example.com", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ transaction_id: transactionId!, csrf_token: csrfToken, connector_policy_id: "cpol_mcp_contract01", decision: "approve" }),
      redirect: "manual",
    }));
    expect(consent.status).toBe(303);
    const callback = new URL(consent.headers.get("location")!);
    expect(callback.origin + callback.pathname).toBe("https://client.example/callback");
    expect(callback.searchParams.get("state")).toBe("chatgpt-state-0001");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    const token = await exports.default.fetch(new Request("https://conduit.example.com/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: code!, client_id: "https://client.example/mcp-contract", redirect_uri: "https://client.example/callback", code_verifier: verifier, resource: "https://conduit.example.com/mcp" }),
    }));
    expect(token.status).toBe(200);
    await expect(token.json()).resolves.toMatchObject({ token_type: "Bearer", scope: "conduit.read", resource: "https://conduit.example.com/mcp" });
    const grant = await env.DB.prepare("SELECT connector_policy_id FROM oauth_grants WHERE id=(SELECT grant_id FROM oauth_authorization_codes WHERE consent_transaction_id=?1)").bind(transactionId).first<{ connector_policy_id: string }>();
    expect(grant?.connector_policy_id).toBe("cpol_mcp_contract01");
  });

  it("renders browser passkey sign-in and step-up surfaces under a self-only CSP", async () => {
    const login = await exports.default.fetch(new Request("https://conduit.example.com/login?return_to=%2Fauthorize%3Fclient_id%3Dstandard"));
    const loginHtml = await login.text();
    expect(login.status).toBe(200);
    expect(loginHtml).toContain("id=passkey-sign-in");
    expect(loginHtml).toContain("/api/v1/auth/browser.js");
    expect(login.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(login.headers.get("content-security-policy")).toContain("connect-src 'self'");
    const script = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/browser.js"));
    expect(script.status).toBe(200);
    expect(await script.text()).toContain("navigator.credentials.get");

    const staleSession = "browser_oauth_stale_session_000000001";
    const staleCsrf = "browser_oauth_stale_csrf_000000000001";
    const old = new Date(Date.now() - 600_000).toISOString();
    await env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_oauth_stale01','prin_board_contract',?1,?2,'owner','active',?3,?3,?4,?5,1)")
      .bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", staleSession), await keyedHash("test-only-token-pepper-with-at-least-32-bytes", staleCsrf), old, new Date().toISOString(), new Date(Date.now() + 60_000).toISOString()).run();
    const request = new URL("https://conduit.example.com/authorize");
    request.search = new URLSearchParams({ response_type: "code", client_id: "https://client.example/mcp-contract", redirect_uri: "https://client.example/callback", resource: "https://conduit.example.com/mcp", scope: "conduit.read", code_challenge: "a".repeat(43), code_challenge_method: "S256" }).toString();
    const stepUp = await exports.default.fetch(new Request(request, { headers: { cookie: `__Host-conduit_session=${staleSession}; __Host-conduit_csrf=${staleCsrf}` } }));
    expect(stepUp.status).toBe(200);
    const staleHtml = await stepUp.text();
    expect(staleHtml).toContain("id=oauth-step-up");
    expect(stepUp.headers.get("content-security-policy")).toContain("connect-src 'self'");
    const staleTransactionId = staleHtml.match(/name=transaction_id value="([^"]+)"/)?.[1];
    expect(staleTransactionId).toMatch(/^consent_/);

    // A successful WebAuthn step-up rotates the browser session and CSRF cookie,
    // then the browser reloads the original authorization URL. Seed that
    // post-verification state directly so this transaction-binding test remains
    // deterministic and does not depend on a platform authenticator in CI.
    const freshSession = "browser_oauth_fresh_session_000000001";
    const freshCsrf = "browser_oauth_fresh_csrf_000000000001";
    const freshNow = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("UPDATE owner_sessions SET status='revoked',revoked_at=?1 WHERE id='bsess_oauth_stale01'").bind(freshNow),
      env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_oauth_fresh01','prin_board_contract',?1,?2,'owner','active',?3,?3,?3,?4,1)")
        .bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", freshSession), await keyedHash("test-only-token-pepper-with-at-least-32-bytes", freshCsrf), freshNow, new Date(Date.now() + 60_000).toISOString()),
    ]);
    const freshCookie = `__Host-conduit_session=${freshSession}; __Host-conduit_csrf=${freshCsrf}`;
    const reloaded = await exports.default.fetch(new Request(request, { headers: { cookie: freshCookie } }));
    expect(reloaded.status).toBe(200);
    const freshHtml = await reloaded.text();
    expect(freshHtml).toContain("name=decision value=approve");
    const freshTransactionId = freshHtml.match(/name=transaction_id value="([^"]+)"/)?.[1];
    expect(freshTransactionId).toMatch(/^consent_/);
    expect(freshTransactionId).not.toBe(staleTransactionId);

    const staleReplay = await exports.default.fetch(new Request("https://conduit.example.com/authorize", {
      method: "POST",
      headers: { cookie: freshCookie, origin: "https://conduit.example.com", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ transaction_id: staleTransactionId!, csrf_token: freshCsrf, connector_policy_id: "cpol_mcp_contract01", decision: "approve" }),
    }));
    expect(staleReplay.status).toBe(400);
    await expect(staleReplay.json()).resolves.toMatchObject({ error: "invalid_request" });
    const staleTransaction = await env.DB.prepare("SELECT consumed_at FROM oauth_consent_transactions WHERE id=?1").bind(staleTransactionId).first<{ consumed_at: string | null }>();
    expect(staleTransaction?.consumed_at).toBeNull();

    const invalidCsrf = await exports.default.fetch(new Request("https://conduit.example.com/authorize", {
      method: "POST",
      headers: { cookie: freshCookie, origin: "https://conduit.example.com", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ transaction_id: freshTransactionId!, csrf_token: staleCsrf, connector_policy_id: "cpol_mcp_contract01", decision: "approve" }),
    }));
    expect(invalidCsrf.status).toBe(403);
    await expect(invalidCsrf.json()).resolves.toMatchObject({ error: { code: "csrf_failed" } });

    const approved = await exports.default.fetch(new Request("https://conduit.example.com/authorize", {
      method: "POST",
      headers: { cookie: freshCookie, origin: "https://conduit.example.com", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ transaction_id: freshTransactionId!, csrf_token: freshCsrf, connector_policy_id: "cpol_mcp_contract01", decision: "approve" }),
      redirect: "manual",
    }));
    expect(approved.status).toBe(303);
    expect(new URL(approved.headers.get("location")!).origin).toBe("https://client.example");
  });

  it("completes a cryptographic passkey step-up and rotates the browser session", async () => {
    const sessionToken = "browser_passkey_stepup_session_00000001";
    const csrfToken = "browser_passkey_stepup_csrf_0000000001";
    const pepper = "test-only-token-pepper-with-at-least-32-bytes";
    const credentialId = base64url(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const exportedPublicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey) as ArrayBuffer;
    const rawPublicKey = new Uint8Array(exportedPublicKey);
    const cosePublicKey = Uint8Array.from([
      0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
      0x21, 0x58, 0x20, ...rawPublicKey.slice(1, 33),
      0x22, 0x58, 0x20, ...rawPublicKey.slice(33, 65),
    ]);
    const old = new Date(Date.now() - 10 * 60_000).toISOString();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_passkey_stepup01','prin_board_contract',?1,?2,'owner','active',?3,?3,?4,?5,1)")
        .bind(await keyedHash(pepper, sessionToken), await keyedHash(pepper, csrfToken), old, new Date().toISOString(), expiresAt),
      env.DB.prepare("INSERT INTO passkeys(id,principal_id,credential_id,public_key,relying_party_id,label,transports_json,sign_count,status,created_at) VALUES ('pkey_stepup_contract01','prin_board_contract',?1,?2,'conduit.example.com','Step-up contract','[\"internal\"]',0,'active',?3)")
        .bind(credentialId, cosePublicKey, old),
    ]);
    const cookie = `__Host-conduit_session=${sessionToken}; __Host-conduit_csrf=${csrfToken}`;
    const headers = { cookie, origin: "https://conduit.example.com", "x-csrf-token": csrfToken, "content-type": "application/json" };
    const optionsResponse = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/step-up/options", { method: "POST", headers, body: "{}" }));
    expect(optionsResponse.status).toBe(200);
    const ceremony = await optionsResponse.json<{ challengeId: string; options: { challenge: string } }>();
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: ceremony.options.challenge, origin: "https://conduit.example.com", crossOrigin: false }));
    const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("conduit.example.com")));
    const authenticatorData = Uint8Array.from([...rpIdHash, 0x05, 0, 0, 0, 1]);
    const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
    const signed = Uint8Array.from([...authenticatorData, ...clientDataHash]);
    const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, signed));
    const verify = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/step-up/verify", {
      method: "POST",
      headers,
      body: JSON.stringify({
        challengeId: ceremony.challengeId,
        challenge: ceremony.options.challenge,
        response: {
          id: credentialId,
          rawId: credentialId,
          type: "public-key",
          authenticatorAttachment: "platform",
          clientExtensionResults: {},
          response: {
            clientDataJSON: base64url(clientDataJSON),
            authenticatorData: base64url(authenticatorData),
            signature: base64url(derEcdsaSignature(rawSignature)),
            userHandle: null,
          },
        },
      }),
    }));
    expect(verify.status, await verify.clone().text()).toBe(200);
    await expect(verify.json()).resolves.toMatchObject({ principalId: "prin_board_contract", fresh: true });
    expect(verify.headers.get("set-cookie")).toContain("__Host-conduit_session=");
    const oldSession = await env.DB.prepare("SELECT status,revoked_at FROM owner_sessions WHERE id='bsess_passkey_stepup01'").first<{ status: string; revoked_at: string | null }>();
    expect(oldSession).toMatchObject({ status: "revoked", revoked_at: expect.any(String) });
    const replacement = await env.DB.prepare("SELECT id,status,fresh_authenticated_at FROM owner_sessions WHERE principal_id='prin_board_contract' ORDER BY authenticated_at DESC,id DESC LIMIT 1").first<{ id: string; status: string; fresh_authenticated_at: string | null }>();
    expect(replacement).toMatchObject({ status: "active", fresh_authenticated_at: expect.any(String) });
    expect(replacement?.id).not.toBe("bsess_passkey_stepup01");
    const passkey = await env.DB.prepare("SELECT sign_count,last_used_at FROM passkeys WHERE id='pkey_stepup_contract01'").first<{ sign_count: number; last_used_at: string | null }>();
    expect(passkey).toMatchObject({ sign_count: 1, last_used_at: expect.any(String) });
  });

  it("denies cross-Project MCP reads and conflicting create bindings using stored ownership", async () => {
    const token = "mcp_project_a_access_token_0000000000001";
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 60_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,name,created_at,updated_at) VALUES ('prj_cross_project_b','Project B',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO sources(id,project_id,display_name,source_kind,created_at,updated_at) VALUES ('src_cross_project_b','prj_cross_project_b','B source','folder',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO locations(id,source_id,device_id,opaque_local_id,display_label,created_at,updated_at) VALUES ('loc_cross_project_b','src_cross_project_b','dev_handshake01','opaque-b','B location',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO collaboration_sessions(id,project_id,title,created_at,updated_at) VALUES ('csess_cross_project_b','prj_cross_project_b','B session',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO assignments(id,project_id,session_id,title,body,state,created_at,updated_at) VALUES ('asg_cross_project_b','prj_cross_project_b','csess_cross_project_b','B assignment','B','draft',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO project_agents(id,project_id,name,adapter_id,role,configuration_json,status,created_at,updated_at) VALUES ('pagent_reviewer_binding','prj_board_contract','Reviewer','codex','reviewer','{}','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_project_a_only','prin_board_contract','https://client.example/mcp-contract',1,'active','{\"mode\":\"all\"}','{\"mode\":\"ids\",\"ids\":[\"prj_board_contract\"]}',?1,'[\"native\"]','project_full','always','[]',0,0,'rate_mcp_contract01',60,600,?2,?2)").bind(JSON.stringify(["project.read", "session.read", "assignment.create"]), now),
      env.DB.prepare("INSERT INTO oauth_grants(id,principal_id,client_id,resource,scopes_json,connector_policy_id,connector_policy_revision,token_family_id,status,created_at,expires_at) VALUES ('grant_project_a_only','prin_board_contract','https://client.example/mcp-contract','https://conduit.example.com/mcp','[\"conduit.read\",\"conduit.board.write\",\"conduit.run.start\"]','cpol_project_a_only',1,'family_project_a_only','active',?1,?2)").bind(now, expires),
      env.DB.prepare("INSERT INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,resource,scopes_json,issued_at,expires_at) VALUES ('tok_project_a_only','grant_project_a_only','family_project_a_only','access',?1,'https://conduit.example.com/mcp','[\"conduit.read\",\"conduit.board.write\",\"conduit.run.start\"]',?2,?3)").bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", token), now, expires),
    ]);
    const call = async (callId: number, name: string, args: Record<string, unknown>) => {
      const protocolVersion = "2026-07-28";
      const response = await exports.default.fetch(new Request("https://conduit.example.com/mcp", { method: "POST", headers: { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json", "MCP-Protocol-Version": protocolVersion, "Mcp-Method": "tools/call", "Mcp-Name": name }, body: JSON.stringify({ jsonrpc: "2.0", id: callId, method: "tools/call", params: { name, arguments: args, _meta: { "io.modelcontextprotocol/protocolVersion": protocolVersion, "io.modelcontextprotocol/clientInfo": { name: "cross-project-test", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} } } }) }));
      expect(response.status).toBe(200);
      return response.json<Record<string, unknown>>();
    };
    const location = await call(1, "source_location_get", { locationId: "loc_cross_project_b", requestKey: "cross-project-location-0001" });
    expect(JSON.stringify(location)).toContain("project_not_allowed");
    expect(JSON.stringify(location)).not.toContain("opaque-b");
    const assignment = await call(2, "assignment_get", { recordId: "asg_cross_project_b", requestKey: "cross-project-assignment-001" });
    expect(JSON.stringify(assignment)).toContain("project_not_allowed");
    const create = await call(3, "assignment_create", { projectId: "prj_board_contract", sessionId: "csess_cross_project_b", title: "invalid cross-project", body: "must fail", idempotencyKey: "cross-project-create-000001" });
    expect(JSON.stringify(create)).toContain("Resource Project bindings disagree");
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM assignments WHERE title='invalid cross-project'").first<{ count: number }>();
    expect(count?.count).toBe(0);

    await env.DB.prepare("UPDATE connector_policies SET allowed_operations_json=?1 WHERE id='cpol_project_a_only'").bind(JSON.stringify(["project.read", "session.read", "assignment.create", "run.start"])).run();
    const reviewer = await call(4, "run_start", { idempotencyKey: "reviewer-role-binding-0001", deviceId: "dev_handshake01", projectId: "prj_board_contract", runtime: { kind: "native", providerId: "native", configurationRevision: 1 }, accessScope: "project_full", approvalMode: "always", sourceRevisions: [], arguments: { projectAgentId: "pagent_reviewer_binding", adapterId: "spoofed", role: "implementer" } });
    expect(JSON.stringify(reviewer)).toContain("operationId");
    const operation = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE idempotency_key='reviewer-role-binding-0001'").first<{ request_json: string }>();
    const request = JSON.parse(operation!.request_json) as Record<string, unknown>;
    expect(request).toMatchObject({ projectId: "prj_board_contract", accessScope: "read_only", arguments: { projectAgentId: "pagent_reviewer_binding", adapterId: "codex", role: "reviewer" } });
  });

  it("replays an idempotent browser grant transition without a second state change", async () => {
    const sessionToken = "browser_grant_session_token_0000000001";
    const csrfToken = "browser_grant_csrf_token_000000000001";
    const now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_grant_contract01','prin_board_contract',?1,?2,'owner','active',?3,?3,?3,?4,1)")
      .bind(await keyedHash("test-only-token-pepper-with-at-least-32-bytes", sessionToken), await keyedHash("test-only-token-pepper-with-at-least-32-bytes", csrfToken), now, new Date(Date.now() + 60_000).toISOString()).run();
    const request = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/oauth/grants/grant_mcp_contract01/pause", {
      method: "POST",
      headers: {
        cookie: `__Host-conduit_session=${sessionToken}`,
        origin: "https://conduit.example.com",
        "x-csrf-token": csrfToken,
        "idempotency-key": "grant-transition-contract-0001",
        "content-type": "application/json",
      },
      body: "{}",
    }));
    const first = await request();
    expect(first.status).toBe(200);
    await expect(first.json()).resolves.toMatchObject({ grantId: "grant_mcp_contract01", status: "paused" });
    const replay = await request();
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toMatchObject({ grantId: "grant_mcp_contract01", status: "paused", replay: true });
    const audit = await env.DB.prepare("SELECT COUNT(*) AS count FROM security_events WHERE event_type='oauth_grant.pause' AND principal_id='prin_board_contract'").first<{ count: number }>();
    expect(audit?.count).toBe(1);
  });

  it("replays an exact connector-policy CAS without a second revision", async () => {
    const request = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/connector-policies/cpol_mcp_contract01", {
      method: "PATCH",
      headers: {
        cookie: "__Host-conduit_session=browser_grant_session_token_0000000001",
        origin: "https://conduit.example.com",
        "x-csrf-token": "browser_grant_csrf_token_000000000001",
        "idempotency-key": "policy-transition-contract-0001",
        "if-match": '"1"',
        "content-type": "application/json",
      },
      body: JSON.stringify({ maxAccessScope: "read_only", requiredApprovalRiskClasses: ["secret_access"] }),
    }));
    const first = await request();
    expect(first.status).toBe(200);
    expect(first.headers.get("etag")).toBe('"2"');
    await expect(first.json()).resolves.toMatchObject({ id: "cpol_mcp_contract01", revision: 2, maxAccessScope: "read_only", requiredApprovalRiskClasses: ["secret_access"] });
    const replay = await request();
    expect(replay.status).toBe(200);
    expect(replay.headers.get("etag")).toBe('"2"');
    await expect(replay.json()).resolves.toMatchObject({ id: "cpol_mcp_contract01", revision: 2, replay: true });
    const stored = await env.DB.prepare("SELECT revision,required_risk_classes_json FROM connector_policies WHERE id='cpol_mcp_contract01'").first<{ revision: number; required_risk_classes_json: string }>();
    expect(stored).toEqual({ revision: 2, required_risk_classes_json: '["secret_access"]' });
  });

  it("replays connector-policy creation with the original generated effect", async () => {
    const body = {
      id: "cpol_create_contract01",
      clientId: "https://client.example/mcp-contract",
      deviceSelector: { mode: "all" },
      projectSelector: { mode: "all" },
      allowedOperations: ["project.read"],
      allowedRuntimes: ["native"],
      maxAccessScope: "read_only",
      mostPermissiveApprovalMode: "always",
      requiredApprovalRiskClasses: ["raw_log_export"],
      rateLimitProfileId: "rate_mcp_contract01",
    };
    const request = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/connector-policies", {
      method: "POST",
      headers: {
        cookie: "__Host-conduit_session=browser_grant_session_token_0000000001",
        origin: "https://conduit.example.com",
        "x-csrf-token": "browser_grant_csrf_token_000000000001",
        "idempotency-key": "policy-create-contract-000001",
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    }));
    const first = await request();
    expect(first.status).toBe(201);
    await expect(first.json()).resolves.toMatchObject({ id: "cpol_create_contract01", revision: 1, requiredApprovalRiskClasses: ["raw_log_export"] });
    const replay = await request();
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toMatchObject({ id: "cpol_create_contract01", revision: 1, replay: true });
    const rows = await env.DB.prepare("SELECT COUNT(*) AS count FROM connector_policies WHERE id='cpol_create_contract01'").first<{ count: number }>();
    expect(rows?.count).toBe(1);
    const duplicate = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/connector-policies", {
      method: "POST",
      headers: {
        cookie: "__Host-conduit_session=browser_grant_session_token_0000000001",
        origin: "https://conduit.example.com",
        "x-csrf-token": "browser_grant_csrf_token_000000000001",
        "idempotency-key": "policy-create-duplicate-0001",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ...body, id: "cpol_duplicate_risks01", requiredApprovalRiskClasses: ["secret_access", "secret_access"] }),
    }));
    expect(duplicate.status).toBe(400);
    await expect(duplicate.json()).resolves.toMatchObject({ error: { code: "invalid_request" } });
  });

  it("operates Task links, owner grant reads, and owner CLI token lifecycle", async () => {
    const ownerToken = "conduit_owner_board_contract_token_00000001";
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO tasks(id,project_id,title,description,status,revision,created_at,updated_at) VALUES ('task_link_contract01','prj_board_contract','Linked task','','open',1,?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO tasks(id,project_id,title,description,status,revision,created_at,updated_at) VALUES ('task_dependency_contract01','prj_board_contract','Dependency','','open',1,?1,?1)").bind(now),
    ]);
    const taskRequest = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/tasks/task_link_contract01/links", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ownerToken}`,
        "content-type": "application/json",
        "idempotency-key": "task-link-contract-key-0001",
        "if-match": '"1"',
      },
      body: JSON.stringify({ dependsOnTaskId: "task_dependency_contract01" }),
    }));
    const linked = await taskRequest();
    expect(linked.status).toBe(200);
    expect(linked.headers.get("etag")).toBe('"2"');
    await expect(linked.json()).resolves.toMatchObject({ taskId: "task_link_contract01", dependsOnTaskId: "task_dependency_contract01", revision: 2 });
    const replay = await taskRequest();
    await expect(replay.json()).resolves.toMatchObject({ revision: 2, replay: true });
    const edge = await env.DB.prepare("SELECT COUNT(*) AS count FROM task_dependencies WHERE task_id='task_link_contract01' AND depends_on_task_id='task_dependency_contract01'").first<{ count: number }>();
    expect(edge?.count).toBe(1);

    const browserHeaders = { cookie: "__Host-conduit_session=browser_grant_session_token_0000000001" };
    const grants = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/oauth/grants", { headers: browserHeaders }));
    expect(grants.status).toBe(200);
    await expect(grants.json()).resolves.toMatchObject({ items: expect.arrayContaining([expect.objectContaining({ id: "grant_mcp_contract01" })]) });
    const grant = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/oauth/grants/grant_mcp_contract01", { headers: browserHeaders }));
    const grantBody = await grant.json<Record<string, unknown>>();
    expect(grantBody).toMatchObject({ id: "grant_mcp_contract01" });
    expect(grantBody).not.toHaveProperty("principal_id");

    const status = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/status", { headers: { authorization: `Bearer ${ownerToken}` } }));
    await expect(status.json()).resolves.toMatchObject({ authenticated: true, principalId: "prin_board_contract", tokenId: "otk_board_contract" });
    const logoutRequest = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/auth/logout", {
      method: "POST",
      headers: { authorization: `Bearer ${ownerToken}`, "content-type": "application/json", "idempotency-key": "owner-logout-contract-0001" },
      body: "{}",
    }));
    const logout = await logoutRequest();
    expect(logout.status).toBe(200);
    await expect(logout.json()).resolves.toMatchObject({ authenticated: false, tokenId: "otk_board_contract" });
    const logoutReplay = await logoutRequest();
    await expect(logoutReplay.json()).resolves.toMatchObject({ authenticated: false, tokenId: "otk_board_contract", replay: true });
  });

  it("enforces limiter idempotency and digest conflicts", async () => {
    const limiter = env.CONNECTOR_LIMITERS.getByName("grant-test");
    const base = { operationId: "op_test_00000001", idempotencyKey: "same-operation", payloadDigest: "a".repeat(64), family: "commandStart", weight: 2, requestLimit: 2, windowSeconds: 60, capacity: 10, refillPerSecond: 1, responseBytes: 10, normalizedLogBytes: 0, rawLogBytes: 0, artifactUploadBytes: 0, byteLimits: { response: 1000, normalizedDaily: 1000, rawDaily: 0, artifactDaily: 0 }, nowMs: 1_788_192_000_000 };
    await expect(limiter.admit(base)).resolves.toEqual({ allowed: true, charged: true });
    await expect(limiter.admit(base)).resolves.toEqual({ allowed: true, charged: false });
    await expect(limiter.admit({ ...base, payloadDigest: "b".repeat(64) })).resolves.toMatchObject({ allowed: false, code: "idempotency_conflict" });
  });

  it("rejects byte budgets before charging an operation", async () => {
    const limiter = env.CONNECTOR_LIMITERS.getByName("grant-byte-test");
    const decision = await limiter.admit({ operationId: "op_test_00000002", idempotencyKey: "oversized-response", payloadDigest: "c".repeat(64), family: "read", weight: 1, requestLimit: 10, windowSeconds: 60, capacity: 10, refillPerSecond: 1, responseBytes: 1001, normalizedLogBytes: 0, rawLogBytes: 0, artifactUploadBytes: 0, byteLimits: { response: 1000, normalizedDaily: 1000, rawDaily: 0, artifactDaily: 0 }, nowMs: 1_788_192_000_000 });
    expect(decision).toMatchObject({ allowed: false, code: "resource_limit", limitClass: "response_bytes" });
  });
});
