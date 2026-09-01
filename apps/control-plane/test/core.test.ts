import { env, exports } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, keyedHash, operationDigest, sha256Hex } from "../src/crypto.ts";
import { readJsonBounded } from "../src/bounds.ts";
import { CLI_CONTROL_PLANE_ROUTE_MANIFEST } from "../src/api.ts";

describe.sequential("control-plane contracts", () => {
  beforeAll(async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    if (version === null) throw new Error("D1 migrations were not applied by the Workers test runtime");
  });

  it("applies forward D1 migrations", async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    expect(version?.version).toBe(6);
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>();
    const names = new Set(tables.results.map((row) => row.name));
    for (const required of ["owner_principals", "oauth_grants", "connector_policies", "devices", "projects", "collaboration_sessions", "runs", "operation_journal", "artifacts", "normalized_events", "security_events"]) expect(names.has(required)).toBe(true);
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
    const response = await env.DEVICE_ROOMS.getByName(deviceId).fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
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
