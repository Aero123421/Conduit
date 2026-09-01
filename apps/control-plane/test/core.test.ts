import { env, exports } from "cloudflare:workers";
import { parseWireDocumentText, schemaIds } from "@conduit/schema";
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, keyedHash, operationDigest, sha256Hex } from "../src/crypto.ts";
import { readJsonBounded } from "../src/bounds.ts";
import { CLI_CONTROL_PLANE_ROUTE_MANIFEST } from "../src/api.ts";
import { durableObjectOperationDispatcher, reconcileOperationDispatches, type OperationDispatcher } from "../src/dispatch.ts";
import { createOperation } from "../src/operations.ts";

describe.sequential("control-plane contracts", () => {
  beforeAll(async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    if (version === null) throw new Error("D1 migrations were not applied by the Workers test runtime");
  });

  it("applies forward D1 migrations", async () => {
    const version = await env.DB.prepare("SELECT version FROM schema_versions WHERE component='control_plane'").first<{ version: number }>();
    expect(version?.version).toBe(7);
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>();
    const names = new Set(tables.results.map((row) => row.name));
    for (const required of ["owner_principals", "oauth_grants", "connector_policies", "devices", "projects", "collaboration_sessions", "runs", "operation_journal", "operation_dispatch_outbox", "artifacts", "normalized_events", "security_events"]) expect(names.has(required)).toBe(true);
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
    expect(JSON.parse(row!.request_json)).toMatchObject({ actorPrincipalId: "prin_board_contract", accessScope: "full_user", approvalMode: "never" });
    const replay = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers, body: JSON.stringify(body) }));
    await expect(replay.json()).resolves.toMatchObject({ operationId: accepted.operationId, replay: true });
    const malformed = await exports.default.fetch(new Request("https://conduit.example.com/api/v1/operations", { method: "POST", headers: { ...headers, "idempotency-key": "owner-operation-contract-0002" }, body: JSON.stringify({ deviceId: "dev_handshake01", capability: "command.start" }) }));
    expect(malformed.status).toBe(400);
    await expect(malformed.json()).resolves.toMatchObject({ error: { code: "invalid_request" } });
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
    expect(await limiter.acquire("commands", 1)).toBe(true);
    expect(await limiter.acquire("commands", 1)).toBe(false);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,connector_policy_id,connector_policy_revision,connector_grant_id,concurrency_class,capability,payload_digest,request_json,state,expires_at,created_at,updated_at) VALUES (?1,'dispatch-expiry-idempotency-0001','prin_board_contract','connector.dispatch-expiry','dev_handshake01','cpol_dispatch_expiry01',1,?2,'commands','command.start',?3,'{}','queued',?4,?5,?5)").bind(operationId, grantId, digest, expiredAt, createdAt),
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES ('scope_dispatch_expiry01','dispatch-expiry-idempotency-0001',?1,?2,'queued',202,NULL,?3,?4)").bind(digest, operationId, expiredAt, createdAt),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at) VALUES (?1,'dev_handshake01',?2,?1,?3,?4,'pending',?5,?5,?6,?6)").bind(operationId, messageId, await sha256Hex(canonicalJson(payload)), canonicalJson(payload), expiredAt, createdAt),
    ]);
    expect(await reconcileOperationDispatches(env, { now })).toEqual({ examined: 1, offered: 0, pending: 0, expired: 1 });
    expect(await reconcileOperationDispatches(env, { now: new Date(now.getTime() + 1_000) })).toEqual({ examined: 0, offered: 0, pending: 0, expired: 0 });
    const states = await env.DB.prepare("SELECT (SELECT state FROM operation_journal WHERE id=?1) AS operation_state,(SELECT state FROM operation_dispatch_outbox WHERE operation_id=?1) AS dispatch_state,(SELECT state FROM idempotency_records WHERE operation_id=?1) AS idempotency_state").bind(operationId).first<{ operation_state: string; dispatch_state: string; idempotency_state: string }>();
    expect(states).toEqual({ operation_state: "expired", dispatch_state: "expired", idempotency_state: "expired" });
    const active = await runInDurableObject(limiter, (_instance, state) => state.storage.sql.exec<{ active: number }>("SELECT active FROM concurrency WHERE class='commands'").one().active);
    expect(active).toBe(0);
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
    const project = await call(3, "tools/call", { name: "project_get", arguments: { projectId: "prj_board_contract", requestKey: "mcp-project-read-000001" } });
    expect(project).toMatchObject({ result: { structuredContent: { id: "prj_board_contract", name: "Board" } } });
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
      body: JSON.stringify({ maxAccessScope: "read_only" }),
    }));
    const first = await request();
    expect(first.status).toBe(200);
    expect(first.headers.get("etag")).toBe('"2"');
    await expect(first.json()).resolves.toMatchObject({ id: "cpol_mcp_contract01", revision: 2, maxAccessScope: "read_only" });
    const replay = await request();
    expect(replay.status).toBe(200);
    expect(replay.headers.get("etag")).toBe('"2"');
    await expect(replay.json()).resolves.toMatchObject({ id: "cpol_mcp_contract01", revision: 2, replay: true });
    const stored = await env.DB.prepare("SELECT revision FROM connector_policies WHERE id='cpol_mcp_contract01'").first<{ revision: number }>();
    expect(stored?.revision).toBe(2);
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
    await expect(first.json()).resolves.toMatchObject({ id: "cpol_create_contract01", revision: 1 });
    const replay = await request();
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toMatchObject({ id: "cpol_create_contract01", revision: 1, replay: true });
    const rows = await env.DB.prepare("SELECT COUNT(*) AS count FROM connector_policies WHERE id='cpol_create_contract01'").first<{ count: number }>();
    expect(rows?.count).toBe(1);
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
