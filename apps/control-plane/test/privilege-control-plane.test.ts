import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { parseWireDocument, parseWireDocumentText, schemaIds } from "@conduit/schema";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, sha256Hex } from "../src/crypto.ts";
import { parsePrivilegeTransportFrame, projectPrivilegeFrame, requireVerifiedPrivilegeReceipt, type PrivilegeTransportFrame } from "../src/privilege.ts";
import { assertFreeD1Ceilings, instrumentD1 } from "../src/usage-instrumentation.ts";
import type { ControlPlaneEnv } from "../src/types.ts";
import { projectNodeState } from "../src/node-projection.ts";
import type { DeviceRoom } from "../src/do/device-room.ts";
import { cleanupHotData } from "../src/retention.ts";

async function keyPair(): Promise<{ privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey;
  if (typeof exported.x !== "string") throw new TypeError("Ed25519 public key is unavailable");
  return { privateKey: pair.privateKey, publicJwk: { kty: "OKP", crv: "Ed25519", x: exported.x } };
}

async function sign(key: CryptoKey, value: unknown): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(canonicalJson(value)))));
}

async function deviceSignedFrame(type: PrivilegeTransportFrame["type"], messageId: string, sequence: string, payload: Record<string, unknown>, deviceKey: CryptoKey, courierEpoch = "7"): Promise<PrivilegeTransportFrame> {
  const unsigned = { ...payload };
  const deviceSignature = await sign(deviceKey, { domain: `conduit.${type}.v1`, deviceId: "dev_privilegeflow01", connectionEpoch: courierEpoch, payload: unsigned });
  const complete = { ...unsigned, deviceSignature };
  const receipt = payload.receipt !== null && typeof payload.receipt === "object" && !Array.isArray(payload.receipt) ? payload.receipt as Record<string, unknown> : undefined;
  const receiptClaims = receipt?.claims !== null && typeof receipt?.claims === "object" && !Array.isArray(receipt.claims) ? receipt.claims as Record<string, unknown> : undefined;
  const correlationId = type === "privilege.ticket_request" || type === "privilege.installation_attestation" ? String(payload.requestId) : String(receiptClaims?.operationId);
  const wire = { protocol: "conduit.node/1", messageId, deviceId: "dev_privilegeflow01", connectionEpoch: courierEpoch, direction: "node_to_control", sequence, type, correlationId, payloadDigest: await sha256Hex(canonicalJson(complete)), payload: complete };
  return parsePrivilegeTransportFrame(parseWireDocument(schemaIds.nodeV1, wire));
}

describe.sequential("privileged helper Control Plane", () => {
  let devicePrivate: CryptoKey;
  let helperPrivate: CryptoKey;
  let helperPublicJwk: JsonWebKey;
  let durableReceipt: { keyId: string; claims: Record<string, unknown>; signature: string };
  const now = "2026-09-03T00:00:00.000Z";
  const operationDigest = "1".repeat(64);
  const manifestDigest = "2".repeat(64);
  const crossRunManifestDigest = "e".repeat(64);
  const runtimeSpecDigest = "3".repeat(64);
  const launchPlanDigest = "4".repeat(64);
  const localPlanDigest = "5".repeat(64);
  let rootPolicyDigest = "";
  const devicePolicyDigest = "7".repeat(64);

  beforeAll(async () => {
    const device = await keyPair();
    const helper = await keyPair();
    devicePrivate = device.privateKey;
    helperPrivate = helper.privateKey;
    helperPublicJwk = helper.publicJwk;
    const deviceFingerprint = await sha256Hex(String(device.publicJwk.x));
    const request = {
      schemaVersion: 1, operationId: "op_privilegeflow01", idempotencyKey: "operation-privilege-flow-0001", actorPrincipalId: "prin_privilegeflow01", clientId: "conduit.cli",
      deviceId: "dev_privilegeflow01", runId: "run_privilegeflow01", connectorPolicyId: "cpol_owner_first_party_v1", connectorPolicyRevision: 1,
      capability: "command.start", accessScope: "full_device", approvalMode: "never", requiredApprovalRiskClasses: [],
      runtime: { kind: "native", providerId: "privileged-native", configurationRevision: 1 }, sourceRevisions: [], arguments: {},
      issuedAt: now, expiresAt: "2099-09-03T00:10:00.000Z", validForMs: 600_000, payloadDigest: operationDigest,
    };
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_privilegeflow01','Privilege test','active',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,approved_by,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_privilegeflow01','completed','dch_privilegeflow01','uch_privilegeflow01','{}','dkey_privilegeflow01',?1,?2,'challenge','signature','prin_privilegeflow01','dev_privilegeflow01',?3,'2099-09-03T00:00:00.000Z',?3)").bind(canonicalJson(device.publicJwk), deviceFingerprint, now),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,revision,connection_epoch,created_at,updated_at) VALUES ('dev_privilegeflow01','enroll_privilegeflow01','privilege-test','linux','x86_64','test','conduit.node/1','active',1,'7',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES ('dkey_privilegeflow01','dev_privilegeflow01',?1,?2,'active',?3)").bind(canonicalJson(device.publicJwk), deviceFingerprint, now),
      env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES ('run_privilegeflow01','dev_privilegeflow01','native','full_device','never','queued',1,?1,'{}',?2,?2)").bind(manifestDigest, now),
      env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES ('run_privilegecross02','dev_privilegeflow01','native','full_device','never','queued',1,?1,'{}',?2,?2)").bind(crossRunManifestDigest, now),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,run_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,node_state_revision) VALUES ('op_privilegeflow01','operation-privilege-flow-0001','prin_privilegeflow01','conduit.cli','dev_privilegeflow01','run_privilegeflow01','cpol_owner_first_party_v1',1,'command.start',?1,?2,'offered','2099-09-03T00:10:00.000Z',?3,?3,'start',0)").bind(operationDigest, canonicalJson(request), now),
    ]);
  });

  it("strictly validates internal privilege transport frames", async () => {
    expect(() => parsePrivilegeTransportFrame({ protocol: "conduit.node/1", messageId: "nmsg_privilegebad01", deviceId: "dev_privilegeflow01", connectionEpoch: "7", direction: "node_to_control", sequence: "1", type: "privilege.ticket_request", payloadDigest: "0".repeat(64), payload: {}, surprise: true })).toThrow(/unknown field/);
  });

  it("registers an Owner-reviewed helper, issues replay-stable action tickets, and verifies chained root receipts", async () => {
    const rootPolicy = {
      policyVersion: 1, installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", uid: 1000, revision: 1, enabled: true, origin: env.PUBLIC_ORIGIN,
      ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"],
      allowedAdapters: [], allowedLaunchProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null },
      allowNever: true, allowUnrestrictedLaunch: true, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
    };
    rootPolicyDigest = await sha256Hex(canonicalJson(rootPolicy));
    const helperKeyId = "hkey_privilegeflow01";
    const capabilityClaims = {
      protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId: "phinst_privilegeflow01", receiptKeyId: helperKeyId, policyRevision: 1, policyDigest: rootPolicyDigest,
      enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true,
      freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: true, unavailableReason: null,
    };
    const policySummary = { enabled: true, allowedOperations: rootPolicy.allowedOperations, allowedAdapters: [], approvalEnforcements: ["exact_command"], allowNever: true, allowUnrestrictedLaunch: true };
    const devicePolicySummary = { ...policySummary };
    const devicePolicy = { revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary, signature: await sign(devicePrivate, { deviceId: "dev_privilegeflow01", revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary }) };
    const registration = await deviceSignedFrame("privilege.installation_attestation", "nmsg_privinstall001", "1", {
      requestId: "phreq_privilegeflow01", registrationBundle: {
        protocol: "conduit.privileged/1", installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", deviceKeyId: "dkey_privilegeflow01", uid: 1000, origin: env.PUBLIC_ORIGIN,
        policyRevision: 1, policyDigest: rootPolicyDigest, receiptPublicJwk: { ...helperPublicJwk, kid: helperKeyId },
        signedPolicyAttestation: { keyId: helperKeyId, claims: rootPolicy, signature: await sign(helperPrivate, rootPolicy) },
        signedCapability: { keyId: helperKeyId, claims: capabilityClaims, signature: await sign(helperPrivate, capabilityClaims) },
      }, devicePolicy, deviceKeyId: "dkey_privilegeflow01",
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, registration)).resolves.toMatchObject({ state: "pending_owner" });
    await env.DB.batch([
      env.DB.prepare("UPDATE privilege_installation_keys SET status='active',approved_at=?1 WHERE installation_id='phinst_privilegeflow01' AND key_id='hkey_privilegeflow01'").bind(now),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='active',approved_by='prin_privilegeflow01',approved_at=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(now),
      env.DB.prepare("UPDATE device_user_policy_attestations SET status='active' WHERE device_id='dev_privilegeflow01' AND revision=1"),
      env.DB.prepare("UPDATE device_privilege_installations SET active_key_id='hkey_privilegeflow01',active_policy_revision=1,active_policy_digest=?1,status='active',owner_principal_id='prin_privilegeflow01',approved_at=?2 WHERE installation_id='phinst_privilegeflow01'").bind(rootPolicyDigest, now),
      env.DB.prepare("INSERT INTO privilege_issuer_keys(key_id,revision,public_jwk_json,fingerprint,status,valid_from,created_at) VALUES ('pkey_testissuer0001',1,?1,?2,'active',?3,?3)").bind(canonicalJson({ kty: "OKP", crv: "Ed25519", x: "BqRlMWvAVKLe2h6jRtRBlfOlZ8I2m5nuwkFqhm_cD0M" }), await sha256Hex("BqRlMWvAVKLe2h6jRtRBlfOlZ8I2m5nuwkFqhm_cD0M"), now),
    ]);
    const unsignedStatus = { protocol: "conduit.node/1", messageId: "nmsg_privstatusbad01", deviceId: "dev_privilegeflow01", connectionEpoch: "7", direction: "node_to_control", sequence: "4", type: "operation.status", correlationId: "op_privilegeflow01", payloadDigest: "8".repeat(64), payload: { operationId: "op_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, state: "running", revision: "1", controllerEpoch: "7", targetRuntimeId: "rt_privilegeflow01", targetDigest: "9".repeat(64), runtimeHandleDigest: "a".repeat(64), runtimeTargetDigest: "b".repeat(64), selectedRuntimeProvider: "privileged-native", observedAt: new Date().toISOString() } };
    await expect(projectNodeState(env, unsignedStatus as never)).rejects.toMatchObject({ code: "privilege_ticket_required" });
    await expect(env.DB.prepare("SELECT state FROM operation_journal WHERE id='op_privilegeflow01'").first<{ state: string }>()).resolves.toEqual({ state: "offered" });
    const ticketPayload = {
      requestId: "ptreq_privilegeflow01", idempotencyKey: "privilege-action-prepare-0001", installationId: "phinst_privilegeflow01", deviceKeyId: "dkey_privilegeflow01",
      operationId: "op_privilegeflow01", runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest,
      controlRequestDigest: null, runManifestDigest: manifestDigest, helperPolicyRevision: 1, helperPolicyDigest: rootPolicyDigest, devicePolicyRevision: 1,
      approvalReceiptDigest: null, approvalEnforcement: "exact_command", allowedOperation: "prepare",
      resourceCeilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, redactedSummary: { adapter: null, operation: "prepare" },
      requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString(),
    };
    const crossRun = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcrossrun01", "2", {
      ...ticketPayload, requestId: "ptreq_privcrossrun01", idempotencyKey: "privilege-cross-run-denial-0001", runManifestDigest: crossRunManifestDigest,
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, crossRun)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const sensitiveSummary = await deviceSignedFrame("privilege.ticket_request", "nmsg_privredactbad1", "2", {
      ...ticketPayload, requestId: "ptreq_privredactbad1", idempotencyKey: "privilege-redaction-denial-0001", redactedSummary: { cwd: "/home/person/private", operation: "prepare" },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, sensitiveSummary)).rejects.toThrow(/unknown field cwd/);
    const ticketFrame = await deviceSignedFrame("privilege.ticket_request", "nmsg_privticket001", "2", ticketPayload, devicePrivate);
    const measured = instrumentD1(env.DB);
    const measuredEnv = new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) });
    const issued = await projectPrivilegeFrame(measuredEnv, ticketFrame) as { ticket: { keyId: string; claims: Record<string, unknown>; signature: string } };
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot().rowsWritten).toBeGreaterThanOrEqual(2);
    expect(issued.ticket.claims).toMatchObject({ allowedOperation: "prepare", operationId: "op_privilegeflow01", runtimeId: "rt_privilegeflow01", helperKeyId: "hkey_privilegeflow01" });
    const replay = await projectPrivilegeFrame(env, ticketFrame) as { ticket: unknown; replay: boolean };
    expect(replay).toMatchObject({ ticket: issued.ticket, replay: true });
    const ticketDigest = await sha256Hex(canonicalJson(issued.ticket));
    const receiptClaims = {
      protocol: "conduit.privileged/1", receiptId: "prcpt_privilegeflow01", installationId: "phinst_privilegeflow01", receiptKeyId: "hkey_privilegeflow01", helperVersion: "0.1.0",
      policyRevision: 1, policyDigest: rootPolicyDigest, ticketId: issued.ticket.claims.ticketId, ticketDigest, operationId: "op_privilegeflow01", requestDigest: operationDigest,
      runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest, controlRequestDigest: null,
      controllerEpoch: 7, stateRevision: 1, transition: "admitted", unitName: "conduit-elevated-rt_privilegeflow01.service", invocationId: null, cgroup: null, mainPid: null, processBirth: null,
      effectiveUid: 0, effectiveGid: 0, stdoutCursor: 0, stderrCursor: 0, exitCode: null, signal: null, observedAt: new Date().toISOString(), previousReceiptDigest: null,
    };
    durableReceipt = { keyId: "hkey_privilegeflow01", claims: receiptClaims, signature: await sign(helperPrivate, receiptClaims) };
    const receiptFrame = await deviceSignedFrame("privilege.receipt", "nmsg_privreceipt01", "3", { receipt: durableReceipt, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate);
    measured.reset();
    const verified = await projectPrivilegeFrame(measuredEnv, receiptFrame) as { receiptDigest: string };
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot().rowsWritten).toBeLessThanOrEqual(10);
    await expect(requireVerifiedPrivilegeReceipt(env, { operationId: "op_privilegeflow01", deviceId: "dev_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, receiptDigest: verified.receiptDigest, transition: "admission", runtimeId: "rt_privilegeflow01", controllerEpoch: "7" })).resolves.toBeUndefined();
    await expect(requireVerifiedPrivilegeReceipt(env, { operationId: "op_privilegeflow01", deviceId: "dev_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, receiptDigest: "f".repeat(64), transition: "running" })).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const unauthorizedClaims = { ...receiptClaims, receiptId: "prcpt_privbadact001", stateRevision: 2, transition: "failed", previousReceiptDigest: verified.receiptDigest, observedAt: new Date().toISOString() };
    const unauthorized = await deviceSignedFrame("privilege.receipt", "nmsg_privbadreceipt1", "4", { receipt: { keyId: "hkey_privilegeflow01", claims: unauthorizedClaims, signature: await sign(helperPrivate, unauthorizedClaims) }, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate);
    await expect(projectPrivilegeFrame(env, unauthorized)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
  });

  it("activates signed narrowing immediately and holds post-enable broadening for fresh Owner approval", async () => {
    const allOperations = ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"];
    const policyClaims = (revision: number, narrowed: boolean) => ({
      policyVersion: 1, installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", uid: 1000, revision, enabled: true, origin: env.PUBLIC_ORIGIN,
      ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: narrowed ? ["prepare", "start"] : allOperations,
      allowedAdapters: [], allowedLaunchProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null },
      allowNever: true, allowUnrestrictedLaunch: !narrowed, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
    });
    const initialSummary = { enabled: true, allowedOperations: allOperations, allowedAdapters: [], approvalEnforcements: ["exact_command"], allowNever: true, allowUnrestrictedLaunch: true };
    const devicePolicy = {
      revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: initialSummary,
      signature: await sign(devicePrivate, { deviceId: "dev_privilegeflow01", revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: initialSummary }),
    };
    const attest = async (input: { requestId: string; messageId: string; sequence: string; revision: number; narrowed: boolean }) => {
      const rootPolicy = policyClaims(input.revision, input.narrowed);
      const digest = await sha256Hex(canonicalJson(rootPolicy));
      const capabilityClaims = {
        protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId: "phinst_privilegeflow01", receiptKeyId: "hkey_privilegeflow01", policyRevision: input.revision, policyDigest: digest,
        enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true,
        freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: true, unavailableReason: null,
      };
      const result = await projectPrivilegeFrame(env, await deviceSignedFrame("privilege.installation_attestation", input.messageId, input.sequence, {
        requestId: input.requestId, registrationBundle: {
          protocol: "conduit.privileged/1", installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", deviceKeyId: "dkey_privilegeflow01", uid: 1000, origin: env.PUBLIC_ORIGIN,
          policyRevision: input.revision, policyDigest: digest, receiptPublicJwk: { ...helperPublicJwk, kid: "hkey_privilegeflow01" },
          signedPolicyAttestation: { keyId: "hkey_privilegeflow01", claims: rootPolicy, signature: await sign(helperPrivate, rootPolicy) },
          signedCapability: { keyId: "hkey_privilegeflow01", claims: capabilityClaims, signature: await sign(helperPrivate, capabilityClaims) },
        }, devicePolicy, deviceKeyId: "dkey_privilegeflow01",
      }, devicePrivate));
      return { result, digest };
    };
    const narrowed = await attest({ requestId: "phreq_privnarrow001", messageId: "nmsg_privnarrow001", sequence: "4", revision: 2, narrowed: true });
    expect(narrowed.result).toMatchObject({ state: "active" });
    const narrowedDigest = narrowed.digest;
    await expect(env.DB.prepare("SELECT active_policy_revision,active_policy_digest,status FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).resolves.toEqual({ active_policy_revision: 2, active_policy_digest: narrowedDigest, status: "active" });
    await expect(env.DB.prepare("SELECT status FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=1").first()).resolves.toEqual({ status: "superseded" });

    const broadened = await attest({ requestId: "phreq_privbroaden01", messageId: "nmsg_privbroaden01", sequence: "5", revision: 3, narrowed: false });
    expect(broadened.result).toMatchObject({ state: "pending_owner" });
    const broadenedDigest = broadened.digest;
    await expect(env.DB.prepare("SELECT active_policy_revision,active_policy_digest,status FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).resolves.toEqual({ active_policy_revision: 2, active_policy_digest: narrowedDigest, status: "policy_review" });
    await expect(env.DB.prepare("SELECT status FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=3").first()).resolves.toEqual({ status: "pending_owner" });
  });

  it("accepts an exact durable helper receipt replay couriered after a Device reconnect", async () => {
    await env.DB.prepare("UPDATE devices SET connection_epoch='8' WHERE id='dev_privilegeflow01'").run();
    const replay = await deviceSignedFrame("privilege.receipt", "nmsg_privreceiptreplay", "6", { receipt: durableReceipt, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate, "8");
    await expect(projectPrivilegeFrame(env, replay)).resolves.toMatchObject({ status: "verified", replay: true });
  });

  it("bounds registration, policy, ticket, and receipt through real DeviceRoom WebSocket invocations", async () => {
    const deviceId = "dev_privilegeflow01";
    const deviceKeyId = "dkey_privilegeflow01";
    const response = await exports.default.fetch(new Request(`https://conduit.example.com/v1/devices/${deviceId}/connect`, { headers: { upgrade: "websocket" } }));
    expect(response.status).toBe(101);
    const socket = response.webSocket!;
    socket.accept();
    const queued: string[] = [];
    const waiters: Array<(message: string) => void> = [];
    let closed = "open";
    socket.addEventListener("close", (event) => { closed = `${event.code}:${event.reason}`; });
    socket.addEventListener("message", (event) => { const waiter = waiters.shift(); if (waiter === undefined) queued.push(String(event.data)); else waiter(String(event.data)); });
    let responseOrdinal = 0;
    const next = () => Promise.race([
      queued.length > 0 ? Promise.resolve(queued.shift()!) : new Promise<string>((resolve) => waiters.push(resolve)),
      new Promise<string>((_resolve, reject) => setTimeout(() => reject(new Error(`privilege DeviceRoom response ${responseOrdinal} timeout (${closed})`)), 2_000)),
    ]).then((message) => { responseOrdinal += 1; return message; });
    const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
    socket.send(JSON.stringify({ type: "device.hello", deviceId, keyId: deviceKeyId, supportedProtocols: ["conduit.node/1"], capabilityDigest: "a".repeat(64), clientNonce, nodeBootId: "node-boot-privilege-budget-0001" }));
    const challenge = parseWireDocumentText(schemaIds.nodeV1, await next());
    if (challenge.type !== "device.challenge") throw new Error("expected Device challenge");
    const authTranscript = { domain: "conduit.device-auth.v1", origin: env.PUBLIC_ORIGIN, clientNonce, connectionId: challenge.connectionId, deviceId, keyId: deviceKeyId, protocol: challenge.selectedProtocol, serverNonce: challenge.serverNonce, serverTime: challenge.serverTime };
    socket.send(JSON.stringify({ type: "device.proof", connectionId: challenge.connectionId, deviceId, keyId: deviceKeyId, signature: await sign(devicePrivate, authTranscript) }));
    const accepted = parseWireDocumentText(schemaIds.nodeV1, await next());
    if (accepted.type !== "transport.accepted") throw new Error("expected transport acceptance");
    let sequence = 1;
    const sendFrame = async (type: PrivilegeTransportFrame["type"] | "reconcile.summary" | "reconcile.complete" | "transport.ack", unsigned: Record<string, unknown>, correlationId?: string) => {
      const payload = type.startsWith("privilege.")
        ? { ...unsigned, deviceSignature: await sign(devicePrivate, { domain: `conduit.${type}.v1`, deviceId, connectionEpoch: accepted.connectionEpoch, payload: unsigned }) }
        : unsigned;
      socket.send(JSON.stringify({ protocol: "conduit.node/1", messageId: `nmsg_privbudget_${sequence.toString().padStart(4, "0")}`, deviceId, connectionEpoch: accepted.connectionEpoch, direction: "node_to_control", sequence: String(sequence++), type, ...(correlationId === undefined ? {} : { correlationId }), payloadDigest: await sha256Hex(canonicalJson(payload)), payload }));
    };
    await sendFrame("reconcile.summary", { nodeBootId: "node-boot-privilege-budget-0001", journalGeneration: "1", capabilityDigest: "a".repeat(64), lastControlSequenceApplied: "0", lastNodeSequenceAcknowledged: "0", lastNodeSequenceRetained: "1", runs: [], retainedEventRanges: [], unresolvedCount: 0, truncated: false, storageHealth: "healthy" }, accepted.connectionId);
    const reconciliation = [parseWireDocumentText(schemaIds.nodeV1, await next()), parseWireDocumentText(schemaIds.nodeV1, await next())];
    const plan = reconciliation.find((frame) => frame.type === "reconcile.plan");
    if (plan?.type !== "reconcile.plan") throw new Error("expected reconcile plan");
    await sendFrame("reconcile.complete", { reconciliationId: plan.payload.reconciliationId, lastControlSequenceApplied: plan.sequence, lastNodeSequenceAcknowledged: "1", unresolvedRunIds: [] }, plan.payload.reconciliationId);
    expect(parseWireDocumentText(schemaIds.nodeV1, await next()).type).toBe("transport.ack");
    await sendFrame("transport.ack", { direction: "control_to_node", throughSequence: plan.sequence });

    const room = env.DEVICE_ROOMS.getByName(deviceId);
    const measured = instrumentD1(env.DB);
    let originalEnv: ControlPlaneEnv | undefined;
    await runInDurableObject(room, (instance: DeviceRoom) => {
      const holder = instance as unknown as { env: ControlPlaneEnv };
      originalEnv = holder.env;
      Object.defineProperty(instance, "env", { value: new Proxy(holder.env, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) }), configurable: true });
    });
    const assertInvocation = () => {
      const snapshot = measured.snapshot();
      assertFreeD1Ceilings(snapshot);
      expect(snapshot.statements).toBeGreaterThan(0);
      expect(snapshot.bindingCalls).toBeLessThanOrEqual(40);
      expect(snapshot.maxBoundParameters).toBeLessThanOrEqual(90);
      measured.reset();
    };
    const receiveAck = async (through: string) => {
      const frame = parseWireDocumentText(schemaIds.nodeV1, await next());
      expect(frame).toMatchObject({ type: "transport.ack", payload: { throughSequence: through } });
    };
    const devicePolicySummary = { enabled: true, allowedOperations: ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"], allowedAdapters: [], approvalEnforcements: ["exact_command"], allowNever: true, allowUnrestrictedLaunch: true };
    const devicePolicy = { revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary, signature: await sign(devicePrivate, { deviceId, revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary }) };
    const bundleFor = async (installationId: string, revision: number, operations: string[], uid = 1000) => {
      const root = {
        policyVersion: 1, installationId, deviceId, uid, revision, enabled: true, origin: env.PUBLIC_ORIGIN, ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: operations,
        allowedAdapters: [], allowedLaunchProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, allowNever: true,
        allowUnrestrictedLaunch: false, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
      };
      const digest = await sha256Hex(canonicalJson(root));
      const capability = { protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId, receiptKeyId: "hkey_privilegeflow01", policyRevision: revision, policyDigest: digest, enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true, freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: false, unavailableReason: null };
      return { digest, bundle: { protocol: "conduit.privileged/1", installationId, deviceId, deviceKeyId, uid, origin: env.PUBLIC_ORIGIN, policyRevision: revision, policyDigest: digest, receiptPublicJwk: { ...helperPublicJwk, kid: "hkey_privilegeflow01" }, signedPolicyAttestation: { keyId: "hkey_privilegeflow01", claims: root, signature: await sign(helperPrivate, root) }, signedCapability: { keyId: "hkey_privilegeflow01", claims: capability, signature: await sign(helperPrivate, capability) } } };
    };
    try {
      const initial = await bundleFor("phinst_privbudgetnew1", 1, ["prepare"], 1001);
      const registrationSequence = String(sequence);
      await sendFrame("privilege.installation_attestation", { requestId: "phreq_privbudgetnew1", registrationBundle: initial.bundle, devicePolicy, deviceKeyId }, "phreq_privbudgetnew1");
      await receiveAck(registrationSequence);
      assertInvocation();
      expect(await env.DB.prepare("SELECT status,expected_uid FROM device_privilege_installations WHERE installation_id='phinst_privbudgetnew1'").first()).toEqual({ status: "pending_owner", expected_uid: 1001 });

      const reattestation = await bundleFor("phinst_privilegeflow01", 4, ["prepare"]);
      const policySequence = String(sequence);
      await sendFrame("privilege.installation_attestation", { requestId: "phreq_privbudgetpol1", registrationBundle: reattestation.bundle, devicePolicy, deviceKeyId }, "phreq_privbudgetpol1");
      await receiveAck(policySequence);
      assertInvocation();
      expect(await env.DB.prepare("SELECT active_policy_revision,active_policy_digest FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).toEqual({ active_policy_revision: 4, active_policy_digest: reattestation.digest });

      const ticketRequestId = "ptreq_privbudget0001";
      const ticketSequence = String(sequence);
      await sendFrame("privilege.ticket_request", { requestId: ticketRequestId, idempotencyKey: "privilege-device-room-budget-0001", installationId: "phinst_privilegeflow01", deviceKeyId, operationId: "op_privilegeflow01", runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest, controlRequestDigest: null, runManifestDigest: manifestDigest, helperPolicyRevision: 4, helperPolicyDigest: reattestation.digest, devicePolicyRevision: 1, approvalReceiptDigest: null, approvalEnforcement: "exact_command", allowedOperation: "prepare", resourceCeilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, redactedSummary: { operation: "prepare" }, requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString() }, ticketRequestId);
      const ticketFrames = [parseWireDocumentText(schemaIds.nodeV1, await next()), parseWireDocumentText(schemaIds.nodeV1, await next())];
      const result = ticketFrames.find((frame) => frame.type === "privilege.ticket_result");
      expect(ticketFrames.find((frame) => frame.type === "transport.ack")).toMatchObject({ payload: { throughSequence: ticketSequence } });
      if (result?.type !== "privilege.ticket_result" || result.payload.status !== "issued") throw new Error("expected issued privilege ticket");
      assertInvocation();
      const ticket = result.payload.ticket as { claims: Record<string, unknown> };
      const previousReceiptDigest = await sha256Hex(canonicalJson(durableReceipt));
      const receiptClaims = { ...durableReceipt.claims, receiptId: "prcpt_privbudget0001", ticketId: ticket.claims.ticketId, ticketDigest: await sha256Hex(canonicalJson(result.payload.ticket)), policyRevision: 4, policyDigest: reattestation.digest, controllerEpoch: Number(accepted.connectionEpoch), stateRevision: 2, transition: "prepared", observedAt: new Date().toISOString(), previousReceiptDigest };
      const receiptSequence = String(sequence);
      await sendFrame("privilege.receipt", { receipt: { keyId: "hkey_privilegeflow01", claims: receiptClaims, signature: await sign(helperPrivate, receiptClaims) }, deviceKeyId }, "op_privilegeflow01");
      await receiveAck(receiptSequence);
      assertInvocation();
      expect(await env.DB.prepare("SELECT transition FROM privilege_receipt_projections WHERE receipt_id='prcpt_privbudget0001'").first()).toEqual({ transition: "prepared" });
    } finally {
      if (originalEnv !== undefined) await runInDurableObject(room, (instance: DeviceRoom) => { Object.defineProperty(instance, "env", { value: originalEnv, configurable: true }); });
      socket.close(1000, "privilege_budget_complete");
    }
  });

  it("keeps a completely idle privilege room free of D1 writes, polling rows, and alarms", async () => {
    const room = env.DEVICE_ROOMS.getByName("dev_privilege_idle_budget01");
    const result = await runInDurableObject(room, async (instance: DeviceRoom, durable) => {
      const holder = instance as unknown as { env: ControlPlaneEnv };
      const original = holder.env;
      const measured = instrumentD1(original.DB);
      Object.defineProperty(instance, "env", { value: new Proxy(original, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) }), configurable: true });
      try { await instance.alarm(); } finally { Object.defineProperty(instance, "env", { value: original, configurable: true }); }
      return {
        usage: measured.snapshot(), alarm: await durable.storage.getAlarm(),
        inbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM inbound_frames").one().count,
        outbound: durable.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM outbound_frames").one().count,
        marker: durable.storage.sql.exec<{ pending: number; min_due_at: number | null }>("SELECT pending,min_due_at FROM room_work_marker WHERE singleton=1").one(),
      };
    });
    expect(result).toEqual({ usage: { statements: 0, bindingCalls: 0, boundParameters: [], maxBoundParameters: 0, rowsRead: 0, rowsWritten: 0 }, alarm: null, inbound: 0, outbound: 0, marker: { pending: 0, min_due_at: null } });
  });

  it("converges denied ticket retention without deleting signed security evidence or storing sensitive summaries", async () => {
    const old = "2026-01-01T00:00:00.000Z";
    await env.DB.prepare(`
      INSERT INTO privilege_ticket_requests(
        request_id,device_id,device_key_id,connection_epoch,idempotency_key,idempotency_key_digest,installation_id,operation_id,assignment_id,run_id,runtime_id,
        runtime_spec_digest,launch_plan_digest,local_execution_plan_digest,control_request_digest,operation_request_digest,run_manifest_digest,helper_policy_revision,
        helper_policy_digest,device_policy_revision,connector_policy_id,connector_policy_revision,project_revision,project_agent_id,project_agent_revision,device_revision,
        runtime_configuration_revision,approval_receipt_digest,approval_enforcement,allowed_operation,resource_ceilings_json,redacted_summary_json,request_digest,
        device_signature,status,denial_code,requested_at,expires_at,terminal_at
      ) SELECT
        'ptreq_privretention1',device_id,device_key_id,connection_epoch,'privilege-retention-denied-0001',?1,installation_id,operation_id,assignment_id,run_id,runtime_id,
        runtime_spec_digest,launch_plan_digest,local_execution_plan_digest,control_request_digest,operation_request_digest,run_manifest_digest,helper_policy_revision,
        helper_policy_digest,device_policy_revision,connector_policy_id,connector_policy_revision,project_revision,project_agent_id,project_agent_revision,device_revision,
        runtime_configuration_revision,approval_receipt_digest,approval_enforcement,allowed_operation,resource_ceilings_json,'{"operation":"prepare"}',?2,
        device_signature,'denied','retention_test',?3,?3,?3
      FROM privilege_ticket_requests WHERE request_id='ptreq_privilegeflow01'
    `).bind("c".repeat(64), "d".repeat(64), old).run();
    const measured = instrumentD1(env.DB);
    const first = await cleanupHotData(new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) }), { now: new Date("2026-09-03T00:00:00.000Z"), limit: 100 });
    assertFreeD1Ceilings(measured.snapshot());
    expect(first.deletedRows).toBeGreaterThanOrEqual(1);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_requests WHERE request_id='ptreq_privretention1'").first()).toEqual({ count: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_issuance WHERE request_id='ptreq_privilegeflow01'").first()).toEqual({ count: 1 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_receipt_projections WHERE receipt_id IN ('prcpt_privilegeflow01','prcpt_privbudget0001')").first()).toEqual({ count: 2 });
    const persisted = await env.DB.prepare("SELECT redacted_summary_json FROM privilege_ticket_requests WHERE request_id='ptreq_privilegeflow01'").first<{ redacted_summary_json: string }>();
    expect(persisted?.redacted_summary_json).not.toContain("/home/");
    expect(persisted?.redacted_summary_json).not.toMatch(/secret|credential|token/i);
    const replay = await cleanupHotData(env, { now: new Date("2026-09-03T00:00:01.000Z"), limit: 100 });
    expect(replay.hasMore).toBe(false);
  });
});
