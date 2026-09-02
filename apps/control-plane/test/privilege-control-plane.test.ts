import { env } from "cloudflare:workers";
import { parseWireDocument, schemaIds } from "@conduit/schema";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, sha256Hex } from "../src/crypto.ts";
import { parsePrivilegeTransportFrame, projectPrivilegeFrame, requireVerifiedPrivilegeReceipt, type PrivilegeTransportFrame } from "../src/privilege.ts";
import { assertFreeD1Ceilings, instrumentD1 } from "../src/usage-instrumentation.ts";
import type { ControlPlaneEnv } from "../src/types.ts";
import { projectNodeState } from "../src/node-projection.ts";

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
  const runtimeSpecDigest = "3".repeat(64);
  const launchPlanDigest = "4".repeat(64);
  const localPlanDigest = "5".repeat(64);
  const rootPolicyDigest = "6".repeat(64);
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
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,run_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,node_state_revision) VALUES ('op_privilegeflow01','operation-privilege-flow-0001','prin_privilegeflow01','conduit.cli','dev_privilegeflow01','run_privilegeflow01','cpol_owner_first_party_v1',1,'command.start',?1,?2,'offered','2099-09-03T00:10:00.000Z',?3,?3,'start',0)").bind(operationDigest, canonicalJson(request), now),
    ]);
  });

  it("strictly validates internal privilege transport frames", async () => {
    expect(() => parsePrivilegeTransportFrame({ protocol: "conduit.node/1", messageId: "nmsg_privilegebad01", deviceId: "dev_privilegeflow01", connectionEpoch: "7", direction: "node_to_control", sequence: "1", type: "privilege.ticket_request", payloadDigest: "0".repeat(64), payload: {}, surprise: true })).toThrow(/unknown field/);
  });

  it("registers an Owner-reviewed helper, issues replay-stable action tickets, and verifies chained root receipts", async () => {
    const capabilityClaims = {
      protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId: "phinst_privilegeflow01", receiptKeyId: "phkey_privilegeflow01", policyRevision: 1, policyDigest: rootPolicyDigest,
      enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true,
      freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: true, unavailableReason: null,
    };
    const policySummary = { enabled: true, allowedOperations: ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"], allowedAdapters: [], approvalEnforcements: ["exact_command"], allowNever: true, allowUnrestrictedLaunch: true };
    const devicePolicySummary = { ...policySummary };
    const policy = { revision: 1, policyDigest: rootPolicyDigest, previousPolicyDigest: null, publicSummary: policySummary, changeClass: "initial", signature: await sign(helperPrivate, { installationId: "phinst_privilegeflow01", revision: 1, policyDigest: rootPolicyDigest, previousPolicyDigest: null, publicSummary: policySummary, changeClass: "initial" }) };
    const devicePolicy = { revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary, signature: await sign(devicePrivate, { deviceId: "dev_privilegeflow01", revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary }) };
    const registration = await deviceSignedFrame("privilege.installation_attestation", "nmsg_privinstall001", "1", {
      requestId: "phreq_privilegeflow01", installationId: "phinst_privilegeflow01", expectedUid: 1000, publicOrigin: env.PUBLIC_ORIGIN, receiptPublicJwk: helperPublicJwk,
      signedCapability: { keyId: "phkey_privilegeflow01", claims: capabilityClaims, signature: await sign(helperPrivate, capabilityClaims) }, policy, devicePolicy, deviceKeyId: "dkey_privilegeflow01",
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, registration)).resolves.toMatchObject({ state: "pending_owner" });
    await env.DB.batch([
      env.DB.prepare("UPDATE privilege_installation_keys SET status='active',approved_at=?1 WHERE installation_id='phinst_privilegeflow01' AND key_id='phkey_privilegeflow01'").bind(now),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='active',approved_by='prin_privilegeflow01',approved_at=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(now),
      env.DB.prepare("UPDATE device_user_policy_attestations SET status='active' WHERE device_id='dev_privilegeflow01' AND revision=1"),
      env.DB.prepare("UPDATE device_privilege_installations SET active_key_id='phkey_privilegeflow01',active_policy_revision=1,active_policy_digest=?1,status='active',owner_principal_id='prin_privilegeflow01',approved_at=?2 WHERE installation_id='phinst_privilegeflow01'").bind(rootPolicyDigest, now),
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
    const ticketFrame = await deviceSignedFrame("privilege.ticket_request", "nmsg_privticket001", "2", ticketPayload, devicePrivate);
    const measured = instrumentD1(env.DB);
    const measuredEnv = new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) });
    const issued = await projectPrivilegeFrame(measuredEnv, ticketFrame) as { ticket: { keyId: string; claims: Record<string, unknown>; signature: string } };
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot().rowsWritten).toBeGreaterThanOrEqual(2);
    expect(issued.ticket.claims).toMatchObject({ allowedOperation: "prepare", operationId: "op_privilegeflow01", runtimeId: "rt_privilegeflow01", helperKeyId: "phkey_privilegeflow01" });
    const replay = await projectPrivilegeFrame(env, ticketFrame) as { ticket: unknown; replay: boolean };
    expect(replay).toMatchObject({ ticket: issued.ticket, replay: true });
    const ticketDigest = await sha256Hex(canonicalJson(issued.ticket));
    const receiptClaims = {
      protocol: "conduit.privileged/1", receiptId: "prcpt_privilegeflow01", installationId: "phinst_privilegeflow01", receiptKeyId: "phkey_privilegeflow01", helperVersion: "0.1.0",
      policyRevision: 1, policyDigest: rootPolicyDigest, ticketId: issued.ticket.claims.ticketId, ticketDigest, operationId: "op_privilegeflow01", requestDigest: operationDigest,
      runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest, controlRequestDigest: null,
      controllerEpoch: 7, stateRevision: 1, transition: "admitted", unitName: "conduit-elevated-rt_privilegeflow01.service", invocationId: null, cgroup: null, mainPid: null, processBirth: null,
      effectiveUid: 0, effectiveGid: 0, stdoutCursor: 0, stderrCursor: 0, exitCode: null, signal: null, observedAt: new Date().toISOString(), previousReceiptDigest: null,
    };
    durableReceipt = { keyId: "phkey_privilegeflow01", claims: receiptClaims, signature: await sign(helperPrivate, receiptClaims) };
    const receiptFrame = await deviceSignedFrame("privilege.receipt", "nmsg_privreceipt01", "3", { receipt: durableReceipt, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate);
    measured.reset();
    const verified = await projectPrivilegeFrame(measuredEnv, receiptFrame) as { receiptDigest: string };
    assertFreeD1Ceilings(measured.snapshot());
    expect(measured.snapshot().rowsWritten).toBeLessThanOrEqual(10);
    await expect(requireVerifiedPrivilegeReceipt(env, { operationId: "op_privilegeflow01", deviceId: "dev_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, receiptDigest: verified.receiptDigest, transition: "admission", runtimeId: "rt_privilegeflow01", controllerEpoch: "7" })).resolves.toBeUndefined();
    await expect(requireVerifiedPrivilegeReceipt(env, { operationId: "op_privilegeflow01", deviceId: "dev_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, receiptDigest: "f".repeat(64), transition: "running" })).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const unauthorizedClaims = { ...receiptClaims, receiptId: "prcpt_privbadact001", stateRevision: 2, transition: "failed", previousReceiptDigest: verified.receiptDigest, observedAt: new Date().toISOString() };
    const unauthorized = await deviceSignedFrame("privilege.receipt", "nmsg_privbadreceipt1", "4", { receipt: { keyId: "phkey_privilegeflow01", claims: unauthorizedClaims, signature: await sign(helperPrivate, unauthorizedClaims) }, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate);
    await expect(projectPrivilegeFrame(env, unauthorized)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
  });

  it("activates signed narrowing immediately and holds post-enable broadening for fresh Owner approval", async () => {
    const initialSummary = { enabled: true, allowedOperations: ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"], allowedAdapters: [], approvalEnforcements: ["exact_command"], allowNever: true, allowUnrestrictedLaunch: true };
    const devicePolicy = {
      revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: initialSummary,
      signature: await sign(devicePrivate, { deviceId: "dev_privilegeflow01", revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: initialSummary }),
    };
    const attest = async (input: { requestId: string; messageId: string; sequence: string; revision: number; digest: string; previousDigest: string; summary: Record<string, unknown>; changeClass: "narrowed" | "broadened" }) => {
      const capabilityClaims = {
        protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId: "phinst_privilegeflow01", receiptKeyId: "phkey_privilegeflow01", policyRevision: input.revision, policyDigest: input.digest,
        enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true,
        freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: true, unavailableReason: null,
      };
      const policy = {
        revision: input.revision, policyDigest: input.digest, previousPolicyDigest: input.previousDigest, publicSummary: input.summary, changeClass: input.changeClass,
        signature: await sign(helperPrivate, { installationId: "phinst_privilegeflow01", revision: input.revision, policyDigest: input.digest, previousPolicyDigest: input.previousDigest, publicSummary: input.summary, changeClass: input.changeClass }),
      };
      return projectPrivilegeFrame(env, await deviceSignedFrame("privilege.installation_attestation", input.messageId, input.sequence, {
        requestId: input.requestId, installationId: "phinst_privilegeflow01", expectedUid: 1000, publicOrigin: env.PUBLIC_ORIGIN, receiptPublicJwk: helperPublicJwk,
        signedCapability: { keyId: "phkey_privilegeflow01", claims: capabilityClaims, signature: await sign(helperPrivate, capabilityClaims) }, policy, devicePolicy, deviceKeyId: "dkey_privilegeflow01",
      }, devicePrivate));
    };
    const narrowedDigest = "8".repeat(64);
    const narrowedSummary = { ...initialSummary, allowedOperations: ["prepare", "start"], allowNever: false, allowUnrestrictedLaunch: false };
    await expect(attest({ requestId: "phreq_privnarrow001", messageId: "nmsg_privnarrow001", sequence: "4", revision: 2, digest: narrowedDigest, previousDigest: rootPolicyDigest, summary: narrowedSummary, changeClass: "narrowed" })).resolves.toMatchObject({ state: "active" });
    await expect(env.DB.prepare("SELECT active_policy_revision,active_policy_digest,status FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).resolves.toEqual({ active_policy_revision: 2, active_policy_digest: narrowedDigest, status: "active" });
    await expect(env.DB.prepare("SELECT status FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=1").first()).resolves.toEqual({ status: "superseded" });

    const broadenedDigest = "9".repeat(64);
    await expect(attest({ requestId: "phreq_privbroaden01", messageId: "nmsg_privbroaden01", sequence: "5", revision: 3, digest: broadenedDigest, previousDigest: narrowedDigest, summary: initialSummary, changeClass: "broadened" })).resolves.toMatchObject({ state: "pending_owner" });
    await expect(env.DB.prepare("SELECT active_policy_revision,active_policy_digest,status FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).resolves.toEqual({ active_policy_revision: 2, active_policy_digest: narrowedDigest, status: "policy_review" });
    await expect(env.DB.prepare("SELECT status FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=3").first()).resolves.toEqual({ status: "pending_owner" });
  });

  it("accepts an exact durable helper receipt replay couriered after a Device reconnect", async () => {
    await env.DB.prepare("UPDATE devices SET connection_epoch='8' WHERE id='dev_privilegeflow01'").run();
    const replay = await deviceSignedFrame("privilege.receipt", "nmsg_privreceiptreplay", "6", { receipt: durableReceipt, deviceKeyId: "dkey_privilegeflow01" }, devicePrivate, "8");
    await expect(projectPrivilegeFrame(env, replay)).resolves.toMatchObject({ status: "verified", replay: true });
  });
});
