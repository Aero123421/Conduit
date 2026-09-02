import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { parseWireDocument, parseWireDocumentText, schemaIds } from "@conduit/schema";
import { beforeAll, describe, expect, it } from "vitest";
import { base64url, canonicalJson, fromBase64url, keyedHash, sha256Hex } from "../src/crypto.ts";
import { assertDevicePolicyTransition, handlePrivilegeAdmin, isDevicePolicyNarrower, parsePrivilegeTransportFrame, projectPrivilegeFrame, requireVerifiedPrivilegeReceipt, rootPolicySummary, type PrivilegeTransportFrame } from "../src/privilege.ts";
import { assertFreeD1Ceilings, instrumentD1, PRIVILEGE_OUTER_INVOCATION_D1_ROW_CEILINGS, type D1UsageSnapshot } from "../src/usage-instrumentation.ts";
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

async function deviceSignedFrame(type: PrivilegeTransportFrame["type"], messageId: string, sequence: string, payload: Record<string, unknown>, deviceKey: CryptoKey, courierEpoch = "7", deviceId = "dev_privilegeflow01"): Promise<PrivilegeTransportFrame> {
  const unsigned = { ...payload };
  const deviceSignature = await sign(deviceKey, { domain: `conduit.${type}.v1`, deviceId, connectionEpoch: courierEpoch, payload: unsigned });
  const complete = { ...unsigned, deviceSignature };
  const receipt = payload.receipt !== null && typeof payload.receipt === "object" && !Array.isArray(payload.receipt) ? payload.receipt as Record<string, unknown> : undefined;
  const receiptClaims = receipt?.claims !== null && typeof receipt?.claims === "object" && !Array.isArray(receipt.claims) ? receipt.claims as Record<string, unknown> : undefined;
  const correlationId = type === "privilege.ticket_request" || type === "privilege.installation_attestation" ? String(payload.requestId) : String(receiptClaims?.operationId);
  const wire = { protocol: "conduit.node/1", messageId, deviceId, connectionEpoch: courierEpoch, direction: "node_to_control", sequence, type, correlationId, payloadDigest: await sha256Hex(canonicalJson(complete)), payload: complete };
  return parsePrivilegeTransportFrame(parseWireDocument(schemaIds.nodeV1, wire));
}

describe.sequential("privileged helper Control Plane", () => {
  let devicePrivate: CryptoKey;
  let helperPrivate: CryptoKey;
  let helperPublicJwk: JsonWebKey;
  let durableReceipt: { keyId: string; claims: Record<string, unknown>; signature: string };
  const now = new Date(Date.now() - 1_000).toISOString();
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
      runtime: { kind: "native", providerId: "privileged-native", configurationRevision: 1 }, sourceRevisions: [], arguments: { launchProfileId: "safe" },
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
    const localPolicy = { revision: 1, capabilities: ["command.start"], providers: ["privileged-native"], accessScopes: ["full_device"], approvalModes: ["never"], requiredApprovalRiskClasses: ["shell"], launchProfiles: ["safe"], credentialProfiles: ["cred_allowed01"], maxCpu: 2, maxMemoryBytes: 2048, maxStorageBytes: 4096, allowFullAccessWithoutApproval: true };
    expect(isDevicePolicyNarrower(localPolicy, { ...localPolicy, revision: 2, capabilities: [], requiredApprovalRiskClasses: ["shell", "network"], maxCpu: 1, allowFullAccessWithoutApproval: false })).toBe(true);
    expect(isDevicePolicyNarrower(localPolicy, { ...localPolicy, revision: 2, requiredApprovalRiskClasses: [] })).toBe(false);
    const firstDigest = "1".repeat(64);
    const secondDigest = "2".repeat(64);
    expect(() => assertDevicePolicyTransition(null, { revision: 1, policyDigest: firstDigest, previousPolicyDigest: null })).not.toThrow();
    expect(() => assertDevicePolicyTransition({ revision: 1, policyDigest: firstDigest, previousPolicyDigest: null }, { revision: 2, policyDigest: secondDigest, previousPolicyDigest: firstDigest })).not.toThrow();
    expect(() => assertDevicePolicyTransition({ revision: 1, policyDigest: firstDigest, previousPolicyDigest: null }, { revision: 2, policyDigest: secondDigest, previousPolicyDigest: null })).toThrow(/exact active predecessor/);
    expect(() => assertDevicePolicyTransition({ revision: 1, policyDigest: firstDigest, previousPolicyDigest: null }, { revision: 1, policyDigest: secondDigest, previousPolicyDigest: firstDigest })).toThrow(/increase its revision/);
    const executableDigest = "d".repeat(64);
    expect(rootPolicySummary({ enabled: true, ticketKeyIds: [], allowedOperations: [], allowedAdapters: [], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: { safe: executableDigest }, allowedCredentialProfiles: ["cred_allowed01"], ceilings: {}, allowNever: false, allowUnrestrictedLaunch: false, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 60 })).toMatchObject({ launchProfileExecutableDigests: { safe: executableDigest }, allowedCredentialProfiles: ["cred_allowed01"] });
    expect(() => rootPolicySummary({ launchProfileExecutableDigests: { "/home/user/bin/tool": executableDigest } })).toThrow(/bounded profile IDs/);
  });

  it("registers an Owner-reviewed helper, issues replay-stable action tickets, and verifies chained root receipts", async () => {
    const rootPolicy = {
      policyVersion: 1, installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", uid: 1000, revision: 1, enabled: true, origin: env.PUBLIC_ORIGIN,
      ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"],
      allowedAdapters: [], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null },
      allowNever: true, allowUnrestrictedLaunch: true, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
    };
    rootPolicyDigest = await sha256Hex(canonicalJson(rootPolicy));
    const helperKeyId = "hkey_privilegeflow01";
    const capabilityClaims = {
      protocol: "conduit.privileged/1", helperVersion: "0.1.0", installationId: "phinst_privilegeflow01", receiptKeyId: helperKeyId, policyRevision: 1, policyDigest: rootPolicyDigest,
      enabled: true, observedAt: new Date().toISOString(), systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true,
      freeze: true, pidfd: true, openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: true, unavailableReason: null,
    };
    const devicePolicySummary = {
      revision: 1, capabilities: ["command.start"], providers: ["privileged-native"], accessScopes: ["full_device"], approvalModes: ["never"],
      requiredApprovalRiskClasses: [], launchProfiles: ["safe"], maxCpu: null, maxMemoryBytes: null, maxStorageBytes: null, allowFullAccessWithoutApproval: true,
    };
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
      env.DB.prepare("UPDATE device_privilege_installations SET active_key_id='hkey_privilegeflow01',active_policy_revision=1,active_policy_digest=?1,status='active',owner_principal_id='prin_privilegeflow01',owner_decision_digest=?2,approved_at=?3 WHERE installation_id='phinst_privilegeflow01'").bind(rootPolicyDigest, "6".repeat(64), now),
      env.DB.prepare("INSERT INTO privilege_issuer_keys(key_id,revision,public_jwk_json,fingerprint,status,valid_from,created_at) VALUES ('pkey_testissuer0001',1,?1,?2,'active',?3,?3)").bind(canonicalJson({ kty: "OKP", crv: "Ed25519", x: "BqRlMWvAVKLe2h6jRtRBlfOlZ8I2m5nuwkFqhm_cD0M" }), await sha256Hex(fromBase64url("BqRlMWvAVKLe2h6jRtRBlfOlZ8I2m5nuwkFqhm_cD0M")), now),
    ]);
    const storedRootPolicy = await env.DB.prepare("SELECT public_summary_json FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=1").first<{ public_summary_json: string }>();
    const storedDevicePolicy = await env.DB.prepare("SELECT public_summary_json FROM device_user_policy_attestations WHERE device_id='dev_privilegeflow01' AND revision=1").first<{ public_summary_json: string }>();
    if (storedRootPolicy === null || storedDevicePolicy === null) throw new Error("privilege policy projection disappeared");
    await env.DB.batch([
      env.DB.prepare("UPDATE privilege_policy_attestations SET public_summary_json=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedRootPolicy.public_summary_json), allowUnrestrictedLaunch: false, launchProfileExecutableDigests: { safe: "d".repeat(64) }, allowedCredentialProfiles: ["cred_allowed01", "cred_rootonly01"] })),
      env.DB.prepare("UPDATE device_user_policy_attestations SET public_summary_json=?1 WHERE device_id='dev_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedDevicePolicy.public_summary_json), launchProfiles: ["safe"], credentialProfiles: ["cred_allowed01"] })),
    ]);
    const unsignedStatus = { protocol: "conduit.node/1", messageId: "nmsg_privstatusbad01", deviceId: "dev_privilegeflow01", connectionEpoch: "7", direction: "node_to_control", sequence: "4", type: "operation.status", correlationId: "op_privilegeflow01", payloadDigest: "8".repeat(64), payload: { operationId: "op_privilegeflow01", runId: "run_privilegeflow01", requestDigest: operationDigest, state: "running", revision: "1", controllerEpoch: "7", targetRuntimeId: "rt_privilegeflow01", targetDigest: "9".repeat(64), runtimeHandleDigest: "a".repeat(64), runtimeTargetDigest: "b".repeat(64), selectedRuntimeProvider: "privileged-native", observedAt: new Date().toISOString() } };
    await expect(projectNodeState(env, unsignedStatus as never)).rejects.toMatchObject({ code: "privilege_ticket_required" });
    await expect(env.DB.prepare("SELECT state FROM operation_journal WHERE id='op_privilegeflow01'").first<{ state: string }>()).resolves.toEqual({ state: "offered" });
    const ticketPayload = {
      requestId: "ptreq_privilegeflow01", idempotencyKey: "privilege-action-prepare-0001", installationId: "phinst_privilegeflow01", deviceKeyId: "dkey_privilegeflow01",
      operationId: "op_privilegeflow01", runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest,
      controlRequestDigest: null, controlAuthority: null, runManifestDigest: manifestDigest, helperPolicyRevision: 1, helperPolicyDigest: rootPolicyDigest, devicePolicyRevision: 1,
      approvalReceiptDigest: null, approvalEnforcement: "exact_command", allowedOperation: "prepare",
      resourceCeilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, redactedSummary: { adapter: null, operation: "prepare", credentialProfiles: [] },
      requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString(),
    };
    const storedCapability = await env.DB.prepare("SELECT capability_summary_json FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first<{ capability_summary_json: string }>();
    if (storedCapability === null) throw new Error("privilege capability projection disappeared");
    const effectiveCapability = JSON.parse(storedCapability.capability_summary_json) as Record<string, unknown>;
    const mandatoryCapabilityFields = ["systemdSystemManager", "socketPeerCredentials", "transientUnits", "cgroupV2", "freeze", "pidfd", "openat2", "execveat", "pty", "streamReplay"];
    for (const [index, field] of mandatoryCapabilityFields.entries()) {
      await env.DB.prepare("UPDATE device_privilege_installations SET capability_summary_json=?1 WHERE installation_id='phinst_privilegeflow01'")
        .bind(canonicalJson({ ...effectiveCapability, [field]: false, unavailableReason: `${field}_unavailable` })).run();
      const unavailable = await deviceSignedFrame("privilege.ticket_request", `nmsg_capdeny${String(index).padStart(4, "0")}`, "2", {
        ...ticketPayload,
        requestId: `ptreq_capdeny${String(index).padStart(4, "0")}`,
        idempotencyKey: `privilege-capability-denial-${String(index).padStart(4, "0")}`,
      }, devicePrivate);
      await expect(projectPrivilegeFrame(env, unavailable)).rejects.toMatchObject({ code: "full_device_capability_unavailable" });
    }
    await env.DB.prepare("UPDATE device_privilege_installations SET capability_summary_json=?1 WHERE installation_id='phinst_privilegeflow01'")
      .bind(storedCapability.capability_summary_json).run();
    const crossRun = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcrossrun01", "2", {
      ...ticketPayload, requestId: "ptreq_privcrossrun01", idempotencyKey: "privilege-cross-run-denial-0001", runManifestDigest: crossRunManifestDigest,
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, crossRun)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const sensitiveSummary = await deviceSignedFrame("privilege.ticket_request", "nmsg_privredactbad1", "2", {
      ...ticketPayload, requestId: "ptreq_privredactbad1", idempotencyKey: "privilege-redaction-denial-0001", redactedSummary: { cwd: "/home/person/private", operation: "prepare" },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, sensitiveSummary)).rejects.toThrow(/unknown field cwd/);
    const secretSummary = await deviceSignedFrame("privilege.ticket_request", "nmsg_privredactbad2", "2", {
      ...ticketPayload, requestId: "ptreq_privredactbad2", idempotencyKey: "privilege-redaction-denial-0002", redactedSummary: { operation: "prepare", credentialProfiles: [{ profileId: "sk_live_supersecret", revision: 1 }] },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, secretSummary)).rejects.toThrow(/profileId is invalid/);
    const rootDeniedCredential = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcreddeny01", "2", {
      ...ticketPayload, requestId: "ptreq_privcreddeny01", idempotencyKey: "privilege-root-credential-denial-1", redactedSummary: { operation: "prepare", credentialProfiles: [{ profileId: "cred_unlisted01", revision: 1 }] },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, rootDeniedCredential)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const deviceDeniedCredential = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcreddeny02", "2", {
      ...ticketPayload, requestId: "ptreq_privcreddeny02", idempotencyKey: "privilege-device-credential-denial", redactedSummary: { operation: "prepare", credentialProfiles: [{ profileId: "cred_rootonly01", revision: 1 }] },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, deviceDeniedCredential)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    const activeRootSummary = JSON.parse((await env.DB.prepare("SELECT public_summary_json FROM privilege_policy_attestations WHERE installation_id='phinst_privilegeflow01' AND revision=1").first<{ public_summary_json: string }>())!.public_summary_json) as Record<string, unknown>;
    const activeCapabilitySummary = JSON.parse((await env.DB.prepare("SELECT capability_summary_json FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first<{ capability_summary_json: string }>())!.capability_summary_json) as Record<string, unknown>;
    const activeDeviceSummary = JSON.parse((await env.DB.prepare("SELECT public_summary_json FROM device_user_policy_attestations WHERE device_id='dev_privilegeflow01' AND revision=1").first<{ public_summary_json: string }>())!.public_summary_json) as Record<string, unknown>;
    const neverAttempt = async (suffix: string) => projectPrivilegeFrame(env, await deviceSignedFrame("privilege.ticket_request", `nmsg_privnever${suffix}`, "2", {
      ...ticketPayload, requestId: `ptreq_privnever${suffix}`, idempotencyKey: `privilege-never-matrix-${suffix}-01`,
    }, devicePrivate));
    await env.DB.prepare("UPDATE privilege_policy_attestations SET public_summary_json=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(canonicalJson({ ...activeRootSummary, allowNever: false })).run();
    await expect(neverAttempt("rootdeny1")).rejects.toMatchObject({ code: "full_device_never_local_opt_in_required" });
    await env.DB.batch([
      env.DB.prepare("UPDATE privilege_policy_attestations SET public_summary_json=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(canonicalJson(activeRootSummary)),
      env.DB.prepare("UPDATE device_privilege_installations SET capability_summary_json=?1 WHERE installation_id='phinst_privilegeflow01'").bind(canonicalJson({ ...activeCapabilitySummary, neverOptIn: false })),
    ]);
    await expect(neverAttempt("capdeny1")).rejects.toMatchObject({ code: "full_device_never_local_opt_in_required" });
    await env.DB.batch([
      env.DB.prepare("UPDATE device_privilege_installations SET capability_summary_json=?1 WHERE installation_id='phinst_privilegeflow01'").bind(canonicalJson(activeCapabilitySummary)),
      env.DB.prepare("UPDATE device_user_policy_attestations SET public_summary_json=?1 WHERE device_id='dev_privilegeflow01' AND revision=1").bind(canonicalJson({ ...activeDeviceSummary, approvalModes: [] })),
    ]);
    await expect(neverAttempt("serverdn1")).rejects.toMatchObject({ code: "privileged_helper_policy_mismatch" });
    await env.DB.prepare("UPDATE device_user_policy_attestations SET public_summary_json=?1 WHERE device_id='dev_privilegeflow01' AND revision=1").bind(canonicalJson(activeDeviceSummary)).run();
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
    const originalOperation = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id='op_privilegeflow01'").first<{ request_json: string }>();
    if (originalOperation === null) throw new Error("privilege start operation disappeared");
    const agentRequest = { ...JSON.parse(originalOperation.request_json), capability: "agent.run.start", arguments: { adapterId: "codex" } };
    await env.DB.batch([
      env.DB.prepare("UPDATE operation_journal SET request_json=?1 WHERE id='op_privilegeflow01'").bind(canonicalJson(agentRequest)),
      env.DB.prepare("INSERT INTO runtime_custody(runtime_id,run_id,start_operation_id,device_id,provider_id,handle_digest,target_digest,controller_epoch,state,revision,created_at,updated_at) VALUES ('rt_privilegeflow01','run_privilegeflow01','op_privilegeflow01','dev_privilegeflow01','privileged-native',?1,?2,'7','running',1,?3,?3)").bind("9".repeat(64), "8".repeat(64), now),
      env.DB.prepare("UPDATE privilege_policy_attestations SET public_summary_json=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedRootPolicy.public_summary_json), allowedAdapters: ["codex"], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: ["cred_allowed01", "cred_rootonly01"] })),
      env.DB.prepare("UPDATE device_user_policy_attestations SET public_summary_json=?1 WHERE device_id='dev_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedDevicePolicy.public_summary_json), capabilities: ["command.start", "agent.run.start"], launchProfiles: ["safe"], credentialProfiles: ["cred_allowed01"] })),
    ]);
    const initialAgentInput = await deviceSignedFrame("privilege.ticket_request", "nmsg_privinitialin1", "4", {
      ...ticketPayload, requestId: "ptreq_privinitialin1", idempotencyKey: "privilege-initial-agent-input-01", controlRequestDigest: "6".repeat(64),
      controlAuthority: { kind: "initial_agent_input", agentStateRevision: "1", targetControllerEpoch: "7" }, approvalEnforcement: "adapter_mediated", allowedOperation: "input", redactedSummary: { operation: "input", adapter: "codex", credentialProfiles: [] },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, initialAgentInput)).resolves.toMatchObject({ status: "issued", ticket: { claims: { operationId: "op_privilegeflow01", allowedOperation: "input", controlDigest: "6".repeat(64) } } });
    const duplicateInitialAgentInput = await deviceSignedFrame("privilege.ticket_request", "nmsg_privinitialin2", "4", {
      ...ticketPayload, requestId: "ptreq_privinitialin2", idempotencyKey: "privilege-initial-agent-input-02", controlRequestDigest: "6".repeat(64),
      controlAuthority: { kind: "initial_agent_input", agentStateRevision: "1", targetControllerEpoch: "7" }, approvalEnforcement: "adapter_mediated", allowedOperation: "input", redactedSummary: { operation: "input", adapter: "codex", credentialProfiles: [] },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, duplicateInitialAgentInput)).rejects.toMatchObject({ code: "privilege_ticket_conflict" });
    await expect(env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_requests WHERE operation_id='op_privilegeflow01' AND control_authority_kind='initial_agent_input' AND control_authority_revision='1'").first()).resolves.toEqual({ count: 1 });
    const unauthorizedLifecycle = await deviceSignedFrame("privilege.ticket_request", "nmsg_privinternbad1", "4", {
      ...ticketPayload, requestId: "ptreq_privinternbad1", idempotencyKey: "privilege-internal-lifecycle-deny", controlRequestDigest: "6".repeat(64),
      controlAuthority: { kind: "agent_lifecycle_stop", terminal: "completed", reasonCode: null, agentStateRevision: "1", targetControllerEpoch: "7" }, approvalEnforcement: "adapter_mediated", allowedOperation: "force_stop", redactedSummary: { operation: "force_stop", adapter: "codex" },
    }, devicePrivate);
    await expect(projectPrivilegeFrame(env, unauthorizedLifecycle)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });
    await env.DB.batch([
      env.DB.prepare("DELETE FROM runtime_custody WHERE runtime_id='rt_privilegeflow01'"),
      env.DB.prepare("UPDATE operation_journal SET request_json=?1 WHERE id='op_privilegeflow01'").bind(originalOperation.request_json),
      env.DB.prepare("UPDATE privilege_policy_attestations SET public_summary_json=?1 WHERE installation_id='phinst_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedRootPolicy.public_summary_json), allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: ["cred_allowed01", "cred_rootonly01"] })),
      env.DB.prepare("UPDATE device_user_policy_attestations SET public_summary_json=?1 WHERE device_id='dev_privilegeflow01' AND revision=1").bind(canonicalJson({ ...JSON.parse(storedDevicePolicy.public_summary_json), launchProfiles: ["safe"], credentialProfiles: ["cred_allowed01"] })),
    ]);
  });

  it("binds control tickets to their own operation and rejects terminal or cross-Device request reuse", async () => {
    const requestPayload = (overrides: Record<string, unknown> = {}) => ({
      requestId: "ptreq_privcontrol001", idempotencyKey: "privilege-runtime-control-0001", installationId: "phinst_privilegeflow01", deviceKeyId: "dkey_privilegeflow01",
      operationId: "op_privcontrol001", runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest,
      controlRequestDigest: "8".repeat(64), controlAuthority: { kind: "external_control", targetControllerEpoch: "7" }, runManifestDigest: manifestDigest, helperPolicyRevision: 1, helperPolicyDigest: rootPolicyDigest, devicePolicyRevision: 1,
      approvalReceiptDigest: null, approvalEnforcement: "exact_command", allowedOperation: "pause",
      resourceCeilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, redactedSummary: { operation: "pause" },
      requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString(), ...overrides,
    });
    const control = {
      operationId: "op_privcontrol001", idempotencyKey: "runtime-control-operation-0001", targetRunId: "run_privilegeflow01", targetRuntimeId: "rt_privilegeflow01",
      targetHandleDigest: "9".repeat(64), targetControllerEpoch: "7", targetDigest: "8".repeat(64), expectedState: "running", expectedRevision: "1", control: "pause",
    };
    const controlDigest = await sha256Hex(canonicalJson(control));
    const expiresAt = new Date(Date.now() + 600_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO runtime_custody(runtime_id,run_id,start_operation_id,device_id,provider_id,handle_digest,target_digest,controller_epoch,state,revision,created_at,updated_at) VALUES ('rt_privilegeflow01','run_privilegeflow01','op_privilegeflow01','dev_privilegeflow01','privileged-native',?1,?2,'7','running',1,?3,?3)").bind("9".repeat(64), "8".repeat(64), now),
      env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,run_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,target_operation_id,target_runtime_id,target_digest,target_controller_epoch,expected_target_state,expected_target_revision,node_state_revision) VALUES ('op_privcontrol001','runtime-control-operation-0001','prin_privilegeflow01','conduit.cli','dev_privilegeflow01','run_privilegeflow01','cpol_owner_first_party_v1',1,'runtime.control',?1,?2,'offered',?3,?4,?4,'runtime_control','op_privilegeflow01','rt_privilegeflow01',?5,'7','running',1,0)").bind(controlDigest, canonicalJson(control), expiresAt, now, "8".repeat(64)),
    ]);

    const legacyStartId = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcontrolold1", "7", requestPayload({ requestId: "ptreq_privcontrolold1", idempotencyKey: "privilege-control-old-start-0001", operationId: "op_privilegeflow01", controlRequestDigest: controlDigest }), devicePrivate);
    await expect(projectPrivilegeFrame(env, legacyStartId)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });

    await env.DB.prepare("UPDATE devices SET connection_epoch='8' WHERE id='dev_privilegeflow01'").run();
    const valid = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcontrol001", "7", requestPayload({ controlRequestDigest: controlDigest }), devicePrivate, "8");
    const measured = instrumentD1(env.DB);
    const measuredEnv = new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) });
    const issued = await projectPrivilegeFrame(measuredEnv, valid) as { ticket: { claims: Record<string, unknown> } };
    assertFreeD1Ceilings(measured.snapshot());
    expect(issued.ticket.claims).toMatchObject({ operationId: "op_privcontrol001", operationRequestDigest: controlDigest, controlDigest, allowedOperation: "pause", controllerEpoch: 7 });
    const courierEpochSubstitution = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcontrolepoch", "8", requestPayload({
      requestId: "ptreq_privcontrolepoch",
      idempotencyKey: "privilege-control-courier-epoch-01",
      controlRequestDigest: controlDigest,
      controlAuthority: { kind: "external_control", targetControllerEpoch: "8" },
    }), devicePrivate, "8");
    await expect(projectPrivilegeFrame(env, courierEpochSubstitution)).rejects.toMatchObject({ code: "privilege_ticket_invalid" });

    await env.DB.prepare("UPDATE operation_journal SET state='failed' WHERE id='op_privcontrol001'").run();
    const terminal = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcontrolterm", "8", requestPayload({ requestId: "ptreq_privcontrolterm", idempotencyKey: "privilege-control-terminal-0001", controlRequestDigest: controlDigest }), devicePrivate, "8");
    await expect(projectPrivilegeFrame(env, terminal)).rejects.toMatchObject({ code: "privilege_ticket_expired" });

    const other = await keyPair();
    const otherFingerprint = await sha256Hex(String(other.publicJwk.x));
    await env.DB.batch([
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,approved_by,assigned_device_id,created_at,expires_at,terminal_at) VALUES ('enroll_privilegeother1','completed','dch_privilegeother1','uch_privilegeother1','{}','dkey_privilegeother1',?1,?2,'challenge','signature','prin_privilegeflow01','dev_privilegeother1',?3,?4,?3)").bind(canonicalJson(other.publicJwk), otherFingerprint, now, expiresAt),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,revision,connection_epoch,created_at,updated_at) VALUES ('dev_privilegeother1','enroll_privilegeother1','other-device','linux','x86_64','test','conduit.node/1','active',1,'1',?1,?1)").bind(now),
      env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES ('dkey_privilegeother1','dev_privilegeother1',?1,?2,'active',?3)").bind(canonicalJson(other.publicJwk), otherFingerprint, now),
    ]);
    const collisionPayload = requestPayload({ idempotencyKey: "privilege-cross-device-collision-1", deviceKeyId: "dkey_privilegeother1" });
    const collision = await deviceSignedFrame("privilege.ticket_request", "nmsg_privcrossdevice1", "1", collisionPayload, other.privateKey, "1", "dev_privilegeother1");
    await expect(projectPrivilegeFrame(env, collision)).rejects.toMatchObject({ code: "privilege_ticket_conflict" });
    await env.DB.prepare("UPDATE devices SET connection_epoch='7' WHERE id='dev_privilegeflow01'").run();
  });

  it("activates signed narrowing immediately and holds post-enable broadening for fresh Owner approval", async () => {
    const allOperations = ["prepare", "start", "input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop", "reconcile"];
    const policyClaims = (revision: number, narrowed: boolean) => ({
      policyVersion: 1, installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", uid: 1000, revision, enabled: true, origin: env.PUBLIC_ORIGIN,
      ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: narrowed ? ["prepare", "start"] : allOperations,
      allowedAdapters: [], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null },
      allowNever: true, allowUnrestrictedLaunch: true, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
    });
    const initialSummary = {
      revision: 1, capabilities: ["command.start"], providers: ["privileged-native"], accessScopes: ["full_device"], approvalModes: ["never"],
      requiredApprovalRiskClasses: [], launchProfiles: ["safe"], maxCpu: null, maxMemoryBytes: null, maxStorageBytes: null, allowFullAccessWithoutApproval: true,
    };
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
    const invocations: Array<{ flow: "registration" | "policy" | "ticket" | "receipt"; usage: D1UsageSnapshot }> = [];
    const assertInvocation = (flow: (typeof invocations)[number]["flow"]) => {
      const snapshot = measured.snapshot();
      assertFreeD1Ceilings(snapshot, PRIVILEGE_OUTER_INVOCATION_D1_ROW_CEILINGS);
      expect(snapshot.statements).toBeGreaterThan(0);
      expect(snapshot.rowsRead).toBeGreaterThan(0);
      expect(snapshot.rowsWritten).toBeGreaterThan(0);
      invocations.push({ flow, usage: snapshot });
      measured.reset();
    };
    const receiveAck = async (through: string) => {
      const frame = parseWireDocumentText(schemaIds.nodeV1, await next());
      expect(frame).toMatchObject({ type: "transport.ack", payload: { throughSequence: through } });
    };
    const devicePolicySummary = {
      revision: 1, capabilities: ["command.start"], providers: ["privileged-native"], accessScopes: ["full_device"], approvalModes: ["never"],
      requiredApprovalRiskClasses: [], launchProfiles: ["safe"], maxCpu: null, maxMemoryBytes: null, maxStorageBytes: null, allowFullAccessWithoutApproval: true,
    };
    const devicePolicy = { revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary, signature: await sign(devicePrivate, { deviceId, revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary }) };
    const bundleFor = async (installationId: string, revision: number, operations: string[], uid = 1000) => {
      const root = {
        policyVersion: 1, installationId, deviceId, uid, revision, enabled: true, origin: env.PUBLIC_ORIGIN, ticketKeyIds: ["pkey_testissuer0001"], allowedOperations: operations,
        allowedAdapters: [], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: [], ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, allowNever: true,
        allowUnrestrictedLaunch: true, allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
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
      assertInvocation("registration");
      expect(await env.DB.prepare("SELECT status,expected_uid FROM device_privilege_installations WHERE installation_id='phinst_privbudgetnew1'").first()).toEqual({ status: "pending_owner", expected_uid: 1001 });

      const reattestation = await bundleFor("phinst_privilegeflow01", 4, ["prepare"]);
      const policySequence = String(sequence);
      await sendFrame("privilege.installation_attestation", { requestId: "phreq_privbudgetpol1", registrationBundle: reattestation.bundle, devicePolicy, deviceKeyId }, "phreq_privbudgetpol1");
      await receiveAck(policySequence);
      assertInvocation("policy");
      expect(await env.DB.prepare("SELECT active_policy_revision,active_policy_digest FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first()).toEqual({ active_policy_revision: 4, active_policy_digest: reattestation.digest });

      const ticketRequestId = "ptreq_privbudget0001";
      const ticketSequence = String(sequence);
      await sendFrame("privilege.ticket_request", { requestId: ticketRequestId, idempotencyKey: "privilege-device-room-budget-0001", installationId: "phinst_privilegeflow01", deviceKeyId, operationId: "op_privilegeflow01", runId: "run_privilegeflow01", runtimeId: "rt_privilegeflow01", runtimeSpecDigest, launchPlanDigest, localExecutionPlanDigest: localPlanDigest, controlRequestDigest: null, controlAuthority: null, runManifestDigest: manifestDigest, helperPolicyRevision: 4, helperPolicyDigest: reattestation.digest, devicePolicyRevision: 1, approvalReceiptDigest: null, approvalEnforcement: "exact_command", allowedOperation: "prepare", resourceCeilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, redactedSummary: { operation: "prepare" }, requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 120_000).toISOString() }, ticketRequestId);
      const ticketFrames = [parseWireDocumentText(schemaIds.nodeV1, await next()), parseWireDocumentText(schemaIds.nodeV1, await next())];
      const result = ticketFrames.find((frame) => frame.type === "privilege.ticket_result");
      expect(ticketFrames.find((frame) => frame.type === "transport.ack")).toMatchObject({ payload: { throughSequence: ticketSequence } });
      if (result?.type !== "privilege.ticket_result" || result.payload.status !== "issued") throw new Error("expected issued privilege ticket");
      assertInvocation("ticket");
      const ticket = result.payload.ticket as { claims: Record<string, unknown> };
      const previousReceiptDigest = await sha256Hex(canonicalJson(durableReceipt));
      const receiptClaims = { ...durableReceipt.claims, receiptId: "prcpt_privbudget0001", ticketId: ticket.claims.ticketId, ticketDigest: await sha256Hex(canonicalJson(result.payload.ticket)), policyRevision: 4, policyDigest: reattestation.digest, controllerEpoch: Number(accepted.connectionEpoch), stateRevision: 2, transition: "prepared", observedAt: new Date().toISOString(), previousReceiptDigest };
      const receiptSequence = String(sequence);
      await sendFrame("privilege.receipt", { receipt: { keyId: "hkey_privilegeflow01", claims: receiptClaims, signature: await sign(helperPrivate, receiptClaims) }, deviceKeyId }, "op_privilegeflow01");
      await receiveAck(receiptSequence);
      assertInvocation("receipt");
      expect(await env.DB.prepare("SELECT transition FROM privilege_receipt_projections WHERE receipt_id='prcpt_privbudget0001'").first()).toEqual({ transition: "prepared" });
      expect(invocations.map(({ flow }) => flow)).toEqual(["registration", "policy", "ticket", "receipt"]);
      for (const { usage } of invocations) {
        expect(usage).toMatchObject({
          statements: expect.any(Number),
          bindingCalls: expect.any(Number),
          maxBoundParameters: expect.any(Number),
          rowsRead: expect.any(Number),
          rowsWritten: expect.any(Number),
        });
      }
      console.log(`CONDUIT_PRIVILEGE_OUTER_D1_BUDGET=${JSON.stringify(invocations)}`);
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
    const scheduler = env.RETRY_SCHEDULER.getByName(`privilege-retention-${crypto.randomUUID()}`);
    await scheduler.backstop("2026-09-03T00:00:00.000Z");
    expect(await scheduler.inspectTarget("retention", "hot-data")).toEqual({ dueAt: "2026-09-03T00:00:00.000Z" });
    const measured = instrumentD1(env.DB);
    const first = await cleanupHotData(new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "DB" ? measured.db : Reflect.get(target, property, receiver) }), { now: new Date("2026-09-03T00:00:00.000Z"), limit: 100 });
    assertFreeD1Ceilings(measured.snapshot());
    expect(first.deletedRows).toBeGreaterThanOrEqual(1);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_requests WHERE request_id='ptreq_privretention1'").first()).toEqual({ count: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_issuance WHERE request_id='ptreq_privilegeflow01'").first()).toEqual({ count: 1 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_receipt_projections WHERE receipt_id IN ('prcpt_privilegeflow01','prcpt_privbudget0001')").first()).toEqual({ count: 2 });
    const persisted = await env.DB.prepare("SELECT redacted_summary_json FROM privilege_ticket_requests WHERE request_id='ptreq_privilegeflow01'").first<{ redacted_summary_json: string }>();
    expect(persisted?.redacted_summary_json).not.toContain("/home/");
    expect(persisted?.redacted_summary_json).not.toMatch(/secret|token/i);
    const replay = await cleanupHotData(env, { now: new Date("2026-09-03T00:00:01.000Z"), limit: 100 });
    expect(replay.hasMore).toBe(false);
  });

  it("requires fresh browser authority for helper and issuer rotation, then revokes outstanding tickets", async () => {
    const pepper = env.TOKEN_PEPPER;
    const freshToken = "privilege-browser-fresh-session-0001";
    const freshCsrf = "privilege-browser-fresh-csrf-000001";
    const staleToken = "privilege-browser-stale-session-0001";
    const staleCsrf = "privilege-browser-stale-csrf-000001";
    const fresh = new Date().toISOString();
    const stale = new Date(Date.now() - 600_000).toISOString();
    const expires = new Date(Date.now() + 600_000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_privfresh001','prin_privilegeflow01',?1,?2,'owner','active',?3,?3,?3,?4,1)").bind(await keyedHash(pepper, freshToken), await keyedHash(pepper, freshCsrf), fresh, expires),
      env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_privstale001','prin_privilegeflow01',?1,?2,'owner','active',?3,?3,?4,?5,1)").bind(await keyedHash(pepper, staleToken), await keyedHash(pepper, staleCsrf), stale, fresh, expires),
    ]);
    const headers = (token: string, csrf: string) => ({ cookie: `__Host-conduit_session=${token}; __Host-conduit_csrf=${csrf}`, origin: env.PUBLIC_ORIGIN, "x-csrf-token": csrf, "content-type": "application/json" });

    const issuer = await keyPair();
    const issuerPrivateJwk = await crypto.subtle.exportKey("jwk", issuer.privateKey) as JsonWebKey;
    const originalKeys = JSON.parse(env.PRIVILEGE_TICKET_SIGNING_KEYS_JSON) as { activeKeyId: string; keys: unknown[] };
    const rotatedEnv = new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "PRIVILEGE_TICKET_SIGNING_KEYS_JSON" ? JSON.stringify({ activeKeyId: "pkey_testissuer0002", keys: [...originalKeys.keys, { keyId: "pkey_testissuer0002", revision: 2, privateJwk: issuerPrivateJwk }] }) : Reflect.get(target, property, receiver) });
    const rotateRequest = new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/issuer/activate`, { method: "POST", headers: headers(freshToken, freshCsrf), body: "{}" });
    const rotated = await handlePrivilegeAdmin(rotateRequest, rotatedEnv, "/v1/privileged/issuer/activate");
    expect(rotated?.status).toBe(200);
    expect(await env.DB.prepare("SELECT status,predecessor_key_id,rotation_statement_digest FROM privilege_issuer_keys WHERE key_id='pkey_testissuer0002'").first()).toMatchObject({ status: "active", predecessor_key_id: "pkey_testissuer0001", rotation_statement_digest: expect.stringMatching(/^[a-f0-9]{64}$/) });

    const rotatedHelper = await keyPair();
    const helperKeyId = "hkey_privilegeflow02";
    const devicePolicySummary = {
      revision: 1, capabilities: ["command.start"], providers: ["privileged-native"], accessScopes: ["full_device"], approvalModes: ["never"],
      requiredApprovalRiskClasses: [], launchProfiles: ["safe"], maxCpu: null, maxMemoryBytes: null, maxStorageBytes: null, allowFullAccessWithoutApproval: true,
    };
    const devicePolicy = { revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary, signature: await sign(devicePrivate, { deviceId: "dev_privilegeflow01", revision: 1, policyDigest: devicePolicyDigest, previousPolicyDigest: null, publicSummary: devicePolicySummary }) };
    const policy = {
      policyVersion: 1, installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", uid: 1000, revision: 5, enabled: true, origin: env.PUBLIC_ORIGIN,
      ticketKeyIds: ["pkey_testissuer0001", "pkey_testissuer0002"], allowedOperations: ["prepare"], allowedAdapters: [], allowedLaunchProfiles: ["safe"], launchProfileExecutableDigests: {}, allowedCredentialProfiles: [],
      ceilings: { cpuQuotaPerSecUsec: null, memoryMaxBytes: null, tasksMax: null, ioWeight: null, runtimeMaxUsec: null }, allowNever: true, allowUnrestrictedLaunch: false,
      allowPersistentSessions: false, allowOfflineControl: false, receiptRetentionSeconds: 86400,
    };
    const policyDigest = await sha256Hex(canonicalJson(policy));
    const device = await env.DB.prepare("SELECT connection_epoch FROM devices WHERE id='dev_privilegeflow01'").first<{ connection_epoch: string }>();
    if (device === null) throw new Error("privilege test Device disappeared");
    const capability = {
      protocol: "conduit.privileged/1", helperVersion: "0.1.1", installationId: "phinst_privilegeflow01", receiptKeyId: helperKeyId, policyRevision: 5, policyDigest,
      enabled: true, observedAt: fresh, systemdSystemManager: true, socketPeerCredentials: true, transientUnits: true, cgroupV2: true, freeze: true, pidfd: true,
      openat2: true, execveat: true, pty: true, streamReplay: true, neverOptIn: true, unrestrictedLaunchOptIn: false, unavailableReason: null,
    };
    const rotation = await deviceSignedFrame("privilege.installation_attestation", "nmsg_privkeyrotate1", "9", {
      requestId: "phreq_privkeyrotate1", registrationBundle: {
        protocol: "conduit.privileged/1", installationId: "phinst_privilegeflow01", deviceId: "dev_privilegeflow01", deviceKeyId: "dkey_privilegeflow01", uid: 1000,
        origin: env.PUBLIC_ORIGIN, policyRevision: 5, policyDigest, receiptPublicJwk: { ...rotatedHelper.publicJwk, kid: helperKeyId },
        signedPolicyAttestation: { keyId: helperKeyId, claims: policy, signature: await sign(rotatedHelper.privateKey, policy) },
        signedCapability: { keyId: helperKeyId, claims: capability, signature: await sign(rotatedHelper.privateKey, capability) },
      }, devicePolicy, deviceKeyId: "dkey_privilegeflow01",
    }, devicePrivate, device.connection_epoch);
    await expect(projectPrivilegeFrame(env, rotation)).resolves.toMatchObject({ state: "pending_owner" });
    expect(await env.DB.prepare("SELECT status,predecessor_key_id FROM privilege_installation_keys WHERE installation_id='phinst_privilegeflow01' AND key_id=?1").bind(helperKeyId).first()).toEqual({ status: "pending_owner", predecessor_key_id: "hkey_privilegeflow01" });

    const installation = await env.DB.prepare("SELECT device_attestation_digest FROM device_privilege_installations WHERE installation_id='phinst_privilegeflow01'").first<{ device_attestation_digest: string }>();
    const decisionBody = JSON.stringify({ decision: "approve", expectedAttestationDigest: installation?.device_attestation_digest });
    const staleResponse = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations/phinst_privilegeflow01/decision`, { method: "POST", headers: headers(staleToken, staleCsrf), body: decisionBody }));
    expect(staleResponse.status).toBe(403);
    await expect(staleResponse.json()).resolves.toMatchObject({ error: { code: "fresh_authentication_required" } });
    const badCsrf = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations/phinst_privilegeflow01/decision`, { method: "POST", headers: headers(freshToken, "wrong-privilege-csrf-token"), body: decisionBody }));
    expect(badCsrf.status).toBe(403);
    const list = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations`, { headers: { cookie: `__Host-conduit_session=${freshToken}` } }));
    const listed = await list.json<{ installations: Array<Record<string, unknown>> }>();
    expect(listed.installations.find((item) => item.installation_id === "phinst_privilegeflow01")).toMatchObject({ helper_key_fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/), reviewed_policy_digest: policyDigest, capability_summary_json: { enabled: true } });
    const approved = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations/phinst_privilegeflow01/decision`, { method: "POST", headers: headers(freshToken, freshCsrf), body: decisionBody }));
    expect(approved.status, await approved.clone().text()).toBe(200);
    expect(await env.DB.prepare("SELECT key_id,status FROM privilege_installation_keys WHERE installation_id='phinst_privilegeflow01' ORDER BY key_id").all()).toMatchObject({ results: [{ key_id: "hkey_privilegeflow01", status: "retiring" }, { key_id: helperKeyId, status: "active" }] });
    const approvalReplay = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations/phinst_privilegeflow01/decision`, { method: "POST", headers: headers(freshToken, freshCsrf), body: decisionBody }));
    expect(approvalReplay.status, await approvalReplay.clone().text()).toBe(200);

    const revokeIssuer = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/issuer/pkey_testissuer0001/revoke`, { method: "POST", headers: headers(freshToken, freshCsrf), body: "{}" }));
    expect(revokeIssuer.status).toBe(204);
    expect(await env.DB.prepare("SELECT status FROM privilege_issuer_keys WHERE key_id='pkey_testissuer0001'").first()).toEqual({ status: "revoked" });
    const revokedIssuerEnv = new Proxy(env as ControlPlaneEnv, { get: (target, property, receiver) => property === "PRIVILEGE_TICKET_SIGNING_KEYS_JSON" ? JSON.stringify(originalKeys) : Reflect.get(target, property, receiver) });
    await expect(handlePrivilegeAdmin(rotateRequest, revokedIssuerEnv, "/v1/privileged/issuer/activate")).rejects.toMatchObject({ code: "privilege_ticket_conflict" });

    const revoked = await exports.default.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/installations/phinst_privilegeflow01/revoke`, { method: "POST", headers: headers(freshToken, freshCsrf), body: "{}" }));
    expect(revoked.status).toBe(204);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_issuance WHERE status='active' AND request_id IN (SELECT request_id FROM privilege_ticket_requests WHERE installation_id='phinst_privilegeflow01')").first()).toEqual({ count: 0 });
  });
});
