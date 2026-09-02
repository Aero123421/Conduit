import { parseWireDocument, schemaIds, type PrivilegedV1WireDocument } from "@conduit/schema";
import { boundedString, readJsonBounded, record } from "./bounds.ts";
import { base64url, canonicalJson, fromBase64url, newId, nowIso, randomToken, sha256Hex, verifyEd25519 } from "./crypto.ts";
import { PublicError, type DenialCode } from "./errors.ts";
import type { ControlPlaneEnv } from "./types.ts";
import { requireBrowserSession } from "./auth/browser.ts";

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9]*_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const RUNTIME_ID = /^rt_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const PRIVILEGE_FRAME_TYPES = new Set([
  "privilege.installation_attestation",
  "privilege.ticket_request",
  "privilege.receipt",
]);
const PRIVILEGE_RESULT_TYPE = "privilege.ticket_result";
const PRIVILEGE_REGISTRATION_RESULT_TYPE = "privilege.registration_result";

export interface PrivilegeTransportFrame {
  protocol: "conduit.node/1";
  messageId: string;
  deviceId: string;
  connectionEpoch: string;
  direction: "node_to_control";
  sequence: string;
  type: "privilege.installation_attestation" | "privilege.ticket_request" | "privilege.receipt";
  correlationId?: string;
  payloadDigest: string;
  payload: Record<string, unknown>;
}

interface SignedDocument {
  keyId: string;
  claims: Record<string, unknown>;
  signature: string;
}

interface IssuerKeyConfig {
  keyId: string;
  revision: number;
  privateJwk: JsonWebKey;
}

interface IssuerKeySet {
  activeKeyId: string;
  keys: IssuerKeyConfig[];
}

interface OperationAuthorityRow {
  id: string;
  actor_principal_id: string;
  device_id: string;
  project_id: string | null;
  assignment_id: string | null;
  run_id: string | null;
  connector_policy_id: string | null;
  connector_policy_revision: number | null;
  connector_grant_id: string | null;
  payload_digest: string;
  request_json: string;
  operation_kind: string;
  operation_state: string;
  operation_expires_at: string;
  target_operation_id: string | null;
  target_runtime_id: string | null;
  target_digest: string | null;
  target_controller_epoch: string | null;
  expected_target_state: string | null;
  expected_target_revision: number | null;
  run_manifest_digest: string | null;
  run_access_scope: string | null;
  run_approval_mode: string | null;
  run_runtime_kind: string | null;
  run_device_id: string | null;
  run_state: string | null;
  project_agent_id: string | null;
  project_agent_revision: number | null;
  adapter_id: string | null;
  binding_project_revision: number | null;
  binding_device_id: string | null;
  binding_device_revision: number | null;
  binding_runtime_kind: string | null;
  binding_runtime_provider_id: string | null;
  binding_runtime_configuration_revision: number | null;
  binding_access_scope: string | null;
  binding_approval_mode: string | null;
  current_project_revision: number | null;
  current_project_status: string | null;
  current_agent_revision: number | null;
  current_agent_status: string | null;
  agent_configuration_json: string | null;
  current_device_revision: number;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new TypeError(`${label} contains unknown field ${key}`);
}

function stringField(value: Record<string, unknown>, key: string, max = 512): string {
  const item = value[key];
  if (typeof item !== "string" || item.length === 0 || item.length > max) throw new TypeError(`${key} is invalid`);
  return item;
}

function idField(value: Record<string, unknown>, key: string): string {
  const item = stringField(value, key, 128);
  if (!ID.test(item)) throw new TypeError(`${key} is invalid`);
  return item;
}

function digestField(value: Record<string, unknown>, key: string, nullable = false): string | null {
  const item = value[key];
  if (nullable && item === null) return null;
  if (typeof item !== "string" || !HASH.test(item)) throw new TypeError(`${key} is invalid`);
  return item;
}

function positiveInteger(value: Record<string, unknown>, key: string, maximum = Number.MAX_SAFE_INTEGER): number {
  const item = value[key];
  if (typeof item !== "number" || !Number.isSafeInteger(item) || item < 1 || item > maximum) throw new TypeError(`${key} is invalid`);
  return item;
}

function publicJwk(value: unknown, expectedKid?: string): JsonWebKey {
  const item = record(value, "publicJwk");
  exactKeys(item, expectedKid === undefined ? ["kty", "crv", "x"] : ["kty", "crv", "x", "kid"], "publicJwk");
  if (item.kty !== "OKP" || item.crv !== "Ed25519" || typeof item.x !== "string" || item.x.length < 16 || item.x.length > 128) throw new TypeError("Ed25519 public JWK is invalid");
  if (expectedKid !== undefined && item.kid !== expectedKid) throw new TypeError("Ed25519 public JWK kid is invalid");
  return { kty: "OKP", crv: "Ed25519", x: item.x, ...(expectedKid === undefined ? {} : { kid: expectedKid }) };
}

function signedDocument(value: unknown, kind: "capability" | "policy" | "receipt"): SignedDocument {
  const parsed = parseWireDocument(schemaIds.privilegedV1, value) as PrivilegedV1WireDocument;
  if (parsed === null || typeof parsed !== "object" || !("keyId" in parsed) || !("claims" in parsed) || !("signature" in parsed)) throw new TypeError(`signed ${kind} is invalid`);
  const claims = record(parsed.claims, `${kind}.claims`);
  if (kind === "capability" && !("receiptKeyId" in claims)) throw new TypeError("signed capability is invalid");
  if (kind === "policy" && !("policyVersion" in claims)) throw new TypeError("signed policy is invalid");
  if (kind === "receipt" && !("receiptId" in claims)) throw new TypeError("signed receipt is invalid");
  return { keyId: String(parsed.keyId), claims, signature: String(parsed.signature) };
}

function parseDate(value: unknown, label: string): number {
  if (typeof value !== "string") throw new TypeError(`${label} is invalid`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`${label} is invalid`);
  return parsed;
}

export function isPrivilegeFrameType(type: unknown): type is PrivilegeTransportFrame["type"] {
  return typeof type === "string" && PRIVILEGE_FRAME_TYPES.has(type);
}

export function parsePrivilegeTransportFrame(value: unknown): PrivilegeTransportFrame {
  const frame = record(value, "privilege frame");
  exactKeys(frame, ["protocol", "messageId", "deviceId", "connectionEpoch", "direction", "sequence", "type", "correlationId", "payloadDigest", "payload", "controlAppliedThrough"], "privilege frame");
  if (frame.protocol !== "conduit.node/1" || frame.direction !== "node_to_control" || !isPrivilegeFrameType(frame.type)) throw new TypeError("privilege frame envelope is invalid");
  const messageId = idField(frame, "messageId");
  const deviceId = idField(frame, "deviceId");
  const connectionEpoch = stringField(frame, "connectionEpoch", 32);
  const sequence = stringField(frame, "sequence", 32);
  if (!/^[1-9][0-9]*$/.test(connectionEpoch) || !/^[1-9][0-9]*$/.test(sequence)) throw new TypeError("privilege frame sequence is invalid");
  const payloadDigest = digestField(frame, "payloadDigest")!;
  const payload = record(frame.payload, "payload");
  if (frame.correlationId !== undefined && (typeof frame.correlationId !== "string" || !ID.test(frame.correlationId))) throw new TypeError("privilege frame correlation is invalid");
  // Parse the signed helper documents before custody; other exact payload
  // fields are validated during projection where D1 authority is available.
  if (frame.type === "privilege.installation_attestation") {
    const bundle = record(payload.registrationBundle, "registrationBundle");
    signedDocument(bundle.signedCapability, "capability");
    signedDocument(bundle.signedPolicyAttestation, "policy");
    if (frame.correlationId !== payload.requestId) throw new TypeError("installation attestation correlation is invalid");
  }
  if (frame.type === "privilege.ticket_request" && frame.correlationId !== payload.requestId) throw new TypeError("ticket request correlation is invalid");
  if (frame.type === "privilege.receipt") {
    const receipt = signedDocument(payload.receipt, "receipt");
    if (frame.correlationId !== receipt.claims.operationId) throw new TypeError("helper receipt correlation is invalid");
  }
  return { protocol: "conduit.node/1", messageId, deviceId, connectionEpoch, direction: "node_to_control", sequence, type: frame.type, ...(frame.correlationId === undefined ? {} : { correlationId: frame.correlationId }), payloadDigest, payload };
}

async function deviceKey(env: ControlPlaneEnv, deviceId: string, keyId: string): Promise<JsonWebKey> {
  const row = await env.DB.prepare("SELECT key.public_jwk_json FROM device_keys AS key JOIN devices AS device ON device.id=key.device_id WHERE key.id=?1 AND key.device_id=?2 AND key.status IN ('active','retiring') AND device.status='active' LIMIT 1")
    .bind(keyId, deviceId).first<{ public_jwk_json: string }>();
  if (row === null) throw new PublicError("device_key_invalid", 403, "Device signing key is not active");
  return JSON.parse(row.public_jwk_json) as JsonWebKey;
}

async function verifyDeviceSignedPayload(env: ControlPlaneEnv, frame: PrivilegeTransportFrame, payload: Record<string, unknown>): Promise<string> {
  const current = await env.DB.prepare("SELECT connection_epoch FROM devices WHERE id=?1 AND status='active' LIMIT 1").bind(frame.deviceId).first<{ connection_epoch: string }>();
  if (current === null || current.connection_epoch !== frame.connectionEpoch) throw new PublicError("device_key_invalid", 403, "Privilege frame connection epoch is stale");
  const keyId = idField(payload, "deviceKeyId");
  const signature = stringField(payload, "deviceSignature", 512);
  const signed = { ...payload };
  delete signed.deviceSignature;
  const transcript = canonicalJson({ domain: `conduit.${frame.type}.v1`, deviceId: frame.deviceId, connectionEpoch: frame.connectionEpoch, payload: signed });
  if (!await verifyEd25519(await deviceKey(env, frame.deviceId, keyId), signature, transcript)) throw new PublicError("device_key_invalid", 403, "Privilege frame Device signature is invalid");
  return keyId;
}

function capabilitySummary(claims: Record<string, unknown>): Record<string, unknown> {
  return {
    enabled: claims.enabled === true,
    systemdSystemManager: claims.systemdSystemManager === true,
    socketPeerCredentials: claims.socketPeerCredentials === true,
    transientUnits: claims.transientUnits === true,
    cgroupV2: claims.cgroupV2 === true,
    freeze: claims.freeze === true,
    pidfd: claims.pidfd === true,
    openat2: claims.openat2 === true,
    execveat: claims.execveat === true,
    pty: claims.pty === true,
    streamReplay: claims.streamReplay === true,
    neverOptIn: claims.neverOptIn === true,
    unrestrictedLaunchOptIn: claims.unrestrictedLaunchOptIn === true,
    unavailableReason: typeof claims.unavailableReason === "string" ? claims.unavailableReason.slice(0, 128) : null,
  };
}

function credentialProfileIds(value: unknown, label: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 32 || new Set(value).size !== value.length || value.some((item) => typeof item !== "string" || !/^cred_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(item))) {
    throw new TypeError(`${label} must contain credential profile IDs only`);
  }
  return value as string[];
}

interface CredentialProjectionSummary { profileId: string; revision: number; }

function credentialProjectionSummaries(value: unknown, label: string): CredentialProjectionSummary[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) throw new TypeError(`${label} is invalid`);
  const profiles = value.map((item) => {
    const projection = record(item, label);
    exactKeys(projection, ["profileId", "revision"], label);
    const profileId = idField(projection, "profileId");
    if (!profileId.startsWith("cred_")) throw new TypeError(`${label} profileId is invalid`);
    return { profileId, revision: positiveInteger(projection, "revision") };
  });
  if (new Set(profiles.map((profile) => profile.profileId)).size !== profiles.length) throw new TypeError(`${label} contains duplicate profile IDs`);
  return profiles;
}

function operationCredentialProjections(value: unknown): Array<CredentialProjectionSummary & { targetName: string }> {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) throw new TypeError("operation credentialProjections is invalid");
  const targets = new Set<string>();
  const projections = value.map((item) => {
    const projection = record(item, "operation credential projection");
    exactKeys(projection, ["profileId", "revision", "targetName"], "operation credential projection");
    const summary = credentialProjectionSummaries([{ profileId: projection.profileId, revision: projection.revision }], "operation credential projection")[0]!;
    const targetName = stringField(projection, "targetName", 256);
    if (targetName.startsWith("/") || targetName.includes("\\") || targetName.split("/").some((part) => part.length === 0 || part === "." || part === ".." || !/^[A-Za-z0-9_.-]+$/.test(part)) || !targets.add(targetName)) {
      throw new TypeError("operation credential targetName is invalid");
    }
    return { ...summary, targetName };
  });
  if (new Set(projections.map((profile) => profile.profileId)).size !== projections.length) throw new TypeError("operation credentialProjections contains duplicate profile IDs");
  return projections;
}

function launchProfileExecutableDigests(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  const digests = record(value, "root policy launchProfileExecutableDigests");
  if (Object.keys(digests).length > 32 || Object.entries(digests).some(([profile, digest]) => !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(profile) || typeof digest !== "string" || !HASH.test(digest))) {
    throw new TypeError("root policy launchProfileExecutableDigests must contain bounded profile IDs and SHA-256 digests only");
  }
  return digests as Record<string, string>;
}

export function rootPolicySummary(claims: Record<string, unknown>): Record<string, unknown> {
  return {
    enabled: claims.enabled === true,
    ticketKeyIds: claims.ticketKeyIds,
    allowedOperations: claims.allowedOperations,
    allowedAdapters: claims.allowedAdapters,
    allowedLaunchProfiles: claims.allowedLaunchProfiles,
    launchProfileExecutableDigests: launchProfileExecutableDigests(claims.launchProfileExecutableDigests),
    allowedCredentialProfiles: credentialProfileIds(claims.allowedCredentialProfiles, "root policy allowedCredentialProfiles"),
    ceilings: claims.ceilings,
    allowNever: claims.allowNever === true,
    allowUnrestrictedLaunch: claims.allowUnrestrictedLaunch === true,
    allowPersistentSessions: claims.allowPersistentSessions === true,
    allowOfflineControl: claims.allowOfflineControl === true,
    receiptRetentionSeconds: claims.receiptRetentionSeconds,
  };
}

function safeRedactedSummary(value: unknown): Record<string, unknown> {
  const summary = record(value, "redactedSummary");
  exactKeys(summary, ["operation", "adapter", "runtimeKind", "reasonCodes", "resourceProfile", "credentialProfiles"], "redactedSummary");
  const safeLabel = (item: unknown, key: string): void => {
    if (item === null || item === undefined) return;
    if (typeof item !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(item)) throw new TypeError(`${key} is not safe metadata`);
  };
  safeLabel(summary.operation, "redactedSummary.operation");
  safeLabel(summary.adapter, "redactedSummary.adapter");
  safeLabel(summary.runtimeKind, "redactedSummary.runtimeKind");
  safeLabel(summary.resourceProfile, "redactedSummary.resourceProfile");
  if (summary.reasonCodes !== undefined && (!Array.isArray(summary.reasonCodes) || summary.reasonCodes.length > 16 || summary.reasonCodes.some((item) => typeof item !== "string" || !/^[a-z][a-z0-9_.-]{0,127}$/.test(item)))) throw new TypeError("redactedSummary.reasonCodes is not safe metadata");
  credentialProjectionSummaries(summary.credentialProfiles, "redactedSummary.credentialProfiles");
  if (new TextEncoder().encode(canonicalJson(summary)).byteLength > 2048) throw new TypeError("redacted summary is too large");
  return summary;
}

function isPolicyNarrower(previous: Record<string, unknown>, next: Record<string, unknown>): boolean {
  const keys = new Set([...Object.keys(previous), ...Object.keys(next)]);
  for (const key of keys) {
    if (key === "allowedCredentialProfiles" || key === "launchProfileExecutableDigests") {
      if (key === "launchProfileExecutableDigests") {
        const before = previous.launchProfileExecutableDigests ?? {};
        const after = next.launchProfileExecutableDigests ?? {};
        if (typeof before !== "object" || before === null || Array.isArray(before) || typeof after !== "object" || after === null || Array.isArray(after)) return false;
        if (Object.entries(after).some(([profile, digest]) => (before as Record<string, unknown>)[profile] !== digest)) return false;
        continue;
      }
      const before = previous.allowedCredentialProfiles ?? [];
      const after = next.allowedCredentialProfiles ?? [];
      if (!Array.isArray(before) || !Array.isArray(after) || after.some((item) => !before.includes(item))) return false;
      continue;
    }
    const before = previous[key];
    const after = next[key];
    if (before === undefined || after === undefined) return false;
    if (typeof before === "boolean" || typeof after === "boolean") {
      if (before === false && after === true) return false;
      if (typeof before !== "boolean" || typeof after !== "boolean") return false;
      continue;
    }
    if (Array.isArray(before) || Array.isArray(after)) {
      if (!Array.isArray(before) || !Array.isArray(after) || after.some((item) => !before.includes(item))) return false;
      continue;
    }
    if (typeof before === "number" || typeof after === "number" || before === null || after === null) {
      if (before === null) continue;
      if (after === null || typeof before !== "number" || typeof after !== "number" || after > before) return false;
      continue;
    }
    if (canonicalJson(before) !== canonicalJson(after)) return false;
  }
  return true;
}

export function isDevicePolicyNarrower(previous: Record<string, unknown>, next: Record<string, unknown>): boolean {
  const allowlists = ["capabilities", "providers", "accessScopes", "approvalModes", "launchProfiles"];
  for (const key of allowlists) {
    const before = previous[key];
    const after = next[key];
    if (!Array.isArray(before) || !Array.isArray(after) || after.some((item) => !before.includes(item))) return false;
  }
  if (previous.credentialProfiles !== undefined || next.credentialProfiles !== undefined) {
    const before = previous.credentialProfiles ?? [];
    const after = next.credentialProfiles ?? [];
    if (!Array.isArray(before) || !Array.isArray(after) || after.some((item) => !before.includes(item))) return false;
  }
  const previousRisks = previous.requiredApprovalRiskClasses;
  const nextRisks = next.requiredApprovalRiskClasses;
  if (!Array.isArray(previousRisks) || !Array.isArray(nextRisks) || previousRisks.some((item) => !nextRisks.includes(item))) return false;
  for (const key of ["maxCpu", "maxMemoryBytes", "maxStorageBytes"]) {
    const before = previous[key];
    const after = next[key];
    if (before === null) {
      if (after !== null && typeof after !== "number") return false;
    } else if (typeof before !== "number" || after === null || typeof after !== "number" || after > before) return false;
  }
  if (previous.allowFullAccessWithoutApproval === false && next.allowFullAccessWithoutApproval === true) return false;
  if (typeof previous.allowFullAccessWithoutApproval !== "boolean" || typeof next.allowFullAccessWithoutApproval !== "boolean") return false;
  const known = new Set(["revision", ...allowlists, "credentialProfiles", "requiredApprovalRiskClasses", "maxCpu", "maxMemoryBytes", "maxStorageBytes", "allowFullAccessWithoutApproval"]);
  for (const key of new Set([...Object.keys(previous), ...Object.keys(next)])) {
    if (!known.has(key) && canonicalJson(previous[key]) !== canonicalJson(next[key])) return false;
  }
  return true;
}

export function assertDevicePolicyTransition(
  current: { revision: number; policyDigest: string; previousPolicyDigest: string | null } | null,
  next: { revision: number; policyDigest: string; previousPolicyDigest: string | null },
): void {
  if (current === null) {
    if (next.previousPolicyDigest !== null) throw new PublicError("privilege_ticket_conflict", 409, "Initial Device policy cannot name a predecessor");
    return;
  }
  if (current.policyDigest === next.policyDigest) {
    if (next.revision !== current.revision || next.previousPolicyDigest !== current.previousPolicyDigest) throw new PublicError("privilege_ticket_conflict", 409, "Device policy replay differs from the active attestation");
    return;
  }
  if (next.revision <= current.revision || next.previousPolicyDigest !== current.policyDigest) throw new PublicError("privilege_ticket_conflict", 409, "Device policy update must name the exact active predecessor and increase its revision");
}

async function projectInstallation(env: ControlPlaneEnv, frame: PrivilegeTransportFrame): Promise<Record<string, unknown>> {
  const payload = frame.payload;
  exactKeys(payload, ["requestId", "registrationBundle", "devicePolicy", "deviceKeyId", "deviceSignature"], "installation attestation");
  const registrationRequestId = idField(payload, "requestId");
  const bundle = record(payload.registrationBundle, "registrationBundle");
  exactKeys(bundle, ["protocol", "installationId", "deviceId", "deviceKeyId", "uid", "origin", "policyRevision", "policyDigest", "receiptPublicJwk", "signedPolicyAttestation", "signedCapability"], "registration bundle");
  if (bundle.protocol !== "conduit.privileged/1" || bundle.deviceId !== frame.deviceId) throw new PublicError("privileged_helper_protocol_unsupported", 409, "Helper registration bundle binding is invalid");
  const installationId = idField(bundle, "installationId");
  const expectedUid = positiveInteger(bundle, "uid", 4_294_967_294);
  const origin = stringField(bundle, "origin", 512);
  if (origin !== env.PUBLIC_ORIGIN) throw new PublicError("privileged_helper_registration_missing", 409, "Helper origin does not match this Control Plane");
  const capability = signedDocument(bundle.signedCapability, "capability");
  const claims = capability.claims;
  if (claims.protocol !== "conduit.privileged/1" || claims.installationId !== installationId || claims.receiptKeyId !== capability.keyId) throw new PublicError("privileged_helper_protocol_unsupported", 409, "Helper capability binding is invalid");
  const receiptJwk = publicJwk(bundle.receiptPublicJwk, capability.keyId);
  if (!await verifyEd25519(receiptJwk, capability.signature, canonicalJson(claims))) throw new PublicError("privilege_ticket_invalid", 403, "Helper capability signature is invalid");
  const helperKeyId = capability.keyId;
  const fingerprint = await sha256Hex(fromBase64url(String(receiptJwk.x)));
  const capabilityDigest = await sha256Hex(canonicalJson(bundle.signedCapability));
  const policy = signedDocument(bundle.signedPolicyAttestation, "policy");
  const policyClaims = policy.claims;
  if (policy.keyId !== helperKeyId || policyClaims.installationId !== installationId || policyClaims.deviceId !== frame.deviceId || policyClaims.uid !== expectedUid || policyClaims.origin !== origin) throw new PublicError("privileged_helper_policy_mismatch", 409, "Signed root policy identity differs from the registration bundle");
  if (!await verifyEd25519(receiptJwk, policy.signature, canonicalJson(policyClaims))) throw new PublicError("privilege_ticket_invalid", 403, "Root policy attestation signature is invalid");
  const policyRevision = positiveInteger(policyClaims, "revision");
  const policyDigest = await sha256Hex(canonicalJson(policyClaims));
  if (bundle.policyRevision !== policyRevision || bundle.policyDigest !== policyDigest) throw new PublicError("privileged_helper_policy_mismatch", 409, "Signed root policy digest differs from the registration bundle");
  if (claims.policyRevision !== policyRevision || claims.policyDigest !== policyDigest) throw new PublicError("privileged_helper_policy_mismatch", 409, "Capability and root policy attestations differ");
  const publicSummary = rootPolicySummary(policyClaims);
  if (Object.keys(publicSummary).length > 32 || new TextEncoder().encode(canonicalJson(publicSummary)).byteLength > 4096) throw new TypeError("policy public summary is too large");
  const devicePolicy = record(payload.devicePolicy, "devicePolicy");
  exactKeys(devicePolicy, ["revision", "policyDigest", "previousPolicyDigest", "publicSummary", "signature"], "Device policy attestation");
  const devicePolicyRevision = positiveInteger(devicePolicy, "revision");
  const devicePolicyDigest = digestField(devicePolicy, "policyDigest")!;
  const previousDevicePolicyDigest = digestField(devicePolicy, "previousPolicyDigest", true);
  const devicePolicySummary = record(devicePolicy.publicSummary, "devicePolicy.publicSummary");
  if (Object.keys(devicePolicySummary).length > 32 || new TextEncoder().encode(canonicalJson(devicePolicySummary)).byteLength > 4096) throw new TypeError("Device policy public summary is too large");
  credentialProfileIds(devicePolicySummary.credentialProfiles, "Device policy credentialProfiles");
  const deviceKeyId = await verifyDeviceSignedPayload(env, frame, payload);
  if (bundle.deviceKeyId !== deviceKeyId) throw new PublicError("device_key_invalid", 403, "Root-owned Device key binding differs from the signing Device key");
  const deviceJwk = await deviceKey(env, frame.deviceId, deviceKeyId);
  if (!await verifyEd25519(deviceJwk, stringField(devicePolicy, "signature", 512), canonicalJson({ deviceId: frame.deviceId, revision: devicePolicyRevision, policyDigest: devicePolicyDigest, previousPolicyDigest: previousDevicePolicyDigest, publicSummary: devicePolicySummary }))) throw new PublicError("device_key_invalid", 403, "Device policy signature is invalid");
  const now = nowIso();
  const observedAt = String(claims.observedAt);
  parseDate(observedAt, "capability observedAt");
  const attestationDigest = await sha256Hex(canonicalJson({ installationId, expectedUid, origin, helperKeyId, fingerprint, capabilityDigest, policyDigest, devicePolicyDigest, deviceKeyId }));
  const registrationUnsigned = { ...payload };
  delete registrationUnsigned.deviceSignature;
  const registrationRequestDigest = await sha256Hex(canonicalJson(registrationUnsigned));
  const priorRegistration = await env.DB.prepare("SELECT request_digest FROM privilege_registration_attestations WHERE request_id=?1 LIMIT 1").bind(registrationRequestId).first<{ request_digest: string }>();
  if (priorRegistration !== null && priorRegistration.request_digest !== registrationRequestDigest) throw new PublicError("privilege_ticket_conflict", 409, "Helper registration request ID is bound to another attestation");
  const existing = await env.DB.prepare("SELECT device_id,expected_uid,public_origin,active_key_id,active_policy_revision,active_policy_digest,status,device_attestation_digest FROM device_privilege_installations WHERE installation_id=?1 LIMIT 1")
    .bind(installationId).first<{ device_id: string; expected_uid: number; public_origin: string; active_key_id: string | null; active_policy_revision: number | null; active_policy_digest: string | null; status: string; device_attestation_digest: string }>();
  if (existing !== null && (existing.device_id !== frame.deviceId || existing.expected_uid !== expectedUid || existing.public_origin !== origin)) throw new PublicError("privilege_ticket_conflict", 409, "Helper installation identity is already bound");
  const existingKey = await env.DB.prepare("SELECT public_jwk_json,fingerprint FROM privilege_installation_keys WHERE installation_id=?1 AND key_id=?2 LIMIT 1")
    .bind(installationId, helperKeyId).first<{ public_jwk_json: string; fingerprint: string }>();
  if (existingKey !== null && (existingKey.public_jwk_json !== canonicalJson(receiptJwk) || existingKey.fingerprint !== fingerprint)) {
    throw new PublicError("privilege_ticket_conflict", 409, "Helper key ID is bound to different key material");
  }
  const previousPolicyDigest = existing?.active_policy_digest ?? null;
  const currentRootPolicy = existing?.active_policy_revision === null || existing?.active_policy_revision === undefined ? null : await env.DB.prepare("SELECT public_summary_json FROM privilege_policy_attestations WHERE installation_id=?1 AND revision=?2 AND status='active' LIMIT 1").bind(installationId, existing.active_policy_revision).first<{ public_summary_json: string }>();
  if (existing?.active_policy_revision !== null && existing?.active_policy_revision !== undefined && existing.active_policy_digest !== policyDigest && policyRevision <= existing.active_policy_revision) {
    throw new PublicError("privilege_ticket_conflict", 409, "Helper policy revision must increase monotonically");
  }
  const actualChangeClass = existing === null || existing.active_policy_digest === null ? "initial" : existing.active_policy_digest === policyDigest ? "same" : currentRootPolicy !== null && isPolicyNarrower(JSON.parse(currentRootPolicy.public_summary_json) as Record<string, unknown>, publicSummary) ? "narrowed" : "broadened";
  const policyStatus = actualChangeClass === "same" || actualChangeClass === "narrowed" && existing?.active_key_id === helperKeyId ? "active" : "pending_owner";
  const policyInsertStatus = actualChangeClass === "narrowed" ? "pending_owner" : policyStatus;
  const predecessorKeyId = existing?.active_key_id !== undefined && existing.active_key_id !== null && existing.active_key_id !== helperKeyId ? existing.active_key_id : null;
  const currentDevicePolicy = await env.DB.prepare("SELECT revision,policy_digest,previous_policy_digest,public_summary_json FROM device_user_policy_attestations WHERE device_id=?1 AND status='active' ORDER BY revision DESC LIMIT 1").bind(frame.deviceId).first<{ revision: number; policy_digest: string; previous_policy_digest: string | null; public_summary_json: string }>();
  assertDevicePolicyTransition(
    currentDevicePolicy === null ? null : { revision: currentDevicePolicy.revision, policyDigest: currentDevicePolicy.policy_digest, previousPolicyDigest: currentDevicePolicy.previous_policy_digest },
    { revision: devicePolicyRevision, policyDigest: devicePolicyDigest, previousPolicyDigest: previousDevicePolicyDigest },
  );
  const devicePolicyNarrowed = currentDevicePolicy !== null && currentDevicePolicy.policy_digest !== devicePolicyDigest && isDevicePolicyNarrower(JSON.parse(currentDevicePolicy.public_summary_json) as Record<string, unknown>, devicePolicySummary);
  const devicePolicyStatus = currentDevicePolicy?.policy_digest === devicePolicyDigest || devicePolicyNarrowed ? "active" : "pending_owner";
  await env.DB.batch([
    env.DB.prepare("INSERT INTO device_privilege_installations(installation_id,device_id,expected_uid,public_origin,helper_version,protocol_version,active_key_id,active_policy_revision,active_policy_digest,capability_digest,capability_summary_json,device_attestation_digest,device_key_id,status,last_observed_at,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'conduit.privileged/1',NULL,NULL,NULL,?6,?7,?8,?9,'pending_owner',?10,?11,?11) ON CONFLICT(installation_id) DO UPDATE SET helper_version=excluded.helper_version,capability_digest=excluded.capability_digest,capability_summary_json=excluded.capability_summary_json,device_attestation_digest=excluded.device_attestation_digest,device_key_id=excluded.device_key_id,status=CASE WHEN device_privilege_installations.active_policy_digest IS NOT NULL AND device_privilege_installations.active_policy_digest<>?12 THEN 'policy_review' ELSE device_privilege_installations.status END,last_observed_at=excluded.last_observed_at,updated_at=excluded.updated_at WHERE device_privilege_installations.status<>'revoked'")
      .bind(installationId, frame.deviceId, expectedUid, origin, String(claims.helperVersion), capabilityDigest, canonicalJson(capabilitySummary(claims)), attestationDigest, deviceKeyId, observedAt, now, policyDigest),
    env.DB.prepare("INSERT OR IGNORE INTO privilege_installation_keys(installation_id,key_id,public_jwk_json,fingerprint,status,valid_from,predecessor_key_id,self_signature,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
      .bind(installationId, helperKeyId, canonicalJson(receiptJwk), fingerprint, existing?.active_key_id === helperKeyId ? "active" : "pending_owner", observedAt, predecessorKeyId, capability.signature, now),
    env.DB.prepare("INSERT OR IGNORE INTO privilege_policy_attestations(installation_id,revision,policy_digest,previous_policy_digest,public_summary_json,change_class,helper_key_id,helper_signature,attestation_digest,status,observed_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)")
      .bind(installationId, policyRevision, policyDigest, previousPolicyDigest, canonicalJson(publicSummary), actualChangeClass, helperKeyId, policy.signature, await sha256Hex(canonicalJson(bundle.signedPolicyAttestation)), policyInsertStatus, observedAt, now),
    env.DB.prepare("INSERT OR IGNORE INTO device_user_policy_attestations(device_id,revision,policy_digest,previous_policy_digest,public_summary_json,device_key_id,device_signature,attestation_digest,status,observed_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
      .bind(frame.deviceId, devicePolicyRevision, devicePolicyDigest, previousDevicePolicyDigest, canonicalJson(devicePolicySummary), deviceKeyId, String(devicePolicy.signature), await sha256Hex(canonicalJson(devicePolicy)), devicePolicyStatus, observedAt, now),
    env.DB.prepare("INSERT OR IGNORE INTO privilege_registration_attestations(request_id,device_id,installation_id,attestation_kind,request_digest,device_key_id,device_signature,observed_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
      .bind(registrationRequestId, frame.deviceId, installationId, existing === null ? "initial" : existing.active_key_id !== helperKeyId && existing.active_policy_digest !== policyDigest ? "combined_update" : existing.active_key_id !== helperKeyId ? "key_rotation" : existing.active_policy_digest !== policyDigest ? "policy_update" : "device_policy_update", registrationRequestDigest, deviceKeyId, String(payload.deviceSignature), observedAt, now),
    ...(actualChangeClass === "narrowed" ? [
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='superseded' WHERE installation_id=?1 AND status='active' AND revision<?2").bind(installationId, policyRevision),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='active' WHERE installation_id=?1 AND revision=?2 AND status='pending_owner'").bind(installationId, policyRevision),
      env.DB.prepare("UPDATE device_privilege_installations SET active_policy_revision=?1,active_policy_digest=?2,status='active',updated_at=?3 WHERE installation_id=?4 AND active_key_id=?5 AND status IN ('active','policy_review')").bind(policyRevision, policyDigest, now, installationId, helperKeyId),
    ] : []),
    ...(devicePolicyNarrowed ? [
      env.DB.prepare("UPDATE device_user_policy_attestations SET status='superseded' WHERE device_id=?1 AND status='active' AND revision<?2").bind(frame.deviceId, devicePolicyRevision),
    ] : []),
  ]);
  const state = existing?.status === "active" && policyStatus === "active" && devicePolicyStatus === "active" ? "active" : "pending_owner";
  if (state === "active") return { state, ...await activePrivilegeRegistrationResult(env, installationId, attestationDigest) };
  return { installationId, state, attestationDigest };
}

export async function activePrivilegeRegistrationResult(env: ControlPlaneEnv, installationId: string, expectedAttestationDigest?: string): Promise<Record<string, unknown>> {
  const active = await env.DB.prepare("SELECT device_id,active_key_id,active_policy_revision,active_policy_digest,device_attestation_digest,owner_decision_digest FROM device_privilege_installations WHERE installation_id=?1 AND status='active' LIMIT 1").bind(installationId).first<{ device_id: string; active_key_id: string; active_policy_revision: number; active_policy_digest: string; device_attestation_digest: string; owner_decision_digest: string | null }>();
  if (active === null || active.owner_decision_digest === null || expectedAttestationDigest !== undefined && active.device_attestation_digest !== expectedAttestationDigest) throw new PublicError("privileged_helper_registration_missing", 409, "Active helper registration does not match the attestation");
  const helper = await env.DB.prepare("SELECT public_jwk_json,fingerprint FROM privilege_installation_keys WHERE installation_id=?1 AND key_id=?2 AND status='active' LIMIT 1").bind(installationId, active.active_key_id).first<{ public_jwk_json: string; fingerprint: string }>();
  const devicePolicy = await env.DB.prepare("SELECT revision,policy_digest,previous_policy_digest FROM device_user_policy_attestations WHERE device_id=?1 AND status='active' ORDER BY revision DESC LIMIT 1").bind(active.device_id).first<{ revision: number; policy_digest: string; previous_policy_digest: string | null }>();
  const issuerKeys = await env.DB.prepare("SELECT key_id,revision,public_jwk_json,fingerprint,status,valid_from,valid_until,predecessor_key_id,rotation_statement_digest,rotation_signature FROM privilege_issuer_keys WHERE status IN ('active','retiring') ORDER BY revision DESC LIMIT 4").all<Record<string, unknown>>();
  if (helper === null || devicePolicy === null || !issuerKeys.results.some((key) => key.status === "active")) throw new PublicError("privileged_helper_registration_missing", 409, "Active helper registration evidence is incomplete");
  return {
    installationId, status: "active", helperKeyId: active.active_key_id,
    helperPublicJwk: JSON.parse(helper.public_jwk_json), helperKeyFingerprint: helper.fingerprint,
    helperPolicyRevision: active.active_policy_revision, helperPolicyDigest: active.active_policy_digest,
    devicePolicyRevision: devicePolicy.revision, devicePolicyDigest: devicePolicy.policy_digest,
    devicePolicyPreviousDigest: devicePolicy.previous_policy_digest,
    issuerKeys: issuerKeys.results.map((key) => ({ keyId: key.key_id, revision: key.revision, publicJwk: JSON.parse(String(key.public_jwk_json)), fingerprint: key.fingerprint, status: key.status, validFrom: key.valid_from, validUntil: key.valid_until, predecessorKeyId: key.predecessor_key_id, rotationStatementDigest: key.rotation_statement_digest, rotationSignature: key.rotation_signature })),
    attestationDigest: active.device_attestation_digest, ownerDecisionDigest: active.owner_decision_digest,
  };
}

function parseIssuerSecret(env: ControlPlaneEnv): IssuerKeySet {
  let parsed: unknown;
  try { parsed = JSON.parse(env.PRIVILEGE_TICKET_SIGNING_KEYS_JSON); } catch { throw new PublicError("full_device_capability_unavailable", 503, "Privilege ticket signer is not configured"); }
  const value = record(parsed, "privilege ticket signer");
  exactKeys(value, ["activeKeyId", "keys"], "privilege ticket signer");
  if (typeof value.activeKeyId !== "string" || !Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > 4) throw new PublicError("full_device_capability_unavailable", 503, "Privilege ticket signer is invalid");
  const keys = value.keys.map((raw) => {
    const item = record(raw, "privilege ticket key");
    exactKeys(item, ["keyId", "revision", "privateJwk"], "privilege ticket key");
    if (typeof item.keyId !== "string" || !ID.test(item.keyId) || typeof item.revision !== "number" || !Number.isSafeInteger(item.revision) || item.revision < 1) throw new PublicError("full_device_capability_unavailable", 503, "Privilege ticket signer is invalid");
    return { keyId: item.keyId, revision: item.revision, privateJwk: record(item.privateJwk, "privateJwk") as unknown as JsonWebKey };
  });
  if (!keys.some((item) => item.keyId === value.activeKeyId)) throw new PublicError("full_device_capability_unavailable", 503, "Active privilege ticket key is unavailable");
  return { activeKeyId: value.activeKeyId, keys };
}

async function issuerMaterial(env: ControlPlaneEnv): Promise<{ config: IssuerKeyConfig; key: CryptoKey; publicJwk: JsonWebKey; fingerprint: string }> {
  const keyset = parseIssuerSecret(env);
  const config = keyset.keys.find((item) => item.keyId === keyset.activeKeyId)!;
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey("jwk", config.privateJwk, { name: "Ed25519" }, true, ["sign"]); } catch { throw new PublicError("full_device_capability_unavailable", 503, "Privilege ticket signer cannot be imported"); }
  const exported = await crypto.subtle.exportKey("jwk", key) as JsonWebKey;
  if (typeof exported.x !== "string") throw new PublicError("full_device_capability_unavailable", 503, "Privilege ticket signer public key is unavailable");
  const publicKey: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: exported.x };
  const fingerprint = await sha256Hex(fromBase64url(String(exported.x)));
  return { config, key, publicJwk: publicKey, fingerprint };
}

async function activateIssuer(env: ControlPlaneEnv): Promise<Record<string, unknown>> {
  const active = await issuerMaterial(env);
  const now = nowIso();
  const existing = await env.DB.prepare("SELECT key_id,revision,public_jwk_json,fingerprint,status FROM privilege_issuer_keys WHERE key_id=?1 LIMIT 1")
    .bind(active.config.keyId).first<{ key_id: string; revision: number; public_jwk_json: string; fingerprint: string; status: string }>();
  if (existing !== null && (existing.revision !== active.config.revision || existing.public_jwk_json !== canonicalJson(active.publicJwk) || existing.fingerprint !== active.fingerprint)) throw new PublicError("privilege_ticket_conflict", 409, "Privilege issuer key ID is bound to different key material");
  if (existing?.status === "revoked") throw new PublicError("privilege_ticket_conflict", 409, "A revoked privilege issuer key cannot be reactivated");
  const predecessor = await env.DB.prepare("SELECT key_id,revision FROM privilege_issuer_keys WHERE status='active' AND key_id<>?1 LIMIT 1").bind(active.config.keyId).first<{ key_id: string; revision: number }>();
  if (predecessor !== null && active.config.revision <= predecessor.revision) throw new PublicError("privilege_ticket_conflict", 409, "Privilege issuer key revision must increase monotonically");
  let rotationStatementDigest: string | null = null;
  let rotationSignature: string | null = null;
  if (predecessor !== null) {
    const predecessorConfig = parseIssuerSecret(env).keys.find((key) => key.keyId === predecessor.key_id);
    if (predecessorConfig === undefined) throw new PublicError("full_device_capability_unavailable", 503, "Issuer rotation requires the currently pinned predecessor private key");
    const predecessorKey = await crypto.subtle.importKey("jwk", predecessorConfig.privateJwk, { name: "Ed25519" }, false, ["sign"]);
    const statement = { domain: "conduit.privilege-issuer-rotation.v1", predecessorKeyId: predecessor.key_id, predecessorRevision: predecessor.revision, keyId: active.config.keyId, revision: active.config.revision, publicJwk: active.publicJwk, fingerprint: active.fingerprint, validFrom: now };
    rotationStatementDigest = await sha256Hex(canonicalJson(statement));
    rotationSignature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", predecessorKey, new TextEncoder().encode(canonicalJson(statement)))));
  }
  await env.DB.batch([
    env.DB.prepare("UPDATE privilege_issuer_keys SET status='retiring',valid_until=COALESCE(valid_until,?1) WHERE status='active' AND key_id<>?2").bind(new Date(Date.now() + 300_000).toISOString(), active.config.keyId),
    env.DB.prepare("INSERT INTO privilege_issuer_keys(key_id,revision,public_jwk_json,fingerprint,status,valid_from,predecessor_key_id,rotation_statement_digest,rotation_signature,created_at) VALUES (?1,?2,?3,?4,'active',?5,?6,?7,?8,?5) ON CONFLICT(key_id) DO UPDATE SET status='active',valid_until=NULL,revoked_at=NULL WHERE privilege_issuer_keys.public_jwk_json=excluded.public_jwk_json AND privilege_issuer_keys.revision=excluded.revision")
      .bind(active.config.keyId, active.config.revision, canonicalJson(active.publicJwk), active.fingerprint, now, predecessor?.key_id ?? null, rotationStatementDigest, rotationSignature),
  ]);
  return { keyId: active.config.keyId, revision: active.config.revision, fingerprint: active.fingerprint, predecessorKeyId: predecessor?.key_id ?? null, rotationStatementDigest, rotationSignature };
}

async function operationAuthority(env: ControlPlaneEnv, operationId: string): Promise<OperationAuthorityRow | null> {
  return env.DB.prepare(`
    SELECT operation.id,operation.actor_principal_id,operation.device_id,operation.project_id,operation.assignment_id,operation.run_id,
           operation.connector_policy_id,operation.connector_policy_revision,operation.connector_grant_id,
           operation.payload_digest,operation.request_json,operation.operation_kind,operation.state AS operation_state,
           operation.expires_at AS operation_expires_at,operation.target_operation_id,operation.target_runtime_id,
           operation.target_digest,operation.target_controller_epoch,operation.expected_target_state,operation.expected_target_revision,
           run.manifest_digest AS run_manifest_digest,run.access_scope AS run_access_scope,
           run.approval_mode AS run_approval_mode,run.runtime_kind AS run_runtime_kind,run.device_id AS run_device_id,
           run.state AS run_state,
           binding.project_agent_id,binding.project_agent_revision,binding.adapter_id,binding.project_revision AS binding_project_revision,
           binding.device_id AS binding_device_id,binding.device_revision AS binding_device_revision,binding.runtime_kind AS binding_runtime_kind,
           binding.runtime_provider_id AS binding_runtime_provider_id,binding.runtime_configuration_revision AS binding_runtime_configuration_revision,
           binding.access_scope AS binding_access_scope,binding.approval_mode AS binding_approval_mode,
           project.revision AS current_project_revision,project.status AS current_project_status,
           agent.revision AS current_agent_revision,agent.status AS current_agent_status,
           agent.configuration_json AS agent_configuration_json,device.revision AS current_device_revision
    FROM operation_journal AS operation
    LEFT JOIN runs AS run ON run.id=operation.run_id
    LEFT JOIN assignment_run_bindings AS binding ON binding.assignment_id=operation.assignment_id
    LEFT JOIN projects AS project ON project.id=operation.project_id
    LEFT JOIN project_agents AS agent ON agent.id=binding.project_agent_id
    JOIN devices AS device ON device.id=operation.device_id AND device.status='active'
    WHERE operation.id=?1 LIMIT 1
  `).bind(operationId).first<OperationAuthorityRow>();
}

function summaryAllows(summaryJson: string, ticketRequest: Record<string, unknown>, operationRequest: Record<string, unknown>, capabilityJson: string, approvalMode: string, adapterId: string | null): void {
  const policy = JSON.parse(summaryJson) as Record<string, unknown>;
  const capability = JSON.parse(capabilityJson) as Record<string, unknown>;
  if (policy.enabled !== true || capability.enabled !== true) throw new PublicError("privileged_helper_disabled", 409, "Effective helper capability is disabled");
  const mandatoryHostCapabilities = ["systemdSystemManager", "socketPeerCredentials", "transientUnits", "cgroupV2", "freeze", "pidfd", "openat2", "execveat", "pty", "streamReplay"] as const;
  if (mandatoryHostCapabilities.some((field) => capability[field] !== true) || capability.unavailableReason !== null) {
    throw new PublicError("full_device_capability_unavailable", 409, "Effective helper host capability is incomplete or degraded");
  }
  const operation = String(ticketRequest.allowedOperation);
  const operations = Array.isArray(policy.allowedOperations) ? policy.allowedOperations : [];
  if (!operations.includes(operation)) throw new PublicError("privileged_helper_policy_mismatch", 409, "Root policy does not allow this operation");
  const adapters = Array.isArray(policy.allowedAdapters) ? policy.allowedAdapters : [];
  if (adapterId !== null && !adapters.includes(adapterId)) throw new PublicError("privileged_helper_policy_mismatch", 409, "Root policy does not allow this Adapter");
  const argumentsValue = operationRequest.arguments !== null && typeof operationRequest.arguments === "object" && !Array.isArray(operationRequest.arguments) ? operationRequest.arguments as Record<string, unknown> : {};
  const launchProfileId = argumentsValue.launchProfileId;
  const launchProfiles = Array.isArray(policy.allowedLaunchProfiles) ? policy.allowedLaunchProfiles : [];
  const exactLaunchProfiles = policy.launchProfileExecutableDigests !== null && typeof policy.launchProfileExecutableDigests === "object" && !Array.isArray(policy.launchProfileExecutableDigests) ? policy.launchProfileExecutableDigests as Record<string, unknown> : {};
  const registeredExactProfile = typeof launchProfileId === "string" && typeof exactLaunchProfiles[launchProfileId] === "string";
  const unrestrictedProfile = typeof launchProfileId === "string" && policy.allowUnrestrictedLaunch === true && launchProfiles.includes(launchProfileId);
  if (adapterId !== null ? policy.allowUnrestrictedLaunch !== true : !registeredExactProfile && !unrestrictedProfile) throw new PublicError("privileged_helper_policy_mismatch", 409, "Root policy does not allow this launch profile");
  const credentialProfiles = credentialProjectionSummaries(record(ticketRequest.redactedSummary, "redactedSummary").credentialProfiles, "redactedSummary.credentialProfiles").map((profile) => profile.profileId);
  const allowedCredentialProfiles = Array.isArray(policy.allowedCredentialProfiles) ? policy.allowedCredentialProfiles : [];
  if (credentialProfiles.some((profile) => !allowedCredentialProfiles.includes(profile))) throw new PublicError("privileged_helper_policy_mismatch", 409, "Root policy does not allow a requested credential profile");
  // Exact commands bind the complete launch plan. Structured Agents may use
  // adapter mediation only when the signed root policy names that Adapter;
  // the Adapter allowlist is the local root authorization for this v1 mode.
  if (ticketRequest.approvalEnforcement !== "exact_command" &&
      (ticketRequest.approvalEnforcement !== "adapter_mediated" || adapterId === null || !adapters.includes(adapterId))) {
    throw new PublicError("full_device_approval_enforcement_unavailable", 409, "Local policy cannot attest this approval enforcement");
  }
  if (approvalMode === "never" && (policy.allowNever !== true || capability.neverOptIn !== true)) throw new PublicError("full_device_never_local_opt_in_required", 409, "Never approval requires both root-policy and effective helper opt-in");
  const requested = record(ticketRequest.resourceCeilings, "resourceCeilings");
  const ceilings = record(policy.ceilings, "root policy ceilings");
  for (const key of ["cpuQuotaPerSecUsec", "memoryMaxBytes", "tasksMax", "ioWeight", "runtimeMaxUsec"] as const) {
    const maximum = ceilings[key];
    const value = requested[key];
    if (typeof maximum === "number" && (typeof value !== "number" || value > maximum)) throw new PublicError("privileged_helper_policy_mismatch", 409, `Requested ${key} exceeds root policy`);
  }
}

function devicePolicyAllows(summaryJson: string, request: Record<string, unknown>, ticketRequest: Record<string, unknown>): void {
  const policy = JSON.parse(summaryJson) as Record<string, unknown>;
  const resourceCeilings = record(ticketRequest.resourceCeilings, "resourceCeilings");
  const runtime = request.runtime !== null && typeof request.runtime === "object" && !Array.isArray(request.runtime) ? request.runtime as Record<string, unknown> : {};
  const argumentsValue = request.arguments !== null && typeof request.arguments === "object" && !Array.isArray(request.arguments) ? request.arguments as Record<string, unknown> : {};
  const includes = (field: string, expected: unknown): boolean => Array.isArray(policy[field]) && policy[field].includes(expected);
  if (!includes("capabilities", request.capability) || !includes("providers", runtime.providerId) || !includes("accessScopes", "full_device") || !includes("approvalModes", request.approvalMode)) {
    throw new PublicError("privileged_helper_policy_mismatch", 409, "Device policy does not allow this exact Full Device operation");
  }
  const launchProfileId = argumentsValue.launchProfileId;
  if (typeof launchProfileId === "string" && !includes("launchProfiles", launchProfileId)) {
    throw new PublicError("privileged_helper_policy_mismatch", 409, "Device policy does not allow this launch profile");
  }
  const credentialProfiles = credentialProjectionSummaries(record(ticketRequest.redactedSummary, "redactedSummary").credentialProfiles, "redactedSummary.credentialProfiles").map((profile) => profile.profileId);
  const allowedCredentialProfiles = Array.isArray(policy.credentialProfiles) ? policy.credentialProfiles : [];
  if (credentialProfiles.some((profile) => !allowedCredentialProfiles.includes(profile))) throw new PublicError("privileged_helper_policy_mismatch", 409, "Device policy does not allow a requested credential profile");
  if (request.approvalMode === "never" && policy.allowFullAccessWithoutApproval !== true) {
    throw new PublicError("full_device_never_local_opt_in_required", 409, "Never approval requires Device user policy opt-in");
  }
  const localRisks = policy.requiredApprovalRiskClasses;
  const effectiveRisks = request.requiredApprovalRiskClasses;
  if (!Array.isArray(localRisks) || !Array.isArray(effectiveRisks) || localRisks.some((risk) => !effectiveRisks.includes(risk))) {
    throw new PublicError("privileged_helper_policy_mismatch", 409, "Operation omits mandatory Device policy risk classes");
  }
  const cpuQuota = resourceCeilings.cpuQuotaPerSecUsec;
  const memoryMax = resourceCeilings.memoryMaxBytes;
  if (typeof policy.maxCpu === "number" && (typeof cpuQuota !== "number" || cpuQuota > policy.maxCpu * 1_000_000)) {
    throw new PublicError("privileged_helper_policy_mismatch", 409, "Requested CPU ceiling exceeds Device policy");
  }
  if (typeof policy.maxMemoryBytes === "number" && (typeof memoryMax !== "number" || memoryMax > policy.maxMemoryBytes)) {
    throw new PublicError("privileged_helper_policy_mismatch", 409, "Requested memory ceiling exceeds Device policy");
  }
}

const CONTROL_ACTIONS = new Set(["input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop"]);
const TERMINAL_OPERATION_STATES = new Set(["completed", "failed", "cancelled", "expired", "rejected", "uncertain"]);
const TERMINAL_RUN_STATES = new Set(["ready_for_review", "accepted", "rejected", "cancelled", "failed", "completed"]);
const INTERNAL_CONTROL_KINDS = new Set(["initial_agent_input", "adapter_approval", "adapter_protocol_response", "agent_lifecycle_stop"]);

function parseControlAuthority(value: unknown): Record<string, unknown> | null {
  if (value === null) return null;
  const authority = record(value, "controlAuthority");
  exactKeys(authority, ["kind", "approvalId", "approvalReceiptDigest", "terminal", "reasonCode", "agentStateRevision"], "controlAuthority");
  const kind = stringField(authority, "kind", 64);
  if (kind === "external_control") {
    if (Object.keys(authority).length !== 1) throw new TypeError("external controlAuthority cannot carry internal authority fields");
    return authority;
  }
  if (!INTERNAL_CONTROL_KINDS.has(kind)) throw new TypeError("controlAuthority.kind is unsupported");
  const revision = stringField(authority, "agentStateRevision", 20);
  if (!/^(0|[1-9][0-9]{0,19})$/.test(revision)) throw new TypeError("controlAuthority.agentStateRevision is invalid");
  if (kind === "initial_agent_input") {
    if (revision !== "1" || Object.keys(authority).some((key) => !["kind", "agentStateRevision"].includes(key))) throw new TypeError("initial agent input authority must bind revision 1 only");
  } else if (kind === "adapter_approval") {
    idField(authority, "approvalId");
    digestField(authority, "approvalReceiptDigest");
    if (Object.keys(authority).some((key) => !["kind", "approvalId", "approvalReceiptDigest", "agentStateRevision"].includes(key))) throw new TypeError("adapter approval authority contains unrelated fields");
  } else if (kind === "adapter_protocol_response") {
    if (authority.approvalId !== null || Object.keys(authority).some((key) => !["kind", "approvalId", "agentStateRevision"].includes(key))) throw new TypeError("adapter protocol response authority cannot claim an approval");
  } else {
    if (!["completed", "failed", "cancelled", "timed_out"].includes(String(authority.terminal))) throw new TypeError("agent lifecycle authority terminal is invalid");
    if (authority.reasonCode !== null && (typeof authority.reasonCode !== "string" || !/^[a-z][a-z0-9_.-]{0,127}$/.test(authority.reasonCode))) throw new TypeError("agent lifecycle authority reasonCode is invalid");
    if (Object.keys(authority).some((key) => !["kind", "terminal", "reasonCode", "agentStateRevision"].includes(key))) throw new TypeError("agent lifecycle authority contains unrelated fields");
  }
  return authority;
}

function expectedControlAction(authority: OperationAuthorityRow, request: Record<string, unknown>): string | null {
  if (authority.operation_kind === "agent_control") {
    if (authority.target_runtime_id !== null) return null;
    const mode = request.mode;
    if (mode === "input" || mode === "follow_up" || mode === "steer") return "input";
    if (mode === "cancel" || mode === "close") return "force_stop";
    return null;
  }
  if (authority.operation_kind === "runtime_control") {
    const control = request.control;
    if (control === "input" || control === "steer") return "input";
    if (control === "pause") return "pause";
    if (control === "resume") return "resume";
    if (control === "stop") return "graceful_stop";
    if (control === "cancel") return "force_stop";
  }
  return null;
}

async function verifyControlTicketBinding(
  env: ControlPlaneEnv,
  authority: OperationAuthorityRow,
  controlRequest: Record<string, unknown>,
  allowedOperation: string,
  controlDigest: string | null,
  runtimeId: string,
  payload: Record<string, unknown>,
): Promise<OperationAuthorityRow> {
  if (!CONTROL_ACTIONS.has(allowedOperation) || controlDigest === null || controlDigest !== authority.payload_digest || expectedControlAction(authority, controlRequest) !== allowedOperation) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control ticket is not bound to the exact Control Plane operation");
  }
  if (authority.target_operation_id === null || authority.target_digest === null || authority.target_controller_epoch === null || authority.expected_target_state === null || authority.expected_target_revision === null) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control target custody is incomplete");
  }
  if (controlRequest.operationId !== authority.id || controlRequest.targetRunId !== authority.run_id || controlRequest.targetDigest !== authority.target_digest || controlRequest.targetControllerEpoch !== authority.target_controller_epoch || controlRequest.expectedState !== authority.expected_target_state || String(controlRequest.expectedRevision) !== String(authority.expected_target_revision)) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control request differs from durable target custody");
  }
  if (authority.operation_kind === "runtime_control" && (authority.target_runtime_id !== runtimeId || controlRequest.targetRuntimeId !== runtimeId)) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege runtime control targets another Runtime");
  }
  const custody = await env.DB.prepare(`
    SELECT runtime_id,run_id,start_operation_id,device_id,target_digest,controller_epoch,state,revision
    FROM runtime_custody WHERE runtime_id=?1 AND run_id=?2 AND start_operation_id=?3 AND device_id=?4 LIMIT 1
  `).bind(runtimeId, authority.run_id, authority.target_operation_id, authority.device_id).first<{ runtime_id: string; run_id: string; start_operation_id: string; device_id: string; target_digest: string; controller_epoch: string; state: string; revision: number }>();
  if (custody === null || (authority.operation_kind === "runtime_control" && (custody.target_digest !== authority.target_digest || custody.controller_epoch !== authority.target_controller_epoch || custody.state !== authority.expected_target_state || custody.revision !== authority.expected_target_revision))) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control target custody changed before ticket issuance");
  }
  if (authority.operation_kind === "agent_control") {
    const agent = await env.DB.prepare("SELECT target_digest,controller_epoch,state,revision FROM agent_sessions WHERE run_id=?1 AND start_operation_id=?2 AND device_id=?3 LIMIT 1")
      .bind(authority.run_id, authority.target_operation_id, authority.device_id).first<{ target_digest: string; controller_epoch: string; state: string; revision: number }>();
    if (agent === null || agent.target_digest !== authority.target_digest || agent.controller_epoch !== authority.target_controller_epoch || agent.state !== authority.expected_target_state || agent.revision !== authority.expected_target_revision) {
      throw new PublicError("privilege_ticket_invalid", 409, "Privilege Agent control target custody changed before ticket issuance");
    }
  }
  const startAuthority = await operationAuthority(env, authority.target_operation_id);
  if (startAuthority === null || startAuthority.operation_kind !== "start" || startAuthority.device_id !== authority.device_id || startAuthority.run_id !== authority.run_id || startAuthority.assignment_id !== authority.assignment_id || startAuthority.project_id !== authority.project_id) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control is not bound to its immutable start operation");
  }
  const startTicket = await env.DB.prepare(`
    SELECT request.runtime_spec_digest,request.launch_plan_digest,request.local_execution_plan_digest
    FROM privilege_ticket_requests AS request
    JOIN privilege_ticket_issuance AS ticket ON ticket.request_id=request.request_id
    WHERE request.operation_id=?1 AND request.runtime_id=?2 AND request.status='issued'
      AND request.allowed_operation IN ('prepare','start')
    ORDER BY request.requested_at DESC,request.request_id DESC LIMIT 1
  `).bind(startAuthority.id, runtimeId).first<{ runtime_spec_digest: string; launch_plan_digest: string; local_execution_plan_digest: string }>();
  if (startTicket === null || startTicket.runtime_spec_digest !== payload.runtimeSpecDigest || startTicket.launch_plan_digest !== payload.launchPlanDigest || startTicket.local_execution_plan_digest !== payload.localExecutionPlanDigest) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege control plan differs from the immutable start ticket");
  }
  return startAuthority;
}

async function verifyInternalControlTicketBinding(env: ControlPlaneEnv, authority: OperationAuthorityRow, request: Record<string, unknown>, controlAuthority: Record<string, unknown>, allowedOperation: string): Promise<OperationAuthorityRow> {
  if (authority.operation_kind !== "start" || request.capability !== "agent.run.start" || authority.run_id === null) throw new PublicError("privilege_ticket_invalid", 409, "Internal control authority is not bound to an Agent start operation");
  const kind = String(controlAuthority.kind);
  if ((kind === "initial_agent_input" || kind === "adapter_approval" || kind === "adapter_protocol_response") && allowedOperation !== "input") throw new PublicError("privilege_ticket_invalid", 409, "Internal Agent input authority cannot request another helper operation");
  if (kind === "agent_lifecycle_stop" && !["graceful_stop", "force_stop"].includes(allowedOperation)) throw new PublicError("privilege_ticket_invalid", 409, "Agent lifecycle authority is limited to stop operations");
  const revision = Number(controlAuthority.agentStateRevision);
  const agent = await env.DB.prepare("SELECT start_operation_id,device_id,run_id,state,revision FROM agent_sessions WHERE start_operation_id=?1 AND device_id=?2 AND run_id=?3 LIMIT 1")
    .bind(authority.id, authority.device_id, authority.run_id).first<{ start_operation_id: string; device_id: string; run_id: string; state: string; revision: number }>();
  if (kind === "initial_agent_input") {
    if (agent !== null && (agent.revision !== 1 || !["starting", "running", "waiting_input"].includes(agent.state))) throw new PublicError("privilege_ticket_invalid", 409, "Initial Agent input no longer matches revision 1 custody");
    return authority;
  }
  if (agent === null || agent.revision !== revision || !["starting", "running", "waiting_input", "waiting_approval", "closing"].includes(agent.state)) throw new PublicError("privilege_ticket_invalid", 409, "Internal Agent control custody changed before ticket issuance");
  if (kind === "adapter_approval") {
    const approvalId = idField(controlAuthority, "approvalId");
    const receiptDigest = digestField(controlAuthority, "approvalReceiptDigest")!;
    const approval = await env.DB.prepare("SELECT approval.operation_id,approval.device_id,approval.run_id,approval.decision,approval.expires_at,outbox.payload_json,outbox.state FROM approvals AS approval JOIN approval_dispatch_outbox AS outbox ON outbox.approval_id=approval.id WHERE approval.id=?1 LIMIT 1")
      .bind(approvalId).first<{ operation_id: string; device_id: string; run_id: string | null; decision: string | null; expires_at: string; payload_json: string; state: string }>();
    let durableReceiptDigest: unknown = null;
    try { durableReceiptDigest = approval === null ? null : (JSON.parse(approval.payload_json) as Record<string, unknown>).receiptDigest; } catch { durableReceiptDigest = null; }
    if (approval === null || approval.operation_id !== authority.id || approval.device_id !== authority.device_id || approval.run_id !== authority.run_id || approval.decision !== "approved" || approval.state !== "offered" || Date.parse(approval.expires_at) <= Date.now() || durableReceiptDigest !== receiptDigest) throw new PublicError("approval_required", 409, "Adapter approval authority is absent, expired, or not durably delivered");
  }
  return authority;
}

async function issueTicket(env: ControlPlaneEnv, frame: PrivilegeTransportFrame): Promise<Record<string, unknown>> {
  const payload = frame.payload;
  exactKeys(payload, ["requestId", "idempotencyKey", "installationId", "deviceKeyId", "operationId", "runId", "runtimeId", "runtimeSpecDigest", "launchPlanDigest", "localExecutionPlanDigest", "controlRequestDigest", "controlAuthority", "runManifestDigest", "helperPolicyRevision", "helperPolicyDigest", "devicePolicyRevision", "approvalReceiptDigest", "approvalEnforcement", "allowedOperation", "resourceCeilings", "redactedSummary", "requestedAt", "expiresAt", "deviceSignature"], "ticket request");
  const redactedSummary = safeRedactedSummary(payload.redactedSummary);
  const controlAuthority = parseControlAuthority(payload.controlAuthority);
  const requestId = idField(payload, "requestId");
  const idempotencyKey = stringField(payload, "idempotencyKey", 256);
  if (idempotencyKey.length < 16) throw new TypeError("ticket idempotency key is too short");
  const installationId = idField(payload, "installationId");
  const operationId = idField(payload, "operationId");
  const runId = idField(payload, "runId");
  const runtimeId = stringField(payload, "runtimeId", 128);
  if (!RUNTIME_ID.test(runtimeId)) throw new TypeError("runtimeId is invalid");
  const requestedAt = parseDate(payload.requestedAt, "requestedAt");
  const requestedExpiresAt = parseDate(payload.expiresAt, "expiresAt");
  if (requestedExpiresAt <= Date.now() || requestedAt > Date.now() + 30_000 || requestedExpiresAt - requestedAt > 300_000) throw new PublicError("privilege_ticket_expired", 409, "Privilege ticket request validity is invalid");
  const deviceKeyId = await verifyDeviceSignedPayload(env, frame, payload);
  const unsignedPayload = { ...payload };
  delete unsignedPayload.deviceSignature;
  const requestDigest = await sha256Hex(canonicalJson(unsignedPayload));
  const authorityKind = controlAuthority === null ? null : String(controlAuthority.kind);
  const authorityRevision = controlAuthority?.agentStateRevision === undefined ? null : String(controlAuthority.agentStateRevision);
  const authorityApprovalId = typeof controlAuthority?.approvalId === "string" ? controlAuthority.approvalId : null;
  const prior = await env.DB.prepare("SELECT request_id,device_id,idempotency_key,request_digest,status FROM privilege_ticket_requests WHERE request_id=?1 OR (device_id=?2 AND idempotency_key=?3) OR (?4='initial_agent_input' AND operation_id=?5 AND control_authority_kind=?4 AND control_authority_revision=?6) LIMIT 1").bind(requestId, frame.deviceId, idempotencyKey, authorityKind, operationId, authorityRevision).first<{ request_id: string; device_id: string; idempotency_key: string; request_digest: string; status: string }>();
  if (prior !== null && (prior.request_digest !== requestDigest || prior.request_id !== requestId || prior.device_id !== frame.deviceId || prior.idempotency_key !== idempotencyKey)) {
    throw new PublicError("privilege_ticket_conflict", 409, "Privilege ticket request identity is bound to another request");
  }
  const authority = await operationAuthority(env, operationId);
  let operationRequest: Record<string, unknown>;
  try { operationRequest = authority === null ? {} : JSON.parse(authority.request_json) as Record<string, unknown>; } catch { operationRequest = {}; }
  if (authority === null || TERMINAL_OPERATION_STATES.has(authority.operation_state) || Date.parse(authority.operation_expires_at) <= Date.now() || authority.run_state === null || TERMINAL_RUN_STATES.has(authority.run_state)) {
    throw new PublicError("privilege_ticket_expired", 409, "Privilege ticket operation is no longer active");
  }
  const allowedOperation = stringField(payload, "allowedOperation", 32);
  const controlDigest = digestField(payload, "controlRequestDigest", true);
  const executionAuthority = CONTROL_ACTIONS.has(allowedOperation)
    ? controlAuthority?.kind === "external_control"
      ? await verifyControlTicketBinding(env, authority, operationRequest, allowedOperation, controlDigest, runtimeId, payload)
      : controlAuthority !== null && INTERNAL_CONTROL_KINDS.has(String(controlAuthority.kind))
        ? await verifyInternalControlTicketBinding(env, authority, operationRequest, controlAuthority, allowedOperation)
        : (() => { throw new PublicError("privilege_ticket_invalid", 409, "Effectful control lacks an exact controlAuthority"); })()
    : authority;
  let request: Record<string, unknown>;
  try { request = JSON.parse(executionAuthority.request_json) as Record<string, unknown>; } catch { request = {}; }
  if (!CONTROL_ACTIONS.has(allowedOperation) && (authority.operation_kind !== "start" || controlDigest !== null || controlAuthority !== null)) {
    throw new PublicError("privilege_ticket_invalid", 409, "Privilege launch ticket is not bound to a start operation");
  }
  const runtime = request.runtime === null || typeof request.runtime !== "object" || Array.isArray(request.runtime) ? {} : request.runtime as Record<string, unknown>;
  if (authority.device_id !== frame.deviceId || authority.run_id !== runId || executionAuthority.run_device_id !== frame.deviceId || executionAuthority.run_access_scope !== "full_device" || executionAuthority.run_runtime_kind !== "native" || request.accessScope !== "full_device" || runtime.kind !== "native" || runtime.providerId !== "privileged-native") throw new PublicError("full_device_capability_unavailable", 409, "Operation is not an exact privileged-native Full Device Run");
  if (executionAuthority.run_manifest_digest === null || executionAuthority.run_manifest_digest !== digestField(payload, "runManifestDigest") || executionAuthority.payload_digest !== request.payloadDigest) throw new PublicError("privilege_ticket_invalid", 409, "Immutable operation or Run Manifest binding differs");
  if (authority.connector_policy_id === null || authority.connector_policy_revision === null || (!CONTROL_ACTIONS.has(allowedOperation) && (request.connectorPolicyId !== authority.connector_policy_id || request.connectorPolicyRevision !== authority.connector_policy_revision))) throw new PublicError("privilege_ticket_invalid", 409, "Connector policy binding differs");
  if (authority.connector_grant_id !== null) {
    const connector = await env.DB.prepare("SELECT grant.id FROM oauth_grants AS grant JOIN connector_policies AS policy ON policy.id=grant.connector_policy_id AND policy.revision=grant.connector_policy_revision WHERE grant.id=?1 AND grant.status='active' AND policy.status='active' AND policy.id=?2 AND policy.revision=?3 AND grant.principal_id=?4 LIMIT 1")
      .bind(authority.connector_grant_id, authority.connector_policy_id, authority.connector_policy_revision, authority.actor_principal_id).first<{ id: string }>();
    if (connector === null) throw new PublicError("grant_reauthorization_required", 403, "Connector authority changed after operation admission");
  } else {
    const owner = await env.DB.prepare("SELECT id FROM owner_principals WHERE id=?1 AND status='active' LIMIT 1").bind(authority.actor_principal_id).first<{ id: string }>();
    if (owner === null || authority.connector_policy_id !== "cpol_owner_first_party_v1" || authority.connector_policy_revision !== 1) throw new PublicError("privilege_ticket_invalid", 403, "Owner authority is not current");
  }
  const argumentsValue = request.arguments === null || typeof request.arguments !== "object" || Array.isArray(request.arguments) ? {} : request.arguments as Record<string, unknown>;
  const adapterId = typeof argumentsValue.adapterId === "string" ? argumentsValue.adapterId : authority.adapter_id;
  const credentialProjections = operationCredentialProjections(argumentsValue.credentialProjections);
  const credentialSummary = credentialProjectionSummaries(redactedSummary.credentialProfiles, "redactedSummary.credentialProfiles");
  if (canonicalJson(credentialSummary) !== canonicalJson(credentialProjections.map(({ profileId, revision }) => ({ profileId, revision })))) {
    throw new PublicError("privilege_ticket_invalid", 409, "Credential projection summary differs from the immutable operation");
  }
  if (credentialProjections.length !== 0) {
    if (authority.assignment_id === null || authority.agent_configuration_json === null || adapterId === null) throw new PublicError("privilege_ticket_invalid", 409, "Credential projection requires exact Assignment and Adapter authority");
    let agentConfiguration: Record<string, unknown>;
    try { agentConfiguration = JSON.parse(authority.agent_configuration_json) as Record<string, unknown>; } catch { throw new PublicError("privilege_ticket_invalid", 409, "Project Agent credential authority is invalid"); }
    const agentProjections = operationCredentialProjections(agentConfiguration.credentialProjections);
    if (canonicalJson(agentProjections) !== canonicalJson(credentialProjections)) throw new PublicError("privilege_ticket_invalid", 409, "Credential projection exceeds the Project Agent Assignment authority");
  }
  const runtimeConfigurationRevision = positiveInteger(runtime, "configurationRevision");
  if (authority.assignment_id !== null && (authority.project_agent_id === null || argumentsValue.projectAgentId !== authority.project_agent_id || argumentsValue.projectAgentRevision !== authority.project_agent_revision || adapterId !== authority.adapter_id || authority.current_agent_status !== "active" || authority.current_agent_revision !== authority.project_agent_revision || authority.current_project_status !== "active" || authority.current_project_revision !== authority.binding_project_revision || authority.binding_device_id !== frame.deviceId || authority.binding_device_revision !== authority.current_device_revision || authority.binding_runtime_kind !== "native" || authority.binding_runtime_provider_id !== "privileged-native" || authority.binding_runtime_configuration_revision !== runtimeConfigurationRevision || authority.binding_access_scope !== "full_device" || authority.binding_approval_mode !== request.approvalMode)) throw new PublicError("privilege_ticket_invalid", 409, "Assignment, Project Agent, Project, Device, or Runtime configuration revision binding differs");
  if (authority.assignment_id === null && typeof argumentsValue.projectAgentId === "string") throw new PublicError("privilege_ticket_invalid", 409, "Project Agent work requires an immutable Assignment binding");
  if (authority.project_id !== null && authority.current_project_status !== "active") throw new PublicError("privilege_ticket_invalid", 409, "Project authority is no longer active");
  const installation = await env.DB.prepare(`
    SELECT installation.device_id,installation.expected_uid,installation.active_key_id,installation.active_policy_revision,
           installation.active_policy_digest,installation.capability_summary_json,installation.status,
           policy.public_summary_json AS root_policy_json,key.public_jwk_json,
           device_policy.revision AS device_policy_revision,device_policy.public_summary_json AS device_policy_json
    FROM device_privilege_installations AS installation
    JOIN privilege_installation_keys AS key ON key.installation_id=installation.installation_id AND key.key_id=installation.active_key_id AND key.status='active'
    JOIN privilege_policy_attestations AS policy ON policy.installation_id=installation.installation_id AND policy.revision=installation.active_policy_revision AND policy.status='active'
    JOIN device_user_policy_attestations AS device_policy ON device_policy.device_id=installation.device_id AND device_policy.status='active'
    WHERE installation.installation_id=?1 LIMIT 1
  `).bind(installationId).first<{ device_id: string; expected_uid: number; active_key_id: string; active_policy_revision: number; active_policy_digest: string; capability_summary_json: string; status: string; root_policy_json: string; public_jwk_json: string; device_policy_revision: number; device_policy_json: string }>();
  if (installation === null) throw new PublicError("privileged_helper_not_installed", 409, "No active Owner-approved helper installation exists");
  if (installation.status !== "active" || installation.device_id !== frame.deviceId) throw new PublicError("privileged_helper_disabled", 409, "Helper installation is not active for this Device");
  if (installation.active_policy_revision !== positiveInteger(payload, "helperPolicyRevision") || installation.active_policy_digest !== digestField(payload, "helperPolicyDigest")) throw new PublicError("privileged_helper_policy_mismatch", 409, "Helper policy revision differs");
  if (installation.device_policy_revision !== positiveInteger(payload, "devicePolicyRevision")) throw new PublicError("privileged_helper_policy_mismatch", 409, "Device user policy revision differs");
  const approvalMode = String(request.approvalMode);
  const requiredRiskClasses = Array.isArray(request.requiredApprovalRiskClasses) && request.requiredApprovalRiskClasses.every((value) => typeof value === "string") ? [...new Set(request.requiredApprovalRiskClasses as string[])] : [];
  if (approvalMode === "never" && requiredRiskClasses.length !== 0) throw new PublicError("approval_required", 409, "Mandatory risk classes prevent Never approval");
  const approvalEnforcement = stringField(payload, "approvalEnforcement", 32);
  if (!['exact_command','adapter_mediated','unavailable'].includes(approvalEnforcement) || approvalEnforcement === "unavailable") throw new PublicError("full_device_approval_enforcement_unavailable", 409, "Full Device approval enforcement is unavailable");
  if (request.capability === "agent.run.start" && approvalEnforcement !== "adapter_mediated" || request.capability === "command.start" && approvalEnforcement !== "exact_command") throw new PublicError("full_device_approval_enforcement_unavailable", 409, "Approval enforcement does not match the operation adapter");
  if (["input", "resize_pty", "pause", "resume", "graceful_stop", "force_stop"].includes(allowedOperation) && controlDigest === null) {
    throw new PublicError("privilege_ticket_invalid", 409, "An effectful control ticket requires an exact control request digest");
  }
  const approvalDigest = digestField(payload, "approvalReceiptDigest", true);
  if (approvalMode !== "never") {
    if (approvalDigest === null) throw new PublicError("approval_required", 409, "An exact approved commitment is required");
    const approval = await env.DB.prepare("SELECT commitment_digest,decision,expires_at,device_id,operation_id,run_id FROM approvals WHERE commitment_digest=?1 AND device_id=?2 AND operation_id=?3 AND run_id=?4 LIMIT 1")
      .bind(approvalDigest, frame.deviceId, executionAuthority.id, runId).first<{ commitment_digest: string; decision: string | null; expires_at: string; device_id: string; operation_id: string; run_id: string | null }>();
    if (approval === null || approval.decision !== "approved" || Date.parse(approval.expires_at) <= Date.now()) throw new PublicError("approval_required", 409, "Exact approval is absent or expired");
  }
  const resourceCeilings = record(payload.resourceCeilings, "resourceCeilings");
  summaryAllows(installation.root_policy_json, payload, request, installation.capability_summary_json, approvalMode, adapterId);
  devicePolicyAllows(installation.device_policy_json, request, payload);
  if (prior !== null) {
    const issuance = await env.DB.prepare("SELECT canonical_ticket_json FROM privilege_ticket_issuance WHERE request_id=?1 LIMIT 1").bind(requestId).first<{ canonical_ticket_json: string }>();
    if (issuance !== null) return { requestId, status: "issued", ticket: JSON.parse(issuance.canonical_ticket_json), replay: true };
  }
  const active = await issuerMaterial(env);
  const publicRow = await env.DB.prepare("SELECT revision,public_jwk_json,fingerprint FROM privilege_issuer_keys WHERE key_id=?1 AND status='active' LIMIT 1").bind(active.config.keyId).first<{ revision: number; public_jwk_json: string; fingerprint: string }>();
  if (publicRow === null || publicRow.revision !== active.config.revision || publicRow.public_jwk_json !== canonicalJson(active.publicJwk) || publicRow.fingerprint !== active.fingerprint) throw new PublicError("full_device_capability_unavailable", 503, "Active privilege issuer key is not Owner-activated");
  const rootPolicy = JSON.parse(installation.root_policy_json) as Record<string, unknown>;
  if (!Array.isArray(rootPolicy.ticketKeyIds) || !rootPolicy.ticketKeyIds.includes(active.config.keyId)) throw new PublicError("privileged_helper_policy_mismatch", 409, "Root policy does not pin the active privilege issuer key");
  const now = new Date();
  const ticketExpiresAt = new Date(Math.min(requestedExpiresAt, now.getTime() + 120_000, Date.parse(authority.operation_expires_at))).toISOString();
  const ticketId = newId("ptkt");
  const idempotencyKeyDigest = await sha256Hex(idempotencyKey);
  const operationRequestDigest = authority.payload_digest;
  const runManifestDigest = executionAuthority.run_manifest_digest;
  if (runManifestDigest === null) throw new PublicError("privilege_ticket_invalid", 409, "Immutable Run Manifest is unavailable");
  const issuedAt = now.toISOString();
  const claims = {
    schemaVersion: 1, protocol: "conduit.privileged/1", ticketId, issuerKind: "control_plane", issuerKeyId: active.config.keyId,
    audience: "conduit-privileged-helper", publicOrigin: env.PUBLIC_ORIGIN,
    helperInstallationId: installationId, helperKeyId: installation.active_key_id, helperPolicyRevision: installation.active_policy_revision, helperPolicyDigest: installation.active_policy_digest,
    deviceId: frame.deviceId, deviceKeyId, devicePolicyRevision: installation.device_policy_revision, expectedUid: installation.expected_uid,
    operationId, idempotencyKeyDigest, operationRequestDigest, runManifestDigest, runId, runtimeId,
    runtimeSpecDigest: digestField(payload, "runtimeSpecDigest")!, launchPlanDigest: digestField(payload, "launchPlanDigest")!, controlDigest, localExecutionPlanDigest: digestField(payload, "localExecutionPlanDigest")!,
    controllerEpoch: Number(frame.connectionEpoch), connectorPolicyId: authority.connector_policy_id, connectorPolicyRevision: authority.connector_policy_revision,
    projectId: authority.project_id, projectRevision: authority.binding_project_revision, assignmentId: authority.assignment_id,
    projectAgentId: authority.project_agent_id, projectAgentRevision: authority.project_agent_revision,
    deviceRevision: authority.current_device_revision, runtimeConfigurationRevision,
    accessScope: "full_device", approvalMode, approvalReceiptDigest: approvalDigest, approvalEnforcement,
    requiredApprovalRiskClasses: requiredRiskClasses,
    allowedOperation, resourceCeilings,
    issuedAt, expiresAt: ticketExpiresAt, nonce: randomToken(), maxUseCount: 1,
  };
  const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", active.key, new TextEncoder().encode(canonicalJson(claims)))));
  const ticket = { keyId: active.config.keyId, claims, signature };
  parseWireDocument(schemaIds.privilegedV1, ticket);
  const canonicalTicket = canonicalJson(ticket);
  const ticketDigest = await sha256Hex(canonicalTicket);
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO privilege_ticket_requests(request_id,device_id,device_key_id,connection_epoch,idempotency_key,idempotency_key_digest,installation_id,operation_id,assignment_id,run_id,runtime_id,runtime_spec_digest,launch_plan_digest,local_execution_plan_digest,control_request_digest,operation_request_digest,run_manifest_digest,helper_policy_revision,helper_policy_digest,device_policy_revision,connector_policy_id,connector_policy_revision,project_revision,project_agent_id,project_agent_revision,device_revision,runtime_configuration_revision,approval_receipt_digest,approval_enforcement,allowed_operation,resource_ceilings_json,redacted_summary_json,request_digest,device_signature,status,requested_at,expires_at,control_authority_kind,control_authority_revision,control_authority_approval_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,'issued',?35,?36,?37,?38,?39)")
      .bind(requestId, frame.deviceId, deviceKeyId, frame.connectionEpoch, idempotencyKey, idempotencyKeyDigest, installationId, operationId, authority.assignment_id, runId, runtimeId, claims.runtimeSpecDigest, claims.launchPlanDigest, claims.localExecutionPlanDigest, controlDigest, operationRequestDigest, runManifestDigest, installation.active_policy_revision, installation.active_policy_digest, installation.device_policy_revision, authority.connector_policy_id, authority.connector_policy_revision, authority.binding_project_revision, authority.project_agent_id, authority.project_agent_revision, authority.current_device_revision, runtimeConfigurationRevision, approvalDigest, approvalEnforcement, claims.allowedOperation, canonicalJson(resourceCeilings), canonicalJson(redactedSummary), requestDigest, String(payload.deviceSignature), issuedAt, ticketExpiresAt, authorityKind, authorityRevision, authorityApprovalId),
    env.DB.prepare("INSERT OR IGNORE INTO privilege_ticket_issuance(ticket_id,request_id,issuer_key_id,issuer_key_revision,canonical_ticket_json,signature,ticket_digest,status,issued_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'active',?8,?9)")
      .bind(ticketId, requestId, active.config.keyId, active.config.revision, canonicalTicket, signature, ticketDigest, issuedAt, ticketExpiresAt),
  ]);
  const persisted = await env.DB.prepare("SELECT canonical_ticket_json FROM privilege_ticket_issuance WHERE request_id=?1 LIMIT 1").bind(requestId).first<{ canonical_ticket_json: string }>();
  if (persisted === null) throw new PublicError("privilege_ticket_conflict", 409, "Privilege ticket issuance raced with another request");
  return { requestId, status: "issued", ticket: JSON.parse(persisted.canonical_ticket_json) };
}

function receiptTransitionAllowed(previous: string | null, next: string): boolean {
  if (previous === null) return next === "admitted";
  const allowed: Record<string, readonly string[]> = {
    admitted: ["prepared", "failed", "cancelled", "uncertain"], prepared: ["unit_created", "failed", "cancelled", "uncertain"],
    unit_created: ["running", "failed", "cancelled", "uncertain", "recovery_required"], running: ["running", "paused", "input_applied", "pty_resized", "stopping", "completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"],
    paused: ["paused", "resumed", "input_applied", "pty_resized", "stopping", "failed", "cancelled", "uncertain", "recovery_required"], resumed: ["running", "paused", "input_applied", "pty_resized", "stopping", "completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"],
    input_applied: ["running", "paused", "input_applied", "pty_resized", "stopping", "completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"],
    pty_resized: ["running", "paused", "input_applied", "pty_resized", "stopping", "completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"],
    stopping: ["completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"],
  };
  return allowed[previous]?.includes(next) === true;
}

function actionAllowsReceipt(allowedOperation: string, transition: string): boolean {
  const terminal = ["completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"];
  const allowed: Record<string, readonly string[]> = {
    prepare: ["admitted", "prepared"],
    start: ["unit_created", "running", ...terminal],
    input: ["input_applied"],
    resize_pty: ["pty_resized"],
    pause: ["paused"],
    resume: ["resumed"],
    graceful_stop: ["stopping", ...terminal],
    force_stop: ["stopping", ...terminal],
    inspect: ["prepared", "running", "paused", "stopping", ...terminal],
    reconcile: ["prepared", "running", "paused", "stopping", ...terminal],
  };
  return allowed[allowedOperation]?.includes(transition) === true;
}

async function projectReceipt(env: ControlPlaneEnv, frame: PrivilegeTransportFrame): Promise<Record<string, unknown>> {
  const payload = frame.payload;
  exactKeys(payload, ["receipt", "deviceKeyId", "deviceSignature"], "receipt projection");
  await verifyDeviceSignedPayload(env, frame, payload);
  const receipt = signedDocument(payload.receipt, "receipt");
  const claims = receipt.claims;
  const installationId = idField(claims, "installationId");
  const helperKeyId = idField(claims, "receiptKeyId");
  if (receipt.keyId !== helperKeyId || claims.protocol !== "conduit.privileged/1") throw new PublicError("privilege_ticket_invalid", 403, "Helper receipt key binding is invalid");
  const authority = await env.DB.prepare(`
    SELECT installation.device_id,installation.expected_uid,installation.status,
           key.public_jwk_json,key.status AS helper_key_status,key.valid_from AS helper_key_valid_from,key.valid_until AS helper_key_valid_until,key.revoked_at AS helper_key_revoked_at,
           ticket.ticket_digest,ticket.canonical_ticket_json,ticket.issuer_key_id,ticket.status AS ticket_status,ticket.expires_at AS ticket_expires_at,ticket.revoked_at AS ticket_revoked_at,
           issuer.status AS issuer_key_status,issuer.valid_from AS issuer_key_valid_from,issuer.valid_until AS issuer_key_valid_until,issuer.revoked_at AS issuer_key_revoked_at,
           request.operation_id,request.run_id,request.runtime_id,request.device_key_id,request.run_manifest_digest,request.device_policy_revision,request.allowed_operation,
           request.runtime_spec_digest,request.launch_plan_digest,request.local_execution_plan_digest,request.control_request_digest,request.operation_request_digest
           ,request.helper_policy_revision,request.helper_policy_digest
    FROM device_privilege_installations AS installation
    JOIN privilege_installation_keys AS key ON key.installation_id=installation.installation_id AND key.key_id=?2
    JOIN privilege_ticket_issuance AS ticket ON ticket.ticket_id=?3
    JOIN privilege_issuer_keys AS issuer ON issuer.key_id=ticket.issuer_key_id
    JOIN privilege_ticket_requests AS request ON request.request_id=ticket.request_id
    WHERE installation.installation_id=?1 LIMIT 1
  `).bind(installationId, helperKeyId, idField(claims, "ticketId")).first<{ device_id: string; expected_uid: number; status: string; public_jwk_json: string; helper_key_status: string; helper_key_valid_from: string; helper_key_valid_until: string | null; helper_key_revoked_at: string | null; ticket_digest: string; canonical_ticket_json: string; issuer_key_id: string; ticket_status: string; ticket_expires_at: string; ticket_revoked_at: string | null; issuer_key_status: string; issuer_key_valid_from: string; issuer_key_valid_until: string | null; issuer_key_revoked_at: string | null; operation_id: string; run_id: string; runtime_id: string; device_key_id: string; run_manifest_digest: string; device_policy_revision: number; allowed_operation: string; runtime_spec_digest: string; launch_plan_digest: string; local_execution_plan_digest: string; control_request_digest: string | null; operation_request_digest: string; helper_policy_revision: number; helper_policy_digest: string }>();
  if (authority === null || authority.device_id !== frame.deviceId) throw new PublicError("privileged_helper_registration_missing", 409, "Receipt helper installation is not registered");
  if (!await verifyEd25519(JSON.parse(authority.public_jwk_json) as JsonWebKey, receipt.signature, canonicalJson(claims))) throw new PublicError("privilege_ticket_invalid", 403, "Helper receipt signature is invalid");
  const receiptDigest = await sha256Hex(canonicalJson(payload.receipt));
  const stateRevision = positiveInteger(claims, "stateRevision");
  const controllerEpoch = positiveInteger(claims, "controllerEpoch");
  const transition = stringField(claims, "transition", 32);
  const previousDigest = digestField(claims, "previousReceiptDigest", true);
  const observedAt = parseDate(claims.observedAt, "receipt observedAt");
  if (observedAt > Date.now() + 30_000) throw new PublicError("privilege_ticket_invalid", 409, "Helper receipt observation time is in the future");
  if (claims.ticketDigest !== authority.ticket_digest || claims.operationId !== authority.operation_id || claims.runId !== authority.run_id || claims.runtimeId !== authority.runtime_id || claims.requestDigest !== authority.operation_request_digest || claims.runtimeSpecDigest !== authority.runtime_spec_digest || claims.launchPlanDigest !== authority.launch_plan_digest || claims.localExecutionPlanDigest !== authority.local_execution_plan_digest || claims.controlRequestDigest !== authority.control_request_digest || claims.policyRevision !== authority.helper_policy_revision || claims.policyDigest !== authority.helper_policy_digest) throw new PublicError("privilege_ticket_invalid", 409, "Helper receipt exact authority binding differs");
  const ticket = JSON.parse(authority.canonical_ticket_json) as { keyId?: unknown; claims?: Record<string, unknown> };
  const ticketClaims = ticket.claims ?? {};
  if (ticket.keyId !== authority.issuer_key_id || ticketClaims.schemaVersion !== 1 || ticketClaims.issuerKind !== "control_plane" || ticketClaims.issuerKeyId !== authority.issuer_key_id || ticketClaims.audience !== "conduit-privileged-helper" || ticketClaims.publicOrigin !== env.PUBLIC_ORIGIN || ticketClaims.helperInstallationId !== installationId || ticketClaims.helperKeyId !== helperKeyId || ticketClaims.helperPolicyRevision !== authority.helper_policy_revision || ticketClaims.helperPolicyDigest !== authority.helper_policy_digest || ticketClaims.deviceId !== frame.deviceId || ticketClaims.deviceKeyId !== authority.device_key_id || ticketClaims.devicePolicyRevision !== authority.device_policy_revision || ticketClaims.expectedUid !== authority.expected_uid || ticketClaims.operationId !== authority.operation_id || ticketClaims.operationRequestDigest !== authority.operation_request_digest || ticketClaims.runManifestDigest !== authority.run_manifest_digest || ticketClaims.runId !== authority.run_id || ticketClaims.runtimeId !== authority.runtime_id || ticketClaims.runtimeSpecDigest !== authority.runtime_spec_digest || ticketClaims.launchPlanDigest !== authority.launch_plan_digest || ticketClaims.localExecutionPlanDigest !== authority.local_execution_plan_digest || ticketClaims.controlDigest !== authority.control_request_digest || ticketClaims.allowedOperation !== authority.allowed_operation || ticketClaims.maxUseCount !== 1 || ticketClaims.controllerEpoch !== controllerEpoch) throw new PublicError("privilege_ticket_invalid", 409, "Issued ticket claims differ from durable authority");
  if (!actionAllowsReceipt(authority.allowed_operation, transition)) throw new PublicError("privilege_ticket_invalid", 409, "Helper receipt transition is not authorized by this action ticket");
  const duplicate = await env.DB.prepare("SELECT receipt_id FROM privilege_receipt_projections WHERE receipt_digest=?1 LIMIT 1").bind(receiptDigest).first<{ receipt_id: string }>();
  if (duplicate !== null) return { receiptDigest, status: "verified", replay: true };
  const previous = await env.DB.prepare("SELECT receipt_digest,transition,state_revision FROM privilege_receipt_projections WHERE runtime_id=?1 ORDER BY state_revision DESC LIMIT 1").bind(authority.runtime_id).first<{ receipt_digest: string; transition: string; state_revision: number }>();
  const priorTicketReceipt = await env.DB.prepare("SELECT receipt_id FROM privilege_receipt_projections WHERE ticket_id=?1 LIMIT 1").bind(idField(claims, "ticketId")).first<{ receipt_id: string }>();
  if (priorTicketReceipt === null) {
    const helperValid = authority.helper_key_status === "active"
      || authority.helper_key_status === "retiring" && authority.helper_key_valid_until !== null && observedAt <= Date.parse(authority.helper_key_valid_until)
      || authority.helper_key_status === "revoked" && authority.helper_key_revoked_at !== null && observedAt <= Date.parse(authority.helper_key_revoked_at);
    const issuerValid = authority.issuer_key_status === "active"
      || authority.issuer_key_status === "retiring" && authority.issuer_key_valid_until !== null && observedAt <= Date.parse(authority.issuer_key_valid_until)
      || authority.issuer_key_status === "revoked" && authority.issuer_key_revoked_at !== null && observedAt <= Date.parse(authority.issuer_key_revoked_at);
    const ticketValid = authority.ticket_status === "active"
      || authority.ticket_status === "revoked" && authority.ticket_revoked_at !== null && observedAt <= Date.parse(authority.ticket_revoked_at);
    if (!helperValid || !issuerValid || !ticketValid || observedAt < Date.parse(authority.helper_key_valid_from) || observedAt < Date.parse(authority.issuer_key_valid_from) || observedAt > Date.parse(authority.ticket_expires_at)) {
      throw new PublicError("privilege_ticket_invalid", 409, "New helper admission is outside active key and ticket authority");
    }
  }
  if (previous === null ? stateRevision !== 1 || previousDigest !== null : stateRevision !== previous.state_revision + 1 || previousDigest !== previous.receipt_digest || !receiptTransitionAllowed(previous.transition, transition)) throw new PublicError("privilege_ticket_replayed", 409, "Helper receipt chain is reordered or illegal");
  const cgroup = claims.cgroup === null ? null : stringField(claims, "cgroup", 256);
  const processBirth = claims.processBirth === null ? null : stringField(claims, "processBirth", 128);
  const now = nowIso();
  await env.DB.prepare("INSERT INTO privilege_receipt_projections(receipt_digest,receipt_id,installation_id,helper_key_id,ticket_id,ticket_digest,device_id,operation_id,request_digest,run_id,runtime_id,runtime_spec_digest,launch_plan_digest,local_execution_plan_digest,control_request_digest,controller_epoch,state_revision,transition,previous_receipt_digest,unit_name,invocation_id,cgroup_identity_digest,main_pid,process_birth_digest,effective_uid,effective_gid,stdout_cursor,stderr_cursor,exit_code,signal,helper_version,helper_policy_revision,helper_policy_digest,observed_at,helper_signature,verified_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36)")
    .bind(receiptDigest, idField(claims, "receiptId"), installationId, helperKeyId, idField(claims, "ticketId"), authority.ticket_digest, frame.deviceId, authority.operation_id, authority.operation_request_digest, authority.run_id, authority.runtime_id, authority.runtime_spec_digest, authority.launch_plan_digest, authority.local_execution_plan_digest, authority.control_request_digest, controllerEpoch, stateRevision, transition, previousDigest, stringField(claims, "unitName", 192), claims.invocationId ?? null, cgroup === null ? null : await sha256Hex(cgroup), claims.mainPid ?? null, processBirth === null ? null : await sha256Hex(processBirth), claims.effectiveUid ?? null, claims.effectiveGid ?? null, claims.stdoutCursor, claims.stderrCursor, claims.exitCode ?? null, claims.signal ?? null, stringField(claims, "helperVersion", 64), authority.helper_policy_revision, authority.helper_policy_digest, stringField(claims, "observedAt", 64), receipt.signature, now).run();
  return { receiptDigest, status: "verified", transition, stateRevision };
}

export async function projectPrivilegeFrame(env: ControlPlaneEnv, frame: PrivilegeTransportFrame): Promise<Record<string, unknown>> {
  if (frame.type === "privilege.installation_attestation") return projectInstallation(env, frame);
  if (frame.type === "privilege.ticket_request") return issueTicket(env, frame);
  return projectReceipt(env, frame);
}

export async function requireVerifiedPrivilegeReceipt(env: ControlPlaneEnv, input: { operationId: string; deviceId: string; runId: string | null; requestDigest: string; receiptDigest: unknown; transition: string; runtimeId?: unknown; controllerEpoch?: unknown }): Promise<void> {
  const operation = await env.DB.prepare("SELECT request_json FROM operation_journal WHERE id=?1 LIMIT 1").bind(input.operationId).first<{ request_json: string }>();
  if (operation === null) return;
  let request: Record<string, unknown>;
  try { request = JSON.parse(operation.request_json) as Record<string, unknown>; } catch { request = {}; }
  if (request.accessScope !== "full_device") return;
  if (typeof input.receiptDigest !== "string" || !HASH.test(input.receiptDigest)) throw new PublicError("privilege_ticket_required", 409, "A verified helper receipt is required for Full Device projection");
  const row = await env.DB.prepare("SELECT transition,runtime_id,controller_epoch FROM privilege_receipt_projections WHERE receipt_digest=?1 AND operation_id=?2 AND device_id=?3 AND run_id IS ?4 AND request_digest=?5 LIMIT 1")
    .bind(input.receiptDigest, input.operationId, input.deviceId, input.runId, input.requestDigest).first<{ transition: string; runtime_id: string; controller_epoch: number }>();
  const compatible = input.transition === "running" ? ["running", "resumed", "input_applied"]
    : input.transition === "control" ? ["paused", "resumed", "input_applied", "stopping", "completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"]
    : input.transition === "terminal" ? ["completed", "failed", "cancelled", "timed_out", "uncertain", "recovery_required"]
    : ["admitted", "prepared", "unit_created"];
  if (row === null || !compatible.includes(row.transition) || (typeof input.runtimeId === "string" && row.runtime_id !== input.runtimeId) || (input.controllerEpoch !== undefined && String(row.controller_epoch) !== String(input.controllerEpoch))) throw new PublicError("privilege_ticket_invalid", 409, "Helper receipt does not match the projected Full Device transition");
}

export async function handlePrivilegeAdmin(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "GET" && path === "/v1/privileged/installations/browser.js") return privilegeBrowserScript();
  if (request.method === "GET" && path === "/v1/privileged/installations") {
    await requireBrowserSession(request, env);
    const rows = await env.DB.prepare(`
      SELECT installation.installation_id,installation.device_id,installation.expected_uid,installation.public_origin,
             installation.helper_version,installation.protocol_version,installation.capability_digest,installation.capability_summary_json,
             installation.device_attestation_digest,installation.status,installation.active_policy_revision,installation.active_policy_digest,
             installation.last_observed_at,
             (SELECT key.fingerprint FROM privilege_installation_keys AS key WHERE key.installation_id=installation.installation_id ORDER BY CASE key.status WHEN 'pending_owner' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,key.created_at DESC LIMIT 1) AS helper_key_fingerprint,
             (SELECT policy.policy_digest FROM privilege_policy_attestations AS policy WHERE policy.installation_id=installation.installation_id ORDER BY CASE policy.status WHEN 'pending_owner' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,policy.revision DESC LIMIT 1) AS reviewed_policy_digest
      FROM device_privilege_installations AS installation ORDER BY installation.created_at DESC LIMIT 64
    `).all<Record<string, unknown>>();
    return Response.json({ installations: rows.results.map((row) => ({ ...row, capability_summary_json: JSON.parse(String(row.capability_summary_json)) })) }, { headers: { "cache-control": "no-store" } });
  }
  const decision = path.match(/^\/v1\/privileged\/installations\/([^/]+)\/decision$/);
  if (request.method === "POST" && decision?.[1] !== undefined) {
    const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
    const body = record(await readJsonBounded(request));
    exactKeys(body, ["decision", "expectedAttestationDigest"], "helper decision");
    const installationId = boundedString(decision[1], "installationId", 128);
    const expectedDigest = boundedString(body.expectedAttestationDigest, "expectedAttestationDigest", 64, 64);
    if (!HASH.test(expectedDigest)) throw new PublicError("invalid_request", 400, "Expected attestation digest is invalid");
    const action = boundedString(body.decision, "decision", 16);
    const row = await env.DB.prepare("SELECT device_id,device_attestation_digest,status FROM device_privilege_installations WHERE installation_id=?1 LIMIT 1").bind(installationId).first<{ device_id: string; device_attestation_digest: string; status: string }>();
    if (row === null || row.device_attestation_digest !== expectedDigest) throw new PublicError("revision_conflict", 409, "Helper attestation changed before the decision");
    const now = nowIso();
    if (action === "deny") {
      await env.DB.batch([
        env.DB.prepare("UPDATE device_privilege_installations SET status='disabled',owner_principal_id=?1,owner_decision_digest=?2,updated_at=?3 WHERE installation_id=?4 AND device_attestation_digest=?5 AND status IN ('pending_owner','policy_review','active')").bind(session.principal_id, await sha256Hex(canonicalJson({ installationId, expectedDigest, action })), now, installationId, expectedDigest),
        env.DB.prepare("UPDATE privilege_installation_keys SET status='revoked',revoked_at=?1 WHERE installation_id=?2 AND status<>'revoked'").bind(now, installationId),
        env.DB.prepare("UPDATE privilege_ticket_issuance SET status='revoked',revoked_at=?1 WHERE status='active' AND request_id IN (SELECT request_id FROM privilege_ticket_requests WHERE installation_id=?2)").bind(now, installationId),
      ]);
      await repo.audit("privileged_helper.denied", { installationId, attestationDigest: expectedDigest }, session.principal_id, undefined, row.device_id);
      return new Response(null, { status: 204 });
    }
    if (action !== "approve") throw new PublicError("invalid_request", 400, "decision must be approve or deny");
    const pending = await env.DB.prepare(`
      SELECT key.key_id,
             COALESCE(policy.revision,installation.active_policy_revision) AS revision,
             COALESCE(policy.policy_digest,installation.active_policy_digest) AS policy_digest,
             device_policy.revision AS device_policy_revision,
             device_policy.policy_digest AS device_policy_digest
      FROM device_privilege_installations AS installation
      JOIN privilege_installation_keys AS key ON key.installation_id=installation.installation_id AND key.status IN ('pending_owner','active')
      LEFT JOIN privilege_policy_attestations AS policy ON policy.installation_id=installation.installation_id AND policy.helper_key_id=key.key_id AND policy.status='pending_owner'
      JOIN device_user_policy_attestations AS device_policy ON device_policy.device_id=installation.device_id AND device_policy.status IN ('pending_owner','active')
      WHERE installation.installation_id=?1
        AND (key.status='pending_owner' OR policy.revision IS NOT NULL OR installation.status='pending_owner' OR (installation.status='active' AND key.key_id=installation.active_key_id))
      ORDER BY CASE WHEN key.status='pending_owner' THEN 0 ELSE 1 END,COALESCE(policy.revision,installation.active_policy_revision) DESC,device_policy.revision DESC
      LIMIT 1
    `).bind(installationId).first<{ key_id: string; revision: number; policy_digest: string; device_policy_revision: number; device_policy_digest: string }>();
    if (pending === null) throw new PublicError("privileged_helper_registration_missing", 409, "No exact pending helper key and policy exist");
    const issuerKeys = await env.DB.prepare("SELECT key_id,revision,public_jwk_json,fingerprint,status,valid_from,valid_until,predecessor_key_id,rotation_statement_digest,rotation_signature FROM privilege_issuer_keys WHERE status IN ('active','retiring') ORDER BY revision DESC LIMIT 4").all<Record<string, unknown>>();
    if (!issuerKeys.results.some((key) => key.status === "active")) {
      throw new PublicError("full_device_capability_unavailable", 409, "Activate the privilege ticket issuer before approving a helper installation");
    }
    const ownerDecisionDigest = await sha256Hex(canonicalJson({ installationId, expectedDigest, action, helperKeyId: pending.key_id, policyRevision: pending.revision, policyDigest: pending.policy_digest, devicePolicyRevision: pending.device_policy_revision, devicePolicyDigest: pending.device_policy_digest }));
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE privilege_installation_keys SET status='retiring',valid_until=?1 WHERE installation_id=?2 AND status='active' AND key_id<>?3").bind(new Date(Date.now() + 300_000).toISOString(), installationId, pending.key_id),
      env.DB.prepare("UPDATE privilege_installation_keys SET status='active',approved_at=?1 WHERE installation_id=?2 AND key_id=?3 AND status='pending_owner'").bind(now, installationId, pending.key_id),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='superseded' WHERE installation_id=?1 AND status='active' AND revision<?2").bind(installationId, pending.revision),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='active',approved_by=?1,approved_at=?2 WHERE installation_id=?3 AND revision=?4 AND status='pending_owner'").bind(session.principal_id, now, installationId, pending.revision),
      env.DB.prepare("UPDATE device_user_policy_attestations SET status='superseded' WHERE device_id=?1 AND status='active' AND revision<?2").bind(row.device_id, pending.device_policy_revision),
      env.DB.prepare("UPDATE device_user_policy_attestations SET status='active' WHERE device_id=?1 AND revision=?2 AND policy_digest=?3 AND status='pending_owner'").bind(row.device_id, pending.device_policy_revision, pending.device_policy_digest),
      env.DB.prepare("UPDATE device_privilege_installations SET active_key_id=?1,active_policy_revision=?2,active_policy_digest=?3,status='active',owner_principal_id=?4,owner_decision_digest=?5,approved_at=?6,updated_at=?6 WHERE installation_id=?7 AND device_attestation_digest=?8 AND status IN ('pending_owner','policy_review','active')").bind(pending.key_id, pending.revision, pending.policy_digest, session.principal_id, ownerDecisionDigest, now, installationId, expectedDigest),
    ]);
    if (results[6]?.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Helper approval raced with another decision");
    const approved = await env.DB.prepare("SELECT key.public_jwk_json,key.fingerprint FROM privilege_installation_keys AS key WHERE key.installation_id=?1 AND key.key_id=?2 AND key.status='active' LIMIT 1").bind(installationId, pending.key_id).first<{ public_jwk_json: string; fingerprint: string }>();
    if (approved === null) throw new PublicError("privileged_helper_registration_missing", 409, "Approved helper key is unavailable");
    await env.DEVICE_ROOMS.getByName(row.device_id).deliverPrivilegeRegistration(
      await activePrivilegeRegistrationResult(env, installationId, expectedDigest),
    );
    await repo.audit("privileged_helper.approved", { installationId, attestationDigest: expectedDigest, helperKeyId: pending.key_id, policyRevision: pending.revision, policyDigest: pending.policy_digest }, session.principal_id, undefined, row.device_id);
    return Response.json({ installationId, state: "active", policyRevision: pending.revision });
  }
  const revoke = path.match(/^\/v1\/privileged\/installations\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revoke?.[1] !== undefined) {
    const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true, allowRecovery: true });
    const installationId = boundedString(revoke[1], "installationId", 128);
    const now = nowIso();
    const row = await env.DB.prepare("SELECT device_id FROM device_privilege_installations WHERE installation_id=?1 AND status<>'revoked' LIMIT 1").bind(installationId).first<{ device_id: string }>();
    if (row === null) throw new PublicError("not_found", 404, "Active helper installation not found");
    await env.DB.batch([
      env.DB.prepare("UPDATE device_privilege_installations SET status='revoked',updated_at=?1 WHERE installation_id=?2 AND status<>'revoked'").bind(now, installationId),
      env.DB.prepare("UPDATE privilege_installation_keys SET status='revoked',revoked_at=?1 WHERE installation_id=?2 AND status<>'revoked'").bind(now, installationId),
      env.DB.prepare("UPDATE privilege_policy_attestations SET status='revoked' WHERE installation_id=?1 AND status<>'revoked'").bind(installationId),
      env.DB.prepare("UPDATE privilege_ticket_issuance SET status='revoked',revoked_at=?1 WHERE status='active' AND request_id IN (SELECT request_id FROM privilege_ticket_requests WHERE installation_id=?2)").bind(now, installationId),
    ]);
    await repo.audit("privileged_helper.revoked", { installationId }, session.principal_id, undefined, row.device_id);
    return new Response(null, { status: 204 });
  }
  if (request.method === "POST" && path === "/v1/privileged/issuer/activate") {
    const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
    const active = await activateIssuer(env);
    await repo.audit("privilege_issuer.activated", active, session.principal_id);
    return Response.json(active);
  }
  const revokeIssuer = path.match(/^\/v1\/privileged\/issuer\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revokeIssuer?.[1] !== undefined) {
    const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true, allowRecovery: true });
    const keyId = boundedString(revokeIssuer[1], "keyId", 128);
    const now = nowIso();
    const [result] = await env.DB.batch([
      env.DB.prepare("UPDATE privilege_issuer_keys SET status='revoked',revoked_at=?1,valid_until=?1 WHERE key_id=?2 AND status<>'revoked'").bind(now, keyId),
      env.DB.prepare("UPDATE privilege_ticket_issuance SET status='revoked',revoked_at=?1 WHERE issuer_key_id=?2 AND status='active'").bind(now, keyId),
    ]);
    if (result?.meta.changes !== 1) throw new PublicError("not_found", 404, "Privilege issuer key not found");
    await repo.audit("privilege_issuer.revoked", { keyId }, session.principal_id);
    return new Response(null, { status: 204 });
  }
  return null;
}

export async function revokeDevicePrivileges(env: ControlPlaneEnv, deviceId: string, at: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE privilege_ticket_issuance SET status='revoked',revoked_at=?1 WHERE status='active' AND request_id IN (SELECT request_id FROM privilege_ticket_requests WHERE device_id=?2)").bind(at, deviceId),
    env.DB.prepare("UPDATE device_privilege_installations SET status='revoked',updated_at=?1 WHERE device_id=?2 AND status<>'revoked'").bind(at, deviceId),
    env.DB.prepare("UPDATE privilege_installation_keys SET status='revoked',revoked_at=?1 WHERE installation_id IN (SELECT installation_id FROM device_privilege_installations WHERE device_id=?2) AND status<>'revoked'").bind(at, deviceId),
    env.DB.prepare("UPDATE privilege_policy_attestations SET status='revoked' WHERE installation_id IN (SELECT installation_id FROM device_privilege_installations WHERE device_id=?1) AND status<>'revoked'").bind(deviceId),
    env.DB.prepare("UPDATE device_user_policy_attestations SET status='revoked' WHERE device_id=?1 AND status<>'revoked'").bind(deviceId),
  ]);
}

export function privilegeResultType(): string { return PRIVILEGE_RESULT_TYPE; }
export function privilegeRegistrationResultType(): string { return PRIVILEGE_REGISTRATION_RESULT_TYPE; }

export async function renderPrivilegePage(): Promise<Response> {
  return new Response(`<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Privileged helper</title><body><h1>Privileged helper</h1><p>Only approve a locally installed helper after comparing its Device, UID, origin, key and policy digests.</p><button id=refresh type=button>Refresh</button><button id=issuer type=button>Verify passkey and activate ticket key</button><ol id=installations></ol><p id=status role=status aria-live=polite></p><script src=/api/v1/privileged/installations/browser.js defer></script></body></html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'none'; frame-ancestors 'none'", "permissions-policy": "publickey-credentials-get=(self)" } });
}

const PRIVILEGE_BROWSER_SCRIPT = `(() => {
  const list = document.querySelector("#installations"), status = document.querySelector("#status");
  const fromB64 = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((value.length+3)%4)), c => c.charCodeAt(0));
  const toB64 = value => { const bytes=new Uint8Array(value); let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,""); };
  const csrf = () => document.cookie.split(";").map(x=>x.trim()).find(x=>x.startsWith("__Host-conduit_csrf="))?.slice(22) ?? "";
  const json = async (path, init={}) => { const response=await fetch(path,{credentials:"same-origin",...init}); const body=response.status===204?{}:await response.json(); if(!response.ok)throw new Error(body?.error?.message??"Request failed"); return body; };
  const stepUp = async () => { const ceremony=await json("/api/v1/auth/step-up/options",{method:"POST",headers:{"content-type":"application/json","x-csrf-token":csrf()},body:"{}"}); const publicKey={...ceremony.options,challenge:fromB64(ceremony.options.challenge),allowCredentials:(ceremony.options.allowCredentials??[]).map(x=>({...x,id:fromB64(x.id)}))}; const credential=await navigator.credentials.get({publicKey}); const response=credential.response; await json("/api/v1/auth/step-up/verify",{method:"POST",headers:{"content-type":"application/json","x-csrf-token":csrf()},body:JSON.stringify({challengeId:ceremony.challengeId,challenge:ceremony.options.challenge,response:{id:credential.id,rawId:toB64(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:toB64(response.clientDataJSON),authenticatorData:toB64(response.authenticatorData),signature:toB64(response.signature),userHandle:response.userHandle===null?null:toB64(response.userHandle)}}})}); };
  const refresh = async () => { const data=await json("/api/v1/privileged/installations"); list.replaceChildren(...data.installations.map(item=>{ const li=document.createElement("li"); const code=document.createElement("code"); code.textContent=[item.installation_id,item.device_id,"uid="+item.expected_uid,item.public_origin,"helper-key="+item.helper_key_fingerprint,"root-policy="+item.reviewed_policy_digest,"capabilities="+JSON.stringify(item.capability_summary_json),item.device_attestation_digest,item.status].join(" | "); li.append(code); for(const decision of ["approve","deny"]){const button=document.createElement("button");button.textContent=decision;button.onclick=async()=>{await stepUp();await json("/api/v1/privileged/installations/"+encodeURIComponent(item.installation_id)+"/decision",{method:"POST",headers:{"content-type":"application/json","x-csrf-token":csrf()},body:JSON.stringify({decision,expectedAttestationDigest:item.device_attestation_digest})});await refresh();};li.append(button);} return li;})); };
  document.querySelector("#refresh").onclick=()=>refresh().catch(e=>status.textContent=e.message); document.querySelector("#issuer").onclick=async()=>{try{await stepUp();await json("/api/v1/privileged/issuer/activate",{method:"POST",headers:{"content-type":"application/json","x-csrf-token":csrf()},body:"{}"});status.textContent="Ticket issuer key activated.";}catch(e){status.textContent=e.message;}}; refresh().catch(e=>status.textContent=e.message);
})();`;

function privilegeBrowserScript(): Response {
  return new Response(PRIVILEGE_BROWSER_SCRIPT, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'" } });
}

export function privilegeDenialResult(requestId: unknown, error: unknown): Record<string, unknown> {
  const code: DenialCode = error instanceof PublicError ? error.code : "privilege_ticket_invalid";
  return { requestId: typeof requestId === "string" && ID.test(requestId) ? requestId : null, status: "denied", error: { code, retryable: false } };
}
