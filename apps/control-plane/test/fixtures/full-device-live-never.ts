import { canonicalJson, sha256Hex } from "../../src/crypto.ts";
import type { ControlPlaneEnv } from "../../src/types.ts";

interface DenialResult {
  requestId?: unknown;
  status?: unknown;
  error?: { code?: unknown };
}

interface NeverDenialAssertion {
  installationId: string;
  deviceId: string;
  deniedRequestId: string;
  initialDevicePolicyRevision: number;
  result: DenialResult;
}

interface NeverIssuanceAssertion {
  installationId: string;
  deviceId: string;
  deniedRequestId: string;
  issuedRequestId: string;
  initialDevicePolicyRevision: number;
  enabledDevicePolicyRevision: number;
}

interface DevicePolicyRow {
  revision: number;
  policy_digest: string;
  previous_policy_digest: string | null;
  public_summary_json: string;
  status: string;
}

interface InstallationRow {
  active_key_id: string | null;
  active_policy_revision: number | null;
  active_policy_digest: string | null;
  device_attestation_digest: string;
  owner_principal_id: string | null;
  owner_decision_digest: string | null;
  approved_at: string | null;
  status: string;
}

const NEVER_DENIAL_CODE = "full_device_never_local_opt_in_required";

function object(value: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} is not JSON`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${label} is not an object`);
  return parsed as Record<string, unknown>;
}

function assertNeverSetting(summary: Record<string, unknown>, expected: boolean, label: string): void {
  const modes = summary.approvalModes;
  const includesNever = Array.isArray(modes) && modes.includes("never");
  if (includesNever !== expected || summary.allowFullAccessWithoutApproval !== expected) {
    throw new Error(`${label} does not ${expected ? "enable" : "deny"} Never consistently`);
  }
}

async function devicePolicy(
  env: ControlPlaneEnv,
  deviceId: string,
  revision: number,
): Promise<DevicePolicyRow> {
  const row = await env.DB.prepare(`
    SELECT revision,policy_digest,previous_policy_digest,public_summary_json,status
    FROM device_user_policy_attestations
    WHERE device_id=?1 AND revision=?2
    LIMIT 1
  `).bind(deviceId, revision).first<DevicePolicyRow>();
  if (row === null) throw new Error(`Device policy revision ${revision} is absent`);
  return row;
}

async function installation(
  env: ControlPlaneEnv,
  installationId: string,
  deviceId: string,
): Promise<InstallationRow> {
  const row = await env.DB.prepare(`
    SELECT active_key_id,active_policy_revision,active_policy_digest,
           device_attestation_digest,owner_principal_id,owner_decision_digest,
           approved_at,status
    FROM device_privilege_installations
    WHERE installation_id=?1 AND device_id=?2
    LIMIT 1
  `).bind(installationId, deviceId).first<InstallationRow>();
  if (row === null) throw new Error("privileged installation is absent");
  return row;
}

async function issuanceCount(env: ControlPlaneEnv): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_issuance").first<{ count: number }>();
  if (row === null || !Number.isSafeInteger(row.count) || row.count < 0) throw new Error("ticket issuance count is unavailable");
  return row.count;
}

/**
 * Assert the first half of the isolated live transition after the signed
 * ticket request has traversed the production privilege projector. The
 * assertion is deliberately read-only: the Device policy is signed by the
 * live Node client and root policy changes remain root-local.
 */
export async function assertServerNeverDenied(
  env: ControlPlaneEnv,
  input: NeverDenialAssertion,
): Promise<Record<string, unknown>> {
  if (input.result.requestId !== input.deniedRequestId || input.result.status !== "denied" || input.result.error?.code !== NEVER_DENIAL_CODE) {
    throw new Error("Never ticket request did not return the expected production denial");
  }

  const activeInstallation = await installation(env, input.installationId, input.deviceId);
  if (activeInstallation.status !== "active") throw new Error("initial helper installation is not Owner-approved and active");
  const initial = await devicePolicy(env, input.deviceId, input.initialDevicePolicyRevision);
  if (initial.status !== "active" || initial.previous_policy_digest !== null) throw new Error("initial Device policy is not the active policy root");
  assertNeverSetting(object(initial.public_summary_json, "initial Device policy"), false, "initial Device policy");

  const request = await env.DB.prepare("SELECT status FROM privilege_ticket_requests WHERE request_id=?1 LIMIT 1")
    .bind(input.deniedRequestId).first<{ status: string }>();
  const ticket = await env.DB.prepare("SELECT ticket_id FROM privilege_ticket_issuance WHERE request_id=?1 LIMIT 1")
    .bind(input.deniedRequestId).first<{ ticket_id: string }>();
  if (request !== null || ticket !== null) throw new Error("server-denied Never request acquired durable ticket authority");

  return {
    schemaVersion: 1,
    productionPrivilegeProjection: true,
    installationOwnerApproved: true,
    initialDevicePolicyRevision: initial.revision,
    initialDevicePolicyDigest: initial.policy_digest,
    initialApprovalModesIncludeNever: false,
    initialAllowFullAccessWithoutApproval: false,
    deniedRequestId: input.deniedRequestId,
    denialCode: NEVER_DENIAL_CODE,
    deniedRequestPersisted: false,
    deniedTicketIssued: false,
    ticketIssuanceCountAfterDenial: await issuanceCount(env),
  };
}

/**
 * Assert the completed transition after the live Node has submitted a signed,
 * predecessor-linked Device policy and the fixture has called the unchanged
 * fresh-Owner privilege decision handler. This never mutates authority.
 */
export async function assertServerNeverEnabledAndIssued(
  env: ControlPlaneEnv,
  input: NeverIssuanceAssertion,
): Promise<Record<string, unknown>> {
  if (input.enabledDevicePolicyRevision <= input.initialDevicePolicyRevision) throw new Error("enabled Device policy revision did not advance");
  const initial = await devicePolicy(env, input.deviceId, input.initialDevicePolicyRevision);
  const enabled = await devicePolicy(env, input.deviceId, input.enabledDevicePolicyRevision);
  assertNeverSetting(object(initial.public_summary_json, "initial Device policy"), false, "initial Device policy");
  assertNeverSetting(object(enabled.public_summary_json, "enabled Device policy"), true, "enabled Device policy");
  if (initial.status !== "superseded" || enabled.status !== "active" || enabled.previous_policy_digest !== initial.policy_digest) {
    throw new Error("Owner-approved Device policy transition is not monotonic and predecessor-linked");
  }

  const activeInstallation = await installation(env, input.installationId, input.deviceId);
  if (activeInstallation.status !== "active" || activeInstallation.active_key_id === null || activeInstallation.active_policy_revision === null || activeInstallation.active_policy_digest === null || activeInstallation.owner_principal_id === null || activeInstallation.owner_decision_digest === null || activeInstallation.approved_at === null) {
    throw new Error("enabled helper installation lacks active Owner-approved authority");
  }

  const expectedDecisionDigest = await sha256Hex(canonicalJson({
    installationId: input.installationId,
    expectedDigest: activeInstallation.device_attestation_digest,
    action: "approve",
    helperKeyId: activeInstallation.active_key_id,
    policyRevision: activeInstallation.active_policy_revision,
    policyDigest: activeInstallation.active_policy_digest,
    devicePolicyRevision: enabled.revision,
    devicePolicyDigest: enabled.policy_digest,
  }));
  if (activeInstallation.owner_decision_digest !== expectedDecisionDigest) throw new Error("Owner decision is not bound to the enabled Device policy revision");

  const approvalEvent = await env.DB.prepare(`
    SELECT principal_id,device_id,metadata_json,created_at
    FROM security_events
    WHERE event_type='privileged_helper.approved' AND principal_id=?1 AND device_id=?2
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(activeInstallation.owner_principal_id, input.deviceId).first<{ principal_id: string; device_id: string; metadata_json: string; created_at: string }>();
  if (approvalEvent === null) throw new Error("immutable Owner approval audit event is absent");
  const approvalMetadata = object(approvalEvent.metadata_json, "Owner approval audit metadata");
  if (approvalMetadata.installationId !== input.installationId || approvalMetadata.attestationDigest !== activeInstallation.device_attestation_digest) {
    throw new Error("Owner approval audit event is not bound to the enabled attestation");
  }
  const ownerSession = await env.DB.prepare(`
    SELECT fresh_authenticated_at,user_verified
    FROM owner_sessions
    WHERE principal_id=?1 AND kind='owner' AND status='active'
    ORDER BY fresh_authenticated_at DESC
    LIMIT 1
  `).bind(activeInstallation.owner_principal_id).first<{ fresh_authenticated_at: string | null; user_verified: number }>();
  const approvalAt = Date.parse(activeInstallation.approved_at);
  const freshAt = Date.parse(ownerSession?.fresh_authenticated_at ?? "");
  if (ownerSession?.user_verified !== 1 || !Number.isFinite(approvalAt) || !Number.isFinite(freshAt) || freshAt > approvalAt || approvalAt - freshAt > 300_000) {
    throw new Error("Owner approval is not backed by a fresh verified Owner session");
  }

  const deniedTicket = await env.DB.prepare("SELECT ticket_id FROM privilege_ticket_issuance WHERE request_id=?1 LIMIT 1")
    .bind(input.deniedRequestId).first<{ ticket_id: string }>();
  if (deniedTicket !== null) throw new Error("previously denied Never request later acquired a ticket");
  const issued = await env.DB.prepare(`
    SELECT request.status AS request_status,request.device_policy_revision,
           request.device_id,request.installation_id,ticket.ticket_id,
           ticket.status AS ticket_status,ticket.canonical_ticket_json
    FROM privilege_ticket_requests AS request
    JOIN privilege_ticket_issuance AS ticket ON ticket.request_id=request.request_id
    WHERE request.request_id=?1
    LIMIT 1
  `).bind(input.issuedRequestId).first<{
    request_status: string;
    device_policy_revision: number;
    device_id: string;
    installation_id: string;
    ticket_id: string;
    ticket_status: string;
    canonical_ticket_json: string;
  }>();
  if (issued === null || issued.request_status !== "issued" || issued.ticket_status !== "active" || issued.device_id !== input.deviceId || issued.installation_id !== input.installationId || issued.device_policy_revision !== enabled.revision) {
    throw new Error("post-opt-in Never request lacks exact active ticket issuance");
  }
  const ticket = object(issued.canonical_ticket_json, "issued Never ticket");
  const claims = ticket.claims;
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) throw new Error("issued Never ticket claims are absent");
  const ticketClaims = claims as Record<string, unknown>;
  if (ticketClaims.devicePolicyRevision !== enabled.revision || ticketClaims.approvalMode !== "never" || ticketClaims.helperInstallationId !== input.installationId || ticketClaims.deviceId !== input.deviceId) {
    throw new Error("issued ticket is not bound to the enabled Never authority");
  }

  return {
    schemaVersion: 1,
    productionPrivilegeProjection: true,
    productionFreshOwnerDecision: true,
    immutableApprovalAuditEvent: true,
    initialDevicePolicyRevision: initial.revision,
    initialDevicePolicyDigest: initial.policy_digest,
    initialApprovalModesIncludeNever: false,
    enabledDevicePolicyRevision: enabled.revision,
    enabledDevicePolicyDigest: enabled.policy_digest,
    enabledPreviousPolicyDigest: enabled.previous_policy_digest,
    enabledApprovalModesIncludeNever: true,
    enabledAllowFullAccessWithoutApproval: true,
    ownerDecisionDigest: activeInstallation.owner_decision_digest,
    deniedRequestRemainsUnissued: true,
    issuedRequestId: input.issuedRequestId,
    issuedTicketId: issued.ticket_id,
    issuedTicketDevicePolicyRevision: issued.device_policy_revision,
    ticketIssuanceCountAfterEnable: await issuanceCount(env),
  };
}
