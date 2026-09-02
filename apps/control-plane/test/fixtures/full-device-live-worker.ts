import worker, { BoardRoom, ConnectorLimiter, DeviceRoom, RetryScheduler } from "../../src/index.ts";
import { canonicalJson, fromBase64url, keyedHash, nowIso, sha256Hex } from "../../src/crypto.ts";
import { handlePrivilegeAdmin } from "../../src/privilege.ts";
import type { ControlPlaneEnv } from "../../src/types.ts";
import { attemptOperationDispatch } from "../../src/dispatch.ts";
import { createExistingTargetControl } from "../../src/controls.ts";
import { assertRemoteRootAdministrationUnavailable } from "./full-device-live-boundaries.ts";
import { assertServerNeverDenied, assertServerNeverEnabledAndIssued } from "./full-device-live-never.ts";

export { BoardRoom, ConnectorLimiter, DeviceRoom, RetryScheduler };

interface LiveEnv extends ControlPlaneEnv {
  FULL_DEVICE_LIVE_E2E: string;
  FULL_DEVICE_LIVE_E2E_TOKEN: string;
}

const ID = /^[a-z][a-z0-9_]{7,127}$/;
const HASH = /^[a-f0-9]{64}$/;

function authorize(request: Request, env: LiveEnv): void {
  const url = new URL(request.url);
  if (env.FULL_DEVICE_LIVE_E2E !== "enabled" || (url.hostname !== "127.0.0.1" && url.hostname !== "localhost")) throw new Error("loopback live E2E is unavailable");
  if (request.headers.get("authorization") !== `Bearer ${env.FULL_DEVICE_LIVE_E2E_TOKEN}`) throw new Error("live E2E authorization failed");
}

async function body(request: Request): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > 65_536) throw new Error("live E2E request is too large");
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("live E2E request must be an object");
  return parsed as Record<string, unknown>;
}

function sessionValues(env: LiveEnv): { token: string; csrf: string } {
  return { token: `${env.FULL_DEVICE_LIVE_E2E_TOKEN}.session`, csrf: `${env.FULL_DEVICE_LIVE_E2E_TOKEN}.csrf` };
}

function adminRequest(env: LiveEnv, path: string, payload: unknown): Request {
  const session = sessionValues(env);
  return new Request(`${env.PUBLIC_ORIGIN}/api${path}`, {
    method: "POST",
    headers: {
      cookie: `__Host-conduit_session=${session.token}; __Host-conduit_csrf=${session.csrf}`,
      origin: env.PUBLIC_ORIGIN,
      "x-csrf-token": session.csrf,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

async function bootstrap(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const deviceId = String(input.deviceId ?? "");
  const deviceKeyId = String(input.deviceKeyId ?? "");
  const expectedUid = Number(input.expectedUid);
  const publicJwk = input.publicJwk as JsonWebKey | undefined;
  if (!ID.test(deviceId) || !ID.test(deviceKeyId) || !Number.isSafeInteger(expectedUid) || expectedUid < 1 || publicJwk?.kty !== "OKP" || publicJwk.crv !== "Ed25519" || typeof publicJwk.x !== "string") throw new Error("invalid live E2E Device bootstrap");
  const now = nowIso();
  const expires = new Date(Date.now() + 3_600_000).toISOString();
  const principalId = "prin_full_device_live";
  const enrollmentId = "enroll_full_device_live";
  const session = sessionValues(env);
  const fingerprint = await sha256Hex(fromBase64url(publicJwk.x));
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES (?1,'Full Device isolated live E2E','active',?2,?2)").bind(principalId, now),
    env.DB.prepare("INSERT OR IGNORE INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,approved_by,assigned_device_id,created_at,expires_at,terminal_at) VALUES (?1,'completed','isolated-live-device-code','isolated-live-user-code','{}',?2,?3,?4,'isolated-live-challenge','isolated-live-signature',?5,?6,?7,?8,?7)").bind(enrollmentId, deviceKeyId, canonicalJson(publicJwk), fingerprint, principalId, deviceId, now, expires),
    env.DB.prepare("INSERT OR IGNORE INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,revision,connection_epoch,created_at,updated_at) VALUES (?1,?2,'isolated-full-device-live','linux','x86_64','live-e2e','conduit.node/1','active',1,'1',?3,?3)").bind(deviceId, enrollmentId, now),
    env.DB.prepare("INSERT OR IGNORE INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(deviceKeyId, deviceId, canonicalJson(publicJwk), fingerprint, now),
    env.DB.prepare("INSERT OR IGNORE INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_full_device_live',?1,?2,?3,'owner','active',?4,?4,?4,?5,1)").bind(principalId, await keyedHash(env.TOKEN_PEPPER, session.token), await keyedHash(env.TOKEN_PEPPER, session.csrf), now, expires),
  ]);
  const activated = await handlePrivilegeAdmin(adminRequest(env, "/v1/privileged/issuer/activate", {}), env, "/v1/privileged/issuer/activate");
  if (activated === null || activated.status !== 200) throw new Error("isolated issuer activation failed");
  return Response.json({ status: "ready", deviceId, deviceKeyId, issuer: await activated.json() });
}

async function projectFrame(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const deviceId = String(input.deviceId ?? "");
  if (!ID.test(deviceId) || input.frame === undefined) throw new Error("invalid live E2E frame request");
  const result = await env.DEVICE_ROOMS.getByName(deviceId).projectFullDeviceLiveE2E(env.FULL_DEVICE_LIVE_E2E_TOKEN, input.frame);
  return Response.json(result);
}

async function approve(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const installationId = String(input.installationId ?? "");
  if (!ID.test(installationId)) throw new Error("invalid live E2E installation");
  const installation = await env.DB.prepare("SELECT device_id,device_attestation_digest FROM device_privilege_installations WHERE installation_id=?1 LIMIT 1").bind(installationId).first<{ device_id: string; device_attestation_digest: string }>();
  if (installation === null) throw new Error("live E2E registration was not projected");
  const response = await handlePrivilegeAdmin(adminRequest(env, `/v1/privileged/installations/${installationId}/decision`, { decision: "approve", expectedAttestationDigest: installation.device_attestation_digest }), env, `/v1/privileged/installations/${installationId}/decision`);
  if (response === null || response.status !== 200) throw new Error(`live E2E approval failed: ${response === null ? "missing" : await response.text()}`);
  const active = await env.DB.prepare("SELECT active_key_id,active_policy_revision,active_policy_digest,owner_decision_digest FROM device_privilege_installations WHERE installation_id=?1 AND status='active' LIMIT 1").bind(installationId).first<{ active_key_id: string; active_policy_revision: number; active_policy_digest: string; owner_decision_digest: string }>();
  const helper = active === null ? null : await env.DB.prepare("SELECT public_jwk_json,fingerprint FROM privilege_installation_keys WHERE installation_id=?1 AND key_id=?2 AND status='active' LIMIT 1").bind(installationId, active.active_key_id).first<{ public_jwk_json: string; fingerprint: string }>();
  const issuers = await env.DB.prepare("SELECT key_id,revision,public_jwk_json,fingerprint,status,valid_from,valid_until,predecessor_key_id,rotation_statement_digest,rotation_signature FROM privilege_issuer_keys WHERE status IN ('active','retiring') ORDER BY revision DESC LIMIT 4").all<Record<string, unknown>>();
  if (active === null || helper === null) throw new Error("live E2E registration did not become active");
  await env.DEVICE_ROOMS.getByName(installation.device_id).acknowledgeFullDeviceLiveRegistrationE2E(env.FULL_DEVICE_LIVE_E2E_TOKEN, installationId);
  return Response.json({
    installationId, status: "active", helperKeyId: active.active_key_id, helperPublicJwk: JSON.parse(helper.public_jwk_json), helperKeyFingerprint: helper.fingerprint,
    helperPolicyRevision: active.active_policy_revision, helperPolicyDigest: active.active_policy_digest,
    issuerKeys: issuers.results.map((key) => ({ keyId: key.key_id, revision: key.revision, publicJwk: JSON.parse(String(key.public_jwk_json)), fingerprint: key.fingerprint, status: key.status, validFrom: key.valid_from, validUntil: key.valid_until, predecessorKeyId: key.predecessor_key_id, rotationStatementDigest: key.rotation_statement_digest, rotationSignature: key.rotation_signature })),
    attestationDigest: installation.device_attestation_digest, ownerDecisionDigest: active.owner_decision_digest,
    isolatedCryptographicTestDeployment: true, freshPasskey: false,
  });
}

async function intent(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const operation = input.operation as Record<string, unknown> | undefined;
  const runId = String(operation?.runId ?? "");
  const operationId = String(operation?.operationId ?? "");
  const deviceId = String(operation?.deviceId ?? "");
  const manifestDigest = String(input.runManifestDigest ?? "");
  if (!ID.test(runId) || !ID.test(operationId) || !ID.test(deviceId) || !HASH.test(manifestDigest) || operation?.accessScope !== "full_device" || operation.approvalMode !== "never" || operation.capability !== "command.start") throw new Error("invalid live E2E operation intent");
  const payloadDigest = String(operation.payloadDigest ?? "");
  const expiresAt = String(operation.expiresAt ?? "");
  if (!HASH.test(payloadDigest) || Date.parse(expiresAt) <= Date.now()) throw new Error("invalid live E2E operation validity");
  const now = nowIso();
  const messageId = `cmsg_${operationId}`;
  const response = { operationId, state: "queued", payloadDigest, expiresAt, runId };
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,revision,manifest_digest,manifest_json,created_at,updated_at) VALUES (?1,?2,'native','full_device','never','queued',1,?3,'{}',?4,?4)").bind(runId, deviceId, manifestDigest, now),
    env.DB.prepare("INSERT INTO operation_journal(id,idempotency_key,actor_principal_id,client_id,device_id,run_id,connector_policy_id,connector_policy_revision,capability,payload_digest,request_json,state,expires_at,created_at,updated_at,operation_kind,node_state_revision) VALUES (?1,?2,'prin_full_device_live','conduit.cli',?3,?4,'cpol_owner_first_party_v1',1,'command.start',?5,?6,'queued',?7,?8,?8,'start',0)").bind(operationId, String(operation.idempotencyKey), deviceId, runId, payloadDigest, canonicalJson(operation), expiresAt, now),
  ];
  if (input.dispatch === true) {
    statements.push(
      env.DB.prepare("INSERT INTO idempotency_records(scope,idempotency_key,payload_digest,operation_id,state,response_status,response_json,expires_at,created_at) VALUES ('owner:prin_full_device_live:conduit.cli',?1,?2,?3,'queued',202,?4,?5,?6)").bind(String(operation.idempotencyKey), payloadDigest, operationId, JSON.stringify(response), expiresAt, now),
      env.DB.prepare("INSERT INTO operation_dispatch_outbox(operation_id,device_id,message_id,correlation_id,payload_digest,payload_json,state,next_attempt_at,expires_at,created_at,updated_at,frame_type) VALUES (?1,?2,?3,?1,?4,?5,'pending',?6,?7,?6,?6,'operation.offer')").bind(operationId, deviceId, messageId, payloadDigest, canonicalJson({ operation, runManifestDigest: manifestDigest }), now, expiresAt),
    );
  }
  await env.DB.batch(statements);
  const dispatch = input.dispatch === true ? await attemptOperationDispatch(env, operationId, { force: true }) : null;
  return Response.json({ status: "custodied", operationId, runId, payloadDigest, manifestDigest, dispatch });
}

async function inspect(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const deviceId = String(input.deviceId ?? "");
  if (!ID.test(deviceId)) throw new Error("invalid live E2E Device inspection");
  const room = await env.DEVICE_ROOMS.getByName(deviceId).inspectFullDeviceLiveE2E(env.FULL_DEVICE_LIVE_E2E_TOKEN);
  const operationId = input.operationId === undefined ? null : String(input.operationId);
  if (operationId !== null && !ID.test(operationId)) throw new Error("invalid live E2E operation inspection");
  const d1 = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM privilege_registration_attestations) AS registrations,(SELECT COUNT(*) FROM privilege_ticket_issuance) AS tickets,(SELECT COUNT(*) FROM privilege_receipt_projections) AS receipts").first<Record<string, number>>();
  const operation = operationId === null ? null : await env.DB.prepare("SELECT id,run_id,state,node_state_revision,result_json FROM operation_journal WHERE id=?1 LIMIT 1").bind(operationId).first<Record<string, unknown>>();
  const runtime = operationId === null ? null : await env.DB.prepare("SELECT custody.runtime_id,custody.run_id,custody.state,custody.revision,custody.target_digest,custody.controller_epoch,receipt.invocation_id FROM runtime_custody AS custody LEFT JOIN privilege_receipt_projections AS receipt ON receipt.operation_id=custody.start_operation_id AND receipt.transition='running' WHERE custody.start_operation_id=?1 ORDER BY receipt.state_revision DESC LIMIT 1").bind(operationId).first<Record<string, unknown>>();
  const operationTickets = operationId === null ? null : await env.DB.prepare("SELECT COUNT(*) AS count FROM privilege_ticket_requests WHERE operation_id=?1 AND status='issued'").bind(operationId).first<{ count: number }>();
  return Response.json({ worker: true, d1, deviceRoom: room, operation, runtime, operationTicketCount: operationTickets?.count ?? 0 });
}

async function control(request: Request, env: LiveEnv): Promise<Response> {
  const input = await body(request);
  const runtimeId = String(input.runtimeId ?? "");
  const expectedState = String(input.expectedState ?? "");
  const expectedRevision = Number(input.expectedRevision);
  if (!ID.test(runtimeId) || expectedState !== "running" || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1) throw new Error("invalid live E2E Runtime control");
  const result = await createExistingTargetControl(env, {
    principalId: "prin_full_device_live", clientId: "conduit.cli", scopes: ["owner"], sessionKind: "owner",
  }, {
    targetKind: "runtime", targetId: runtimeId, idempotencyKey: `full-device-live-stop-${runtimeId}`,
    body: { command: "stop", expectedState, expectedRevision, expiresInSeconds: 300 },
  }, "owner");
  return Response.json(result);
}

async function assertNever(request: Request, env: LiveEnv, enabled: boolean): Promise<Response> {
  const input = await body(request);
  return Response.json(enabled
    ? await assertServerNeverEnabledAndIssued(env, input as never)
    : await assertServerNeverDenied(env, input as never));
}

async function liveRoute(request: Request, env: LiveEnv, ctx: ExecutionContext): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/__full-device-live/")) return null;
  authorize(request, env);
  if (request.method === "GET" && path === "/__full-device-live/health") return Response.json({ status: "ok", worker: true });
  if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
  if (path === "/__full-device-live/assert-remote-denials") return Response.json(await assertRemoteRootAdministrationUnavailable(worker, env, ctx, env.FULL_DEVICE_LIVE_E2E_TOKEN));
  if (path === "/__full-device-live/bootstrap") return bootstrap(request, env);
  if (path === "/__full-device-live/frame") return projectFrame(request, env);
  if (path === "/__full-device-live/approve") return approve(request, env);
  if (path === "/__full-device-live/intent") return intent(request, env);
  if (path === "/__full-device-live/inspect") return inspect(request, env);
  if (path === "/__full-device-live/control") return control(request, env);
  if (path === "/__full-device-live/assert-never-denied") return assertNever(request, env, false);
  if (path === "/__full-device-live/assert-never-enabled") return assertNever(request, env, true);
  return new Response("not found", { status: 404 });
}

export default {
  async fetch(request: Request, env: LiveEnv, ctx: ExecutionContext): Promise<Response> {
    try {
      const response = await liveRoute(request, env, ctx);
      return response ?? worker.fetch(request, env, ctx);
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : "live E2E failure" }, { status: 400 });
    }
  },
  queue: worker.queue,
  scheduled: worker.scheduled,
} satisfies ExportedHandler<LiveEnv, unknown>;
