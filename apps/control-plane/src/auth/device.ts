import { boundedString, readJsonBounded, record } from "../bounds.ts";
import { canonicalJson, keyedHash, newId, nowIso, randomToken, sha256Hex, verifyEd25519 } from "../crypto.ts";
import { PublicError } from "../errors.ts";
import type { ControlPlaneEnv } from "../types.ts";
import { requireBrowserSession } from "./browser.ts";

interface EnrollmentRow {
  id: string;
  state: string;
  claims_json: string;
  requested_key_id: string;
  requested_public_jwk_json: string;
  requested_fingerprint: string;
  assigned_device_id: string | null;
  expires_at: string;
}

function enrollmentTranscript(claims: unknown, keyId: string, publicJwk: unknown, clientNonce: string): string {
  return `conduit.enrollment.v1\n${canonicalJson({ claims, keyId, publicJwk, clientNonce })}`;
}

async function createEnrollment(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const body = record(await readJsonBounded(request));
  const claims = record(body.claims, "claims");
  const hostnameLabel = boundedString(claims.hostnameLabel, "claims.hostnameLabel", 128);
  const os = boundedString(claims.os, "claims.os", 16);
  if (!["linux", "windows", "macos", "unknown"].includes(os)) throw new PublicError("invalid_request", 400, "claims.os is invalid");
  const normalizedClaims = { hostnameLabel, os, arch: boundedString(claims.arch, "claims.arch", 64), nodeVersion: boundedString(claims.nodeVersion, "claims.nodeVersion", 64), protocolVersion: boundedString(claims.protocolVersion, "claims.protocolVersion", 64) };
  const keyId = boundedString(body.keyId, "keyId", 128);
  const publicJwkInput = record(body.publicJwk, "publicJwk");
  if (publicJwkInput.kty !== "OKP" || publicJwkInput.crv !== "Ed25519" || typeof publicJwkInput.x !== "string") throw new PublicError("invalid_request", 400, "Ed25519 public JWK is required");
  const publicJwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: publicJwkInput.x };
  const clientNonce = boundedString(body.clientNonce, "clientNonce", 256);
  const signature = boundedString(body.signature, "signature", 512);
  if (!await verifyEd25519(publicJwk, signature, enrollmentTranscript(normalizedClaims, keyId, publicJwk, clientNonce))) throw new PublicError("device_key_invalid", 401, "Enrollment proof of possession is invalid");
  const id = newId("enroll");
  const deviceCode = randomToken();
  const userCode = `${randomToken(4).slice(0, 4).toUpperCase()}-${randomToken(3).slice(0, 3).toUpperCase()}`;
  const fingerprint = await sha256Hex(String(publicJwk.x));
  const now = new Date();
  await env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,created_at,expires_at) VALUES (?1,'pending_owner',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
    .bind(id, await keyedHash(env.TOKEN_PEPPER, deviceCode), await keyedHash(env.TOKEN_PEPPER, userCode), JSON.stringify(normalizedClaims), keyId, JSON.stringify(publicJwk), fingerprint, clientNonce, signature, now.toISOString(), new Date(now.getTime() + 600_000).toISOString()).run();
  return Response.json({ enrollmentId: id, deviceCode, userCode, verificationUri: `${env.PUBLIC_ORIGIN}/device`, expiresIn: 600, fingerprint }, { status: 201, headers: { "cache-control": "no-store" } });
}

async function pollEnrollment(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const body = record(await readJsonBounded(request));
  const deviceCode = boundedString(body.deviceCode, "deviceCode", 512);
  const row = await env.DB.prepare("SELECT id,state,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,assigned_device_id,expires_at FROM device_enrollments WHERE device_code_hash=?1 LIMIT 1")
    .bind(await keyedHash(env.TOKEN_PEPPER, deviceCode)).first<EnrollmentRow>();
  if (row === null) throw new PublicError("not_found", 404, "Enrollment not found");
  if (Date.parse(row.expires_at) <= Date.now() && row.state === "pending_owner") {
    await env.DB.prepare("UPDATE device_enrollments SET state='expired',terminal_at=?1 WHERE id=?2 AND state='pending_owner'").bind(nowIso(), row.id).run();
    return Response.json({ state: "expired" }, { status: 410, headers: { "cache-control": "no-store" } });
  }
  if (row.state !== "approved" && row.state !== "completed") return Response.json({ state: row.state }, { status: row.state === "pending_owner" ? 202 : 409, headers: { "cache-control": "no-store", "retry-after": "5" } });
  if (row.assigned_device_id === null) throw new PublicError("invalid_request", 500, "Approved enrollment is missing its Device binding");
  if (row.state === "approved") await env.DB.prepare("UPDATE device_enrollments SET state='completed',terminal_at=?1 WHERE id=?2 AND state='approved'").bind(nowIso(), row.id).run();
  const receipt = { version: 1, enrollmentId: row.id, deviceId: row.assigned_device_id, keyId: row.requested_key_id, completedAt: nowIso() };
  return Response.json({ state: "completed", deviceId: row.assigned_device_id, keyId: row.requested_key_id, controlPlaneOrigin: env.PUBLIC_ORIGIN, receipt, receiptMac: await keyedHash(env.RECEIPT_SIGNING_KEY, canonicalJson(receipt)) }, { headers: { "cache-control": "no-store" } });
}

async function approveEnrollment(request: Request, env: ControlPlaneEnv, enrollmentId: string): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const row = await env.DB.prepare("SELECT id,state,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,assigned_device_id,expires_at FROM device_enrollments WHERE id=?1 LIMIT 1").bind(enrollmentId).first<EnrollmentRow>();
  if (row === null) throw new PublicError("not_found", 404, "Enrollment not found");
  if (row.state !== "pending_owner" || Date.parse(row.expires_at) <= Date.now()) throw new PublicError("invalid_request", 409, "Enrollment is not pending approval");
  const body = record(await readJsonBounded(request));
  const decision = boundedString(body.decision, "decision", 16);
  const now = nowIso();
  if (decision === "deny") {
    await env.DB.prepare("UPDATE device_enrollments SET state='denied',approved_by=?1,terminal_at=?2 WHERE id=?3 AND state='pending_owner'").bind(session.principal_id, now, enrollmentId).run();
    await repo.audit("device_enrollment.denied", { enrollmentId }, session.principal_id);
    return new Response(null, { status: 204 });
  }
  if (decision !== "approve") throw new PublicError("invalid_request", 400, "decision must be approve or deny");
  const claims = JSON.parse(row.claims_json) as Record<string, unknown>;
  const deviceId = newId("dev");
  const updated = await env.DB.prepare("UPDATE device_enrollments SET state='approved',approved_by=?1,assigned_device_id=?2 WHERE id=?3 AND state='pending_owner'").bind(session.principal_id, deviceId, enrollmentId).run();
  if (updated.meta.changes !== 1) throw new PublicError("invalid_request", 409, "Enrollment approval raced with another decision");
  await env.DB.batch([
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'active',?8,?8)").bind(deviceId, enrollmentId, String(claims.hostnameLabel), String(claims.os), String(claims.arch), String(claims.nodeVersion), String(claims.protocolVersion), now),
    env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(row.requested_key_id, deviceId, row.requested_public_jwk_json, row.requested_fingerprint, now),
  ]);
  await repo.audit("device_enrollment.approved", { enrollmentId, keyFingerprint: row.requested_fingerprint }, session.principal_id, undefined, deviceId);
  return Response.json({ deviceId, state: "approved" });
}

async function rotateKey(request: Request, env: ControlPlaneEnv, deviceId: string): Promise<Response> {
  const body = record(await readJsonBounded(request));
  const currentKeyId = boundedString(body.currentKeyId, "currentKeyId", 128);
  const newKeyId = boundedString(body.newKeyId, "newKeyId", 128);
  const newPublicJwkInput = record(body.newPublicJwk, "newPublicJwk");
  const currentEpoch = boundedString(body.connectionEpoch, "connectionEpoch", 32);
  const oldSignature = boundedString(body.oldSignature, "oldSignature", 512);
  const newSignature = boundedString(body.newSignature, "newSignature", 512);
  const device = await env.DB.prepare("SELECT status,connection_epoch FROM devices WHERE id=?1 LIMIT 1").bind(deviceId).first<{ status: string; connection_epoch: string }>();
  if (device === null || device.status !== "active" || device.connection_epoch !== currentEpoch) throw new PublicError("device_key_invalid", 403, "Device connection epoch is not current");
  const oldKey = await env.DB.prepare("SELECT public_jwk_json FROM device_keys WHERE id=?1 AND device_id=?2 AND status='active' LIMIT 1").bind(currentKeyId, deviceId).first<{ public_jwk_json: string }>();
  if (oldKey === null) throw new PublicError("device_key_invalid", 403, "Current Device key is not active");
  if (newPublicJwkInput.kty !== "OKP" || newPublicJwkInput.crv !== "Ed25519" || typeof newPublicJwkInput.x !== "string") throw new PublicError("invalid_request", 400, "New Ed25519 public JWK is invalid");
  const newPublicJwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: newPublicJwkInput.x };
  const transcript = `conduit.device-key-rotation.v1\n${canonicalJson({ deviceId, currentKeyId, newKeyId, newPublicJwk, connectionEpoch: currentEpoch })}`;
  if (!await verifyEd25519(JSON.parse(oldKey.public_jwk_json) as JsonWebKey, oldSignature, transcript) || !await verifyEd25519(newPublicJwk, newSignature, transcript)) throw new PublicError("device_key_invalid", 403, "Dual-signature key rotation proof is invalid");
  const now = new Date();
  const retireAfter = new Date(now.getTime() + 300_000).toISOString();
  await env.DB.batch([
    env.DB.prepare("UPDATE device_keys SET status='retiring',retire_after=?1 WHERE id=?2 AND status='active'").bind(retireAfter, currentKeyId),
    env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) VALUES (?1,?2,?3,?4,'active',?5)").bind(newKeyId, deviceId, JSON.stringify(newPublicJwk), await sha256Hex(newPublicJwkInput.x), now.toISOString()),
    env.DB.prepare("INSERT INTO security_events(id,event_type,device_id,metadata_json,created_at) VALUES (?1,'device_key.rotated',?2,?3,?4)").bind(newId("sevt"), deviceId, JSON.stringify({ currentKeyId, newKeyId, retireAfter }), now.toISOString()),
  ]);
  return Response.json({ deviceId, activeKeyId: newKeyId, retiringKeyId: currentKeyId, retireAfter });
}

async function revokeDevice(request: Request, env: ControlPlaneEnv, deviceId: string): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true, allowRecovery: true });
  const now = nowIso();
  const result = await env.DB.prepare("UPDATE devices SET status='revoked',revoked_at=?1,updated_at=?1,revision=revision+1 WHERE id=?2 AND status<>'revoked'").bind(now, deviceId).run();
  if (result.meta.changes !== 1) throw new PublicError("not_found", 404, "Active Device not found");
  await env.DB.prepare("UPDATE device_keys SET status='revoked',revoked_at=?1 WHERE device_id=?2 AND status<>'revoked'").bind(now, deviceId).run();
  await env.DEVICE_ROOMS.getByName(deviceId).revoke("device_revoked");
  await repo.audit("device.revoked", { terminateManagedRunsRequested: record(await readJsonBounded(request)).terminateManagedRuns === true }, session.principal_id, undefined, deviceId);
  return new Response(null, { status: 204 });
}

export async function handleDeviceIdentity(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "POST" && path === "/v1/device-enrollments") return createEnrollment(request, env);
  if (request.method === "POST" && path === "/v1/device-enrollments/poll") return pollEnrollment(request, env);
  const approve = path.match(/^\/v1\/device-enrollments\/([^/]+)\/decision$/);
  if (request.method === "POST" && approve?.[1] !== undefined) return approveEnrollment(request, env, approve[1]);
  const rotate = path.match(/^\/v1\/devices\/([^/]+)\/keys\/rotate$/);
  if (request.method === "POST" && rotate?.[1] !== undefined) return rotateKey(request, env, rotate[1]);
  const revoke = path.match(/^\/v1\/devices\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revoke?.[1] !== undefined) return revokeDevice(request, env, revoke[1]);
  const connect = path.match(/^\/v1\/devices\/([^/]+)\/connect$/);
  if (request.method === "GET" && connect?.[1] !== undefined && request.headers.get("upgrade")?.toLowerCase() === "websocket") return env.DEVICE_ROOMS.getByName(connect[1]).fetch(request);
  return null;
}
