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

async function pendingEnrollment(request: Request, env: ControlPlaneEnv): Promise<Response> {
  await requireBrowserSession(request, env);
  const supplied = boundedString(new URL(request.url).searchParams.get("userCode"), "userCode", 16).trim().toUpperCase();
  if (!/^[A-Z0-9_-]{4,8}-[A-Z0-9_-]{3,8}$/.test(supplied)) throw new PublicError("invalid_request", 400, "User code is invalid");
  const row = await env.DB.prepare("SELECT id,state,claims_json,requested_fingerprint,expires_at FROM device_enrollments WHERE user_code_hash=?1 LIMIT 1")
    .bind(await keyedHash(env.TOKEN_PEPPER, supplied)).first<{ id: string; state: string; claims_json: string; requested_fingerprint: string; expires_at: string }>();
  if (row === null) throw new PublicError("not_found", 404, "Enrollment not found");
  if (row.state === "pending_owner" && Date.parse(row.expires_at) <= Date.now()) {
    await env.DB.prepare("UPDATE device_enrollments SET state='expired',terminal_at=?1 WHERE id=?2 AND state='pending_owner'").bind(nowIso(), row.id).run();
    throw new PublicError("invalid_request", 410, "Enrollment expired");
  }
  if (row.state !== "pending_owner") throw new PublicError("invalid_request", 409, `Enrollment is ${row.state}`);
  return Response.json({ enrollmentId: row.id, state: row.state, userCode: supplied, fingerprint: row.requested_fingerprint, claims: JSON.parse(row.claims_json), expiresAt: row.expires_at }, { headers: { "cache-control": "no-store" } });
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
    const denied = await env.DB.prepare("UPDATE device_enrollments SET state='denied',approved_by=?1,terminal_at=?2 WHERE id=?3 AND state='pending_owner'").bind(session.principal_id, now, enrollmentId).run();
    if (denied.meta.changes !== 1) throw new PublicError("invalid_request", 409, "Enrollment decision raced with another request");
    await repo.audit("device_enrollment.denied", { enrollmentId }, session.principal_id);
    return new Response(null, { status: 204 });
  }
  if (decision !== "approve") throw new PublicError("invalid_request", 400, "decision must be approve or deny");
  const claims = JSON.parse(row.claims_json) as Record<string, unknown>;
  const deviceId = newId("dev");
  const [updated, device, key] = await env.DB.batch([
    env.DB.prepare("UPDATE device_enrollments SET state='approved',approved_by=?1,assigned_device_id=?2 WHERE id=?3 AND state='pending_owner'").bind(session.principal_id, deviceId, enrollmentId),
    env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) SELECT ?1,?2,?3,?4,?5,?6,?7,'active',?8,?8 WHERE EXISTS (SELECT 1 FROM device_enrollments WHERE id=?2 AND state='approved' AND assigned_device_id=?1)").bind(deviceId, enrollmentId, String(claims.hostnameLabel), String(claims.os), String(claims.arch), String(claims.nodeVersion), String(claims.protocolVersion), now),
    env.DB.prepare("INSERT INTO device_keys(id,device_id,public_jwk_json,fingerprint,status,created_at) SELECT ?1,?2,?3,?4,'active',?5 WHERE EXISTS (SELECT 1 FROM device_enrollments WHERE id=?6 AND state='approved' AND assigned_device_id=?2) AND EXISTS (SELECT 1 FROM devices WHERE id=?2 AND enrollment_id=?6)").bind(row.requested_key_id, deviceId, row.requested_public_jwk_json, row.requested_fingerprint, now, enrollmentId),
  ]);
  if (updated?.meta.changes !== 1 || device?.meta.changes !== 1 || key?.meta.changes !== 1) throw new PublicError("invalid_request", 409, "Enrollment approval raced with another decision");
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
  if (request.method === "GET" && path === "/v1/device-enrollments/pending") return pendingEnrollment(request, env);
  if (request.method === "GET" && path === "/v1/device-enrollments/browser.js") return deviceEnrollmentScript();
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

export async function renderDevicePage(): Promise<Response> {
  return new Response(`<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Device enrollment</title><body><h1>Device enrollment</h1><p>Enter the code displayed by the Node. Verify the hostname, platform, and public-key fingerprint before approving.</p><form id=device-enrollment-lookup><label>User code <input id=device-user-code required autocomplete=one-time-code maxlength=16></label><button id=device-lookup-submit type=submit>Review device</button></form><section id=device-review hidden><dl><dt>Hostname</dt><dd id=device-hostname></dd><dt>Platform</dt><dd id=device-platform></dd><dt>Node version</dt><dd id=device-node-version></dd><dt>Public-key fingerprint</dt><dd><code id=device-fingerprint></code></dd><dt>Expires</dt><dd id=device-expires></dd></dl><button id=device-approve type=button>Verify passkey and approve</button><button id=device-deny type=button>Verify passkey and deny</button></section><p id=device-status role=status aria-live=polite></p><p><a href=/login?return_to=/device>Sign in with a passkey</a></p><script src=/api/v1/device-enrollments/browser.js defer></script></body></html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'none'; frame-ancestors 'none'", "permissions-policy": "publickey-credentials-get=(self)" } });
}

const DEVICE_ENROLLMENT_SCRIPT = `(() => {
  let pending;
  const fromBase64url = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)), (character) => character.charCodeAt(0));
  const toBase64url = (value) => { if (value === null) return null; const bytes = new Uint8Array(value); let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, ""); };
  const csrf = () => document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("__Host-conduit_csrf="))?.slice("__Host-conduit_csrf=".length) ?? "";
  const json = async (path, init = {}) => { const response = await fetch(path, { credentials: "same-origin", ...init }); const value = response.status === 204 ? {} : await response.json(); if (!response.ok) throw new Error(value?.error?.message ?? "Device enrollment request failed"); return value; };
  const stepUp = async () => {
    const ceremony = await json("/api/v1/auth/step-up/options", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: "{}" });
    const publicKey = { ...ceremony.options, challenge: fromBase64url(ceremony.options.challenge), allowCredentials: (ceremony.options.allowCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })) };
    const credential = await navigator.credentials.get({ publicKey });
    if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser did not return a passkey credential");
    const response = credential.response;
    await json("/api/v1/auth/step-up/verify", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: JSON.stringify({ challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, response: { id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { clientDataJSON: toBase64url(response.clientDataJSON), authenticatorData: toBase64url(response.authenticatorData), signature: toBase64url(response.signature), userHandle: toBase64url(response.userHandle) } } }) });
  };
  document.querySelector("#device-enrollment-lookup")?.addEventListener("submit", async (event) => {
    event.preventDefault(); const status = document.querySelector("#device-status");
    try { const code = document.querySelector("#device-user-code")?.value.trim().toUpperCase() ?? ""; pending = await json("/api/v1/device-enrollments/pending?userCode=" + encodeURIComponent(code)); document.querySelector("#device-hostname").textContent = pending.claims.hostnameLabel; document.querySelector("#device-platform").textContent = pending.claims.os + " / " + pending.claims.arch; document.querySelector("#device-node-version").textContent = pending.claims.nodeVersion + " (" + pending.claims.protocolVersion + ")"; document.querySelector("#device-fingerprint").textContent = pending.fingerprint; document.querySelector("#device-expires").textContent = pending.expiresAt; document.querySelector("#device-review").hidden = false; if (status) status.textContent = "Compare every value with the Node before deciding."; } catch (error) { if (status) status.textContent = error instanceof Error ? error.message : "Lookup failed"; }
  });
  const decide = async (decision) => { const status = document.querySelector("#device-status"); if (!pending) return; try { if (status) status.textContent = "Waiting for passkey verification…"; await stepUp(); await json("/api/v1/device-enrollments/" + encodeURIComponent(pending.enrollmentId) + "/decision", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: JSON.stringify({ decision }) }); document.querySelector("#device-review").hidden = true; if (status) status.textContent = decision === "approve" ? "Device approved. Return to the Node." : "Device denied."; } catch (error) { if (status) status.textContent = error instanceof Error ? error.message : "Decision failed"; } };
  document.querySelector("#device-approve")?.addEventListener("click", () => decide("approve"));
  document.querySelector("#device-deny")?.addEventListener("click", () => decide("deny"));
})();`;

function deviceEnrollmentScript(): Response {
  return new Response(DEVICE_ENROLLMENT_SCRIPT, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'" } });
}
