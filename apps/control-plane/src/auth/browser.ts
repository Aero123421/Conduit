import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { boundedString, boundedStringArray, readJsonBounded, record } from "../bounds.ts";
import { fromBase64url, keyedHash, newId, randomToken, sha256Hex } from "../crypto.ts";
import { PublicError } from "../errors.ts";
import type { ControlPlaneEnv } from "../types.ts";
import { AuthRepository, readCookie, sessionCookie, type SessionRow } from "../repositories/auth.ts";

function equalFixed(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

function responseJson(value: unknown, status = 200, headers?: HeadersInit): Response {
  return Response.json(value, { status, headers: { "cache-control": "no-store", ...headers } });
}

function assertSameOrigin(request: Request, env: ControlPlaneEnv): void {
  const origin = request.headers.get("origin");
  if (origin !== env.PUBLIC_ORIGIN) throw new PublicError("csrf_failed", 403, "Request origin is not allowed");
}

export async function requireBrowserSession(request: Request, env: ControlPlaneEnv, options: { csrf?: boolean; fresh?: boolean; allowRecovery?: boolean } = {}): Promise<{ repo: AuthRepository; session: SessionRow }> {
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  const token = readCookie(request, "__Host-conduit_session");
  if (token === null) throw new PublicError("authentication_required", 401, "Browser session is required");
  const session = await repo.session(token);
  if (!options.allowRecovery && session.kind === "recovery") throw new PublicError("scope_insufficient", 403, "Recovery sessions cannot access this API");
  if (options.csrf) {
    assertSameOrigin(request, env);
    await repo.verifyCsrf(session, boundedString(request.headers.get("x-csrf-token"), "X-CSRF-Token", 128));
  }
  if (options.fresh) repo.requireFresh(session);
  return { repo, session };
}

async function registrationOptions(request: Request, env: ControlPlaneEnv, mode: "setup" | "add" | "recovery"): Promise<Response> {
  const body = record(await readJsonBounded(request));
  let principalId: string | undefined;
  let sessionId: string | undefined;
  let displayName = boundedString(body.displayName ?? "Owner", "displayName", 128);
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  if (mode === "setup") {
    if (await repo.owner() !== null) throw new PublicError("invalid_request", 409, "Owner already exists");
    const supplied = await sha256Hex(boundedString(body.bootstrapSecret, "bootstrapSecret", 1024));
    if (!equalFixed(supplied, env.BOOTSTRAP_VERIFIER)) throw new PublicError("authentication_required", 401, "Bootstrap verification failed");
  } else {
    const auth = await requireBrowserSession(request, env, { csrf: true, fresh: mode === "add", allowRecovery: mode === "recovery" });
    if ((mode === "recovery") !== (auth.session.kind === "recovery")) throw new PublicError("scope_insufficient", 403, "Wrong session type for registration");
    principalId = auth.session.principal_id;
    sessionId = auth.session.id;
    const owner = await repo.owner();
    displayName = owner?.display_name ?? "Owner";
  }
  const registrationInput = {
    rpName: env.WEBAUTHN_RP_NAME,
    rpID: env.WEBAUTHN_RP_ID,
    userName: displayName,
    ...(principalId === undefined ? {} : { userID: Uint8Array.from(new TextEncoder().encode(principalId)) }),
    attestationType: "none" as const,
    authenticatorSelection: { residentKey: "preferred" as const, userVerification: "required" as const },
    timeout: 300_000,
  };
  const options = await generateRegistrationOptions(registrationInput);
  const challengeId = await repo.createChallenge({ kind: mode === "recovery" ? "recovery_registration" : "registration", ...(principalId === undefined ? {} : { principalId }), ...(sessionId === undefined ? {} : { sessionId }), challenge: options.challenge, origin: env.PUBLIC_ORIGIN, rpId: env.WEBAUTHN_RP_ID, state: { mode, displayName } });
  return responseJson({ challengeId, options });
}

async function registrationVerify(request: Request, env: ControlPlaneEnv, mode: "setup" | "add" | "recovery"): Promise<Response> {
  const body = record(await readJsonBounded(request));
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  if (mode === "setup") {
    const supplied = await sha256Hex(boundedString(body.bootstrapSecret, "bootstrapSecret", 1024));
    if (!equalFixed(supplied, env.BOOTSTRAP_VERIFIER)) throw new PublicError("authentication_required", 401, "Bootstrap verification failed");
  } else {
    await requireBrowserSession(request, env, { csrf: true, fresh: mode === "add", allowRecovery: mode === "recovery" });
  }
  const challenge = boundedString(body.challenge, "challenge", 512);
  const stored = await repo.consumeChallenge(boundedString(body.challengeId, "challengeId", 128), challenge, mode === "recovery" ? "recovery_registration" : "registration");
  const verification = await verifyRegistrationResponse({
    response: body.response as RegistrationResponseJSON,
    expectedChallenge: challenge,
    expectedOrigin: stored.expected_origin,
    expectedRPID: stored.expected_rp_id,
    requireUserVerification: true,
  });
  if (!verification.verified) throw new PublicError("authentication_required", 401, "Passkey registration verification failed");
  const credential = verification.registrationInfo.credential;
  const label = body.label === undefined ? undefined : boundedString(body.label, "label", 128);
  const transports = body.transports === undefined ? [] : boundedStringArray(body.transports, "transports", 16, 32);
  let principalId = stored.principal_id;
  if (mode === "setup") {
    principalId = await repo.createOwnerAndPasskey({ displayName: boundedString(body.displayName, "displayName", 128), credentialId: credential.id, publicKey: credential.publicKey, rpId: stored.expected_rp_id, ...(label === undefined ? {} : { label }), transports, signCount: credential.counter });
  } else {
    if (principalId === null) throw new PublicError("authentication_required", 401, "Challenge is not bound to an owner");
    await env.DB.prepare("INSERT INTO passkeys(id,principal_id,credential_id,public_key,relying_party_id,label,transports_json,sign_count,status,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9)")
      .bind(`pkey_${crypto.randomUUID().replaceAll("-", "")}`, principalId, credential.id, credential.publicKey, stored.expected_rp_id, label ?? null, JSON.stringify(transports), credential.counter, new Date().toISOString()).run();
    await repo.audit("passkey.registered", { credentialIdDigest: await sha256Hex(credential.id), mode }, principalId);
  }
  if (principalId === null) throw new PublicError("authentication_required", 401, "Owner bootstrap did not complete");
  const session = await repo.createSession(principalId, "owner", true);
  let recoveryCodes: string[] | undefined;
  if (mode === "setup" || mode === "recovery") {
    if (mode === "recovery") {
      const now = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare("UPDATE owner_sessions SET status='revoked',revoked_at=?1 WHERE principal_id=?2 AND id<>?3 AND status='active'").bind(now, principalId, session.id),
        env.DB.prepare("UPDATE oauth_grants SET status='reauthorization_required' WHERE principal_id=?1 AND status IN ('active','paused')").bind(principalId),
        env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE grant_id IN (SELECT id FROM oauth_grants WHERE principal_id=?2) AND revoked_at IS NULL").bind(now, principalId),
        env.DB.prepare("UPDATE recovery_codes SET revoked_at=?1 WHERE principal_id=?2 AND consumed_at IS NULL AND revoked_at IS NULL").bind(now, principalId),
      ]);
    }
    recoveryCodes = await repo.generateRecoveryCodes(principalId);
  }
  return responseJson({ principalId, csrfToken: session.csrf, recoveryCodes }, 201, { "set-cookie": sessionCookie(session.token, session.expiresAt) });
}

async function authenticationOptions(request: Request, env: ControlPlaneEnv, stepUp: boolean): Promise<Response> {
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  let principalId: string | undefined;
  let sessionId: string | undefined;
  if (stepUp) {
    const auth = await requireBrowserSession(request, env, { csrf: true });
    principalId = auth.session.principal_id;
    sessionId = auth.session.id;
  }
  const passkeys = await repo.passkeys(principalId);
  if (passkeys.length === 0) throw new PublicError("authentication_required", 401, "No active passkey is registered");
  const options = await generateAuthenticationOptions({
    rpID: env.WEBAUTHN_RP_ID,
    userVerification: "required",
    timeout: 300_000,
    allowCredentials: passkeys.map((passkey) => ({ id: passkey.credential_id, transports: JSON.parse(passkey.transports_json) as [] })),
  });
  const challengeId = await repo.createChallenge({ kind: stepUp ? "step_up" : "authentication", ...(principalId === undefined ? {} : { principalId }), ...(sessionId === undefined ? {} : { sessionId }), challenge: options.challenge, origin: env.PUBLIC_ORIGIN, rpId: env.WEBAUTHN_RP_ID });
  return responseJson({ challengeId, options });
}

async function authenticationVerify(request: Request, env: ControlPlaneEnv, stepUp: boolean): Promise<Response> {
  const body = record(await readJsonBounded(request));
  if (stepUp) await requireBrowserSession(request, env, { csrf: true });
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  const challenge = boundedString(body.challenge, "challenge", 512);
  const stored = await repo.consumeChallenge(boundedString(body.challengeId, "challengeId", 128), challenge, stepUp ? "step_up" : "authentication");
  const response = body.response as AuthenticationResponseJSON;
  const passkey = await repo.passkeyByCredential(boundedString(response.id, "response.id", 8192));
  if (stored.principal_id !== null && passkey.principal_id !== stored.principal_id) throw new PublicError("authentication_required", 401, "Passkey does not match challenge owner");
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: stored.expected_origin,
    expectedRPID: stored.expected_rp_id,
    credential: { id: passkey.credential_id, publicKey: new Uint8Array(passkey.public_key), counter: passkey.sign_count, transports: JSON.parse(passkey.transports_json) as [] },
    requireUserVerification: true,
  });
  if (!verification.verified || !verification.authenticationInfo.userVerified) throw new PublicError("authentication_required", 401, "Passkey authentication failed");
  await repo.notePasskeyUse(passkey.id, verification.authenticationInfo.newCounter);
  const session = await repo.createSession(passkey.principal_id, "owner", true);
  if (stepUp && stored.session_id !== null) {
    await env.DB.prepare("UPDATE owner_sessions SET status='revoked',revoked_at=?1 WHERE id=?2").bind(new Date().toISOString(), stored.session_id).run();
  }
  await repo.audit(stepUp ? "passkey.step_up" : "passkey.authentication", { passkeyId: passkey.id }, passkey.principal_id);
  let ownerAccessToken: string | undefined;
  let ownerAccessTokenExpiresAt: string | undefined;
  if (!stepUp && body.issueCliToken === true) {
    ownerAccessToken = `conduit_owner_${randomToken(32)}`;
    ownerAccessTokenExpiresAt = new Date(Date.now() + 8 * 60 * 60_000).toISOString();
    await env.DB.prepare("INSERT INTO owner_api_tokens(id,principal_id,verifier_hash,label,status,issued_from_session_id,created_at,expires_at) VALUES (?1,?2,?3,?4,'active',?5,?6,?7)")
      .bind(newId("otk"), passkey.principal_id, await keyedHash(env.TOKEN_PEPPER, ownerAccessToken), body.cliTokenLabel === undefined ? "Conduit CLI" : boundedString(body.cliTokenLabel, "cliTokenLabel", 128), session.id, new Date().toISOString(), ownerAccessTokenExpiresAt).run();
    await repo.audit("owner_api_token.issued", { expiresAt: ownerAccessTokenExpiresAt }, passkey.principal_id);
  }
  return responseJson({ principalId: passkey.principal_id, csrfToken: session.csrf, fresh: true, ...(ownerAccessToken === undefined ? {} : { ownerAccessToken, ownerAccessTokenExpiresAt }) }, 200, { "set-cookie": sessionCookie(session.token, session.expiresAt) });
}

export async function authenticateOwnerCli(request: Request, env: ControlPlaneEnv): Promise<{ principalId: string; clientId: string; scopes: string[] }> {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Bearer conduit_owner_")) throw new PublicError("authentication_required", 401, "Owner CLI bearer token is required");
  const token = boundedString(authorization.slice(7), "owner bearer token", 512);
  const row = await env.DB.prepare("SELECT id,principal_id,status FROM owner_api_tokens WHERE verifier_hash=?1 AND expires_at>?2 LIMIT 1").bind(await keyedHash(env.TOKEN_PEPPER, token), new Date().toISOString()).first<{ id: string; principal_id: string; status: string }>();
  if (row === null || row.status !== "active") throw new PublicError("authentication_required", 401, "Owner CLI bearer token is invalid or expired");
  await env.DB.prepare("UPDATE owner_api_tokens SET last_used_at=?1 WHERE id=?2").bind(new Date().toISOString(), row.id).run();
  return { principalId: row.principal_id, clientId: "conduit.cli", scopes: ["conduit.admin"] };
}

async function recovery(request: Request, env: ControlPlaneEnv): Promise<Response> {
  assertSameOrigin(request, env);
  const body = record(await readJsonBounded(request));
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  const principalId = await repo.consumeRecoveryCode(boundedString(body.recoveryCode, "recoveryCode", 256));
  const session = await repo.createSession(principalId, "recovery", false);
  await repo.audit("recovery_code.used", {}, principalId);
  return responseJson({ principalId, csrfToken: session.csrf, allowedActions: ["passkey.register", "sessions.revoke", "grants.reauthorize", "recovery.replace", "devices.revoke"] }, 200, { "set-cookie": sessionCookie(session.token, session.expiresAt) });
}

async function revokePasskey(request: Request, env: ControlPlaneEnv, passkeyId: string): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM passkeys WHERE principal_id=?1 AND status='active'").bind(session.principal_id).first<{ count: number }>();
  if ((count?.count ?? 0) <= 1) throw new PublicError("invalid_request", 409, "The final active passkey cannot be revoked");
  const now = new Date().toISOString();
  const result = await env.DB.prepare("UPDATE passkeys SET status='revoked',revoked_at=?1 WHERE id=?2 AND principal_id=?3 AND status='active'").bind(now, passkeyId, session.principal_id).run();
  if (result.meta.changes !== 1) throw new PublicError("not_found", 404, "Active passkey not found");
  await repo.audit("passkey.revoked", { passkeyId }, session.principal_id);
  return new Response(null, { status: 204 });
}

export async function handleBrowserAuth(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "POST" && path === "/v1/auth/setup/options") return registrationOptions(request, env, "setup");
  if (request.method === "POST" && path === "/v1/auth/setup/verify") return registrationVerify(request, env, "setup");
  if (request.method === "POST" && path === "/v1/auth/login/options") return authenticationOptions(request, env, false);
  if (request.method === "POST" && path === "/v1/auth/login/verify") return authenticationVerify(request, env, false);
  if (request.method === "POST" && path === "/v1/auth/login") return authenticationVerify(request, env, false);
  if (request.method === "POST" && path === "/v1/auth/step-up/options") return authenticationOptions(request, env, true);
  if (request.method === "POST" && path === "/v1/auth/step-up/verify") return authenticationVerify(request, env, true);
  if (request.method === "POST" && path === "/v1/auth/passkeys/options") return registrationOptions(request, env, "add");
  if (request.method === "POST" && path === "/v1/auth/passkeys/verify") return registrationVerify(request, env, "add");
  if (request.method === "POST" && path === "/v1/auth/passkeys/register") return registrationVerify(request, env, (await new AuthRepository(env.DB, env.TOKEN_PEPPER).owner()) === null ? "setup" : "add");
  if (request.method === "POST" && path === "/v1/auth/recovery") return recovery(request, env);
  if (request.method === "POST" && path === "/v1/auth/recovery/passkeys/options") return registrationOptions(request, env, "recovery");
  if (request.method === "POST" && path === "/v1/auth/recovery/passkeys/verify") return registrationVerify(request, env, "recovery");
  const revoke = path.match(/^\/v1\/auth\/passkeys\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revoke?.[1] !== undefined) return revokePasskey(request, env, revoke[1]);
  return null;
}

export async function renderAuthPage(env: ControlPlaneEnv): Promise<Response> {
  const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
  const owner = await repo.owner();
  const body = owner === null
    ? "<h1>Set up Conduit</h1><p>Use a WebAuthn-capable client to call the versioned setup ceremony endpoints.</p>"
    : "<h1>Conduit sign in</h1><p>Use a WebAuthn-capable client to call the versioned login ceremony endpoints.</p>";
  return new Response(`<!doctype html><meta charset=utf-8><title>Conduit authentication</title>${body}`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" } });
}
