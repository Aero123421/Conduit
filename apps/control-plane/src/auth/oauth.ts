import { boundedString, boundedStringArray, readJsonBounded, readTextBounded, record } from "../bounds.ts";
import { canonicalJson, keyedHash, newId, nowIso, operationDigest, randomToken, sha256Hex } from "../crypto.ts";
import { PublicError } from "../errors.ts";
import { completeEffect, reserveEffect } from "../idempotency.ts";
import { readCookie } from "../repositories/auth.ts";
import type { AuthActor, ControlPlaneEnv } from "../types.ts";
import { requireBrowserFormSession, requireBrowserSession } from "./browser.ts";

const SUPPORTED_SCOPES = new Set([
  "conduit.read", "conduit.board.write", "conduit.run.start", "conduit.run.control",
  "conduit.runtime.manage", "conduit.logs.read", "conduit.logs.raw",
  "conduit.approval.resolve", "conduit.config.write", "conduit.admin",
]);

interface ClientRow {
  client_id: string;
  registration_mechanism: string;
  client_name: string;
  redirect_uris_json: string;
  token_endpoint_auth_method: string;
  status: string;
}

interface GrantRow {
  id: string;
  principal_id: string;
  client_id: string;
  resource: string;
  scopes_json: string;
  connector_policy_id: string;
  connector_policy_revision: number;
  token_family_id: string;
  status: string;
}

function oauthError(error: string, description: string, status = 400): Response {
  return Response.json({ error, error_description: description }, { status, headers: { "cache-control": "no-store", pragma: "no-cache" } });
}

function exactResource(env: ControlPlaneEnv): string { return `${env.PUBLIC_ORIGIN}/mcp`; }

function parseScopes(value: string): string[] {
  const scopes = [...new Set(value.split(/\s+/).filter(Boolean))];
  if (scopes.length === 0 || scopes.length > 32 || scopes.some((scope) => !SUPPORTED_SCOPES.has(scope))) {
    throw new PublicError("invalid_request", 400, "Requested OAuth scope is not supported");
  }
  return scopes;
}

async function readMetadataDocument(clientId: string): Promise<{ clientName: string; redirectUris: string[]; digest: string }> {
  let url: URL;
  try { url = new URL(clientId); } catch { throw new PublicError("client_not_registered", 400, "Client ID is neither registered nor an HTTPS metadata document URL"); }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hash !== "") throw new PublicError("client_not_registered", 400, "Client ID Metadata Document URL is invalid");
  const response = await fetch(url, { redirect: "manual", headers: { accept: "application/json" } });
  if (!response.ok || (response.status >= 300 && response.status < 400)) throw new PublicError("client_not_registered", 400, "Client ID Metadata Document could not be fetched without redirects");
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > 32_768) throw new PublicError("invalid_request", 413, "Client metadata document is too large");
  const reader = response.body?.getReader();
  if (reader === undefined) throw new PublicError("client_not_registered", 400, "Client metadata document has no body");
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    bytes += part.value.byteLength;
    if (bytes > 32_768) { await reader.cancel(); throw new PublicError("invalid_request", 413, "Client metadata document is too large"); }
    chunks.push(part.value);
  }
  const joined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  let metadata: Record<string, unknown>;
  try { metadata = record(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(joined))); } catch { throw new PublicError("client_not_registered", 400, "Client metadata document is not valid UTF-8 JSON"); }
  if (boundedString(metadata.client_id, "client_id", 2048) !== clientId) throw new PublicError("client_not_registered", 400, "Metadata client_id must exactly equal its document URL");
  const redirectUris = boundedStringArray(metadata.redirect_uris, "redirect_uris", 64, 2048);
  for (const uri of redirectUris) if (new URL(uri).protocol !== "https:") throw new PublicError("client_not_registered", 400, "Metadata redirect URIs must use HTTPS");
  if ((metadata.token_endpoint_auth_method ?? "none") !== "none") throw new PublicError("client_not_registered", 400, "Only public PKCE metadata clients are supported");
  const clientName = boundedString(metadata.client_name, "client_name", 256);
  return { clientName, redirectUris, digest: await sha256Hex(canonicalJson(metadata)) };
}

async function client(env: ControlPlaneEnv, clientId: string): Promise<ClientRow> {
  let row = await env.DB.prepare("SELECT client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,status FROM oauth_clients WHERE client_id=?1 LIMIT 1").bind(clientId).first<ClientRow>();
  if (clientId.startsWith("https://") && (row === null || row.registration_mechanism === "client_id_metadata_document")) {
    const metadata = await readMetadataDocument(clientId);
    const stored = await env.DB.prepare("SELECT metadata_digest,status FROM oauth_clients WHERE client_id=?1 LIMIT 1").bind(clientId).first<{ metadata_digest: string; status: string }>();
    const now = nowIso();
    if (stored === null) {
      await env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,metadata_uri,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'client_id_metadata_document',?2,?1,?3,'none',?4,'active',?5,?5)").bind(clientId, metadata.clientName, JSON.stringify(metadata.redirectUris), metadata.digest, now).run();
    } else if (stored.metadata_digest !== metadata.digest) {
      await env.DB.batch([
        env.DB.prepare("UPDATE oauth_clients SET client_name=?1,redirect_uris_json=?2,metadata_digest=?3,status='metadata_changed',updated_at=?4 WHERE client_id=?5").bind(metadata.clientName, JSON.stringify(metadata.redirectUris), metadata.digest, now, clientId),
        env.DB.prepare("UPDATE oauth_grants SET status='reauthorization_required' WHERE client_id=?1 AND status IN ('active','paused')").bind(clientId),
        env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE grant_id IN (SELECT id FROM oauth_grants WHERE client_id=?2) AND revoked_at IS NULL").bind(now, clientId),
      ]);
      throw new PublicError("grant_reauthorization_required", 403, "Client metadata changed and requires owner review");
    }
    row = await env.DB.prepare("SELECT client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,status FROM oauth_clients WHERE client_id=?1 LIMIT 1").bind(clientId).first<ClientRow>();
  }
  if (row === null || row.status !== "active") throw new PublicError("client_not_registered", 400, "OAuth client is not active");
  return row;
}

function assertRedirect(clientRow: ClientRow, redirectUri: string): void {
  const allowed = JSON.parse(clientRow.redirect_uris_json) as unknown;
  if (!Array.isArray(allowed) || !allowed.includes(redirectUri)) throw new PublicError("invalid_request", 400, "redirect_uri does not exactly match registration");
}

async function registerClient(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const dcrMode: string = env.DCR_MODE;
  if (dcrMode === "disabled") return oauthError("invalid_client_metadata", "Dynamic registration is disabled", 403);
  const body = record(await readJsonBounded(request));
  const redirectUris = boundedStringArray(body.redirect_uris, "redirect_uris", 64, 2048);
  for (const uri of redirectUris) {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") throw new PublicError("invalid_request", 400, "redirect_uri must use HTTPS or loopback");
  }
  const authMethod = body.token_endpoint_auth_method === undefined ? "none" : boundedString(body.token_endpoint_auth_method, "token_endpoint_auth_method", 64);
  if (authMethod !== "none") throw new PublicError("invalid_request", 400, "Only public PKCE clients are supported by dynamic registration");
  const clientName = boundedString(body.client_name, "client_name", 256);
  const clientId = `dcr_${randomToken(24)}`;
  const metadata = { client_name: clientName, redirect_uris: redirectUris, token_endpoint_auth_method: authMethod };
  const status = dcrMode === "owner_confirmed" ? "pending_owner" : "active";
  const now = nowIso();
  await env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'dynamic',?2,?3,?4,?5,?6,?7,?7)")
    .bind(clientId, clientName, JSON.stringify(redirectUris), authMethod, await sha256Hex(JSON.stringify(metadata)), status, now).run();
  return Response.json({ client_id: clientId, client_name: clientName, redirect_uris: redirectUris, token_endpoint_auth_method: authMethod, registration_status: status }, { status: 201, headers: { "cache-control": "no-store" } });
}

async function approveClient(request: Request, env: ControlPlaneEnv, clientId: string): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: true });
  const result = await env.DB.prepare("UPDATE oauth_clients SET status='active',updated_at=?1 WHERE client_id=?2 AND status='pending_owner'").bind(nowIso(), clientId).run();
  if (result.meta.changes !== 1) throw new PublicError("not_found", 404, "Pending OAuth client not found");
  await repo.audit("oauth_client.approved", { clientId }, session.principal_id, clientId);
  return new Response(null, { status: 204 });
}

async function authorizeGet(request: Request, env: ControlPlaneEnv): Promise<Response> {
  if (request.url.length > 8192) throw new PublicError("invalid_request", 414, "Authorization request is too large");
  let auth: Awaited<ReturnType<typeof requireBrowserSession>>;
  try {
    auth = await requireBrowserSession(request, env);
  } catch (error) {
    if (!(error instanceof PublicError) || error.code !== "authentication_required") throw error;
    const login = new URL("/login", env.PUBLIC_ORIGIN);
    const requested = new URL(request.url);
    login.searchParams.set("return_to", `${requested.pathname}${requested.search}`);
    return Response.redirect(login.toString(), 303);
  }
  const { repo, session } = auth;
  const csrfToken = readCookie(request, "__Host-conduit_csrf");
  if (csrfToken === null) {
    const login = new URL("/login", env.PUBLIC_ORIGIN);
    const requested = new URL(request.url);
    login.searchParams.set("return_to", `${requested.pathname}${requested.search}`);
    return Response.redirect(login.toString(), 303);
  }
  await repo.verifyCsrf(session, csrfToken);
  const url = new URL(request.url);
  const clientId = boundedString(url.searchParams.get("client_id"), "client_id", 2048);
  const clientRow = await client(env, clientId);
  const redirectUri = boundedString(url.searchParams.get("redirect_uri"), "redirect_uri", 2048);
  assertRedirect(clientRow, redirectUri);
  if (url.searchParams.get("response_type") !== "code") return oauthError("unsupported_response_type", "Only authorization code is supported");
  const resource = boundedString(url.searchParams.get("resource"), "resource", 2048);
  if (resource !== exactResource(env)) return oauthError("invalid_target", "OAuth resource does not match the MCP protected resource");
  const codeChallenge = boundedString(url.searchParams.get("code_challenge"), "code_challenge", 128);
  if (url.searchParams.get("code_challenge_method") !== "S256") return oauthError("invalid_request", "PKCE S256 is required");
  const scopes = parseScopes(url.searchParams.get("scope") ?? "");
  const policies = await env.DB.prepare("SELECT id,revision,max_access_scope,most_permissive_approval_mode FROM connector_policies WHERE principal_id=?1 AND client_id=?2 AND status='active' AND (expires_at IS NULL OR expires_at>?3) ORDER BY id LIMIT 100")
    .bind(session.principal_id, clientId, nowIso()).all<{ id: string; revision: number; max_access_scope: string; most_permissive_approval_mode: string }>();
  if (policies.results.length === 0) throw new PublicError("connector_ceiling_exceeded", 403, "No active Connector Policy is available for this client");
  const transactionId = newId("consent");
  const now = new Date();
  await env.DB.prepare("INSERT INTO oauth_consent_transactions(id,principal_id,browser_session_id,client_id,redirect_uri,resource,scopes_json,state_value,code_challenge,code_challenge_method,connector_policy_id,expires_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'S256',?10,?11,?12)")
    .bind(transactionId, session.principal_id, session.id, clientId, redirectUri, resource, JSON.stringify(scopes), url.searchParams.get("state"), codeChallenge, policies.results[0]!.id, new Date(now.getTime() + 300_000).toISOString(), now.toISOString()).run();
  let fresh = true;
  try { repo.requireFresh(session); } catch (error) {
    if (!(error instanceof PublicError) || error.code !== "fresh_authentication_required") throw error;
    fresh = false;
  }
  const policyOptions = policies.results.map((policy) => `<option value="${escapeHtml(policy.id)}">${escapeHtml(policy.id)} · revision ${policy.revision} · ${escapeHtml(policy.max_access_scope)} · approval ${escapeHtml(policy.most_permissive_approval_mode)}</option>`).join("");
  const approval = fresh
    ? "<button name=decision value=approve>Approve</button>"
    : "<button id=oauth-step-up type=button>Verify passkey to approve</button><p id=oauth-status role=status aria-live=polite></p>";
  const html = `<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Authorize ${escapeHtml(clientRow.client_name)}</title><body><h1>Authorize ${escapeHtml(clientRow.client_name)}</h1><p>Scopes: ${escapeHtml(scopes.join(" "))}</p><form method=post action=/authorize><input type=hidden name=transaction_id value="${escapeHtml(transactionId)}"><input type=hidden name=csrf_token value="${escapeHtml(csrfToken)}"><label>Connector Policy <select name=connector_policy_id required>${policyOptions}</select></label>${approval}<button name=decision value=deny>Deny</button></form>${fresh ? "" : "<script src=/api/v1/auth/browser.js defer></script>"}</body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; script-src 'self'; form-action 'self'; frame-ancestors 'none'", "permissions-policy": "publickey-credentials-get=(self)" } });
}

function escapeHtml(value: string): string { return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char); }

async function authorizePost(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const form = new URLSearchParams(await readTextBounded(request, 8192));
  const csrfToken = boundedString(form.get("csrf_token"), "csrf_token", 128);
  const { repo, session } = await requireBrowserFormSession(request, env, csrfToken);
  const transactionId = boundedString(form.get("transaction_id"), "transaction_id", 128);
  const transaction = await env.DB.prepare("SELECT * FROM oauth_consent_transactions WHERE id=?1 AND principal_id=?2 AND browser_session_id=?3 AND consumed_at IS NULL AND expires_at>?4 LIMIT 1")
    .bind(transactionId, session.principal_id, session.id, nowIso()).first<Record<string, unknown>>();
  if (transaction === null) return oauthError("invalid_request", "Consent transaction is invalid or expired");
  const redirect = new URL(String(transaction.redirect_uri));
  if (form.get("decision") !== "approve") {
    await env.DB.prepare("UPDATE oauth_consent_transactions SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL").bind(nowIso(), transactionId).run();
    redirect.searchParams.set("error", "access_denied");
    if (typeof transaction.state_value === "string") redirect.searchParams.set("state", transaction.state_value);
    return Response.redirect(redirect.toString(), 303);
  }
  repo.requireFresh(session);
  const policyId = boundedString(form.get("connector_policy_id"), "connector_policy_id", 128);
  const policy = await env.DB.prepare("SELECT revision FROM connector_policies WHERE id=?1 AND principal_id=?2 AND client_id=?3 AND status='active' AND (expires_at IS NULL OR expires_at>?4) LIMIT 1").bind(policyId, session.principal_id, String(transaction.client_id), nowIso()).first<{ revision: number }>();
  if (policy === null) throw new PublicError("connector_ceiling_exceeded", 403, "Connector policy changed before consent");
  const grantId = newId("grant");
  const familyId = newId("tfam");
  const code = randomToken();
  const codeId = newId("code");
  const now = new Date();
  const consumed = await env.DB.prepare("UPDATE oauth_consent_transactions SET connector_policy_id=?1,consumed_at=?2 WHERE id=?3 AND consumed_at IS NULL").bind(policyId, now.toISOString(), transactionId).run();
  if (consumed.meta.changes !== 1) return oauthError("invalid_request", "Consent transaction was already consumed");
  await env.DB.batch([
    env.DB.prepare("INSERT INTO oauth_grants(id,principal_id,client_id,resource,scopes_json,connector_policy_id,connector_policy_revision,token_family_id,status,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9)").bind(grantId, session.principal_id, String(transaction.client_id), String(transaction.resource), String(transaction.scopes_json), policyId, policy.revision, familyId, now.toISOString()),
    env.DB.prepare("INSERT INTO oauth_authorization_codes(id,code_hash,consent_transaction_id,grant_id,client_id,redirect_uri,resource,scopes_json,code_challenge,expires_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)").bind(codeId, await keyedHash(env.TOKEN_PEPPER, code), transactionId, grantId, String(transaction.client_id), String(transaction.redirect_uri), String(transaction.resource), String(transaction.scopes_json), String(transaction.code_challenge), new Date(now.getTime() + 300_000).toISOString(), now.toISOString()),
  ]);
  await repo.audit("oauth_grant.created", { grantId, policyId, policyRevision: policy.revision }, session.principal_id, String(transaction.client_id));
  redirect.searchParams.set("code", code);
  if (typeof transaction.state_value === "string") redirect.searchParams.set("state", transaction.state_value);
  return Response.redirect(redirect.toString(), 303);
}

async function issueTokens(env: ControlPlaneEnv, grant: GrantRow, parentRefreshId?: string): Promise<Response> {
  const access = randomToken();
  const refresh = randomToken();
  const accessId = newId("atok");
  const refreshId = newId("rtok");
  const now = new Date();
  const accessExpires = new Date(now.getTime() + 15 * 60_000);
  const refreshExpires = new Date(now.getTime() + 30 * 86_400_000);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,parent_token_id,resource,scopes_json,issued_at,expires_at) VALUES (?1,?2,?3,'access',?4,NULL,?5,?6,?7,?8)").bind(accessId, grant.id, grant.token_family_id, await keyedHash(env.TOKEN_PEPPER, access), grant.resource, grant.scopes_json, now.toISOString(), accessExpires.toISOString()),
    env.DB.prepare("INSERT INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,parent_token_id,resource,scopes_json,issued_at,expires_at) VALUES (?1,?2,?3,'refresh',?4,?5,?6,?7,?8,?9)").bind(refreshId, grant.id, grant.token_family_id, await keyedHash(env.TOKEN_PEPPER, refresh), parentRefreshId ?? null, grant.resource, grant.scopes_json, now.toISOString(), refreshExpires.toISOString()),
  ]);
  return Response.json({ access_token: access, token_type: "Bearer", expires_in: 900, refresh_token: refresh, scope: (JSON.parse(grant.scopes_json) as string[]).join(" "), resource: grant.resource }, { headers: { "cache-control": "no-store", pragma: "no-cache" } });
}

async function token(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const form = new URLSearchParams(await readTextBounded(request, 16_384));
  const grantType = form.get("grant_type");
  if (grantType === "authorization_code") {
    const rawCode = boundedString(form.get("code"), "code", 512);
    const clientId = boundedString(form.get("client_id"), "client_id", 2048);
    const redirectUri = boundedString(form.get("redirect_uri"), "redirect_uri", 2048);
    const verifier = boundedString(form.get("code_verifier"), "code_verifier", 128, 43);
    const digest = await sha256Hex(verifier);
    const challenge = btoa(String.fromCharCode(...Uint8Array.from(digest.match(/.{2}/g)!.map((value) => parseInt(value, 16))))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const row = await env.DB.prepare("SELECT c.id AS code_id,c.grant_id,c.client_id,c.redirect_uri,c.resource,c.scopes_json,c.code_challenge,g.principal_id,g.connector_policy_id,g.connector_policy_revision,g.token_family_id,g.status FROM oauth_authorization_codes c JOIN oauth_grants g ON g.id=c.grant_id WHERE c.code_hash=?1 AND c.consumed_at IS NULL AND c.expires_at>?2 LIMIT 1")
      .bind(await keyedHash(env.TOKEN_PEPPER, rawCode), nowIso()).first<Record<string, unknown>>();
    if (row === null || row.client_id !== clientId || row.redirect_uri !== redirectUri || row.code_challenge !== challenge) return oauthError("invalid_grant", "Authorization code or PKCE verifier is invalid");
    const consumed = await env.DB.prepare("UPDATE oauth_authorization_codes SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL").bind(nowIso(), String(row.code_id)).run();
    if (consumed.meta.changes !== 1) return oauthError("invalid_grant", "Authorization code was already used");
    return issueTokens(env, { id: String(row.grant_id), principal_id: String(row.principal_id), client_id: clientId, resource: String(row.resource), scopes_json: String(row.scopes_json), connector_policy_id: String(row.connector_policy_id), connector_policy_revision: Number(row.connector_policy_revision), token_family_id: String(row.token_family_id), status: String(row.status) });
  }
  if (grantType === "refresh_token") {
    const rawRefresh = boundedString(form.get("refresh_token"), "refresh_token", 512);
    const row = await env.DB.prepare("SELECT t.id AS token_id,t.consumed_at,t.revoked_at,t.token_family_id,g.* FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id WHERE t.verifier_hash=?1 AND t.kind='refresh' AND t.expires_at>?2 LIMIT 1").bind(await keyedHash(env.TOKEN_PEPPER, rawRefresh), nowIso()).first<Record<string, unknown>>();
    if (row === null) return oauthError("invalid_grant", "Refresh token is invalid");
    if (row.consumed_at !== null || row.revoked_at !== null) {
      const now = nowIso();
      await env.DB.batch([
        env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE token_family_id=?2 AND revoked_at IS NULL").bind(now, String(row.token_family_id)),
        env.DB.prepare("UPDATE oauth_grants SET status='reauthorization_required' WHERE id=?1").bind(String(row.id)),
      ]);
      return oauthError("invalid_grant", "Refresh token reuse revoked the token family");
    }
    const consumed = await env.DB.prepare("UPDATE oauth_tokens SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL").bind(nowIso(), String(row.token_id)).run();
    if (consumed.meta.changes !== 1) return oauthError("invalid_grant", "Refresh token was already used");
    if (row.status !== "active") return oauthError("invalid_grant", "OAuth grant is not active");
    return issueTokens(env, { id: String(row.id), principal_id: String(row.principal_id), client_id: String(row.client_id), resource: String(row.resource), scopes_json: String(row.scopes_json), connector_policy_id: String(row.connector_policy_id), connector_policy_revision: Number(row.connector_policy_revision), token_family_id: String(row.token_family_id), status: String(row.status) }, String(row.token_id));
  }
  return oauthError("unsupported_grant_type", "Only authorization_code and refresh_token are supported");
}

async function revoke(request: Request, env: ControlPlaneEnv): Promise<Response> {
  const form = new URLSearchParams(await readTextBounded(request, 8192));
  const raw = boundedString(form.get("token"), "token", 512);
  const row = await env.DB.prepare("SELECT token_family_id,grant_id FROM oauth_tokens WHERE verifier_hash=?1 LIMIT 1").bind(await keyedHash(env.TOKEN_PEPPER, raw)).first<{ token_family_id: string; grant_id: string }>();
  if (row !== null) {
    const now = nowIso();
    await env.DB.batch([
      env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE token_family_id=?2 AND revoked_at IS NULL").bind(now, row.token_family_id),
      env.DB.prepare("UPDATE oauth_grants SET status='revoked',revoked_at=?1 WHERE id=?2").bind(now, row.grant_id),
    ]);
  }
  return new Response(null, { status: 200, headers: { "cache-control": "no-store" } });
}

async function changeGrantState(request: Request, env: ControlPlaneEnv, grantId: string, action: "pause" | "resume" | "revoke" | "reauthorize"): Promise<Response> {
  const { repo, session } = await requireBrowserSession(request, env, { csrf: true, fresh: action === "resume", allowRecovery: action === "revoke" || action === "reauthorize" });
  const idempotencyKey = boundedString(request.headers.get("idempotency-key"), "Idempotency-Key", 256, 16);
  const reserved = await reserveEffect(env.DB, `oauth-grant:${session.principal_id}`, idempotencyKey, await operationDigest({ grantId, action }));
  if (reserved.replay !== undefined) return Response.json(reserved.replay);
  const grant = await env.DB.prepare("SELECT client_id,connector_policy_id,connector_policy_revision,status,token_family_id FROM oauth_grants WHERE id=?1 AND principal_id=?2 LIMIT 1").bind(grantId, session.principal_id).first<{ client_id: string; connector_policy_id: string; connector_policy_revision: number; status: string; token_family_id: string }>();
  if (grant === null) throw new PublicError("not_found", 404, "OAuth grant not found");
  const transitions: Record<typeof action, readonly string[]> = { pause: ["active"], resume: ["paused"], revoke: ["active", "paused", "reauthorization_required"], reauthorize: ["active", "paused"] };
  if (!transitions[action].includes(grant.status)) throw new PublicError("invalid_request", 409, `OAuth grant cannot ${action} from ${grant.status}`);
  if (action === "resume") {
    const policy = await env.DB.prepare("SELECT revision,status FROM connector_policies WHERE id=?1 LIMIT 1").bind(grant.connector_policy_id).first<{ revision: number; status: string }>();
    if (policy?.status !== "active" || policy.revision !== grant.connector_policy_revision) throw new PublicError("grant_reauthorization_required", 409, "Connector policy changed while the grant was paused");
  }
  const status = action === "pause" ? "paused" : action === "resume" ? "active" : action === "revoke" ? "revoked" : "reauthorization_required";
  const now = nowIso();
  const statements = [env.DB.prepare("UPDATE oauth_grants SET status=?1,revoked_at=CASE WHEN ?1='revoked' THEN ?2 ELSE revoked_at END WHERE id=?3 AND principal_id=?4 AND status=?5").bind(status, now, grantId, session.principal_id, grant.status)];
  if (action === "revoke" || action === "reauthorize") statements.push(env.DB.prepare("UPDATE oauth_tokens SET revoked_at=?1 WHERE token_family_id=?2 AND revoked_at IS NULL").bind(now, grant.token_family_id));
  const [updated] = await env.DB.batch(statements);
  if (updated?.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "OAuth grant changed concurrently");
  await repo.audit(`oauth_grant.${action}`, { grantId, previousStatus: grant.status, status }, session.principal_id, grant.client_id);
  const response = { grantId, status };
  await completeEffect(env.DB, reserved.reservation!, response);
  return Response.json(response);
}

export async function authenticateBearer(request: Request, env: ControlPlaneEnv): Promise<AuthActor> {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Bearer ")) throw new PublicError("authentication_required", 401, "Bearer token is required");
  const tokenValue = boundedString(authorization.slice(7), "bearer token", 512);
  const row = await env.DB.prepare("SELECT g.id AS grant_id,g.principal_id,g.client_id,g.resource,g.scopes_json,g.connector_policy_id,g.connector_policy_revision,g.status AS grant_status,p.revision AS current_policy_revision,p.status AS policy_status FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id JOIN connector_policies p ON p.id=g.connector_policy_id WHERE t.verifier_hash=?1 AND t.kind='access' AND t.revoked_at IS NULL AND t.expires_at>?2 LIMIT 1")
    .bind(await keyedHash(env.TOKEN_PEPPER, tokenValue), nowIso()).first<Record<string, unknown>>();
  if (row === null) throw new PublicError("authentication_required", 401, "Access token is invalid or expired");
  if (row.resource !== exactResource(env)) throw new PublicError("scope_insufficient", 403, "Access token audience is invalid");
  if (row.grant_status === "paused") throw new PublicError("grant_paused", 403, "OAuth grant is paused");
  if (row.grant_status === "revoked") throw new PublicError("grant_revoked", 403, "OAuth grant is revoked");
  if (row.grant_status !== "active" || row.policy_status !== "active" || row.connector_policy_revision !== row.current_policy_revision) throw new PublicError("grant_reauthorization_required", 403, "OAuth grant requires reauthorization");
  await env.DB.prepare("UPDATE oauth_grants SET last_used_at=?1 WHERE id=?2").bind(nowIso(), String(row.grant_id)).run();
  return { principalId: String(row.principal_id), clientId: String(row.client_id), grantId: String(row.grant_id), policyId: String(row.connector_policy_id), policyRevision: Number(row.connector_policy_revision), scopes: JSON.parse(String(row.scopes_json)) as string[] };
}

export async function handleOAuth(request: Request, env: ControlPlaneEnv, path: string): Promise<Response | null> {
  if (request.method === "GET" && path === "/.well-known/oauth-protected-resource") return Response.json({ resource: exactResource(env), authorization_servers: [env.OAUTH_ISSUER], scopes_supported: [...SUPPORTED_SCOPES], bearer_methods_supported: ["header"], resource_name: "Conduit MCP" });
  if (request.method === "GET" && path === "/.well-known/oauth-authorization-server") return Response.json({ issuer: env.OAUTH_ISSUER, authorization_endpoint: `${env.PUBLIC_ORIGIN}/authorize`, token_endpoint: `${env.PUBLIC_ORIGIN}/oauth/token`, revocation_endpoint: `${env.PUBLIC_ORIGIN}/oauth/revoke`, registration_endpoint: `${env.PUBLIC_ORIGIN}/oauth/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], scopes_supported: [...SUPPORTED_SCOPES] });
  if (request.method === "POST" && path === "/oauth/register") return registerClient(request, env);
  if (request.method === "GET" && path === "/authorize") return authorizeGet(request, env);
  if (request.method === "POST" && path === "/authorize") return authorizePost(request, env);
  if (request.method === "POST" && path === "/oauth/token") return token(request, env);
  if (request.method === "POST" && path === "/oauth/revoke") return revoke(request, env);
  const approve = path.match(/^\/v1\/oauth\/clients\/([^/]+)\/approve$/);
  if (request.method === "POST" && approve?.[1] !== undefined) return approveClient(request, env, decodeURIComponent(approve[1]));
  const grantAction = path.match(/^\/v1\/oauth\/grants\/([^/]+)\/(pause|resume|revoke|reauthorize)$/);
  if (request.method === "POST" && grantAction?.[1] !== undefined && grantAction[2] !== undefined) return changeGrantState(request, env, decodeURIComponent(grantAction[1]), grantAction[2] as "pause" | "resume" | "revoke" | "reauthorize");
  return null;
}
