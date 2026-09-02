import { canonicalJson, keyedHash, nowIso, sha256Hex } from "../../src/crypto.ts";
import type { ControlPlaneEnv } from "../../src/types.ts";

interface ProductionWorker {
  fetch(request: Request, env: ControlPlaneEnv, ctx: ExecutionContext): Promise<Response>;
}

const FORBIDDEN_TOOLS = [
  "privileged_helper_install",
  "privileged_helper_enable",
  "privileged_helper_policy_update",
] as const;

const FORBIDDEN_HTTP_ACTIONS = ["install", "enable", "root-policy"] as const;

const RATE_PROFILE = {
  requestWindows: {
    read: { limit: 32, windowSeconds: 60 },
    boardWrite: { limit: 1, windowSeconds: 60 },
    commandStart: { limit: 1, windowSeconds: 60 },
    agentRunStart: { limit: 1, windowSeconds: 60 },
    runtimeStart: { limit: 1, windowSeconds: 60 },
    approvalResolve: { limit: 1, windowSeconds: 60 },
    rawLogRead: { limit: 1, windowSeconds: 60 },
  },
  weightedBudget: { capacity: 32, refillPerSecond: 1, weights: {} },
  bytes: {
    responseBytes: 1_048_576,
    normalizedLogBytesPerDay: 0,
    rawLogBytesPerDay: 0,
    artifactUploadBytesPerDay: 0,
  },
  concurrency: { commands: 0, agentRuns: 0, runtimeStarts: 0 },
};

async function authoritySnapshot(env: ControlPlaneEnv): Promise<string> {
  const queries = [
    "SELECT installation_id,device_id,active_key_id,active_policy_revision,active_policy_digest,status FROM device_privilege_installations ORDER BY installation_id",
    "SELECT installation_id,key_id,status,valid_from,valid_until,predecessor_key_id FROM privilege_installation_keys ORDER BY installation_id,key_id",
    "SELECT installation_id,revision,policy_digest,change_class,helper_key_id,status,approved_by,approved_at FROM privilege_policy_attestations ORDER BY installation_id,revision",
    "SELECT key_id,revision,fingerprint,status,valid_from,valid_until,predecessor_key_id FROM privilege_issuer_keys ORDER BY revision,key_id",
    "SELECT request_id,installation_id,operation_id,status,denial_code FROM privilege_ticket_requests ORDER BY request_id",
    "SELECT receipt_id,installation_id,operation_id,transition,state_revision FROM privilege_receipt_projections ORDER BY receipt_id",
  ] as const;
  const rows: unknown[] = [];
  for (const query of queries) rows.push((await env.DB.prepare(query).all()).results);
  return sha256Hex(canonicalJson(rows));
}

async function seedNarrowMcpActor(env: ControlPlaneEnv, liveToken: string): Promise<string> {
  const token = `${liveToken}.mcp-boundary`;
  const now = nowIso();
  const expires = new Date(Date.now() + 15 * 60_000).toISOString();
  const resource = `${env.PUBLIC_ORIGIN}/mcp`;
  const clientId = "https://full-device-live.invalid/mcp-boundary";
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered','Full Device live boundary','[\"https://full-device-live.invalid/callback\"]','none',?2,'active',?3,?3)").bind(clientId, "a".repeat(64), now),
    env.DB.prepare("INSERT OR IGNORE INTO rate_limit_profiles(id,revision,status,name,profile_json,created_at,updated_at) VALUES ('rate_full_device_live_boundary',1,'active','Full Device live boundary',?1,?2,?2)").bind(canonicalJson(RATE_PROFILE), now),
    env.DB.prepare("INSERT OR IGNORE INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_full_device_live_boundary','prin_full_device_live',?1,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}','[\"project.read\"]','[\"native\"]','read_only','always','[]',0,0,'rate_full_device_live_boundary',1,1,?2,?2)").bind(clientId, now),
    env.DB.prepare("INSERT OR IGNORE INTO oauth_grants(id,principal_id,client_id,resource,scopes_json,connector_policy_id,connector_policy_revision,token_family_id,status,created_at,expires_at) VALUES ('grant_full_device_live_boundary','prin_full_device_live',?1,?2,'[\"conduit.read\"]','cpol_full_device_live_boundary',1,'family_full_device_live_boundary','active',?3,?4)").bind(clientId, resource, now, expires),
    env.DB.prepare("INSERT OR IGNORE INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,resource,scopes_json,issued_at,expires_at) VALUES ('tok_full_device_live_boundary','grant_full_device_live_boundary','family_full_device_live_boundary','access',?1,?2,'[\"conduit.read\"]',?3,?4)").bind(await keyedHash(env.TOKEN_PEPPER, token), resource, now, expires),
  ]);
  return token;
}

async function callMcp(
  worker: ProductionWorker,
  env: ControlPlaneEnv,
  ctx: ExecutionContext,
  token: string,
  id: number,
  method: string,
  params: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const protocolVersion = "2026-07-28";
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
    "MCP-Protocol-Version": protocolVersion,
    "Mcp-Method": method,
  };
  if (method === "tools/call" && typeof params.name === "string") headers["Mcp-Name"] = params.name;
  const response = await worker.fetch(new Request(`${env.PUBLIC_ORIGIN}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: {
        ...params,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": protocolVersion,
          "io.modelcontextprotocol/clientInfo": { name: "full-device-live-boundary", version: "1" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  }), env, ctx);
  const text = await response.text();
  if (response.status !== 200) throw new Error(`live MCP boundary request failed with ${response.status}: ${text.slice(0, 256)}`);
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("live MCP boundary response is not an object");
  return parsed as Record<string, unknown>;
}

/**
 * Exercise the unchanged production HTTP and MCP surfaces from the guarded
 * isolated-live Worker. This helper deliberately cannot install, enable, or
 * edit a helper: it only provisions a narrow OAuth actor and proves those
 * root-local operations remain absent while every privilege table is stable.
 */
export async function assertRemoteRootAdministrationUnavailable(
  worker: ProductionWorker,
  env: ControlPlaneEnv,
  ctx: ExecutionContext,
  liveToken: string,
): Promise<Record<string, unknown>> {
  const token = await seedNarrowMcpActor(env, liveToken);
  const before = await authoritySnapshot(env);
  const listed = await callMcp(worker, env, ctx, token, 1, "tools/list", {});
  const listedText = canonicalJson(listed);
  for (const name of FORBIDDEN_TOOLS) {
    if (listedText.includes(`\"name\":\"${name}\"`)) throw new Error(`forbidden root administration tool is discoverable: ${name}`);
  }

  for (const [index, name] of FORBIDDEN_TOOLS.entries()) {
    const denied = await callMcp(worker, env, ctx, token, 20 + index, "tools/call", {
      name,
      arguments: { idempotencyKey: `full-device-live-remote-denial-${index}` },
    });
    const error = denied.error as Record<string, unknown> | undefined;
    if (error?.code !== -32602 || error.message !== `Tool ${name} not found`) throw new Error(`forbidden MCP tool did not fail closed: ${name}`);
  }

  for (const action of FORBIDDEN_HTTP_ACTIONS) {
    const denied = await worker.fetch(new Request(`${env.PUBLIC_ORIGIN}/api/v1/privileged/helper/${action}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: "{}",
    }), env, ctx);
    const payload = await denied.json() as { error?: { code?: unknown } };
    if (denied.status !== 404 || payload.error?.code !== "not_found") throw new Error(`forbidden HTTP helper action did not return not_found: ${action}`);
  }

  const after = await authoritySnapshot(env);
  if (after !== before) throw new Error("remote root administration denial changed privileged authority state");
  return {
    schemaVersion: 1,
    productionWorkerSurface: true,
    oauthActorAccessScope: "read_only",
    forbiddenToolsAbsentFromDiscovery: FORBIDDEN_TOOLS.length,
    forbiddenToolCallsDenied: FORBIDDEN_TOOLS.length,
    forbiddenToolErrorCode: -32602,
    forbiddenHttpCallsDenied: FORBIDDEN_HTTP_ACTIONS.length,
    forbiddenHttpStatus: 404,
    privilegedAuthorityDigestBefore: before,
    privilegedAuthorityDigestAfter: after,
    privilegedAuthorityUnchanged: true,
  };
}
