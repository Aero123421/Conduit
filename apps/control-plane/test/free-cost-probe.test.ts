import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { AuthRepository } from "../src/repositories/auth.ts";
import { authenticateBearer } from "../src/auth/oauth.ts";
import { keyedHash } from "../src/crypto.ts";

function measuredD1(database: D1Database): { db: D1Database; rowsWritten(): number; statements(): number } {
  let rows = 0;
  let calls = 0;
  const wrap = (statement: D1PreparedStatement, parameters = 0): D1PreparedStatement => new Proxy(statement, {
    get(target, property, receiver) {
      if (property === "bind") return (...values: unknown[]) => wrap(target.bind(...values), values.length);
      if (property === "run" || property === "first" || property === "all" || property === "raw") return async (...args: unknown[]) => {
        calls += 1;
        const result = await (Reflect.get(target, property, receiver) as (...inner: unknown[]) => Promise<unknown>).apply(target, args);
        const written = (result as { meta?: { rows_written?: number } } | null)?.meta?.rows_written;
        if (typeof written === "number") rows += written;
        void parameters;
        return result;
      };
      return Reflect.get(target, property, receiver);
    },
  });
  return { db: new Proxy(database, { get(target, property, receiver) { if (property === "prepare") return (query: string) => wrap(target.prepare(query)); return Reflect.get(target, property, receiver); } }), rowsWritten: () => rows, statements: () => calls };
}

describe("Free tier before/after cost probe", () => {
  it("measures auth and limiter steady-state writes", async () => {
    const pepper = "test-only-token-pepper-with-at-least-32-bytes";
    const now = new Date();
    const stale = new Date(now.getTime() - 20 * 60_000).toISOString();
    const expires = new Date(now.getTime() + 3_600_000).toISOString();
    const browserToken = "browser-cost-probe-token-0000000000001";
    const oauthToken = "oauth-cost-probe-token-0000000000000001";
    const clientId = "https://cost-probe.example/client";
    const profile = { requestWindows: { read: { limit: 1000, windowSeconds: 60 } }, weightedBudget: { capacity: 1000, refillPerSecond: 100, weights: {} }, bytes: { responseBytes: 1048576, normalizedLogBytesPerDay: 1048576, rawLogBytesPerDay: 0, artifactUploadBytesPerDay: 0 }, concurrency: { commands: 2, agentRuns: 2, runtimeStarts: 1 } };
    await env.DB.batch([
      env.DB.prepare("INSERT INTO owner_principals(id,display_name,status,created_at,updated_at) VALUES ('prin_cost_probe','Cost probe','active',?1,?1)").bind(now.toISOString()),
      env.DB.prepare("INSERT INTO owner_sessions(id,principal_id,verifier_hash,csrf_hash,kind,status,authenticated_at,fresh_authenticated_at,last_activity_at,expires_at,user_verified) VALUES ('bsess_cost_probe','prin_cost_probe',?1,?2,'owner','active',?3,?3,?4,?5,1)").bind(await keyedHash(pepper, browserToken), await keyedHash(pepper, "csrf-cost-probe"), now.toISOString(), stale, expires),
      env.DB.prepare("INSERT INTO oauth_clients(client_id,registration_mechanism,client_name,redirect_uris_json,token_endpoint_auth_method,metadata_digest,status,created_at,updated_at) VALUES (?1,'pre_registered','Cost probe','[\"https://cost-probe.example/callback\"]','none',?2,'active',?3,?3)").bind(clientId, "a".repeat(64), now.toISOString()),
      env.DB.prepare("INSERT INTO rate_limit_profiles(id,revision,status,name,profile_json,created_at,updated_at) VALUES ('rate_cost_probe',1,'active','Cost probe',?1,?2,?2)").bind(JSON.stringify(profile), now.toISOString()),
      env.DB.prepare("INSERT INTO connector_policies(id,principal_id,client_id,revision,status,device_selector_json,project_selector_json,allowed_operations_json,allowed_runtimes_json,max_access_scope,most_permissive_approval_mode,required_risk_classes_json,allow_raw_content,allow_artifact_upload,rate_limit_profile_id,max_command_seconds,max_run_seconds,created_at,updated_at) VALUES ('cpol_cost_probe','prin_cost_probe',?1,1,'active','{\"mode\":\"all\"}','{\"mode\":\"all\"}','[\"project.read\"]','[\"native\"]','read_only','always','[]',0,0,'rate_cost_probe',60,600,?2,?2)").bind(clientId, now.toISOString()),
      env.DB.prepare("INSERT INTO oauth_grants(id,principal_id,client_id,resource,scopes_json,connector_policy_id,connector_policy_revision,token_family_id,status,created_at,expires_at) VALUES ('grant_cost_probe','prin_cost_probe',?1,'https://conduit.example.com/mcp','[\"conduit.read\"]','cpol_cost_probe',1,'family_cost_probe','active',?2,?3)").bind(clientId, now.toISOString(), expires),
      env.DB.prepare("INSERT INTO oauth_tokens(id,grant_id,token_family_id,kind,verifier_hash,resource,scopes_json,issued_at,expires_at) VALUES ('tok_cost_probe','grant_cost_probe','family_cost_probe','access',?1,'https://conduit.example.com/mcp','[\"conduit.read\"]',?2,?3)").bind(await keyedHash(pepper, oauthToken), now.toISOString(), expires),
    ]);

    const browser = measuredD1(env.DB);
    const repo = new AuthRepository(browser.db, pepper);
    for (let index = 0; index < 10; index += 1) await repo.session(browserToken);

    const oauth = measuredD1(env.DB);
    const oauthEnv = { ...env, DB: oauth.db };
    for (let index = 0; index < 10; index += 1) await authenticateBearer(new Request("https://conduit.example.com/mcp", { headers: { authorization: `Bearer ${oauthToken}` } }), oauthEnv);

    const limiter = env.CONNECTOR_LIMITERS.getByName("grant-cost-probe");
    for (let index = 0; index < 100; index += 1) await limiter.admit({ operationId: `op_cost_probe_${index.toString().padStart(8, "0")}`, idempotencyKey: `read-${index}`, payloadDigest: index.toString(16).padStart(64, "0"), family: "read", weight: 1, requestLimit: 1000, windowSeconds: 60, capacity: 1000, refillPerSecond: 100, responseBytes: 0, normalizedLogBytes: 0, rawLogBytes: 0, artifactUploadBytes: 0, byteLimits: { response: 1048576, normalizedDaily: 1048576, rawDaily: 0, artifactDaily: 0 }, nowMs: now.getTime() });
    const limiterRows = await runInDurableObject(limiter, (_instance, state) => ({
      idempotency: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM idempotency").one().count,
      requestWindows: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM request_windows").one().count,
      tokenBucket: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM token_bucket").one().count,
      byteUsage: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM byte_usage").one().count,
      leases: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM concurrency_leases").one().count,
    }));
    const metrics = { browser10: { statements: browser.statements(), rowsWritten: browser.rowsWritten() }, oauth10: { statements: oauth.statements(), rowsWritten: oauth.rowsWritten() }, limiterRead100: limiterRows };
    expect(metrics.browser10).toEqual({ statements: 11, rowsWritten: 1 });
    expect(metrics.oauth10).toEqual({ statements: 11, rowsWritten: 1 });
    expect(metrics.limiterRead100).toEqual({ idempotency: 0, requestWindows: 0, tokenBucket: 0, byteUsage: 0, leases: 0 });
    console.log("CLOUDFLARE_COST_PROBE=" + JSON.stringify(metrics));
  });
});
