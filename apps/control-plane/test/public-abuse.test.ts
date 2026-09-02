import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { requestSourceHash } from "../src/abuse.ts";
import { AuthRepository } from "../src/repositories/auth.ts";
import { base64url, canonicalJson } from "../src/crypto.ts";

describe.sequential("public write endpoint budgets", () => {
  it("deduplicates identical owner-confirmed DCR and caps one keyed source", async () => {
    const metadata = { client_name: "DCR cost fixture", redirect_uris: ["https://client.example/callback"], token_endpoint_auth_method: "none" };
    const request = (body: Record<string, unknown>, source: string) => exports.default.fetch(new Request("https://conduit.example.com/oauth/register", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": source }, body: JSON.stringify(body) }));
    const first = await request(metadata, "192.0.2.10");
    const duplicate = await request(metadata, "192.0.2.10");
    expect(first.status).toBe(201);
    expect(duplicate.status).toBe(200);
    expect((await duplicate.json<{ client_id: string }>()).client_id).toBe((await first.json<{ client_id: string }>()).client_id);
    for (let index = 0; index < 20; index += 1) {
      const accepted = await request({ ...metadata, client_name: `DCR cap ${index}`, redirect_uris: [`https://client.example/callback/${index}`] }, "192.0.2.20");
      expect(accepted.status).toBe(201);
    }
    const limited = await request({ ...metadata, client_name: "DCR over cap", redirect_uris: ["https://client.example/over-cap"] }, "192.0.2.20");
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    const stored = await env.DB.prepare("SELECT source_hash FROM oauth_clients WHERE registration_mechanism='dynamic' AND source_hash IS NOT NULL LIMIT 1").first<{ source_hash: string }>();
    expect(stored?.source_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored?.source_hash).not.toContain("192.0.2");
  });

  it("caps authentication challenges per source without storing its address", async () => {
    const repo = new AuthRepository(env.DB, env.TOKEN_PEPPER);
    const sourceHash = await requestSourceHash(new Request("https://conduit.example.com/login", { headers: { "cf-connecting-ip": "198.51.100.8" } }), env);
    for (let index = 0; index < 50; index += 1) await repo.createChallenge({ kind: "authentication", challenge: `challenge-${index}`, origin: env.PUBLIC_ORIGIN, rpId: env.WEBAUTHN_RP_ID, sourceHash });
    await expect(repo.createChallenge({ kind: "authentication", challenge: "challenge-over-cap", origin: env.PUBLIC_ORIGIN, rpId: env.WEBAUTHN_RP_ID, sourceHash })).rejects.toMatchObject({ code: "rate_limited", status: 429, retryAfterSeconds: 60 });
  });

  it("returns exponential Retry-After and enforces the pending enrollment cap", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey;
    const claims = { hostnameLabel: "cost-fixture", os: "linux", arch: "x86_64", nodeVersion: "0.1.0", protocolVersion: "conduit.node/1" };
    const create = async (source: string, keyId: string, clientNonce: string) => {
      const jwk = { kty: "OKP", crv: "Ed25519", x: publicJwk.x };
      const transcript = `conduit.enrollment.v1\n${canonicalJson({ claims, keyId, publicJwk: jwk, clientNonce })}`;
      const signature = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(transcript))));
      return exports.default.fetch(new Request("https://conduit.example.com/api/v1/device-enrollments", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": source }, body: JSON.stringify({ claims, keyId, publicJwk: jwk, clientNonce, signature }) }));
    };
    const enrolled = await create("203.0.113.5", "dkey_poll_budget01", "poll-budget-nonce-01");
    expect(enrolled.status).toBe(201);
    const enrollment = await enrolled.json<{ deviceCode: string }>();
    const pollRequest = () => exports.default.fetch(new Request("https://conduit.example.com/api/v1/device-enrollments/poll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ deviceCode: enrollment.deviceCode }) }));
    const pending = await pollRequest();
    expect(pending.status).toBe(202);
    expect(pending.headers.get("retry-after")).toBe("5");
    const tooFast = await pollRequest();
    expect(tooFast.status).toBe(429);
    expect(Number(tooFast.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);

    const capSource = "203.0.113.6";
    const sourceHash = await requestSourceHash(new Request("https://conduit.example.com/device", { headers: { "cf-connecting-ip": capSource } }), env);
    const now = new Date();
    const expires = new Date(now.getTime() + 600_000).toISOString();
    const rows = Array.from({ length: 10 }, (_, index) => env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,created_at,expires_at,source_hash) VALUES (?1,'pending_owner',?2,?3,'{}',?4,'{}',?5,'challenge','signature',?6,?7,?8)").bind(`enroll_cap_${index}_${crypto.randomUUID().replaceAll("-", "")}`, index.toString(16).padStart(64, "1"), index.toString(16).padStart(64, "2"), `dkey_cap_${index}_${crypto.randomUUID().replaceAll("-", "")}`, index.toString(16).padStart(64, "3"), now.toISOString(), expires, sourceHash));
    await env.DB.batch(rows);
    const overCap = await create(capSource, "dkey_enrollment_overcap", "enrollment-over-cap-nonce");
    expect(overCap.status).toBe(429);
    expect(overCap.headers.get("retry-after")).toBe("60");
  });
});
