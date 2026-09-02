import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { ensureArtifactObject } from "../src/artifacts.ts";
import { sha256Hex } from "../src/crypto.ts";

describe("R2 idempotent upload budget", () => {
  it("uses HEAD to avoid a second PUT after a lost D1 response", async () => {
    const calls = { head: 0, put: 0 };
    const bucket = new Proxy(env.ARTIFACTS, {
      get(target, property, receiver) {
        if (property === "head") return async (...args: Parameters<R2Bucket["head"]>) => { calls.head += 1; return target.head(...args); };
        if (property === "put") return async (...args: Parameters<R2Bucket["put"]>) => { calls.put += 1; return target.put(...args); };
        return Reflect.get(target, property, receiver);
      },
    });
    const body = new TextEncoder().encode("exact artifact bytes");
    const digest = await sha256Hex(body);
    const key = `budget/${crypto.randomUUID()}`;
    const request = () => ({ artifactId: "artifact_budget_01", digest, bytes: body.byteLength, body: new Response(body).body!, contentType: "application/octet-stream" });
    expect(await ensureArtifactObject(bucket, key, request())).toBe("stored");
    expect(await ensureArtifactObject(bucket, key, request())).toBe("existing");
    expect(calls).toEqual({ head: 2, put: 1 });
    console.log(`CLOUDFLARE_R2_PROBE=${JSON.stringify({ retryAfterLostD1Response: calls })}`);

    await expect(ensureArtifactObject(bucket, key, { ...request(), digest: "0".repeat(64) })).rejects.toMatchObject({ code: "idempotency_conflict", status: 409 });
    expect(calls.put).toBe(1);
  });
});
