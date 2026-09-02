import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
  plugins: [cloudflareTest({
    wrangler: { configPath: "./wrangler.jsonc" },
    miniflare: {
      bindings: {
        BOOTSTRAP_VERIFIER: "037adaa308de85457b17b701002945af4c5edc0e07e826384ec3695000d440dc",
        TOKEN_PEPPER: "test-only-token-pepper-with-at-least-32-bytes",
        RECEIPT_SIGNING_KEY: "test-only-receipt-key-with-at-least-32-bytes",
        PRIVILEGE_TICKET_SIGNING_KEYS_JSON: JSON.stringify({ activeKeyId: "pkey_testissuer0001", keys: [{ keyId: "pkey_testissuer0001", revision: 1, privateJwk: { crv: "Ed25519", d: "nrtJu6YH_rZfrr6JSuItGhCt3C4zFkXIxHOQgsLD6Os", x: "BqRlMWvAVKLe2h6jRtRBlfOlZ8I2m5nuwkFqhm_cD0M", kty: "OKP" } }] }),
        TEST_MIGRATIONS: migrations,
      },
    },
  })],
  test: { setupFiles: ["./test/apply-migrations.ts"] },
};
});
