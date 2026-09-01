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
        BOOTSTRAP_VERIFIER: "7d9e6c4b70446e145c94a2e718d9cb5b3654221e08ca250f941353448d4f8f76",
        TOKEN_PEPPER: "test-only-token-pepper-with-at-least-32-bytes",
        RECEIPT_SIGNING_KEY: "test-only-receipt-key-with-at-least-32-bytes",
        TEST_MIGRATIONS: migrations,
      },
    },
  })],
  test: { setupFiles: ["./test/apply-migrations.ts"] },
};
});
