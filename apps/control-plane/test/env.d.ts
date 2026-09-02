declare module "cloudflare:workers" {
  interface ProvidedEnv extends Env {
    TEST_MIGRATIONS: import("@cloudflare/vitest-plugin").D1Migration[];
  }
}

declare global {
  interface Env {
    TEST_MIGRATIONS: import("@cloudflare/vitest-plugin").D1Migration[];
  }

  namespace Cloudflare {
    interface Env {
      TEST_MIGRATIONS: import("@cloudflare/vitest-plugin").D1Migration[];
      BOOTSTRAP_VERIFIER: string;
      TOKEN_PEPPER: string;
      RECEIPT_SIGNING_KEY: string;
    }
  }
}

export {};
