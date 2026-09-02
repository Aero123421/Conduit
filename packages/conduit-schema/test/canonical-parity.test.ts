import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { canonicalJson, canonicalSha256 } from "../src/index.ts";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

interface CanonicalFixture {
  fixtureVersion: 1;
  algorithm: "RFC 8785";
  digestAlgorithm: "SHA-256";
  cases: Array<{
    name: string;
    value: unknown;
    expectedCanonical: string;
    expectedSha256: string;
  }>;
}

describe("canonical JSON parity fixture", () => {
  it("matches every shared RFC 8785 and SHA-256 vector", async () => {
    const path = `${repositoryRoot}/spec/fixtures/canonical-json-v1.json`;
    const fixture = JSON.parse(
      await readFile(path, "utf8"),
    ) as CanonicalFixture;

    expect(fixture.fixtureVersion).toBe(1);
    expect(fixture.algorithm).toBe("RFC 8785");
    expect(fixture.digestAlgorithm).toBe("SHA-256");
    expect(fixture.cases.length).toBeGreaterThan(0);

    for (const fixtureCase of fixture.cases) {
      expect(canonicalJson(fixtureCase.value), fixtureCase.name).toBe(
        fixtureCase.expectedCanonical,
      );
      expect(canonicalSha256(fixtureCase.value), fixtureCase.name).toBe(
        fixtureCase.expectedSha256,
      );
    }
  });
});
