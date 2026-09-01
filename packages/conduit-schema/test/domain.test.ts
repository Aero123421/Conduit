import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  canonicalSha256,
  parseAnyRunId,
  parseLocalRunId,
  parseProjectId,
  parseRunId,
  parseSha256Digest,
  parseU64Decimal,
  parseUtcTimestamp,
} from "../src/index.ts";

describe("domain values", () => {
  it("validates prefixed IDs", () => {
    expect(parseProjectId("prj_abcdefgh")).toBe("prj_abcdefgh");
    expect(() => parseProjectId("project_abcdefgh")).toThrow();
    expect(() => parseProjectId("prj_short")).toThrow();
    expect(parseRunId("run_abcdefgh")).toBe("run_abcdefgh");
    expect(() => parseRunId("lrun_abcdefgh")).toThrow();
    expect(parseLocalRunId("lrun_abcdefgh")).toBe("lrun_abcdefgh");
    expect(parseAnyRunId("run_abcdefgh")).toBe("run_abcdefgh");
    expect(parseAnyRunId("lrun_abcdefgh")).toBe("lrun_abcdefgh");
  });

  it("validates canonical u64 decimals", () => {
    expect(parseU64Decimal("0")).toBe("0");
    expect(parseU64Decimal("18446744073709551615")).toBe(
      "18446744073709551615",
    );
    expect(() => parseU64Decimal("01")).toThrow();
    expect(() => parseU64Decimal("18446744073709551616")).toThrow();
  });

  it("validates lowercase SHA-256", () => {
    const digest =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(parseSha256Digest(digest)).toBe(digest);
    expect(() => parseSha256Digest(digest.toUpperCase())).toThrow();
  });

  it("validates UTC timestamps", () => {
    expect(parseUtcTimestamp("2026-09-01T12:00:00Z")).toBe(
      "2026-09-01T12:00:00Z",
    );
    expect(() => parseUtcTimestamp("2026-09-01T21:00:00+09:00")).toThrow();
    expect(() => parseUtcTimestamp("2026-02-30T00:00:00Z")).toThrow();
    expect(() => parseUtcTimestamp("2026-09-01T24:00:00Z")).toThrow();
  });
});

describe("canonical JSON", () => {
  it("sorts object keys and returns a lowercase SHA-256 digest", () => {
    const value = { z: 1, a: "x", nested: { b: true, a: null } };
    expect(canonicalJson(value)).toBe(
      '{"a":"x","nested":{"a":null,"b":true},"z":1}',
    );
    expect(canonicalSha256(value)).toMatch(/^[a-f0-9]{64}$/);
  });
});
