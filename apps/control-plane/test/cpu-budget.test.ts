import { env } from "cloudflare:workers";
import { parseWireDocument, schemaIds } from "@conduit/schema";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/crypto.ts";
import { createConduitMcpServer } from "../src/mcp/server.ts";
import { measureCpu } from "../src/usage-instrumentation.ts";

const wireFixture = {
  protocol: "conduit.node/1",
  messageId: "nmsg_cpu_budget_event_batch",
  deviceId: "dev_cpu_budget_01",
  connectionEpoch: "1",
  direction: "node_to_control",
  sequence: "1",
  type: "transport.ack",
  payloadDigest: "a".repeat(64),
  payload: { direction: "control_to_node", throughSequence: "1" },
};

describe("Workers Free CPU budget", () => {
  it("keeps warm MCP registration, canonical JSON, and wire validation below p95 8 ms", () => {
    const canonicalFixture = { records: Array.from({ length: 128 }, (_, index) => ({ id: `record_${index}`, revision: index + 1, state: index % 2 === 0 ? "ready" : "running" })) };
    const profile = measureCpu(() => {
      createConduitMcpServer(env, { principalId: "prin_cpu_budget", clientId: "conduit.cli", scopes: ["owner"] });
      canonicalJson(canonicalFixture);
      parseWireDocument(schemaIds.nodeV1, wireFixture);
    }, { samples: 100, warmup: 20 });
    console.log(`CLOUDFLARE_CPU_PROBE=${JSON.stringify({ samples: profile.samplesMs.length, medianMs: profile.medianMs, p95Ms: profile.p95Ms, maxMs: profile.maxMs })}`);
    expect(profile.p95Ms).toBeLessThanOrEqual(8);
  });
});
