import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  MAX_EVENT_BATCH_EVENTS,
  MAX_EVENT_QUEUE_MESSAGE_BYTES,
  buildEventBatch,
  commitDurableInboxBatch,
  consumeEvents,
  splitEventBatches,
  type EventBatchMessage,
} from "../src/ingestion.ts";
import { canonicalJson, sha256Hex } from "../src/crypto.ts";
import type { QueueEventMessage } from "../src/types.ts";

const deviceId = "dev_ingestion_batch01";
const runId = "run_ingestion_batch01";

function digest(sequence: number): string {
  return sequence.toString(16).padStart(64, "0");
}

function event(sequence: number, eventId = `evt_ingestion_${String(sequence).padStart(8, "0")}`): QueueEventMessage {
  return {
    schemaVersion: 1,
    kind: "normalized_event",
    eventId,
    runId,
    deviceId,
    sequence: String(sequence),
    eventType: "adapter.assistant_message_delta",
    source: "agent",
    observedAt: "2026-09-02T00:00:00.000Z",
    nodeBootId: "boot_ingestion_batch01",
    evidenceLevel: "observed",
    sensitivity: "metadata",
    retentionClass: "R1",
    payloadDigest: digest(1000 + sequence),
    eventDigest: digest(sequence),
    previousChainHash: digest(sequence - 1),
    chainHash: digest(2000 + sequence),
    payload: { text: `delta-${sequence}` },
  } as QueueEventMessage;
}

async function sourceRangeDigest(events: readonly QueueEventMessage[], from: string, through: string): Promise<string> {
  return sha256Hex(canonicalJson({
    runId,
    fromSequence: from,
    throughSequence: through,
    events: events.map((item) => ({ sequence: item.sequence, eventDigest: item.eventDigest })),
  }));
}

describe.sequential("Control Plane event ingestion", () => {
  it("bulk commits a durable-inbox batch and records one trace index update", async () => {
    const now = "2026-09-02T00:00:00.000Z";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO device_enrollments(id,state,device_code_hash,user_code_hash,claims_json,requested_key_id,requested_public_jwk_json,requested_fingerprint,possession_challenge,possession_signature,assigned_device_id,created_at,expires_at) VALUES ('enroll_ingestion_batch01','completed',?1,?2,'{}','dkey_ingestion_batch01','{}',?3,'challenge','signature',?4,?5,?5)").bind("a".repeat(64), "b".repeat(64), "c".repeat(64), deviceId, now),
      env.DB.prepare("INSERT INTO devices(id,enrollment_id,display_label,os,arch,node_version,protocol_version,status,created_at,updated_at) VALUES (?1,'enroll_ingestion_batch01','Ingestion test','linux','x86_64','0.1.0','conduit.node/1','active',?2,?2)").bind(deviceId, now),
      env.DB.prepare("INSERT INTO runs(id,device_id,runtime_kind,access_scope,approval_mode,state,created_at,updated_at) VALUES (?1,?2,'native','project_full','always','queued',?3,?3)").bind(runId, deviceId, now),
    ]);

    const events = [event(1), event(2)];
    const batch: EventBatchMessage = {
      runId,
      fromSequence: "1",
      throughSequence: "2",
      sourceSequenceRange: { from: "1", through: "2" },
      sourceRangeDigest: await sourceRangeDigest(events, "1", "2"),
      traceSchema: "conduit.trace/1",
      events,
      deviceId,
    };
    const committed = await commitDurableInboxBatch(env as never, batch, { now: new Date(now) });
    expect(committed).toMatchObject({ accepted: 2, duplicate: 0, poisoned: 0 });
    expect(committed.d1.statements).toBe(3);
    expect(committed.d1.bindingCalls).toBe(3);
    expect(committed.d1.maxBoundParameters).toBe(6);
    expect(committed.d1.boundParameters).toBe(9);
    expect(committed.d1.rowsRead).toBeGreaterThanOrEqual(0);
    expect(committed.d1.rowsWritten).toBeGreaterThanOrEqual(0);

    const counts = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM normalized_events WHERE run_id=?1) AS event_count,(SELECT last_sequence FROM trace_indexes WHERE run_id=?1) AS last_sequence,(SELECT MIN(retention_class) FROM normalized_events WHERE run_id=?1) AS retention_class,(SELECT MIN(expires_at) FROM normalized_events WHERE run_id=?1) AS expires_at").bind(runId).first<{ event_count: number; last_sequence: string; retention_class: string; expires_at: string | null }>();
    expect(counts).toMatchObject({ event_count: 2, last_sequence: "2", retention_class: "streaming_delta" });
    expect(counts?.expires_at).not.toBeNull();
  });

  it("isolates one poison event while committing valid and duplicate siblings", async () => {
    const good = event(3);
    const duplicate = event(2);
    const poison = { ...event(4), eventDigest: "not-a-digest" } as QueueEventMessage;
    const result = await commitDurableInboxBatch(env as never, {
      runId,
      fromSequence: "2",
      throughSequence: "4",
      traceSchema: "conduit.trace/1",
      events: [duplicate, good, poison],
      deviceId,
    }, { messageId: "queue-ingestion-poison01", now: new Date("2026-09-02T00:00:01.000Z") });

    expect(result).toMatchObject({ accepted: 1, duplicate: 1, poisoned: 1 });
    expect(result.d1.statements).toBe(4);
    expect(result.d1.bindingCalls).toBe(4);
    expect(result.d1.maxBoundParameters).toBe(6);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM normalized_events WHERE run_id=?1").bind(runId).first<{ count: number }>();
    expect(count?.count).toBe(3);
    const evidence = await env.DB.prepare("SELECT reason_code,metadata_json FROM security_events WHERE event_type='event_ingestion.poison' AND json_extract(metadata_json,'$.messageId')=?1").bind("queue-ingestion-poison01").all<{ reason_code: string; metadata_json: string }>();
    expect(evidence.results).toHaveLength(1);
    expect(evidence.results[0]?.reason_code).toBe("event_digest_invalid");
    expect(JSON.parse(evidence.results[0]!.metadata_json)).toMatchObject({ eventId: "evt_ingestion_00000004", runId, sequence: "4" });
  });

  it("keeps queue messages below the 64 KiB ceiling and bounds event count", () => {
    const events = Array.from({ length: MAX_EVENT_BATCH_EVENTS }, (_, index) => event(index + 10));
    const batch = buildEventBatch(events);
    expect(batch.events).toHaveLength(MAX_EVENT_BATCH_EVENTS);
    expect(new TextEncoder().encode(JSON.stringify(batch)).byteLength).toBeLessThan(65_536);
    expect(MAX_EVENT_QUEUE_MESSAGE_BYTES).toBeLessThan(65_536);

    const large = Array.from({ length: 64 }, (_, index) => ({ ...event(index + 100), payload: { text: "x".repeat(2_500) } })) as QueueEventMessage[];
    const split = splitEventBatches(large);
    expect(split.length).toBeGreaterThan(1);
    expect(split.every((item) => item.events.length <= MAX_EVENT_BATCH_EVENTS)).toBe(true);
    expect(split.every((item) => new TextEncoder().encode(JSON.stringify(item)).byteLength <= MAX_EVENT_QUEUE_MESSAGE_BYTES)).toBe(true);
  });

  it("acknowledges a queue batch after isolating malformed siblings", async () => {
    const calls: string[] = [];
    const poison = { ...event(6), eventDigest: "bad" } as QueueEventMessage;
    await consumeEvents({ messages: [{
      id: "queue-ingestion-consumer01",
      body: { runId, fromSequence: "5", throughSequence: "6", traceSchema: "conduit.trace/1", events: [event(5), poison], deviceId },
      attempts: 1,
      ack: () => calls.push("ack"),
      retry: () => calls.push("retry"),
    }] } as never, env as never);
    expect(calls).toEqual(["ack"]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM normalized_events WHERE run_id=?1").bind(runId).first<{ count: number }>();
    expect(count?.count).toBe(4);
    const evidence = await env.DB.prepare("SELECT reason_code FROM security_events WHERE event_type='event_ingestion.poison' AND json_extract(metadata_json,'$.messageId')=?1").bind("queue-ingestion-consumer01").all<{ reason_code: string }>();
    expect(evidence.results).toHaveLength(1);
    expect(evidence.results[0]?.reason_code).toBe("event_digest_invalid");
  });
});
