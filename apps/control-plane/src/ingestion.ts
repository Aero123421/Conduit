import type { ControlPlaneEnv, QueueEventMessage } from "./types.ts";
import { nowIso } from "./crypto.ts";

function validEvent(value: unknown): value is QueueEventMessage {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return item.schemaVersion === 1 && ["eventId", "runId", "deviceId", "sequence", "eventType", "eventDigest", "chainHash", "evidenceLevel", "sensitivity", "observedAt"].every((field) => typeof item[field] === "string") && item.payload !== null && typeof item.payload === "object" && !Array.isArray(item.payload) && Object.keys(item.payload as object).length <= 128;
}

export async function consumeEvents(batch: MessageBatch<unknown>, env: ControlPlaneEnv): Promise<void> {
  for (const message of batch.messages) {
    if (!validEvent(message.body)) { message.ack(); continue; }
    const event = message.body;
    try {
      await env.DB.prepare("INSERT INTO normalized_events(event_id,run_id,device_id,sequence,event_type,event_digest,chain_hash,evidence_level,sensitivity,payload_json,observed_at,ingested_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(event_id) DO NOTHING")
        .bind(event.eventId, event.runId, event.deviceId, event.sequence, event.eventType, event.eventDigest, event.chainHash, event.evidenceLevel, event.sensitivity, JSON.stringify(event.payload), event.observedAt, nowIso()).run();
      const existing = await env.DB.prepare("SELECT event_id,event_digest FROM normalized_events WHERE run_id=?1 AND sequence=?2 LIMIT 1").bind(event.runId, event.sequence).first<{ event_id: string; event_digest: string }>();
      if (existing === null || existing.event_id !== event.eventId || existing.event_digest !== event.eventDigest) throw new Error("event_sequence_conflict");
      await env.DB.prepare("INSERT INTO trace_indexes(run_id,device_id,first_sequence,last_sequence,chain_hash,observability_state,event_counts_json,updated_at) VALUES (?1,?2,?3,?3,?4,'complete','{}',?5) ON CONFLICT(run_id) DO UPDATE SET last_sequence=excluded.last_sequence,chain_hash=excluded.chain_hash,updated_at=excluded.updated_at")
        .bind(event.runId, event.deviceId, event.sequence, event.chainHash, nowIso()).run();
      message.ack();
    } catch {
      message.retry({ delaySeconds: 5 });
    }
  }
}
