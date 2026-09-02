import { canonicalJson, nowIso, sha256Hex } from "./crypto.ts";
import type { ControlPlaneEnv, QueueEventMessage } from "./types.ts";

/** Keep enough headroom below Queue's 64 KiB message limit for provider framing. */
export const MAX_EVENT_QUEUE_MESSAGE_BYTES = 60_000;
export const MAX_EVENT_BATCH_EVENTS = 32;
/**
 * One hostile Queue message can consume five D1 statements (poison evidence,
 * identity probe, bulk insert, trace update, and a commit-time conflict
 * receipt). Six messages therefore leave ten statements of headroom below
 * the release ceiling for the outer Queue invocation.
 */
export const MAX_QUEUE_MESSAGES_PER_INVOCATION = 6;

const U64 = /^(0|[1-9][0-9]{0,19})$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const EVENT_ID = /^evt_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u;
const RUN_ID = /^(?:run|lrun)_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u;
const DEVICE_ID = /^dev_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/u;
const EVENT_NAME = /^[a-z][a-z0-9_.-]{0,127}$/u;
const NODE_BOOT_ID = /^.{16,128}$/us;
const EVIDENCE_LEVELS = new Set(["explicit", "observed", "inferred", "unknown"]);
const SENSITIVITY_CLASSES = new Set(["public", "metadata", "project_content", "raw_log", "credential_reference", "secret"]);
const RETENTION_CLASSES = new Set(["R0", "R1", "R2", "R3"]);

/** Internal queue representation of a wire event.batch payload. */
export interface EventBatchMessage {
  /** Internal marker; wire event.batch payloads omit this field. */
  schemaVersion?: 1;
  runId: string;
  fromSequence: string;
  throughSequence: string;
  /** Source-local range carried by current protocol producers. */
  sourceSequenceRange?: { from: string; through: string };
  /** Digest of the source-local range and event commitments. */
  sourceRangeDigest?: string;
  traceSchema: "conduit.trace/1";
  events: QueueEventMessage[];
  /** Not on the wire payload; used to fence a queue message to one Device. */
  deviceId?: string;
  /** Optional local source range commitment supplied by the Device accumulator. */
  rangeDigest?: string;
}

export type EventIngestionMode = "durable_inbox" | "queue";

export interface D1Usage {
  statements: number;
  bindingCalls: number;
  boundParameters: number;
  /** Largest parameter vector on any individual prepared statement. */
  maxBoundParameters: number;
  rowsRead: number;
  rowsWritten: number;
}

export interface EventIngestionResult {
  accepted: number;
  duplicate: number;
  poisoned: number;
  /** D1 meta aggregation is intentionally returned for budget tests. */
  d1: D1Usage;
}

interface PoisonedEvent {
  event: QueueEventMessage | null;
  reason: string;
  fingerprint: string;
  messageId?: string;
}

interface ParsedBatch {
  batch: EventBatchMessage;
  malformed: PoisonedEvent[];
}

interface ExistingIdentityRow {
  event_id: string;
  run_id: string;
  device_id: string;
  sequence: string;
  event_digest: string;
  chain_hash: string;
}

interface EventIdentityProbeRow {
  event_id: string;
  run_id: string;
  device_id: string;
  sequence: string;
  id_event_id: string | null;
  id_run_id: string | null;
  id_device_id: string | null;
  id_sequence: string | null;
  id_event_digest: string | null;
  id_chain_hash: string | null;
  sequence_event_id: string | null;
  sequence_run_id: string | null;
  sequence_device_id: string | null;
  sequence_sequence: string | null;
  sequence_event_digest: string | null;
  sequence_chain_hash: string | null;
  run_found: string | null;
  run_device_id: string | null;
  device_found: string | null;
}

export interface BatchCommitOptions {
  messageId?: string;
  messageAttempts?: number;
  now?: Date;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function isString(value: unknown, pattern?: RegExp): value is string {
  return typeof value === "string" && (pattern === undefined || pattern.test(value));
}

function parseQueueBody(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value) as unknown; } catch { return value; }
}

/** Return a stable reason instead of throwing so one poison event is isolated. */
function eventReason(value: unknown): string | null {
  const item = asRecord(value);
  if (item === null) return "event_not_object";
  if (item.schemaVersion !== 1) return "event_schema_version";
  if (item.kind !== undefined && item.kind !== "normalized_event") return "event_kind";
  if (!isString(item.eventId, EVENT_ID)) return "event_id_invalid";
  if (!isString(item.runId, RUN_ID)) return "event_run_id_invalid";
  if (!isString(item.deviceId, DEVICE_ID)) return "event_device_id_invalid";
  if (!isString(item.sequence, U64)) return "event_sequence_invalid";
  if (!isString(item.eventType, EVENT_NAME)) return "event_type_invalid";
  // The legacy producer did not include the normalized-event discriminator or
  // the source commitment fields. Keep that shape readable during rollout,
  // while enforcing every field whenever a current normalized event claims
  // `kind: normalized_event`.
  const currentWireEvent = item.kind === "normalized_event";
  if (currentWireEvent && !isString(item.source, EVENT_NAME)) return "event_source_invalid";
  if (item.source !== undefined && !isString(item.source, EVENT_NAME)) return "event_source_invalid";
  if (!isString(item.eventDigest, SHA256)) return "event_digest_invalid";
  if (!isString(item.chainHash, SHA256)) return "event_chain_hash_invalid";
  if (currentWireEvent && !isString(item.previousChainHash, SHA256)) return "event_previous_chain_hash_invalid";
  if (item.previousChainHash !== undefined && !isString(item.previousChainHash, SHA256)) return "event_previous_chain_hash_invalid";
  if (currentWireEvent && !isString(item.payloadDigest, SHA256)) return "event_payload_digest_invalid";
  if (item.payloadDigest !== undefined && !isString(item.payloadDigest, SHA256)) return "event_payload_digest_invalid";
  if (!isString(item.evidenceLevel) || !EVIDENCE_LEVELS.has(item.evidenceLevel)) return "event_evidence_level_invalid";
  if (!isString(item.sensitivity) || !SENSITIVITY_CLASSES.has(item.sensitivity)) return "event_sensitivity_invalid";
  if (currentWireEvent && (!isString(item.retentionClass) || !RETENTION_CLASSES.has(item.retentionClass))) return "event_retention_class_invalid";
  if (item.retentionClass !== undefined && (!isString(item.retentionClass) || !RETENTION_CLASSES.has(item.retentionClass))) return "event_retention_class_invalid";
  if (!isString(item.observedAt) || !Number.isFinite(Date.parse(item.observedAt))) return "event_observed_at_invalid";
  if (currentWireEvent && !isString(item.nodeBootId, NODE_BOOT_ID)) return "event_node_boot_invalid";
  if (item.nodeBootId !== undefined && !isString(item.nodeBootId, NODE_BOOT_ID)) return "event_node_boot_invalid";
  if (item.payload === null || typeof item.payload !== "object" || Array.isArray(item.payload)) return "event_payload_invalid";
  if (Object.keys(item.payload as object).length > 128) return "event_payload_too_large";
  if (item.monotonicNanos !== undefined && !isString(item.monotonicNanos, U64)) return "event_monotonic_invalid";
  if (item.correlationId !== undefined && (!isString(item.correlationId) || item.correlationId.length > 256)) return "event_correlation_invalid";
  if (item.parentEventId !== undefined && !isString(item.parentEventId, EVENT_ID)) return "event_parent_invalid";
  if (item.traceId !== undefined && !isString(item.traceId, /^[a-f0-9]{32}$/u)) return "event_trace_id_invalid";
  if (item.spanId !== undefined && !isString(item.spanId, /^[a-f0-9]{16}$/u)) return "event_span_id_invalid";
  if (item.parentSpanId !== undefined && !isString(item.parentSpanId, /^[a-f0-9]{16}$/u)) return "event_parent_span_id_invalid";
  if (item.contentReference !== undefined && asRecord(item.contentReference) === null) return "event_content_reference_invalid";
  return null;
}

/** True only for an event that can be admitted to normalized_events. */
export function validEvent(value: unknown): value is QueueEventMessage {
  return eventReason(value) === null;
}

function eventAsQueueMessage(value: unknown): QueueEventMessage | null {
  return validEvent(value) ? value : null;
}

function eventIdentity(value: QueueEventMessage): string {
  return `${value.eventId}\u0000${value.runId}\u0000${value.deviceId}\u0000${value.sequence}\u0000${value.eventDigest}\u0000${value.chainHash}`;
}

function eventBytes(value: unknown): number {
  const json = JSON.stringify(value);
  if (json === undefined) throw new TypeError("event batch is not JSON serializable");
  return new TextEncoder().encode(json).byteLength;
}

function committedEventBatchBytes(batch: EventBatchMessage): number {
  return eventBytes({
    ...batch,
    sourceSequenceRange: { from: batch.fromSequence, through: batch.throughSequence },
    // The digest is always a lowercase SHA-256 value, so a zero digest has
    // the same encoded width as the real commitment without doing async work
    // during the producer's greedy packing pass.
    sourceRangeDigest: "0".repeat(64),
  });
}

function emptyUsage(): D1Usage {
  return { statements: 0, bindingCalls: 0, boundParameters: 0, maxBoundParameters: 0, rowsRead: 0, rowsWritten: 0 };
}

function usageFromMeta(meta: { rows_read?: number; rows_written?: number } | undefined): Pick<D1Usage, "rowsRead" | "rowsWritten"> {
  return { rowsRead: typeof meta?.rows_read === "number" ? meta.rows_read : 0, rowsWritten: typeof meta?.rows_written === "number" ? meta.rows_written : 0 };
}

function addUsage(target: D1Usage, source: Pick<D1Usage, "statements" | "bindingCalls" | "boundParameters" | "rowsRead" | "rowsWritten"> & Partial<Pick<D1Usage, "maxBoundParameters">>): void {
  target.statements += source.statements;
  target.bindingCalls += source.bindingCalls;
  target.boundParameters += source.boundParameters;
  target.maxBoundParameters = Math.max(target.maxBoundParameters, source.maxBoundParameters ?? source.boundParameters);
  target.rowsRead += source.rowsRead;
  target.rowsWritten += source.rowsWritten;
}

function prepared(db: D1Database, sql: string, ...parameters: unknown[]): D1PreparedStatement {
  return db.prepare(sql).bind(...parameters);
}

async function poisonFingerprint(event: QueueEventMessage | null, reason: string, messageId?: string): Promise<string> {
  const digest = await sha256Hex(canonicalJson({ eventId: event?.eventId ?? null, runId: event?.runId ?? null, deviceId: event?.deviceId ?? null, sequence: event?.sequence ?? null, eventDigest: event?.eventDigest ?? null, reason, messageId: messageId ?? null }));
  return `sevt_${digest.slice(0, 48)}`;
}

/** Match the Node accumulator's source-range commitment without another D1
 * round trip. Invalid JSON event members use the same canonical-value
 * fallback as the local accumulator so a bad sibling can be isolated while
 * valid siblings remain eligible for commit. */
async function sourceRangeDigestForBatch(batch: EventBatchMessage, values: readonly unknown[]): Promise<string> {
  const commitments = await Promise.all(values.map(async (value, index) => {
    const item = asRecord(value);
    const sequence = item !== null && isString(item.sequence, U64) ? item.sequence : String(BigInt(batch.fromSequence) + BigInt(index));
    const eventDigest = item !== null && typeof item.eventDigest === "string"
      ? item.eventDigest
      : await sha256Hex(canonicalJson(value));
    return { sequence, eventDigest };
  }));
  return sha256Hex(canonicalJson({ runId: batch.runId, fromSequence: batch.fromSequence, throughSequence: batch.throughSequence, events: commitments }));
}

async function securityEvidence(env: ControlPlaneEnv, poisoned: PoisonedEvent[], now: string): Promise<D1Usage> {
  if (poisoned.length === 0) return emptyUsage();
  const rows: Array<Record<string, unknown>> = [];
  for (const item of poisoned) {
    const event = item.event;
    const fingerprint = item.fingerprint || await poisonFingerprint(event, item.reason, item.messageId);
    rows.push({
      id: fingerprint,
      eventType: "event_ingestion.poison",
      deviceId: typeof event?.deviceId === "string" ? event.deviceId : null,
      reasonCode: item.reason,
      // Do not copy payload/content into immutable security evidence.
      metadata: JSON.stringify({ eventId: event?.eventId ?? null, runId: event?.runId ?? null, sequence: event?.sequence ?? null, eventDigest: event?.eventDigest ?? null, messageId: item.messageId ?? null }),
    });
  }
  const statement = prepared(env.DB, `
    INSERT OR IGNORE INTO security_events(id,event_type,device_id,reason_code,metadata_json,created_at)
    SELECT json_extract(value,'$.id'),json_extract(value,'$.eventType'),json_extract(value,'$.deviceId'),
           json_extract(value,'$.reasonCode'),json_extract(value,'$.metadata'),?2
    FROM json_each(?1)
  `, canonicalJson(rows), now);
  const [result] = await env.DB.batch([statement]);
  return { statements: 1, bindingCalls: 1, boundParameters: 2, maxBoundParameters: 2, ...usageFromMeta(result?.meta) };
}

function probeRowToExisting(row: EventIdentityProbeRow, prefix: "id" | "sequence"): ExistingIdentityRow | null {
  const eventId = prefix === "id" ? row.id_event_id : row.sequence_event_id;
  const runId = prefix === "id" ? row.id_run_id : row.sequence_run_id;
  const deviceId = prefix === "id" ? row.id_device_id : row.sequence_device_id;
  const sequence = prefix === "id" ? row.id_sequence : row.sequence_sequence;
  const eventDigest = prefix === "id" ? row.id_event_digest : row.sequence_event_digest;
  const chainHash = prefix === "id" ? row.id_chain_hash : row.sequence_chain_hash;
  return eventId === null || runId === null || deviceId === null || sequence === null || eventDigest === null || chainHash === null
    ? null
    : { event_id: eventId, run_id: runId, device_id: deviceId, sequence, event_digest: eventDigest, chain_hash: chainHash };
}

function identityMatches(event: QueueEventMessage, row: ExistingIdentityRow | null): boolean {
  return row !== null && row.event_id === event.eventId && row.run_id === event.runId && row.device_id === event.deviceId && row.sequence === event.sequence && row.event_digest === event.eventDigest && row.chain_hash === event.chainHash;
}

function sequenceLess(left: string, right: string): boolean {
  return left.length < right.length || (left.length === right.length && left < right);
}

function sequenceGreater(left: string, right: string): boolean {
  return left.length > right.length || (left.length === right.length && left > right);
}

/**
 * Commit one event.batch with bounded D1 work.  The identity probe is one
 * json_each set query. The commit is one batch containing one bulk INSERT,
 * one run trace-index upsert, and (only when needed) one evidence INSERT.
 */
export async function commitEventBatch(env: ControlPlaneEnv, input: EventBatchMessage, options: BatchCommitOptions = {}): Promise<EventIngestionResult> {
  const usage = emptyUsage();
  const now = (options.now ?? new Date()).toISOString();
  const malformed: PoisonedEvent[] = [];
  const events: QueueEventMessage[] = [];
  const inputEvents = Array.isArray(input.events) ? input.events : [];
  const rangeValid = isString(input.fromSequence, U64) && isString(input.throughSequence, U64) && BigInt(input.fromSequence) <= BigInt(input.throughSequence);
  const sourceRange = input.sourceSequenceRange;
  const sourceRangePresent = sourceRange !== undefined || input.sourceRangeDigest !== undefined;
  const sourceRangeValid = !sourceRangePresent || (sourceRange !== undefined
    && isString(sourceRange.from, U64)
    && isString(sourceRange.through, U64)
    && BigInt(sourceRange.from) <= BigInt(sourceRange.through)
    && sourceRange.from === input.fromSequence
    && sourceRange.through === input.throughSequence
    && isString(input.sourceRangeDigest, SHA256));
  const metadataValid = (input.schemaVersion === undefined || input.schemaVersion === 1)
    && input.traceSchema === "conduit.trace/1"
    && isString(input.runId, RUN_ID)
    && rangeValid
    && sourceRangeValid
    && (input.deviceId === undefined || isString(input.deviceId, DEVICE_ID));
  if (!metadataValid) {
    for (const event of inputEvents) malformed.push({ event: event ?? null, reason: "batch_metadata_invalid", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
  } else if (inputEvents.length < 1 || inputEvents.length > MAX_EVENT_BATCH_EVENTS) {
    for (const event of inputEvents.slice(0, MAX_EVENT_BATCH_EVENTS)) malformed.push({ event, reason: "batch_size_invalid", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
  } else {
    const from = BigInt(input.fromSequence);
    const through = BigInt(input.throughSequence);
    for (const candidate of inputEvents) {
      const reason = eventReason(candidate);
      if (reason !== null) malformed.push({ event: candidate, reason, fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
      else if (candidate.runId !== input.runId) malformed.push({ event: candidate, reason: "event_run_batch_mismatch", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
      else if (input.deviceId !== undefined && candidate.deviceId !== input.deviceId) malformed.push({ event: candidate, reason: "event_device_batch_mismatch", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
      else if (BigInt(candidate.sequence) < from || BigInt(candidate.sequence) > through) malformed.push({ event: candidate, reason: "event_sequence_out_of_batch_range", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
      else events.push(candidate);
    }
  }
  if (metadataValid && sourceRangePresent && sourceRangeValid && input.sourceRangeDigest !== undefined) {
    try {
      const expected = await sourceRangeDigestForBatch(input, inputEvents);
      if (expected !== input.sourceRangeDigest) malformed.push({ event: null, reason: "batch_source_range_digest_invalid", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
    } catch {
      malformed.push({ event: null, reason: "batch_source_range_digest_invalid", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
    }
  }

  const identityGroups = new Map<string, QueueEventMessage[]>();
  for (const event of events) {
    const key = `${event.eventId}\u0000${event.runId}\u0000${event.deviceId}\u0000${event.sequence}`;
    const group = identityGroups.get(key) ?? [];
    group.push(event);
    identityGroups.set(key, group);
  }
  const candidates: QueueEventMessage[] = [];
  let duplicate = 0;
  for (const group of identityGroups.values()) {
    const first = group[0]!;
    if (group.every((event) => eventIdentity(event) === eventIdentity(first))) {
      candidates.push(first);
      duplicate += group.length - 1;
    } else {
      for (const event of group) malformed.push({ event, reason: "event_batch_identity_conflict", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
    }
  }

  const probeJson = canonicalJson(candidates.map((event) => ({ eventId: event.eventId, runId: event.runId, deviceId: event.deviceId, sequence: event.sequence })));
  const probe = prepared(env.DB, `
    WITH requested AS (
      SELECT json_extract(value,'$.eventId') AS event_id,
             json_extract(value,'$.runId') AS run_id,
             json_extract(value,'$.deviceId') AS device_id,
             json_extract(value,'$.sequence') AS sequence
      FROM json_each(?1)
    )
    SELECT requested.event_id,requested.run_id,requested.device_id,requested.sequence,
           by_id.event_id AS id_event_id,by_id.run_id AS id_run_id,by_id.device_id AS id_device_id,
           by_id.sequence AS id_sequence,by_id.event_digest AS id_event_digest,by_id.chain_hash AS id_chain_hash,
           by_sequence.event_id AS sequence_event_id,by_sequence.run_id AS sequence_run_id,
           by_sequence.device_id AS sequence_device_id,by_sequence.sequence AS sequence_sequence,
           by_sequence.event_digest AS sequence_event_digest,by_sequence.chain_hash AS sequence_chain_hash,
           run.id AS run_found,run.device_id AS run_device_id,device.id AS device_found
    FROM requested
    LEFT JOIN normalized_events AS by_id ON by_id.event_id=requested.event_id
    LEFT JOIN normalized_events AS by_sequence ON by_sequence.run_id=requested.run_id AND by_sequence.sequence=requested.sequence
    LEFT JOIN runs AS run ON run.id=requested.run_id
    LEFT JOIN devices AS device ON device.id=requested.device_id
  `, probeJson);
  const probeResult = await probe.all<EventIdentityProbeRow>();
  addUsage(usage, { statements: 1, bindingCalls: 1, boundParameters: 1, ...usageFromMeta(probeResult.meta) });
  const probes = new Map(probeResult.results.map((row) => [row.event_id, row]));
  const fresh: QueueEventMessage[] = [];
  for (const event of candidates) {
    const row = probes.get(event.eventId);
    const byId = row === undefined ? null : probeRowToExisting(row, "id");
    const bySequence = row === undefined ? null : probeRowToExisting(row, "sequence");
    if (row === undefined || row.run_found === null || row.device_found === null || row.run_device_id !== event.deviceId) {
      malformed.push({ event, reason: "event_target_missing", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
    } else if (identityMatches(event, byId) && (bySequence === null || identityMatches(event, bySequence))) {
      duplicate += 1;
    } else if (byId !== null || bySequence !== null) {
      malformed.push({ event, reason: "event_identity_conflict", fingerprint: "", ...(options.messageId === undefined ? {} : { messageId: options.messageId }) });
    } else {
      fresh.push(event);
    }
  }

  if (fresh.length > 0) {
    const sorted = [...fresh].sort((left, right) => sequenceLess(left.sequence, right.sequence) ? -1 : sequenceGreater(left.sequence, right.sequence) ? 1 : 0);
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const insert = prepared(env.DB, `
      INSERT OR IGNORE INTO normalized_events(
        event_id,run_id,device_id,sequence,event_type,event_digest,chain_hash,
        evidence_level,sensitivity,payload_json,observed_at,ingested_at,retention_class,expires_at
      )
      SELECT json_extract(value,'$.eventId'),json_extract(value,'$.runId'),json_extract(value,'$.deviceId'),
             json_extract(value,'$.sequence'),json_extract(value,'$.eventType'),json_extract(value,'$.eventDigest'),
             json_extract(value,'$.chainHash'),json_extract(value,'$.evidenceLevel'),json_extract(value,'$.sensitivity'),
             json(json_extract(value,'$.payload')),json_extract(value,'$.observedAt'),?2,
             CASE WHEN json_extract(value,'$.eventType')='adapter.assistant_message_delta' THEN 'streaming_delta' ELSE 'long_lived' END,
             CASE WHEN json_extract(value,'$.eventType')='adapter.assistant_message_delta' THEN strftime('%Y-%m-%dT%H:%M:%fZ',?2,'+3 days') ELSE NULL END
      FROM json_each(?1)
    `, canonicalJson(fresh), now);
    const trace = prepared(env.DB, `
      INSERT INTO trace_indexes(run_id,device_id,first_sequence,last_sequence,chain_hash,observability_state,event_counts_json,updated_at)
      VALUES (?1,?2,?3,?4,?5,'complete','{}',?6)
      ON CONFLICT(run_id) DO UPDATE SET
        first_sequence=CASE
          WHEN length(excluded.first_sequence)<length(trace_indexes.first_sequence)
            OR (length(excluded.first_sequence)=length(trace_indexes.first_sequence) AND excluded.first_sequence<trace_indexes.first_sequence)
          THEN excluded.first_sequence ELSE trace_indexes.first_sequence END,
        last_sequence=CASE
          WHEN length(excluded.last_sequence)>length(trace_indexes.last_sequence)
            OR (length(excluded.last_sequence)=length(trace_indexes.last_sequence) AND excluded.last_sequence>trace_indexes.last_sequence)
          THEN excluded.last_sequence ELSE trace_indexes.last_sequence END,
        chain_hash=CASE
          WHEN length(excluded.last_sequence)>length(trace_indexes.last_sequence)
            OR (length(excluded.last_sequence)=length(trace_indexes.last_sequence) AND excluded.last_sequence>=trace_indexes.last_sequence)
          THEN excluded.chain_hash ELSE trace_indexes.chain_hash END,
        updated_at=excluded.updated_at
    `, first.runId, first.deviceId, first.sequence, last.sequence, last.chainHash, now);
    const results = await env.DB.batch([insert, trace]);
    const parameterCounts = [2, 6];
    results.forEach((result, index) => addUsage(usage, { statements: 1, bindingCalls: 1, boundParameters: parameterCounts[index] ?? 0, ...usageFromMeta(result.meta) }));
  }

  addUsage(usage, await securityEvidence(env, malformed, now));
  return { accepted: fresh.length, duplicate, poisoned: malformed.length, d1: usage };
}

/** Free/default path: DeviceRoom retains custody and invokes this from its alarm. */
export async function commitDurableInboxBatch(env: ControlPlaneEnv, input: EventBatchMessage, options: BatchCommitOptions = {}): Promise<EventIngestionResult> {
  return commitEventBatch(env, input, options);
}

/** Select durable_inbox by default; standard profile may opt into Queue mode. */
export function eventIngestionMode(env: ControlPlaneEnv, requested?: EventIngestionMode): EventIngestionMode {
  if (requested !== undefined) return requested;
  const configured = env as ControlPlaneEnv & { CLOUDFLARE_EVENT_INGESTION_MODE?: unknown; CLOUDFLARE_USAGE_PROFILE?: unknown };
  if (configured.CLOUDFLARE_EVENT_INGESTION_MODE === "queue" || String(configured.CLOUDFLARE_USAGE_PROFILE) === "standard") return "queue";
  return "durable_inbox";
}

function normalizeBatch(value: unknown, messageId?: string): ParsedBatch | null {
  const parsed = asRecord(parseQueueBody(value));
  if (parsed === null) return null;
  // DeviceRoom may pass the complete wire frame; queue producers usually pass
  // only frame.payload. Both forms are deliberately accepted.
  const framePayload = parsed.type === "event.batch" ? asRecord(parsed.payload) : null;
  const body = framePayload ?? parsed;
  if (body === null || !Array.isArray(body.events)) {
    const event = eventAsQueueMessage(parsed);
    if (event === null) return null;
    return { batch: { schemaVersion: 1, runId: event.runId, fromSequence: event.sequence, throughSequence: event.sequence, traceSchema: "conduit.trace/1", events: [event], deviceId: event.deviceId }, malformed: [] };
  }
  const malformed: PoisonedEvent[] = [];
  const events: QueueEventMessage[] = [];
  const runId = typeof body.runId === "string" ? body.runId : "";
  const fromSequence = typeof body.fromSequence === "string" ? body.fromSequence : "";
  const throughSequence = typeof body.throughSequence === "string" ? body.throughSequence : "";
  const deviceId = typeof body.deviceId === "string" ? body.deviceId : undefined;
  const rangeValid = isString(fromSequence, U64) && isString(throughSequence, U64) && BigInt(fromSequence) <= BigInt(throughSequence);
  const sourceRangeRaw = body.sourceSequenceRange;
  const legacyRangeDigest = typeof body.rangeDigest === "string" ? body.rangeDigest : undefined;
  const sourceSequenceRange = sourceRangeRaw === undefined && legacyRangeDigest !== undefined
    ? { from: fromSequence, through: throughSequence }
    : asRecord(sourceRangeRaw);
  const sourceRangeDigest = typeof body.sourceRangeDigest === "string" ? body.sourceRangeDigest : legacyRangeDigest;
  const sourceRangePresent = sourceRangeRaw !== undefined || sourceRangeDigest !== undefined;
  const sourceRangeValid = !sourceRangePresent || (sourceSequenceRange !== null
    && isString(sourceSequenceRange.from, U64)
    && isString(sourceSequenceRange.through, U64)
    && BigInt(sourceSequenceRange.from) <= BigInt(sourceSequenceRange.through)
    && sourceSequenceRange.from === fromSequence
    && sourceSequenceRange.through === throughSequence
    && isString(sourceRangeDigest, SHA256));
  const batchMetadataValid = isString(runId, RUN_ID) && rangeValid && body.traceSchema === "conduit.trace/1"
    && (deviceId === undefined || isString(deviceId, DEVICE_ID)) && sourceRangeValid;
  if (!isString(runId, RUN_ID)) malformed.push({ event: null, reason: "batch_run_id_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  if (!rangeValid) malformed.push({ event: null, reason: "batch_range_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  if (body.traceSchema !== "conduit.trace/1") malformed.push({ event: null, reason: "batch_trace_schema_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  if (deviceId !== undefined && !isString(deviceId, DEVICE_ID)) malformed.push({ event: null, reason: "batch_device_id_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  if (!sourceRangeValid) malformed.push({ event: null, reason: "batch_source_range_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  const batchSizeValid = body.events.length >= 1 && body.events.length <= MAX_EVENT_BATCH_EVENTS;
  if (!batchSizeValid) {
    // A size violation is a malformed batch, not permission to project an
    // arbitrary prefix.  Keeping the event list empty prevents an untrusted
    // Queue body containing 33+ entries from silently committing its first
    // 32 while the sender is supposed to retry/fix the whole envelope.
    malformed.push({ event: null, reason: "batch_size_invalid", fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
  }
  for (const candidate of (batchMetadataValid && batchSizeValid ? body.events : [])) {
    const reason = eventReason(candidate);
    if (reason !== null) malformed.push({ event: asRecord(candidate) === null ? null : candidate as QueueEventMessage, reason, fingerprint: "", ...(messageId === undefined ? {} : { messageId }) });
    else events.push(candidate as QueueEventMessage);
  }
  return {
    batch: {
      schemaVersion: 1,
      runId,
      fromSequence,
      throughSequence,
      traceSchema: "conduit.trace/1",
      events,
      ...(deviceId === undefined ? {} : { deviceId }),
      ...(sourceSequenceRange !== null ? { sourceSequenceRange: sourceSequenceRange as { from: string; through: string } } : {}),
      ...(sourceRangeDigest === undefined ? {} : { sourceRangeDigest }),
      // Older local accumulators called this field rangeDigest. Preserve it
      // when reading an already-custodied inbox row.
    },
    malformed,
  };
}

/**
 * Parse a Device `event.batch` frame or payload for the durable inbox hook.
 * The returned malformed list is intentionally exposed so DeviceRoom can
 * record poison evidence before acknowledging custody without duplicating the
 * wire parser or splitting the batch into Queue messages.
 */
export function parseEventBatch(value: unknown, messageId?: string): { batch: EventBatchMessage; malformed: Array<{ event: QueueEventMessage | null; reason: string; messageId?: string }> } | null {
  return normalizeBatch(value, messageId);
}

/** Build a queue-safe event.batch envelope. */
export function buildEventBatch(events: readonly QueueEventMessage[], options: { fromSequence?: string; throughSequence?: string; deviceId?: string; rangeDigest?: string; sourceRangeDigest?: string; sourceSequenceRange?: { from: string; through: string } } = {}): EventBatchMessage {
  if (events.length < 1 || events.length > MAX_EVENT_BATCH_EVENTS) throw new RangeError(`event batch must contain 1-${MAX_EVENT_BATCH_EVENTS} events`);
  const first = events[0]!;
  if (!validEvent(first)) throw new TypeError("event batch contains an invalid event");
  for (const event of events) {
    if (!validEvent(event)) throw new TypeError("event batch contains an invalid event");
    if (event.runId !== first.runId || event.deviceId !== first.deviceId) throw new TypeError("event batch must contain one run and device");
  }
  const sorted = [...events].sort((left, right) => sequenceLess(left.sequence, right.sequence) ? -1 : sequenceGreater(left.sequence, right.sequence) ? 1 : 0);
  const fromSequence = options.fromSequence ?? sorted[0]!.sequence;
  const throughSequence = options.throughSequence ?? sorted[sorted.length - 1]!.sequence;
  if (!isString(fromSequence, U64) || !isString(throughSequence, U64) || BigInt(fromSequence) > BigInt(throughSequence)) throw new RangeError("event batch range is invalid");
  const sourceRangeDigest = options.sourceRangeDigest ?? options.rangeDigest;
  const sourceSequenceRange = options.sourceSequenceRange ?? (sourceRangeDigest === undefined ? undefined : { from: fromSequence, through: throughSequence });
  const result: EventBatchMessage = { runId: first.runId, fromSequence, throughSequence, traceSchema: "conduit.trace/1", events: [...events], deviceId: options.deviceId ?? first.deviceId,
    ...(sourceSequenceRange === undefined ? {} : { sourceSequenceRange }),
    ...(sourceRangeDigest === undefined ? {} : { sourceRangeDigest }),
  };
  if (eventBytes(result) >= 65_536) throw new RangeError(`event batch exceeds Queue 64 KiB limit (${eventBytes(result)} bytes)`);
  return result;
}

/** Split a local accumulator at both the event-count and Queue byte ceilings. */
export function splitEventBatches(events: readonly QueueEventMessage[], options: { maxBytes?: number } = {}): EventBatchMessage[] {
  if (events.length === 0) return [];
  const maxBytes = Math.min(options.maxBytes ?? MAX_EVENT_QUEUE_MESSAGE_BYTES, MAX_EVENT_QUEUE_MESSAGE_BYTES);
  if (maxBytes < 1_024) throw new RangeError("event batch byte limit is too small");
  const result: EventBatchMessage[] = [];
  let current: QueueEventMessage[] = [];
  for (const event of events) {
    if (!validEvent(event)) throw new TypeError("event batch contains an invalid event");
    const candidate = [...current, event];
    let fits = false;
    try {
      const candidateBatch = buildEventBatch(candidate);
      // Queue messages gain a source range and a 32-byte digest before send.
      // Include representative fields in the fit check so the final message
      // remains below the configured headroom, not merely below it before
      // commitment metadata is attached.
      fits = candidate.length <= MAX_EVENT_BATCH_EVENTS && committedEventBatchBytes(candidateBatch) <= maxBytes;
    } catch { fits = false; }
    if (fits) { current = candidate; continue; }
    if (current.length === 0) throw new RangeError("single normalized event exceeds Queue message limit");
    result.push(buildEventBatch(current));
    current = [event];
    if (committedEventBatchBytes(buildEventBatch(current)) > maxBytes) throw new RangeError("single normalized event exceeds Queue message limit");
  }
  if (current.length > 0) result.push(buildEventBatch(current));
  return result;
}

/** Add the current wire-required source range commitment to a queue chunk. */
export async function withSourceRangeCommitment(batch: EventBatchMessage): Promise<EventBatchMessage> {
  const sourceSequenceRange = { from: batch.fromSequence, through: batch.throughSequence };
  const sourceRangeDigest = await sourceRangeDigestForBatch(batch, batch.events);
  if (batch.sourceRangeDigest !== undefined && batch.sourceRangeDigest !== sourceRangeDigest) throw new TypeError("event batch source range digest is invalid");
  return { ...batch, sourceSequenceRange, sourceRangeDigest };
}

/** Queue producer: each event.batch is exactly one Queue message. */
export async function enqueueEventBatch(env: ControlPlaneEnv, input: EventBatchMessage, options: { mode?: EventIngestionMode; maxBytes?: number } = {}): Promise<{ mode: EventIngestionMode; messages: number; bytes: number }> {
  const mode = eventIngestionMode(env, options.mode);
  if (mode === "durable_inbox") return { mode, messages: 0, bytes: 0 };
  if (!isString(input.runId, RUN_ID) || !isString(input.fromSequence, U64) || !isString(input.throughSequence, U64) || BigInt(input.fromSequence) > BigInt(input.throughSequence) || input.traceSchema !== "conduit.trace/1") throw new TypeError("event batch metadata is invalid");
  if (input.events.length < 1 || input.events.length > MAX_EVENT_BATCH_EVENTS) throw new RangeError(`event batch must contain 1-${MAX_EVENT_BATCH_EVENTS} events`);
  const first = input.events[0];
  if (first === undefined || first.runId !== input.runId || (input.deviceId !== undefined && input.deviceId !== first.deviceId)) throw new TypeError("event batch metadata does not match events");
  if (input.sourceSequenceRange !== undefined && (input.sourceSequenceRange.from !== input.fromSequence || input.sourceSequenceRange.through !== input.throughSequence)) throw new TypeError("event batch source range does not match batch range");
  const chunks = splitEventBatches(input.events, options.maxBytes === undefined ? {} : { maxBytes: options.maxBytes });
  const sendChunks = chunks.length === 1
    ? [{ ...chunks[0]!, runId: input.runId, fromSequence: input.fromSequence, throughSequence: input.throughSequence, deviceId: input.deviceId ?? first.deviceId }]
    : chunks;
  const messages = await Promise.all(sendChunks.map(async (chunk) => {
    // A Node-produced batch normally fits in one chunk and already carries
    // the authoritative digest. Recompute for split chunks so every Queue
    // message remains independently verifiable.
    if (chunks.length === 1 && input.sourceRangeDigest !== undefined) {
      const preserved = input.sourceSequenceRange === undefined
        ? { ...chunk, sourceRangeDigest: input.sourceRangeDigest }
        : { ...chunk, sourceSequenceRange: input.sourceSequenceRange, sourceRangeDigest: input.sourceRangeDigest };
      return withSourceRangeCommitment(preserved);
    }
    return withSourceRangeCommitment(chunk);
  }));
  let bytes = 0;
  for (const message of messages) {
    bytes += eventBytes(message);
    await env.EVENT_INGESTION.send(message, { contentType: "json" });
  }
  return { mode, messages: messages.length, bytes };
}

/** Queue consumer: one Queue message is one bounded event.batch commit. */
export async function consumeEvents(batch: MessageBatch<unknown>, env: ControlPlaneEnv): Promise<void> {
  for (const [index, message] of batch.messages.entries()) {
    if (index >= MAX_QUEUE_MESSAGES_PER_INVOCATION) {
      // The deployment binding also caps max_batch_size. Keep this fail-safe
      // so a test harness or future configuration drift cannot make one
      // invocation exceed its D1 budget.
      message.retry({ delaySeconds: 1 });
      continue;
    }
    const parsed = normalizeBatch(message.body, message.id);
    if (parsed === null) {
      await securityEvidence(env, [{ event: null, reason: "queue_message_invalid", fingerprint: "", messageId: message.id }], nowIso());
      message.ack();
      continue;
    }
    if (parsed.malformed.length > 0) await securityEvidence(env, parsed.malformed, nowIso());
    if (parsed.batch.events.length === 0) {
      message.ack();
      continue;
    }
    try {
      // A source-range digest covers every source event, including a poison
      // sibling that was removed by the parser. Keep the exact poison in
      // security evidence and commit valid siblings without asserting a
      // digest over a now-partial list.
      let commitBatch = parsed.batch;
      if (parsed.malformed.length > 0) {
        const { sourceSequenceRange: _sourceSequenceRange, sourceRangeDigest: _sourceRangeDigest, ...withoutSourceCommitment } = parsed.batch;
        commitBatch = withoutSourceCommitment;
      }
      await commitEventBatch(env, commitBatch, { messageId: message.id, messageAttempts: message.attempts });
      message.ack();
    } catch {
      // D1/network failures retry the whole message; poison siblings have
      // already been isolated and are not allowed to poison valid events.
      message.retry({ delaySeconds: 5 });
    }
  }
}
