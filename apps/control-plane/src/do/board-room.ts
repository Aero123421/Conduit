import { DurableObject } from "cloudflare:workers";
import { canonicalJson, nowIso } from "../crypto.ts";
import type { ControlPlaneEnv } from "../types.ts";

interface BoardAttachment { sessionId: string; subscriberId: string; }
interface BoardProjectionEvent { eventId: string; sessionId: string; type: string; recordId: string; revision: number; }
interface PublishedBoardEvent extends BoardProjectionEvent { sequence: number; }

const FANOUT_RETENTION_MS = 24 * 60 * 60 * 1_000;
const MAX_BATCH_EVENTS = 32;

export class BoardRoom extends DurableObject<ControlPlaneEnv> {
  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fanout_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL, event_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
      `);
      const columns = this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(fanout_events)").toArray();
      if (!columns.some((column) => column.name === "expires_at")) this.ctx.storage.sql.exec("ALTER TABLE fanout_events ADD COLUMN expires_at TEXT");
      this.ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idx_fanout_events_expiry ON fanout_events(expires_at,sequence); UPDATE fanout_events SET expires_at=datetime(created_at,'+1 day') WHERE expires_at IS NULL; INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (2,datetime('now'));");
      this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    });
  }

  override async fetch(request: Request): Promise<Response> {
    const match = new URL(request.url).pathname.match(/^\/v1\/sessions\/([^/]+)\/stream$/);
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket" || match?.[1] === undefined) return new Response("WebSocket required", { status: 426 });
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const attachment: BoardAttachment = { sessionId: match[1], subscriberId: crypto.randomUUID() };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async publish(event: BoardProjectionEvent): Promise<number> {
    const published = await this.publishBatch([event]);
    const first = published[0];
    if (first === undefined) throw new TypeError("Board event was not published");
    return first.sequence;
  }

  async publishBatch(events: BoardProjectionEvent[]): Promise<PublishedBoardEvent[]> {
    if (events.length < 1 || events.length > MAX_BATCH_EVENTS) throw new RangeError(`Board event batch must contain 1-${MAX_BATCH_EVENTS} events`);
    const sessionId = events[0]?.sessionId;
    if (sessionId === undefined || events.some((event) => event.sessionId !== sessionId)) throw new TypeError("Board event batch must target exactly one Session");
    const canonicalEvents = events.map((event) => ({ ...event, json: canonicalJson(event) }));
    if (new Set(canonicalEvents.map((event) => event.eventId)).size !== canonicalEvents.length) throw new TypeError("Board event batch contains duplicate IDs");
    const input = canonicalJson(canonicalEvents.map(({ json: _json, ...event }) => event));
    const existing = this.ctx.storage.sql.exec<{ sequence: number; event_id: string; session_id: string; event_json: string }>(
      "SELECT sequence,event_id,session_id,event_json FROM fanout_events WHERE event_id IN (SELECT json_extract(value,'$.eventId') FROM json_each(?))",
      input,
    ).toArray();
    const byId = new Map(existing.map((row) => [row.event_id, row]));
    for (const event of canonicalEvents) {
      const prior = byId.get(event.eventId);
      if (prior !== undefined && (prior.session_id !== event.sessionId || canonicalJson(JSON.parse(prior.event_json) as unknown) !== event.json)) throw new TypeError("Board event ID is bound to another projection");
    }
    const fresh = canonicalEvents.filter((event) => !byId.has(event.eventId));
    const createdAt = nowIso();
    const expiresAt = new Date(Date.parse(createdAt) + FANOUT_RETENTION_MS).toISOString();
    if (fresh.length > 0) {
      this.ctx.storage.sql.exec(
        "INSERT OR IGNORE INTO fanout_events(event_id,session_id,event_json,created_at,expires_at) SELECT json_extract(value,'$.eventId'),json_extract(value,'$.sessionId'),value,?,? FROM json_each(?)",
        createdAt,
        expiresAt,
        canonicalJson(fresh.map(({ json: _json, ...event }) => event)),
      );
    }
    const stored = this.ctx.storage.sql.exec<{ sequence: number; event_id: string; event_json: string }>(
      "SELECT sequence,event_id,event_json FROM fanout_events WHERE event_id IN (SELECT json_extract(value,'$.eventId') FROM json_each(?))",
      input,
    ).toArray();
    const storedById = new Map(stored.map((row) => [row.event_id, row]));
    const published = canonicalEvents.map(({ json: _json, ...event }) => {
      const row = storedById.get(event.eventId);
      if (row === undefined || canonicalJson(JSON.parse(row.event_json) as unknown) !== canonicalJson(event)) throw new TypeError("Board event batch was not durably stored");
      return { sequence: row.sequence, ...event };
    });
    const freshIds = new Set(fresh.map((event) => event.eventId));
    const outgoing = published.filter((event) => freshIds.has(event.eventId));
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as BoardAttachment | null;
      if (attachment?.sessionId === sessionId && outgoing.length > 0) ws.send(canonicalJson({ type: "events.batch", events: outgoing }));
    }
    this.ctx.storage.sql.exec("DELETE FROM fanout_events WHERE sequence IN (SELECT sequence FROM fanout_events WHERE expires_at<=? ORDER BY expires_at,sequence LIMIT 250)", createdAt);
    return published;
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message === "ping") ws.send("pong");
  }
}
