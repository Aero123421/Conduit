import { DurableObject } from "cloudflare:workers";
import { nowIso } from "../crypto.ts";
import type { ControlPlaneEnv } from "../types.ts";

interface BoardAttachment { sessionId: string; subscriberId: string; }

export class BoardRoom extends DurableObject<ControlPlaneEnv> {
  constructor(ctx: DurableObjectState, env: ControlPlaneEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS _sql_schema_migrations(id INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fanout_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL, event_json TEXT NOT NULL, created_at TEXT NOT NULL);
        INSERT OR IGNORE INTO _sql_schema_migrations(id,applied_at) VALUES (1,datetime('now'));
      `);
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

  async publish(event: { eventId: string; sessionId: string; type: string; recordId: string; revision: number }): Promise<number> {
    const json = JSON.stringify(event);
    const row = this.ctx.storage.sql.exec<{ sequence: number }>("INSERT INTO fanout_events(event_id,session_id,event_json,created_at) VALUES (?,?,?,?) RETURNING sequence", event.eventId, event.sessionId, json, nowIso()).one();
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as BoardAttachment | null;
      if (attachment?.sessionId === event.sessionId) ws.send(JSON.stringify({ sequence: row.sequence, ...event }));
    }
    return row.sequence;
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message === "ping") ws.send("pong");
  }
}
