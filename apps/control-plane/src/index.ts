import { createMcpHandler } from "agents/mcp/server";
import { handleApi } from "./api.ts";
import { handleBrowserAuth, renderAuthPage } from "./auth/browser.ts";
import { handleDeviceIdentity } from "./auth/device.ts";
import { authenticateBearer, handleOAuth } from "./auth/oauth.ts";
import { MAX_MCP_BYTES } from "./bounds.ts";
import { BoardRoom } from "./do/board-room.ts";
import { ConnectorLimiter } from "./do/connector-limiter.ts";
import { DeviceRoom } from "./do/device-room.ts";
import { reconcileOperationDispatches } from "./dispatch.ts";
import { errorResponse, PublicError } from "./errors.ts";
import { consumeEvents } from "./ingestion.ts";
import { createConduitMcpServer } from "./mcp/server.ts";
import { handlePolicyAdmin } from "./policy.ts";
import type { ControlPlaneEnv } from "./types.ts";

export { BoardRoom, ConnectorLimiter, DeviceRoom };

function withSecurityHeaders(response: Response, requestId: string): Response {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-frame-options", "DENY");
  headers.set("x-request-id", requestId);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers, webSocket: response.webSocket });
}

async function fetchHandler(request: Request, env: ControlPlaneEnv, ctx: ExecutionContext): Promise<Response> {
  const requestId = crypto.randomUUID();
  const url = new URL(request.url);
  try {
    const publicUrl = new URL(env.PUBLIC_ORIGIN);
    const configuredForLoopback = publicUrl.hostname === "localhost" || publicUrl.hostname === "127.0.0.1";
    const requestIsLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.origin !== publicUrl.origin && !(configuredForLoopback && requestIsLoopback)) throw new PublicError("invalid_request", 400, "Request Host does not match the configured public origin");
    let routePath = url.pathname.startsWith("/api/v1/") ? url.pathname.slice(4) : url.pathname;
    routePath = routePath.replace(/^\/v1\/board\/messages(?=\/|$)/, "/v1/messages").replace(/^\/v1\/projects\/sources$/, "/v1/sources").replace(/^\/v1\/agents(?=\/|$)/, "/v1/project_agents").replace(/^\/v1\/evaluations\/([^/]+)$/, "/v1/evidence/$1");
    if (url.pathname === "/healthz" && request.method === "GET") return withSecurityHeaders(Response.json({ status: "ok", version: 1 }), requestId);
    if ((url.pathname === "/setup" || url.pathname === "/login") && request.method === "GET") return withSecurityHeaders(await renderAuthPage(request, env), requestId);
    if (url.pathname === "/device" && request.method === "GET") return withSecurityHeaders(new Response("<!doctype html><meta charset=utf-8><title>Device enrollment</title><h1>Device enrollment</h1><p>Sign in, perform fresh passkey authentication, then review the displayed code and public-key fingerprint.</p>", { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; frame-ancestors 'none'" } }), requestId);
    const oauth = await handleOAuth(request, env, routePath);
    if (oauth !== null) return withSecurityHeaders(oauth, requestId);
    const browser = await handleBrowserAuth(request, env, routePath);
    if (browser !== null) return withSecurityHeaders(browser, requestId);
    const device = await handleDeviceIdentity(request, env, routePath);
    if (device !== null) return withSecurityHeaders(device, requestId);
    const policy = await handlePolicyAdmin(request, env, routePath);
    if (policy !== null) return withSecurityHeaders(policy, requestId);
    if (url.pathname === "/mcp") {
      const length = request.headers.get("content-length");
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_MCP_BYTES)) throw new PublicError("invalid_request", 413, "MCP request is too large");
      const actor = await authenticateBearer(request, env);
      const handler = createMcpHandler(() => createConduitMcpServer(env, actor), { route: "/mcp", legacy: "reject", corsOptions: false, allowedOriginHostnames: [new URL(env.PUBLIC_ORIGIN).hostname] });
      return withSecurityHeaders(await handler(request, env, ctx), requestId);
    }
    const api = await handleApi(request, env, routePath);
    if (api !== null) return withSecurityHeaders(api, requestId);
    return withSecurityHeaders(Response.json({ error: { code: "not_found", message: "Route not found", requestId } }, { status: 404 }), requestId);
  } catch (error) {
    return withSecurityHeaders(errorResponse(error, requestId), requestId);
  }
}

export default {
  fetch: fetchHandler,
  queue: consumeEvents,
  scheduled(controller, env, ctx) {
    ctx.waitUntil(reconcileOperationDispatches(env, { now: new Date(controller.scheduledTime) }));
  },
} satisfies ExportedHandler<ControlPlaneEnv, unknown>;
