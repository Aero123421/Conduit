import worker, { BoardRoom, ConnectorLimiter, DeviceRoom, RetryScheduler } from "../../src/index.ts";
import type { ControlPlaneEnv } from "../../src/types.ts";

export { BoardRoom, ConnectorLimiter, DeviceRoom, RetryScheduler };

interface IdleProbeEnv extends ControlPlaneEnv {
  IDLE_E2E_PROBE_TOKEN: string;
}

async function probeRoute(request: Request, env: IdleProbeEnv): Promise<Response | null> {
  const url = new URL(request.url);
  const match = url.pathname.match(/^\/__idle-e2e\/devices\/([^/]+)\/(reset|advance|inspect)$/);
  if (match?.[1] === undefined || match[2] === undefined) return null;
  if (request.headers.get("authorization") !== `Bearer ${env.IDLE_E2E_PROBE_TOKEN}`) return new Response("forbidden", { status: 403 });
  if (url.hostname !== "127.0.0.1" && url.hostname !== "localhost") return new Response("loopback required", { status: 403 });
  const room = env.DEVICE_ROOMS.getByName(match[1]);
  if (match[2] === "inspect") return Response.json(await room.inspectIdleE2EProbe());
  const body = await request.json<{ nowMs?: unknown }>();
  if (typeof body.nowMs !== "number" || !Number.isFinite(body.nowMs)) return new Response("invalid time", { status: 400 });
  if (match[2] === "reset") await room.resetIdleE2EProbe(body.nowMs);
  else await room.advanceIdleE2EProbe(body.nowMs);
  return Response.json({ ok: true });
}

export default {
  async fetch(request: Request, env: IdleProbeEnv, ctx: ExecutionContext): Promise<Response> {
    const probe = await probeRoute(request, env);
    return probe ?? worker.fetch(request, env, ctx);
  },
  queue: worker.queue,
  scheduled: worker.scheduled,
} satisfies ExportedHandler<IdleProbeEnv, unknown>;
