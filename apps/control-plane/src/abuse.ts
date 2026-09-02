import { keyedHash } from "./crypto.ts";
import type { ControlPlaneEnv } from "./types.ts";

/** Store only a keyed source pseudonym; never persist an IP address. */
export async function requestSourceHash(request: Request, env: Pick<ControlPlaneEnv, "TOKEN_PEPPER">): Promise<string> {
  const source = request.headers.get("cf-connecting-ip")?.trim().slice(0, 128) || "cloudflare-source-unavailable";
  return keyedHash(env.TOKEN_PEPPER, `conduit.abuse-source.v1\n${source}`);
}
