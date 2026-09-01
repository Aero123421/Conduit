const encoder = new TextEncoder();

export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Non-finite number cannot be canonicalized");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported canonical JSON value: ${typeof value}`);
}

export async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const input = typeof value === "string" ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", input);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function keyedHash(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64url(value);
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function operationDigest(value: unknown): Promise<string> {
  return sha256Hex(`conduit.operation.v1\n${canonicalJson(value)}`);
}

export async function verifyEd25519(publicJwk: JsonWebKey, signature: string, transcript: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("jwk", publicJwk, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, fromBase64url(signature), encoder.encode(transcript));
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function newId(prefix: string): string {
  // Wire IDs require an ASCII alphanumeric immediately after the prefix.
  // Prefixing the entropy with a fixed version marker avoids the 1/32 chance
  // that a base64url token begins with '-' or '_'.
  return `${prefix}_x${randomToken(18)}`;
}
