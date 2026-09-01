import { PublicError } from "./errors.ts";

export const MAX_JSON_BYTES = 65_536;
export const MAX_MCP_BYTES = 1_048_576;
export const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

export async function readJsonBounded(request: Request, maxBytes = MAX_JSON_BYTES): Promise<unknown> {
  const text = await readTextBounded(request, maxBytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new PublicError("invalid_request", 400, "Malformed JSON body");
  }
}

export async function readTextBounded(request: Request, maxBytes = MAX_JSON_BYTES): Promise<string> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    throw new PublicError("invalid_request", 413, "Request body is too large");
  }
  if (request.body === null) throw new PublicError("invalid_request", 400, "JSON body is required");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel("body limit exceeded");
      throw new PublicError("invalid_request", 413, "Request body is too large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes); }
  catch { throw new PublicError("invalid_request", 400, "Request body is not valid UTF-8"); }
}

export function boundedString(value: unknown, name: string, max = 256, min = 1): string {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw new PublicError("invalid_request", 400, `${name} must be ${min}-${max} characters`);
  }
  return value;
}

export function boundedStringArray(value: unknown, name: string, maxItems: number, maxLength = 256): string[] {
  if (!Array.isArray(value) || value.length > maxItems || !value.every((item) => typeof item === "string" && item.length >= 1 && item.length <= maxLength)) {
    throw new PublicError("invalid_request", 400, `${name} is invalid`);
  }
  return [...new Set(value)];
}

export function record(value: unknown, name = "body"): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new PublicError("invalid_request", 400, `${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function boundedLimit(value: string | null, fallback = 50, max = 200): number {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) throw new PublicError("invalid_request", 400, "limit is invalid");
  return Math.min(Number(value), max);
}
