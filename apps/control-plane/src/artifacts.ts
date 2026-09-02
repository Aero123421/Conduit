import { MAX_ARTIFACT_BYTES, boundedString } from "./bounds.ts";
import { newId, nowIso } from "./crypto.ts";
import { PublicError } from "./errors.ts";
import { authenticateBearer } from "./auth/oauth.ts";
import { authorizeConnector } from "./policy.ts";
import { resolveResourceAuthority } from "./repositories/resource-authority.ts";
import type { ControlPlaneEnv } from "./types.ts";

export async function ensureArtifactObject(bucket: R2Bucket, key: string, request: { artifactId: string; digest: string; bytes: number; body: ReadableStream; contentType: string }): Promise<"existing" | "stored"> {
  const existing = await bucket.head(key);
  if (existing !== null) {
    if (existing.size !== request.bytes || existing.customMetadata?.artifactId !== request.artifactId || existing.customMetadata?.digest !== request.digest) {
      throw new PublicError("idempotency_conflict", 409, "R2 artifact key is bound to different content");
    }
    return "existing";
  }
  await bucket.put(key, request.body, { sha256: request.digest, customMetadata: { artifactId: request.artifactId, digest: request.digest, uploadedAt: nowIso() }, httpMetadata: { contentType: request.contentType } });
  return "stored";
}

export async function uploadArtifact(request: Request, env: ControlPlaneEnv, artifactId: string): Promise<Response> {
  const actor = await authenticateBearer(request, env);
  const lengthText = request.headers.get("content-length");
  if (lengthText === null || !/^\d+$/.test(lengthText)) throw new PublicError("invalid_request", 411, "Content-Length is required for artifact upload");
  const bytes = Number(lengthText);
  if (bytes < 0 || bytes > MAX_ARTIFACT_BYTES) throw new PublicError("resource_limit", 413, "Artifact exceeds the upload boundary");
  const digest = boundedString(request.headers.get("x-conduit-content-sha256"), "X-Conduit-Content-SHA256", 64, 64);
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new PublicError("invalid_request", 400, "Artifact digest must be lowercase SHA-256 hex");
  const artifact = await env.DB.prepare("SELECT id,project_id,content_digest,bytes,custody,status FROM artifacts WHERE id=?1 LIMIT 1").bind(artifactId).first<{ id: string; project_id: string | null; content_digest: string; bytes: number; custody: string; status: string }>();
  if (artifact === null) throw new PublicError("not_found", 404, "Artifact metadata not found");
  if (artifact.content_digest !== digest || artifact.bytes !== bytes || artifact.custody !== "upload_pending") throw new PublicError("invalid_request", 409, "Artifact upload does not match committed metadata");
  const operationId = newId("op");
  await authorizeConnector(env, actor, { operation: "artifact.upload", ...await resolveResourceAuthority(env.DB, "artifacts", artifactId), artifactUploadBytes: bytes, idempotencyKey: request.headers.get("idempotency-key") ?? `${artifactId}:${digest}`, operationId, payloadDigest: digest });
  if (request.body === null) throw new PublicError("invalid_request", 400, "Artifact body is required");
  const r2Key = `artifacts/${artifactId}/${digest}`;
  await ensureArtifactObject(env.ARTIFACTS, r2Key, { artifactId, digest, bytes, body: request.body, contentType: request.headers.get("content-type") ?? "application/octet-stream" });
  const result = await env.DB.prepare("UPDATE artifacts SET custody='r2',r2_key=?1,status='available',updated_at=?2 WHERE id=?3 AND custody='upload_pending'").bind(r2Key, nowIso(), artifactId).run();
  if (result.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Artifact custody changed during upload");
  return Response.json({ artifactId, custody: "r2", contentDigest: digest, bytes }, { status: 201 });
}
