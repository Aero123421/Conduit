export type DenialCode =
  | "authentication_required"
  | "fresh_authentication_required"
  | "csrf_failed"
  | "client_not_registered"
  | "client_metadata_changed"
  | "grant_required"
  | "grant_paused"
  | "grant_revoked"
  | "grant_reauthorization_required"
  | "scope_insufficient"
  | "connector_ceiling_exceeded"
  | "project_not_allowed"
  | "device_not_allowed"
  | "device_offline"
  | "device_revoked"
  | "device_key_invalid"
  | "runtime_not_allowed"
  | "operation_not_allowed"
  | "approval_required"
  | "approval_expired"
  | "approval_digest_mismatch"
  | "rate_limited"
  | "resource_limit"
  | "platform_capability_unavailable"
  | "idempotency_conflict"
  | "revision_conflict"
  | "invalid_request"
  | "not_found";

export class PublicError extends Error {
  constructor(
    readonly code: DenialCode,
    readonly status: number,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "PublicError";
  }
}

export function errorResponse(error: unknown, requestId: string): Response {
  if (error instanceof PublicError) {
    const headers = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
    if (error.retryAfterSeconds !== undefined) headers.set("retry-after", String(error.retryAfterSeconds));
    return Response.json(
      { error: { code: error.code, message: error.message, requestId } },
      { status: error.status, headers },
    );
  }
  console.error(JSON.stringify({ level: "error", message: "request failed", requestId, error: error instanceof Error ? error.message : "unknown" }));
  return Response.json(
    { error: { code: "internal_error", message: "Internal server error", requestId } },
    { status: 500, headers: { "cache-control": "no-store" } },
  );
}
