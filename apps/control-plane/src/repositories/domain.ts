import { boundedLimit, record } from "../bounds.ts";
import { newId, nowIso } from "../crypto.ts";
import { PublicError } from "../errors.ts";

interface ResourceSpec {
  table: string;
  prefix: string;
  fields: readonly string[];
  required: readonly string[];
  revisioned: boolean;
}

export const resourceSpecs = {
  projects: { table: "projects", prefix: "prj", fields: ["name", "description", "status", "policy_json"], required: ["name"], revisioned: true },
  sources: { table: "sources", prefix: "src", fields: ["project_id", "display_name", "source_kind", "repository_identity"], required: ["display_name", "source_kind"], revisioned: true },
  locations: { table: "locations", prefix: "loc", fields: ["source_id", "device_id", "opaque_local_id", "display_label", "observed_state_json", "status", "last_observed_at"], required: ["source_id", "device_id", "opaque_local_id", "display_label"], revisioned: true },
  sessions: { table: "collaboration_sessions", prefix: "csess", fields: ["project_id", "title", "accepted_baseline_id", "status"], required: ["title"], revisioned: true },
  messages: { table: "messages", prefix: "msg", fields: ["session_id", "author_principal_id", "origin", "body", "attachments_json"], required: ["session_id", "origin", "body"], revisioned: true },
  project_agents: { table: "project_agents", prefix: "pagent", fields: ["project_id", "name", "adapter_id", "role", "configuration_json", "status"], required: ["project_id", "name", "adapter_id", "role", "configuration_json"], revisioned: true },
  assignments: { table: "assignments", prefix: "asg", fields: ["project_id", "session_id", "source_message_id", "title", "body", "state"], required: ["title", "body", "state"], revisioned: true },
  runs: { table: "runs", prefix: "run", fields: ["assignment_id", "project_id", "session_id", "device_id", "runtime_kind", "access_scope", "approval_mode", "state", "manifest_digest", "manifest_json"], required: ["device_id", "runtime_kind", "access_scope", "approval_mode", "state"], revisioned: true },
  approvals: { table: "approvals", prefix: "appr", fields: ["operation_id", "requester_principal_id", "client_id", "device_id", "run_id", "commitment_digest", "operation_type", "normalized_arguments_json", "revisions_json", "decision", "reuse_scope_json", "expires_at", "resolved_at"], required: ["operation_id", "requester_principal_id", "client_id", "device_id", "commitment_digest", "operation_type", "normalized_arguments_json", "revisions_json", "expires_at"], revisioned: false },
  tasks: { table: "tasks", prefix: "task", fields: ["project_id", "session_id", "assignment_id", "title", "description", "status"], required: ["title", "status"], revisioned: true },
  artifacts: { table: "artifacts", prefix: "art", fields: ["run_id", "project_id", "artifact_kind", "content_digest", "bytes", "sensitivity", "retention_class", "custody", "opaque_device_locator", "r2_key", "upload_policy_json", "status"], required: ["artifact_kind", "content_digest", "bytes", "sensitivity", "retention_class", "custody", "status"], revisioned: false },
  devices: { table: "devices", prefix: "dev", fields: [], required: [], revisioned: true },
  traces: { table: "trace_indexes", prefix: "trace", fields: [], required: [], revisioned: false },
  evidence: { table: "evidence_summaries", prefix: "evid", fields: [], required: [], revisioned: false },
  operations: { table: "operation_journal", prefix: "op", fields: [], required: [], revisioned: false },
} as const satisfies Record<string, ResourceSpec>;

export type ResourceName = keyof typeof resourceSpecs;

function specFor(name: string): ResourceSpec {
  const candidate = resourceSpecs[name as ResourceName];
  if (candidate === undefined) throw new PublicError("not_found", 404, "Unknown API resource");
  return candidate;
}

function dbValue(value: unknown): string | number | null {
  if (value === null || typeof value === "string" || typeof value === "number") return value;
  if (typeof value === "boolean") return value ? 1 : 0;
  return JSON.stringify(value);
}

export class DomainRepository {
  constructor(private readonly db: D1Database) {}

  async list(resource: string, url: URL): Promise<Record<string, unknown>[]> {
    const spec = specFor(resource);
    const limit = boundedLimit(url.searchParams.get("limit"));
    const cursor = url.searchParams.get("cursor") ?? "";
    const result = await this.db
      .prepare(`SELECT * FROM ${spec.table} WHERE id > ?1 ORDER BY id LIMIT ?2`)
      .bind(cursor, limit)
      .all<Record<string, unknown>>();
    return result.results;
  }

  async get(resource: string, id: string): Promise<Record<string, unknown>> {
    const spec = specFor(resource);
    const row = await this.db.prepare(`SELECT * FROM ${spec.table} WHERE id = ?1 LIMIT 1`).bind(id).first<Record<string, unknown>>();
    if (row === null) throw new PublicError("not_found", 404, "Record not found");
    return row;
  }

  async create(resource: string, input: unknown): Promise<Record<string, unknown>> {
    const spec = specFor(resource);
    if (spec.fields.length === 0) throw new PublicError("invalid_request", 405, "This resource is created through a specialized endpoint");
    const body = record(input);
    for (const field of spec.required) {
      if (body[field] === undefined || body[field] === null) throw new PublicError("invalid_request", 400, `${field} is required`);
    }
    const id = typeof body.id === "string" && body.id.length <= 128 ? body.id : newId(spec.prefix);
    const fields = spec.fields.filter((field) => body[field] !== undefined);
    const now = nowIso();
    const columns = ["id", ...fields, ...(spec.revisioned ? ["revision"] : []), "created_at", "updated_at"];
    if (spec.table === "messages" || spec.table === "approvals") columns.pop();
    const values: (string | number | null)[] = [id, ...fields.map((field) => dbValue(body[field])), ...(spec.revisioned ? [1] : []), now];
    if (columns.at(-1) === "updated_at") values.push(now);
    const placeholders = columns.map((_, index) => `?${index + 1}`).join(",");
    await this.db.prepare(`INSERT INTO ${spec.table} (${columns.join(",")}) VALUES (${placeholders})`).bind(...values).run();
    if (spec.table === "messages") {
      await this.db.prepare("INSERT INTO message_revisions(message_id, revision, body, editor_principal_id, created_at) VALUES (?1, 1, ?2, ?3, ?4)")
        .bind(id, String(body.body), body.author_principal_id === undefined ? null : dbValue(body.author_principal_id), now).run();
    }
    return this.get(resource, id);
  }

  async update(resource: string, id: string, expectedRevision: number, input: unknown): Promise<Record<string, unknown>> {
    const spec = specFor(resource);
    if (!spec.revisioned || spec.fields.length === 0) throw new PublicError("invalid_request", 405, "Resource is not updated through this endpoint");
    const body = record(input);
    const fields = spec.fields.filter((field) => body[field] !== undefined && field !== "manifest_digest" && field !== "manifest_json");
    if (fields.length === 0) throw new PublicError("invalid_request", 400, "No mutable fields supplied");
    const assignments = fields.map((field, index) => `${field} = ?${index + 1}`);
    const result = await this.db.prepare(
      `UPDATE ${spec.table} SET ${assignments.join(",")}, revision = revision + 1, updated_at = ?${fields.length + 1} WHERE id = ?${fields.length + 2} AND revision = ?${fields.length + 3}`,
    ).bind(...fields.map((field) => dbValue(body[field])), nowIso(), id, expectedRevision).run();
    if (result.meta.changes !== 1) throw new PublicError("revision_conflict", 409, "Target revision is stale");
    return this.get(resource, id);
  }
}
