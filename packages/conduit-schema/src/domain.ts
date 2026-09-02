import { createHash } from "node:crypto";
import canonicalizeModule from "canonicalize";

export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type ProjectId = Brand<string, "ProjectId">;
export type CollaborationSessionId = Brand<string, "CollaborationSessionId">;
export type AssignmentId = Brand<string, "AssignmentId">;
export type RunId = Brand<string, "RunId">;
export type LocalRunId = Brand<string, "LocalRunId">;
export type AnyRunId = RunId | LocalRunId;
export type DeviceId = Brand<string, "DeviceId">;
export type SourceId = Brand<string, "SourceId">;
export type LocationId = Brand<string, "LocationId">;
export type RuntimeId = Brand<string, "RuntimeId">;
export type BaselineId = Brand<string, "BaselineId">;
export type ChangeSetId = Brand<string, "ChangeSetId">;
export type OperationId = Brand<string, "OperationId">;
export type Sha256Digest = Brand<string, "Sha256Digest">;
export type U64Decimal = Brand<string, "U64Decimal">;
export type UtcTimestamp = Brand<string, "UtcTimestamp">;

const idSuffix = "[A-Za-z0-9][A-Za-z0-9_-]{7,127}";

function parsePrefixedId<T extends string>(
  value: unknown,
  prefix: string,
  name: string,
): T {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }
  const pattern = new RegExp(`^${prefix}${idSuffix}$`);
  if (!pattern.test(value)) {
    throw new TypeError(`${name} has an invalid format`);
  }
  return value as T;
}

export const parseProjectId = (value: unknown): ProjectId =>
  parsePrefixedId<ProjectId>(value, "prj_", "Project ID");
export const parseCollaborationSessionId = (
  value: unknown,
): CollaborationSessionId =>
  parsePrefixedId<CollaborationSessionId>(
    value,
    "csess_",
    "Collaboration Session ID",
  );
export const parseAssignmentId = (value: unknown): AssignmentId =>
  parsePrefixedId<AssignmentId>(value, "asg_", "Assignment ID");
export const parseRunId = (value: unknown): RunId =>
  parsePrefixedId<RunId>(value, "run_", "Run ID");
export const parseLocalRunId = (value: unknown): LocalRunId =>
  parsePrefixedId<LocalRunId>(value, "lrun_", "Local Run ID");
export const parseAnyRunId = (value: unknown): AnyRunId =>
  typeof value === "string" && value.startsWith("lrun_")
    ? parseLocalRunId(value)
    : parseRunId(value);
export const parseDeviceId = (value: unknown): DeviceId =>
  parsePrefixedId<DeviceId>(value, "dev_", "Device ID");
export const parseSourceId = (value: unknown): SourceId =>
  parsePrefixedId<SourceId>(value, "src_", "Source ID");
export const parseLocationId = (value: unknown): LocationId =>
  parsePrefixedId<LocationId>(value, "loc_", "Location ID");
export const parseRuntimeId = (value: unknown): RuntimeId =>
  parsePrefixedId<RuntimeId>(value, "rt_", "Runtime ID");
export const parseBaselineId = (value: unknown): BaselineId =>
  parsePrefixedId<BaselineId>(value, "bln_", "Baseline ID");
export const parseChangeSetId = (value: unknown): ChangeSetId =>
  parsePrefixedId<ChangeSetId>(value, "chg_", "Change Set ID");
export const parseOperationId = (value: unknown): OperationId =>
  parsePrefixedId<OperationId>(value, "op_", "Operation ID");

export function parseU64Decimal(value: unknown): U64Decimal {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    throw new TypeError("U64 decimal has an invalid format");
  }
  const parsed = BigInt(value);
  if (parsed > 18_446_744_073_709_551_615n) {
    throw new RangeError("U64 decimal is outside the unsigned 64-bit range");
  }
  return value as U64Decimal;
}

export function parseSha256Digest(value: unknown): Sha256Digest {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError("SHA-256 digest must be lowercase hexadecimal text");
  }
  return value as Sha256Digest;
}

export function parseUtcTimestamp(value: unknown): UtcTimestamp {
  if (typeof value !== "string") {
    throw new TypeError("timestamp must be a UTC RFC 3339 value ending in Z");
  }

  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(
      value,
    );
  const epochMilliseconds = Date.parse(value);
  if (match === null || Number.isNaN(epochMilliseconds)) {
    throw new TypeError("timestamp must be a UTC RFC 3339 value ending in Z");
  }

  const parsed = new Date(epochMilliseconds);
  const components = match.slice(1, 7).map(Number);
  if (
    parsed.getUTCFullYear() !== components[0] ||
    parsed.getUTCMonth() + 1 !== components[1] ||
    parsed.getUTCDate() !== components[2] ||
    parsed.getUTCHours() !== components[3] ||
    parsed.getUTCMinutes() !== components[4] ||
    parsed.getUTCSeconds() !== components[5]
  ) {
    throw new TypeError("timestamp must be a UTC RFC 3339 value ending in Z");
  }
  return value as UtcTimestamp;
}

const canonicalize = canonicalizeModule as unknown as (
  value: unknown,
) => string | undefined;

export function canonicalJson(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) {
    throw new TypeError("value cannot be represented as canonical JSON");
  }
  return result;
}

export function canonicalSha256(value: unknown): Sha256Digest {
  const digest = createHash("sha256").update(canonicalJson(value)).digest("hex");
  return parseSha256Digest(digest);
}

export const schemaIds = {
  authV1: "https://conduit.dev/spec/schemas/auth-v1.schema.json",
  nodeV1: "https://conduit.dev/spec/schemas/node-protocol-v1.schema.json",
  privilegedV1:
    "https://conduit.dev/spec/schemas/privileged-helper-v1.schema.json",
  traceV1: "https://conduit.dev/spec/schemas/trace-v1.schema.json",
  runtimeV1: "https://conduit.dev/spec/schemas/runtime-v1.schema.json",
  changeSetV1: "https://conduit.dev/spec/schemas/changeset-v1.schema.json",
} as const;
