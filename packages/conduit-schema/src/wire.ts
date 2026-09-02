import type { ErrorObject } from "ajv";
import type { ConduitAuthenticationAndAuthorizationRecordsV1 } from "./generated/auth-v1.generated.js";
import type { ConduitSessionBaselineAndChangeSetContractV1 } from "./generated/changeset-v1.generated.js";
import type {
  ConduitNodeTransportProtocolV1,
  PostAuthFrame as GeneratedPostAuthFrame,
} from "./generated/node-protocol-v1.generated.js";
import type { NodeProtocolPayloadCatalogV1 } from "./generated/node-protocol-v1.payloads.generated.js";
import type { ConduitRuntimeProviderContractV1 } from "./generated/runtime-v1.generated.js";
import type { ConduitRunManifestAndTraceRecordsV1 } from "./generated/trace-v1.generated.js";
import {
  authV1 as authV1DomainValidator,
  changeSetV1 as changeSetV1DomainValidator,
  nodeV1 as nodeV1DomainValidator,
  runtimeV1 as runtimeV1DomainValidator,
  traceV1 as traceV1DomainValidator,
} from "./generated/wire-domain-validators.generated.js";
import {
  authV1 as authV1SchemaValidator,
  changeSetV1 as changeSetV1SchemaValidator,
  nodeV1 as nodeV1SchemaValidator,
  runtimeV1 as runtimeV1SchemaValidator,
  traceV1 as traceV1SchemaValidator,
} from "./generated/wire-schema-validators.generated.js";
import { schemaIds } from "./domain.js";

export type AuthV1WireDocument =
  ConduitAuthenticationAndAuthorizationRecordsV1;
export type NodeV1PostAuthFrame = {
  [Type in keyof NodeProtocolPayloadCatalogV1]: Omit<
    GeneratedPostAuthFrame,
    "type" | "payload"
  > & {
    type: Type;
    payload: NodeProtocolPayloadCatalogV1[Type];
  };
}[keyof NodeProtocolPayloadCatalogV1];
export type NodeV1WireDocument =
  | Exclude<ConduitNodeTransportProtocolV1, GeneratedPostAuthFrame>
  | NodeV1PostAuthFrame;
export type TraceV1WireDocument = ConduitRunManifestAndTraceRecordsV1;
export type RuntimeV1WireDocument = ConduitRuntimeProviderContractV1;
export type ChangeSetV1WireDocument =
  ConduitSessionBaselineAndChangeSetContractV1;

/** Schema-generated transport records. Domain IDs remain the branded parser types. */
export interface WireDocumentMap {
  [schemaIds.authV1]: AuthV1WireDocument;
  [schemaIds.nodeV1]: NodeV1WireDocument;
  [schemaIds.traceV1]: TraceV1WireDocument;
  [schemaIds.runtimeV1]: RuntimeV1WireDocument;
  [schemaIds.changeSetV1]: ChangeSetV1WireDocument;
}

export type WireSchemaId = keyof WireDocumentMap;
export type WireDocument = WireDocumentMap[WireSchemaId];
export type WireDocumentFor<SchemaId extends WireSchemaId> =
  WireDocumentMap[SchemaId];
export type WireValidationLayer = "schema" | "domain";
export type WireDocumentDecodeErrorCode =
  | "document_too_large"
  | "malformed_json";

export const MAX_NODE_PROTOCOL_DOCUMENT_BYTES = 65_536;

const MAX_VALIDATION_ISSUES = 16;
const MAX_VALIDATION_PATH_BYTES = 512;
const MAX_VALIDATION_KEYWORD_BYTES = 64;
const MAX_VALIDATION_MESSAGE_BYTES = 256;
const MAX_ERROR_SUMMARY_BYTES = 2048;

export interface WireValidationIssue {
  readonly instancePath: string;
  readonly schemaPath: string;
  readonly keyword: string;
  readonly reason: string;
  readonly message: string;
}

type WireValidator = ((value: unknown) => boolean) & {
  errors?: readonly ErrorObject[] | null;
};

export class WireValidationError extends TypeError {
  readonly schemaId: string;
  readonly layer: WireValidationLayer;
  readonly issues: readonly WireValidationIssue[];

  constructor(
    schemaId: string,
    layer: WireValidationLayer,
    errors: readonly ErrorObject[] | null | undefined,
  ) {
    const issues = toIssues(errors);
    const summary = issues
      .slice(0, 3)
      .map((issue) => `${issue.instancePath || "/"} ${issue.message}`)
      .join("; ");
    super(
      boundUtf8(
        `${schemaId} failed ${layer} validation${summary ? `: ${summary}` : ""}`,
        MAX_ERROR_SUMMARY_BYTES,
      ),
    );
    this.name = "WireValidationError";
    this.schemaId = schemaId;
    this.layer = layer;
    this.issues = issues;
  }
}

export class WireDocumentDecodeError extends TypeError {
  readonly schemaId: WireSchemaId;
  readonly code: WireDocumentDecodeErrorCode;
  readonly maxBytes: number | undefined;
  readonly actualBytes: number;

  constructor(
    schemaId: WireSchemaId,
    code: WireDocumentDecodeErrorCode,
    actualBytes: number,
    maxBytes?: number,
  ) {
    super(
      code === "document_too_large"
        ? `${schemaId} document is ${actualBytes} bytes; maximum is ${maxBytes}`
        : `${schemaId} document is not valid UTF-8 JSON`,
    );
    this.name = "WireDocumentDecodeError";
    this.schemaId = schemaId;
    this.code = code;
    this.maxBytes = maxBytes;
    this.actualBytes = actualBytes;
  }
}

const wireSchemaIds = new Set<string>(Object.values(schemaIds));

export function isWireSchemaId(value: string): value is WireSchemaId {
  return wireSchemaIds.has(value);
}

/** Runs only the checked-in JSON Schema, without the domain parser overlay. */
export function validateJsonSchemaDocument<SchemaId extends WireSchemaId>(
  schemaId: SchemaId,
  value: unknown,
): value is WireDocumentFor<SchemaId> {
  const validator = getValidator(getSchemaValidators(), schemaId);
  return validator(value);
}

/** Runs JSON Schema and then the shared hand-written domain primitive parsers. */
export function validateWireDocument<SchemaId extends WireSchemaId>(
  schemaId: SchemaId,
  value: unknown,
): value is WireDocumentFor<SchemaId> {
  return (
    validateJsonSchemaDocument(schemaId, value) &&
    getValidator(getDomainValidators(), schemaId)(value)
  );
}

export function parseWireDocument<SchemaId extends WireSchemaId>(
  schemaId: SchemaId,
  value: unknown,
): WireDocumentFor<SchemaId> {
  const schemaValidator = getValidator(getSchemaValidators(), schemaId);
  if (!schemaValidator(value)) {
    throw new WireValidationError(schemaId, "schema", schemaValidator.errors);
  }

  const domainValidator = getValidator(getDomainValidators(), schemaId);
  if (!domainValidator(value)) {
    throw new WireValidationError(schemaId, "domain", domainValidator.errors);
  }

  return value as WireDocumentFor<SchemaId>;
}

/**
 * Enforces the encoded transport limit before UTF-8 and JSON decoding, then
 * performs the same schema and domain validation as `parseWireDocument`.
 */
export function parseWireDocumentText<SchemaId extends WireSchemaId>(
  schemaId: SchemaId,
  document: string | Uint8Array,
): WireDocumentFor<SchemaId> {
  const encoded =
    typeof document === "string" ? new TextEncoder().encode(document) : document;
  const actualBytes = encoded.byteLength;
  const maxBytes = maxDocumentBytes[schemaId];
  if (maxBytes !== undefined && actualBytes > maxBytes) {
    throw new WireDocumentDecodeError(
      schemaId,
      "document_too_large",
      actualBytes,
      maxBytes,
    );
  }

  let text: string;
  let value: unknown;
  try {
    text =
      typeof document === "string"
        ? document
        : new TextDecoder("utf-8", { fatal: true }).decode(document);
    value = JSON.parse(text) as unknown;
  } catch {
    throw new WireDocumentDecodeError(schemaId, "malformed_json", actualBytes);
  }
  return parseWireDocument(schemaId, value);
}

const maxDocumentBytes: Partial<Record<WireSchemaId, number>> = {
  [schemaIds.nodeV1]: MAX_NODE_PROTOCOL_DOCUMENT_BYTES,
};

// Ajv standalone output preserves the exact checked-in JSON Schema and domain
// format validation without compiling dynamic functions inside a Worker.
const schemaValidators = new Map<WireSchemaId, WireValidator>([
  [schemaIds.authV1, authV1SchemaValidator],
  [schemaIds.changeSetV1, changeSetV1SchemaValidator],
  [schemaIds.nodeV1, nodeV1SchemaValidator],
  [schemaIds.runtimeV1, runtimeV1SchemaValidator],
  [schemaIds.traceV1, traceV1SchemaValidator],
]);
const domainValidators = new Map<WireSchemaId, WireValidator>([
  [schemaIds.authV1, authV1DomainValidator],
  [schemaIds.changeSetV1, changeSetV1DomainValidator],
  [schemaIds.nodeV1, nodeV1DomainValidator],
  [schemaIds.runtimeV1, runtimeV1DomainValidator],
  [schemaIds.traceV1, traceV1DomainValidator],
]);

function getSchemaValidators(): ReadonlyMap<WireSchemaId, WireValidator> {
  return schemaValidators;
}

function getDomainValidators(): ReadonlyMap<WireSchemaId, WireValidator> {
  return domainValidators;
}

function getValidator(
  validators: ReadonlyMap<WireSchemaId, WireValidator>,
  schemaId: WireSchemaId,
): WireValidator {
  const validator = validators.get(schemaId);
  if (validator === undefined) {
    throw new TypeError(`unknown wire schema: ${schemaId}`);
  }
  return validator;
}

function toIssues(
  errors: readonly ErrorObject[] | null | undefined,
): WireValidationIssue[] {
  const orderedErrors = [...(errors ?? [])].sort(
    (left, right) => issuePriority(left) - issuePriority(right),
  );
  return orderedErrors.slice(0, MAX_VALIDATION_ISSUES).map((error) => ({
    instancePath: boundUtf8(error.instancePath, MAX_VALIDATION_PATH_BYTES),
    schemaPath: boundUtf8(error.schemaPath, MAX_VALIDATION_PATH_BYTES),
    keyword: boundUtf8(error.keyword, MAX_VALIDATION_KEYWORD_BYTES),
    reason: boundUtf8(issueReason(error), MAX_VALIDATION_KEYWORD_BYTES),
    message: boundUtf8(
      error.message ?? "schema constraint failed",
      MAX_VALIDATION_MESSAGE_BYTES,
    ),
  }));
}

function issuePriority(error: ErrorObject): number {
  if (error.keyword === "format") {
    return 0;
  }
  if (error.instancePath !== "") {
    return 1;
  }
  return 2;
}

function issueReason(error: ErrorObject): string {
  if (error.keyword === "format") {
    const format = (error.params as { format?: unknown }).format;
    if (typeof format === "string") {
      return format;
    }
  }
  return error.keyword;
}

function boundUtf8(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) {
    return value;
  }

  const suffix = "...";
  const contentLimit = maxBytes - Buffer.byteLength(suffix, "utf8");
  let bytes = 0;
  let bounded = "";
  for (const character of value) {
    const characterBytes = Buffer.byteLength(character, "utf8");
    if (bytes + characterBytes > contentLimit) {
      break;
    }
    bounded += character;
    bytes += characterBytes;
  }
  return `${bounded}${suffix}`;
}
