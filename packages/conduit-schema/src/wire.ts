import {
  Ajv2020,
  type ErrorObject,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";

import authV1Schema from "./generated/auth-v1.schema.json" with {
  type: "json",
};
import changeSetV1Schema from "./generated/changeset-v1.schema.json" with {
  type: "json",
};
import nodeV1Schema from "./generated/node-protocol-v1.schema.json" with {
  type: "json",
};
import runtimeV1Schema from "./generated/runtime-v1.schema.json" with {
  type: "json",
};
import traceV1Schema from "./generated/trace-v1.schema.json" with {
  type: "json",
};
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
  parseAssignmentId,
  parseAnyRunId,
  parseBaselineId,
  parseChangeSetId,
  parseCollaborationSessionId,
  parseDeviceId,
  parseLocationId,
  parseOperationId,
  parseProjectId,
  parseRuntimeId,
  parseSha256Digest,
  parseSourceId,
  parseU64Decimal,
  parseUtcTimestamp,
  schemaIds,
} from "./domain.js";

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

type JsonSchemaObject = {
  $defs?: Record<string, JsonSchemaObject>;
  format?: string;
};

const schemas = {
  [schemaIds.authV1]: authV1Schema,
  [schemaIds.nodeV1]: nodeV1Schema,
  [schemaIds.traceV1]: traceV1Schema,
  [schemaIds.runtimeV1]: runtimeV1Schema,
  [schemaIds.changeSetV1]: changeSetV1Schema,
} satisfies Record<WireSchemaId, unknown>;

export function isWireSchemaId(value: string): value is WireSchemaId {
  return Object.hasOwn(schemas, value);
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

function compileValidators(
  withDomainFormats: boolean,
): ReadonlyMap<WireSchemaId, ValidateFunction> {
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: true,
    strict: true,
    strictRequired: false,
  });
  const addFormats = addFormatsModule as unknown as (
    instance: Ajv2020,
  ) => Ajv2020;
  addFormats(ajv);

  if (withDomainFormats) {
    for (const [format, parser] of Object.entries(domainFormats)) {
      ajv.addFormat(format, {
        type: "string",
        validate: (value: string) => accepts(parser, value),
      });
    }
  }

  const preparedSchemas = new Map<WireSchemaId, JsonSchemaObject>();
  for (const schemaId of Object.keys(schemas) as WireSchemaId[]) {
    const schema = structuredClone(schemas[schemaId]) as JsonSchemaObject;
    if (withDomainFormats) {
      applyDomainFormats(schema);
    }
    preparedSchemas.set(schemaId, schema);
    ajv.addSchema(schema, schemaId);
  }

  const validators = new Map<WireSchemaId, ValidateFunction>();
  for (const schemaId of preparedSchemas.keys()) {
    const validator = ajv.getSchema(schemaId);
    if (validator === undefined) {
      throw new TypeError(`failed to compile wire schema: ${schemaId}`);
    }
    validators.set(schemaId, validator);
  }
  return validators;
}

const domainFormats: Readonly<
  Record<string, (value: unknown) => unknown>
> = {
  "conduit-assignment-id": parseAssignmentId,
  "conduit-baseline-id": parseBaselineId,
  "conduit-change-set-id": parseChangeSetId,
  "conduit-collaboration-session-id": parseCollaborationSessionId,
  "conduit-device-id": parseDeviceId,
  "conduit-location-id": parseLocationId,
  "conduit-operation-id": parseOperationId,
  "conduit-project-id": parseProjectId,
  "conduit-run-id": parseAnyRunId,
  "conduit-runtime-id": parseRuntimeId,
  "conduit-sha256": parseSha256Digest,
  "conduit-source-id": parseSourceId,
  "conduit-u64-decimal": parseU64Decimal,
  "conduit-utc-timestamp": parseUtcTimestamp,
};

const formatByDefinition: Readonly<Record<string, string>> = {
  AssignmentId: "conduit-assignment-id",
  BaselineId: "conduit-baseline-id",
  ChangeSetId: "conduit-change-set-id",
  DeviceId: "conduit-device-id",
  LocationId: "conduit-location-id",
  OperationId: "conduit-operation-id",
  ProjectId: "conduit-project-id",
  RunId: "conduit-run-id",
  RuntimeId: "conduit-runtime-id",
  SessionId: "conduit-collaboration-session-id",
  Sha256Hex: "conduit-sha256",
  SourceId: "conduit-source-id",
  Timestamp: "conduit-utc-timestamp",
  U64Decimal: "conduit-u64-decimal",
};

let schemaValidators: ReadonlyMap<WireSchemaId, ValidateFunction> | undefined;
let domainValidators: ReadonlyMap<WireSchemaId, ValidateFunction> | undefined;

function getSchemaValidators(): ReadonlyMap<WireSchemaId, ValidateFunction> {
  return (schemaValidators ??= compileValidators(false));
}

function getDomainValidators(): ReadonlyMap<WireSchemaId, ValidateFunction> {
  return (domainValidators ??= compileValidators(true));
}

function applyDomainFormats(schema: JsonSchemaObject): void {
  for (const [definitionName, format] of Object.entries(formatByDefinition)) {
    const definition = schema.$defs?.[definitionName];
    if (definition !== undefined) {
      definition.format = format;
    }
  }
}

function accepts(
  parser: (value: unknown) => unknown,
  value: string,
): boolean {
  try {
    parser(value);
    return true;
  } catch {
    return false;
  }
}

function getValidator(
  validators: ReadonlyMap<WireSchemaId, ValidateFunction>,
  schemaId: WireSchemaId,
): ValidateFunction {
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
