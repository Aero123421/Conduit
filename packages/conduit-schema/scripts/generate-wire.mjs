import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  compile,
  compileFromFile,
} from "json-schema-to-typescript";
import { Ajv2020 } from "ajv/dist/2020.js";
import { _ } from "ajv/dist/compile/codegen/index.js";
import standaloneCode from "ajv/dist/standalone/index.js";
import addFormatsModule from "ajv-formats";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const schemaSourceDirectory = `${repositoryRoot}/spec/schemas`;
const generatedDirectory =
  process.argv[2] === undefined
    ? `${packageRoot}/src/generated`
    : resolve(process.argv[2]);

const schemaFiles = [
  "auth-v1.schema.json",
  "changeset-v1.schema.json",
  "node-protocol-v1.schema.json",
  "privileged-helper-v1.schema.json",
  "runtime-v1.schema.json",
  "trace-v1.schema.json",
];

const schemaExports = {
  authV1: "auth-v1.schema.json",
  changeSetV1: "changeset-v1.schema.json",
  nodeV1: "node-protocol-v1.schema.json",
  privilegedV1: "privileged-helper-v1.schema.json",
  runtimeV1: "runtime-v1.schema.json",
  traceV1: "trace-v1.schema.json",
};

const domainFormatByDefinition = {
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

const compilerOptions = {
  // Explicit schema constraints remain authoritative. Open JSON objects must
  // retain their string index signature instead of collapsing to TypeScript `{}`.
  additionalProperties: true,
  cwd: generatedDirectory,
};

await mkdir(generatedDirectory, { recursive: true });

for (const schemaFile of schemaFiles) {
  const source = `${schemaSourceDirectory}/${schemaFile}`;
  const destination = `${generatedDirectory}/${schemaFile}`;
  await copyFile(source, destination);
}

for (const schemaFile of schemaFiles) {
  const destination = `${generatedDirectory}/${schemaFile}`;
  const generatedTypeFile = schemaFile.replace(
    ".schema.json",
    ".generated.ts",
  );
  const generatedTypes = await compileFromFile(destination, compilerOptions);
  await writeFile(
    `${generatedDirectory}/${generatedTypeFile}`,
    generatedTypes,
    "utf8",
  );
}

const nodeSchemaPath = `${generatedDirectory}/node-protocol-v1.schema.json`;
const nodeSchema = JSON.parse(await readFile(nodeSchemaPath, "utf8"));
const payloadCatalogSchema = buildNodePayloadCatalogSchema(nodeSchema);
const payloadCatalogTypes = await compile(
  payloadCatalogSchema,
  "NodeProtocolPayloadCatalogV1",
  compilerOptions,
);
await writeFile(
  `${generatedDirectory}/node-protocol-v1.payloads.generated.ts`,
  payloadCatalogTypes,
  "utf8",
);

await generateStandaloneValidators(false);
await generateStandaloneValidators(true);

function buildNodePayloadCatalogSchema(schema) {
  const postAuthFrame = schema.$defs?.PostAuthFrame;
  const frameTypes = postAuthFrame?.properties?.type?.enum;
  const rules = postAuthFrame?.allOf;
  if (!Array.isArray(frameTypes) || !Array.isArray(rules)) {
    throw new TypeError("node PostAuthFrame must define type enum and allOf rules");
  }

  const properties = {};
  for (const rule of rules) {
    const condition = rule.if?.properties?.type;
    const payloadReference = rule.then?.properties?.payload?.$ref;
    const messageTypes =
      typeof condition?.const === "string" ? [condition.const] : condition?.enum;
    if (
      !Array.isArray(messageTypes) ||
      messageTypes.length === 0 ||
      typeof payloadReference !== "string" ||
      !payloadReference.startsWith("#/$defs/")
    ) {
      throw new TypeError("node PostAuthFrame rule has an unsupported shape");
    }

    for (const messageType of messageTypes) {
      if (typeof messageType !== "string" || properties[messageType] !== undefined) {
        throw new TypeError(`invalid or duplicate node frame type: ${messageType}`);
      }
      properties[messageType] = { $ref: payloadReference };
    }
  }

  const mappedTypes = Object.keys(properties);
  if (
    frameTypes.length !== mappedTypes.length ||
    frameTypes.some((frameType) => !Object.hasOwn(properties, frameType))
  ) {
    throw new TypeError("every node PostAuthFrame type must map to one payload schema");
  }

  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "Node Protocol Payload Catalog V1",
    type: "object",
    additionalProperties: false,
    required: frameTypes,
    properties,
    $defs: schema.$defs,
  };
}

async function generateStandaloneValidators(withDomainFormats) {
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: true,
    strict: true,
    strictRequired: false,
    code: { esm: true, source: true, formats: _`wireFormats` },
  });
  addFormatsModule(ajv);
  if (withDomainFormats) {
    for (const format of Object.values(domainFormatByDefinition)) {
      ajv.addFormat(format, { type: "string", validate: () => true });
    }
  }

  const exports = {};
  for (const [exportName, schemaFile] of Object.entries(schemaExports)) {
    const schema = JSON.parse(
      await readFile(`${generatedDirectory}/${schemaFile}`, "utf8"),
    );
    if (withDomainFormats) applyDomainFormats(schema);
    ajv.addSchema(schema, schema.$id);
    exports[exportName] = schema.$id;
  }

  const moduleCode = standaloneCode(ajv, exports)
    .replaceAll(
      'require("ajv/dist/runtime/ucs2length").default',
      "ajvUcs2Length",
    )
    .replaceAll(
      'require("ajv/dist/runtime/equal").default',
      "ajvDeepEqual",
    );
  if (moduleCode.includes("require(")) {
    throw new TypeError(
      "standalone wire validators contain an unsupported CommonJS runtime helper",
    );
  }
  const formatsExport = withDomainFormats ? "domainFormats" : "schemaFormats";
  const output = `// Generated by scripts/generate-wire.mjs. Do not edit.\n// @ts-nocheck\nimport ajvDeepEqualModule from "ajv/dist/runtime/equal.js";\nimport ajvUcs2LengthModule from "ajv/dist/runtime/ucs2length.js";\nimport { ${formatsExport} as wireFormats } from "../standalone-formats.js";\nconst ajvDeepEqual = typeof ajvDeepEqualModule === "function" ? ajvDeepEqualModule : ajvDeepEqualModule.default;\nconst ajvUcs2Length = typeof ajvUcs2LengthModule === "function" ? ajvUcs2LengthModule : ajvUcs2LengthModule.default;\n${moduleCode}\n`;
  const suffix = withDomainFormats ? "domain" : "schema";
  await writeFile(
    `${generatedDirectory}/wire-${suffix}-validators.generated.ts`,
    output,
    "utf8",
  );
}

function applyDomainFormats(schema) {
  for (const [definitionName, format] of Object.entries(
    domainFormatByDefinition,
  )) {
    const definition = schema.$defs?.[definitionName];
    if (definition !== undefined) definition.format = format;
  }
}
