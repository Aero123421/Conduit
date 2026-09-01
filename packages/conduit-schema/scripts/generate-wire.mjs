import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  compile,
  compileFromFile,
} from "json-schema-to-typescript";

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
  "runtime-v1.schema.json",
  "trace-v1.schema.json",
];

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
