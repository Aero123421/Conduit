import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, expectTypeOf, it } from "vitest";

import {
  isWireSchemaId,
  MAX_NODE_PROTOCOL_DOCUMENT_BYTES,
  parseWireDocument,
  parseWireDocumentText,
  schemaIds,
  validateJsonSchemaDocument,
  validateWireDocument,
  WireValidationError,
  WireDocumentDecodeError,
  type NodeV1WireDocument,
  type WireSchemaId,
} from "../src/index.ts";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

const exampleSchemas = {
  auth: schemaIds.authV1,
  changeset: schemaIds.changeSetV1,
  "node-protocol": schemaIds.nodeV1,
  runtime: schemaIds.runtimeV1,
  trace: schemaIds.traceV1,
} as const;

describe("schema-derived wire documents", () => {
  for (const [directory, schemaId] of Object.entries(exampleSchemas)) {
    it(`validates every ${directory} example`, async () => {
      const exampleDirectory = `${repositoryRoot}/spec/examples/${directory}`;
      const fileNames = (await readdir(exampleDirectory))
        .filter((fileName) => fileName.endsWith(".json"))
        .sort();

      expect(fileNames.length).toBeGreaterThan(0);
      for (const fileName of fileNames) {
        const value = await readJson(`${exampleDirectory}/${fileName}`);
        expect(
          validateWireDocument(schemaId, value),
          `${directory}/${fileName}`,
        ).toBe(true);
        expect(parseWireDocument(schemaId, value)).toBe(value);
      }
    });
  }

  it("keeps generated schema copies synchronized with the specification", async () => {
    const generatedDirectory = `${repositoryRoot}/packages/conduit-schema/src/generated`;
    for (const fileName of [
      "auth-v1.schema.json",
      "changeset-v1.schema.json",
      "node-protocol-v1.schema.json",
      "runtime-v1.schema.json",
      "trace-v1.schema.json",
    ]) {
      const [source, generated] = await Promise.all([
        readJson(`${repositoryRoot}/spec/schemas/${fileName}`),
        readJson(`${generatedDirectory}/${fileName}`),
      ]);
      expect(generated, fileName).toEqual(source);
    }
  });

  it("keeps the Node approval risk vocabulary identical to Auth v1", async () => {
    const [auth, node] = await Promise.all([
      readJson(`${repositoryRoot}/spec/schemas/auth-v1.schema.json`),
      readJson(`${repositoryRoot}/spec/schemas/node-protocol-v1.schema.json`),
    ]) as Array<{ $defs: Record<string, { enum?: unknown[] }> }>;
    expect(node!.$defs.RiskClass?.enum).toEqual(auth!.$defs.RiskClass?.enum);
    expect(node!.$defs.RiskClass?.enum).toHaveLength(10);
  });

  it("preserves node frame type and payload discrimination", () => {
    type OfferFrame = Extract<
      NodeV1WireDocument,
      { type: "operation.offer" }
    >;
    type TerminalFrame = Extract<
      NodeV1WireDocument,
      { type: "operation.terminal" }
    >;
    type EventBatchFrame = Extract<
      NodeV1WireDocument,
      { type: "event.batch" }
    >;

    expectTypeOf<OfferFrame["payload"]>().toMatchTypeOf<{
      operation: { operationId: string };
    }>();
    expectTypeOf<TerminalFrame["payload"]>().toMatchTypeOf<{
      operationId: string;
      state: string;
    }>();
    expectTypeOf<EventBatchFrame["payload"]>().toMatchTypeOf<{
      events: readonly [{ eventId: string }, ...Array<{ eventId: string }>];
    }>();
    expectTypeOf<
      OfferFrame["payload"]["operation"]["arguments"]
    >().toEqualTypeOf<Record<string, unknown>>();
    expectTypeOf<
      NonNullable<TerminalFrame["payload"]["resultSummary"]>
    >().toEqualTypeOf<Record<string, unknown>>();
    expectTypeOf<
      EventBatchFrame["payload"]["events"][number]["payload"]
    >().toEqualTypeOf<Record<string, unknown>>();
    expectTypeOf<
      Extract<NodeV1WireDocument, { type: "unknown.frame" }>
    >().toEqualTypeOf<never>();
  });

  it("requires the bounded source range commitment on event batches", async () => {
    const fixture = await readJson(
      `${repositoryRoot}/spec/examples/node-protocol/event-batch.json`,
    ) as Record<string, any>;
    expect(validateWireDocument(schemaIds.nodeV1, fixture)).toBe(true);

    const missingCommitment = structuredClone(fixture);
    delete missingCommitment.payload.sourceRangeDigest;
    expect(validateWireDocument(schemaIds.nodeV1, missingCommitment)).toBe(false);

    const oversized = structuredClone(fixture);
    oversized.payload.events = Array.from(
      { length: 33 },
      () => structuredClone(fixture.payload.events[0]),
    );
    expect(validateWireDocument(schemaIds.nodeV1, oversized)).toBe(false);
  });

  it("decodes Node text only after enforcing its UTF-8 byte limit", async () => {
    const path = `${repositoryRoot}/spec/examples/node-protocol/operation-offer.json`;
    const text = await readFile(path, "utf8");
    const parsed = parseWireDocumentText(schemaIds.nodeV1, text);
    expect(parsed.type).toBe("operation.offer");
    const parsedBytes = parseWireDocumentText(
      schemaIds.nodeV1,
      new TextEncoder().encode(text),
    );
    expect(parsedBytes.type).toBe("operation.offer");

    const exactlyAtLimit = new Uint8Array(
      MAX_NODE_PROTOCOL_DOCUMENT_BYTES,
    ).fill(0x20);
    expectDocumentDecodeError(
      () => parseWireDocumentText(schemaIds.nodeV1, exactlyAtLimit),
      "malformed_json",
      MAX_NODE_PROTOCOL_DOCUMENT_BYTES,
    );

    const oversizedBytes = new Uint8Array(
      MAX_NODE_PROTOCOL_DOCUMENT_BYTES + 1,
    );
    expectDocumentDecodeError(
      () => parseWireDocumentText(schemaIds.nodeV1, oversizedBytes),
      "document_too_large",
      MAX_NODE_PROTOCOL_DOCUMENT_BYTES + 1,
    );

    const oversizedUnicode = `"${"界".repeat(21_846)}"`;
    expect(oversizedUnicode.length).toBeLessThan(
      MAX_NODE_PROTOCOL_DOCUMENT_BYTES,
    );
    expectDocumentDecodeError(
      () => parseWireDocumentText(schemaIds.nodeV1, oversizedUnicode),
      "document_too_large",
      new TextEncoder().encode(oversizedUnicode).byteLength,
    );
  });

  it("reports malformed UTF-8 JSON without copying document content", () => {
    const secretMarker = `PRIVATE_DOCUMENT_${"x".repeat(1_000)}`;
    try {
      parseWireDocumentText(
        schemaIds.nodeV1,
        `{"secret":"${secretMarker}"`,
      );
      throw new Error("malformed JSON unexpectedly parsed");
    } catch (error) {
      expect(error).toBeInstanceOf(WireDocumentDecodeError);
      const decodeError = error as WireDocumentDecodeError;
      expect(decodeError.code).toBe("malformed_json");
      expect(String(decodeError)).not.toContain(secretMarker);
    }

    expectDocumentDecodeError(
      () =>
        parseWireDocumentText(schemaIds.nodeV1, new Uint8Array([0xff])),
      "malformed_json",
      1,
    );
  });
});

interface InvalidFixture {
  fixtureVersion: 1;
  schemaId: string;
  validationLayer: "schema" | "domain";
  validatorKind: "json_schema" | "u64_decimal" | "utc_timestamp";
  instancePath: string;
  expectedInvalidReason: string;
  instance: unknown;
}

const validationReason = {
  duplicate_item: "uniqueItems",
  invalid_digest: "pattern",
  malformed_id: "pattern",
  unknown_schema_version: "const",
  u64_overflow: "conduit-u64-decimal",
  utc_offset_not_z: "conduit-utc-timestamp",
} as const;

describe("invalid wire fixtures", () => {
  it("rejects every fixture at its declared validation layer", async () => {
    const directory = `${repositoryRoot}/spec/fixtures/invalid`;
    const fileNames = (await readdir(directory))
      .filter((fileName) => fileName.endsWith(".json"))
      .sort();

    expect(fileNames).toHaveLength(6);
    for (const fileName of fileNames) {
      const fixture = (await readJson(
        `${directory}/${fileName}`,
      )) as InvalidFixture;
      expect(fixture.fixtureVersion, fileName).toBe(1);
      expect(fixture.expectedInvalidReason, fileName).not.toBe("");
      expect(isWireSchemaId(fixture.schemaId), fileName).toBe(true);
      if (!isWireSchemaId(fixture.schemaId)) {
        throw new TypeError(`unknown fixture schema: ${fixture.schemaId}`);
      }

      assertInvalidFixture(fixture.schemaId, fixture, fileName);
    }
  });

  it("bounds diagnostics without copying rejected values", () => {
    const secretMarker = `do-not-expose-${"x".repeat(10_000)}`;
    const instance = {
      schemaVersion: 1,
      kind: "owner_principal",
      id: "prin_owner_01",
      displayName: secretMarker,
      status: "active",
      createdAt: "2026-09-01T00:00:00Z",
    };

    try {
      parseWireDocument(schemaIds.authV1, instance);
      throw new Error("oversized displayName unexpectedly parsed");
    } catch (error) {
      expect(error).toBeInstanceOf(WireValidationError);
      const validationError = error as WireValidationError;
      expect(validationError.issues.length).toBeLessThanOrEqual(16);
      expect(String(validationError)).not.toContain(secretMarker);
      expect(JSON.stringify(validationError.issues)).not.toContain(secretMarker);
      for (const issue of validationError.issues) {
        expect(Buffer.byteLength(issue.instancePath, "utf8")).toBeLessThanOrEqual(
          512,
        );
        expect(Buffer.byteLength(issue.schemaPath, "utf8")).toBeLessThanOrEqual(
          512,
        );
        expect(Buffer.byteLength(issue.keyword, "utf8")).toBeLessThanOrEqual(
          64,
        );
        expect(Buffer.byteLength(issue.reason, "utf8")).toBeLessThanOrEqual(
          64,
        );
        expect(Buffer.byteLength(issue.message, "utf8")).toBeLessThanOrEqual(
          256,
        );
      }
    }
  });
});

function assertInvalidFixture(
  schemaId: WireSchemaId,
  fixture: InvalidFixture,
  fileName: string,
): void {
  const schemaValid = validateJsonSchemaDocument(schemaId, fixture.instance);
  expect(schemaValid, `${fileName} JSON Schema layer`).toBe(
    fixture.validationLayer === "domain",
  );
  expect(validateWireDocument(schemaId, fixture.instance), fileName).toBe(false);

  try {
    parseWireDocument(schemaId, fixture.instance);
    throw new Error(`${fileName} unexpectedly parsed`);
  } catch (error) {
    expect(error, fileName).toBeInstanceOf(WireValidationError);
    const validationError = error as WireValidationError;
    expect(validationError.layer, fileName).toBe(fixture.validationLayer);
    const expectedReason =
      validationReason[
        fixture.expectedInvalidReason as keyof typeof validationReason
      ];
    expect(expectedReason, `${fileName} expectedInvalidReason`).toBeDefined();
    expect(
      validationError.issues.some(
        (issue) =>
          issue.instancePath === fixture.instancePath &&
          issue.reason === expectedReason,
      ),
      `${fileName} errors: ${validationError.issues
        .map((issue) => `${issue.instancePath} (${issue.reason})`)
        .join(", ")}`,
    ).toBe(true);
  }
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function expectDocumentDecodeError(
  parse: () => unknown,
  code: "document_too_large" | "malformed_json",
  actualBytes: number,
): void {
  try {
    parse();
    throw new Error(`${code} document unexpectedly parsed`);
  } catch (error) {
    expect(error).toBeInstanceOf(WireDocumentDecodeError);
    const decodeError = error as WireDocumentDecodeError;
    expect(decodeError.code).toBe(code);
    expect(decodeError.actualBytes).toBe(actualBytes);
  }
}
