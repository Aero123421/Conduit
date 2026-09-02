import { fullFormats } from "ajv-formats/dist/formats.js";

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
} from "./domain.js";

function accepts(parser: (value: unknown) => unknown, value: string): boolean {
  try {
    parser(value);
    return true;
  } catch {
    return false;
  }
}

const parserFormat = (parser: (value: unknown) => unknown) => ({
  type: "string" as const,
  validate: (value: string) => accepts(parser, value),
});

export const schemaFormats = fullFormats;

export const domainFormats = {
  ...fullFormats,
  "conduit-assignment-id": parserFormat(parseAssignmentId),
  "conduit-baseline-id": parserFormat(parseBaselineId),
  "conduit-change-set-id": parserFormat(parseChangeSetId),
  "conduit-collaboration-session-id": parserFormat(
    parseCollaborationSessionId,
  ),
  "conduit-device-id": parserFormat(parseDeviceId),
  "conduit-location-id": parserFormat(parseLocationId),
  "conduit-operation-id": parserFormat(parseOperationId),
  "conduit-project-id": parserFormat(parseProjectId),
  "conduit-run-id": parserFormat(parseAnyRunId),
  "conduit-runtime-id": parserFormat(parseRuntimeId),
  "conduit-sha256": parserFormat(parseSha256Digest),
  "conduit-source-id": parserFormat(parseSourceId),
  "conduit-u64-decimal": parserFormat(parseU64Decimal),
  "conduit-utc-timestamp": parserFormat(parseUtcTimestamp),
};
