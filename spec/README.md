# Specifications

Machine-checkable protocol and record schemas live under `spec/schemas/`.

Rules:

- a schema version is immutable after release
- incompatible changes create a new schema file and migration notes
- IDs, revisions, byte limits, and terminal states are part of the contract
- examples under `spec/examples/` must validate against the referenced schema
- secret values do not appear in examples or fixtures
- provider-private reasoning is not a protocol field

Run the validator with:

```bash
python -m pip install -r requirements-spec.txt
python scripts/validate_spec.py
```

## Wire schemas and domain types

The JSON Schemas define versioned wire records. They check the JSON shape, required fields, bounded collections, string patterns, and JSON Schema formats accepted at a protocol boundary. Rust schema-marker documents and schema-generated TypeScript representations retain that accepted JSON shape; they are transport types, not trusted domain values. Schema validation does not replace construction of the hand-written values in `conduit-domain` and `@conduit/schema`.

Code that admits an external record performs both steps in order:

1. validate the complete record against the schema identified by its version;
2. parse contract-sensitive fields into the corresponding domain types before using or persisting them.

The distinction is observable for these v1 wire types:

- an ID is a JSON string whose schema pattern checks its namespace and wire shape; the matching domain constructor prevents unvalidated strings from entering typed code;
- `U64Decimal` is a canonical decimal JSON string so JavaScript does not lose integer precision. Its schema pattern bounds the wire shape to at most 20 digits, while the domain parser also rejects values above `18446744073709551615`;
- `Timestamp` uses JSON Schema `date-time` for interoperable wire validation. The domain `UtcTimestamp` additionally requires the normalized UTC form ending in uppercase `Z`;
- `Sha256Hex` is exactly 64 lowercase hexadecimal characters on the wire and becomes a digest domain value after parsing.

This boundary is intentional. Tightening a released schema remains a schema change; stronger semantic parsing in a domain type does not silently change the accepted JSON Schema document.

## Shared fixtures

`fixtures/canonical-json-v1.json` is the Rust/TypeScript parity suite for RFC 8785 canonical JSON and lowercase SHA-256 output. Each case contains the input JSON value, exact canonical UTF-8 text, and digest. The cases cover recursive key ordering, arrays and nested values, Unicode key ordering and escaping, and ECMAScript-compatible number serialization.

Files under `fixtures/invalid/` identify their `schemaId`, validation layer, validator kind, RFC 6901 instance path, and expected reason. A `schema` fixture must be rejected at the stated path by JSON Schema. A `domain` fixture must first pass the wire schema and then be rejected by the named hand-written-value validator. This prevents a semantic boundary test from being misreported as a schema constraint.

## Authentication v1

`schemas/auth-v1.schema.json` contains:

- owner and Passkey metadata
- browser-session metadata
- OAuth client registrations and grants
- Connector ceilings
- exact application rate-limit profiles
- Device enrollment and public-key records
- bounded security Events

The prose contract is `docs/AUTHORIZATION.md`.

## Node protocol v1

`schemas/node-protocol-v1.schema.json` contains:

- Device hello, challenge, proof, and accepted connection records
- persistent connection epochs and directional sequence numbers
- operation offer, admission, state, input, approval, cancellation, and terminal receipts
- Trace-v1 Event batches and explicit retention gaps
- reconciliation summary, plan, and completion records
- bounded Device health and protocol errors

Examples are under `examples/node-protocol/`.

The prose contract is `docs/NODE_PROTOCOL.md`.

## Trace v1

`schemas/trace-v1.schema.json` contains:

- immutable Run Manifests
- per-input Context Snapshots
- normalized Device Events with evidence, sensitivity, retention, and chain commitments
- Content Objects and raw Segment descriptors
- opaque trace cursors
- instruction and Skill catalogs needed for later evaluation

Examples are under `examples/trace/`.

The prose contract is `docs/TRACE_FORMAT.md`.

## Runtime v1

`schemas/runtime-v1.schema.json` contains:

- Native, Restricted Native, Container, and VM Runtime requests
- effective Capability Receipts
- Run Workspace and Credential Projection records
- prepared and live Runtime receipts
- CPU, memory, PID, storage, GPU, and network observations
- Snapshot, collection, destroy, and reconciliation receipts

Examples are under `examples/runtime/`.

The prose contract is `docs/RUNTIME_PROVIDER.md`.
