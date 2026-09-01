# Codex adapter fixtures

`fixtures.json` is one `codex_fixture_bundle` validated by:

- `spec/schemas/codex-adapter-v1.schema.json`
- `spec/schemas/codex-adapter-common-v1.schema.json`
- `spec/schemas/codex-adapter-session-v1.schema.json`
- `spec/schemas/codex-adapter-event-v1.schema.json`
- `spec/schemas/codex-adapter-conformance-v1.schema.json`

It contains representative records for:

- adapter discovery/status
- new and resumed session open
- turn request and correlated turn admission
- retained active-turn state
- steer and cancel control requests
- normalized assistant and completion events
- exact-action approval bridging
- protocol conformance receipt
- deterministic conformance plan

Fixtures contain no provider credential, local absolute path, user content, or
private reasoning.

## Validation

The Rust and TypeScript implementations must validate the same fixture bundle,
round-trip every record without semantic drift, and compute matching canonical
JSON digests.

The conformance cases are executable test requirements rather than support
claims. A case may be marked passed only when the exact executable and adapter
revision produce the expected observation.
