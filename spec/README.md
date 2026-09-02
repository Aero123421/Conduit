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
