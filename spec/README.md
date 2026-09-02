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

- owner and passkey metadata
- browser-session metadata
- OAuth client registrations and grants
- connector ceilings
- exact application rate-limit profiles
- device enrollment and public-key records
- bounded security events

The prose contract is `docs/AUTHORIZATION.md`.

## Node protocol v1

`schemas/node-protocol-v1.schema.json` contains:

- device hello, challenge, proof, and accepted connection records
- persistent connection epochs and directional sequence numbers
- operation offer, admission, state, input, approval, cancellation, and terminal receipts
- trace-v1 event batches and explicit retention gaps
- reconciliation summary, plan, and completion records
- bounded device health and protocol errors

Examples are under `examples/node-protocol/`.

The prose contract is `docs/NODE_PROTOCOL.md`.

## Trace v1

`schemas/trace-v1.schema.json` contains:

- immutable Run Manifests
- per-input Context Snapshots
- normalized device Events with evidence, sensitivity, retention, and chain commitments
- Content Objects and raw Segment descriptors
- opaque trace cursors
- instruction and Skill catalogs needed for later evaluation

Examples are under `examples/trace/`.

The prose contract is `docs/TRACE_FORMAT.md`.
