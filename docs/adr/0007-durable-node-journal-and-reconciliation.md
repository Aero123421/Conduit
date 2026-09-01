# ADR 0007: Durable node records and reconciliation before dispatch

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit sends commands and agent work from a Cloudflare control plane to ordinary personal computers and servers. A device can lose Internet access, restart, or keep a process alive after the control plane has lost its request context.

A WebSocket connection proves current connectivity. It does not prove whether an earlier side effect started, completed, or remained alive.

Cloudflare Durable Objects may hibernate and discard memory while their accepted WebSockets remain connected. The node therefore cannot depend on one in-memory correlation map in the Durable Object.

A retry after an ambiguous launch can create a second agent, command, container, or VM against the same files. Selecting a convenient state without evidence would hide data loss or duplicate effects.

## Decision

### Separate connection sequence and durable record sequence

Every connection epoch has an independent per-direction frame sequence.

Each device also has a durable record sequence that survives reconnects and restarts. Admission receipts, transitions, terminal receipts, runtime observations, approval requests, and normalized events use this record sequence.

### Persist admission before side effects

The node reserves the operation ID and idempotency key, stores the signed offer commitment, allocates an execution ID, and appends a signed admission receipt in one SQLite transaction before asking a runtime provider to start work.

The same operation and digest reuses the first execution. The same operation ID or idempotency key with another digest is rejected.

### Stable runtime execution identity

A runtime provider receives a stable execution ID. Starting the same execution ID is idempotent or returns an explicit unknown result. An unknown launch outcome is never retried as a fresh execution.

### Acknowledge only durable ingress

The per-device Durable Object acknowledges a node record only after committing its sequence and body hash to SQLite-backed Durable Object storage.

D1 materialization may lag. It retries from the Durable Object ingress journal.

### Reconcile before new dispatch

After every accepted connection, the node sends a signed bounded summary. The control plane requests missing record ranges and operation snapshots. New effectful work is held until reconciliation completes.

Reconciliation does not directly start or kill a runtime. Effectful changes use signed operation offers and the normal admission journal.

### Expected state and observed state remain separate

The control plane records intended state. The node reports runtime observations and signed terminal receipts.

A control-plane timeout after admission is not an execution result. A valid late terminal receipt may finalize the operation.

A mismatch that cannot be proven safe becomes `uncertain` or `recovery_required`.

### Retention

Unacknowledged records and non-terminal or uncertain operation entries are not automatically evicted.

Terminal receipts have a bounded node replay window. The control-plane idempotency tombstone outlives that window plus reconnect grace.

If safe compaction cannot free enough local journal space, the node refuses new effectful admissions.

## Rejected alternatives

### Keep correlation state only in the live Durable Object

Rejected because hibernation and code updates discard memory. A WebSocket attachment is suitable for bounded connection metadata, not the complete operation ledger.

### Retry an operation whenever the control plane did not receive an acknowledgement

Rejected because the process may already be running or finished locally.

### Treat HTTP or MCP timeout as operation failure

Rejected after admission. Client wait time and execution outcome are different facts.

### Use one sequence for both WebSocket frames and retained events

Rejected because connection sequences reset at a new epoch while retained node records must replay across connections.

### Let reconciliation issue unjournaled start and kill directives

Rejected because those actions would bypass operation authorization, idempotency, and approval binding.

### Drop old unacknowledged events under storage pressure

Rejected for authority-bearing records. The node blocks new effectful admissions before discarding an unacknowledged admission or terminal receipt.

## Consequences

- The node needs a local SQLite journal before the first Native execution path.
- Runtime providers need an execution-ID lookup and reconciliation contract.
- DeviceRoom needs a small durable ingress table and background D1 materializer.
- The UI can display control-plane intent and device observation separately.
- Reconnect may take longer before the device becomes dispatch-ready.
- Local storage pressure can intentionally stop new remote work.
- Terminal receipts and idempotency tombstones need coordinated retention settings.
- Tests must inject crashes at admission, launch, runtime-binding, and terminal-commit boundaries.

## Contract

- `docs/NODE_TRANSPORT.md`
- `spec/schemas/node-transport-v1.schema.json`
- `spec/examples/node-transport/`
