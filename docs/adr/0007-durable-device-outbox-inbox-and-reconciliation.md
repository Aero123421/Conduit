# ADR 0007: Durable device outbox, inbox, and reconciliation

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit devices connect outbound through Cloudflare and may run commands or agents for hours. The control plane, Durable Object, network, node process, runtime provider, and agent process can fail independently.

A WebSocket delivery acknowledgement cannot prove that a process started or completed. Cloudflare Queues are at-least-once and can deliver duplicates. Durable Objects may hibernate and discard memory while retaining accepted WebSockets. Native child processes may outlive `conduit-node`.

The protocol must not start one effect twice or turn missing evidence into success.

## Decision

### Per-device serialization

Each enrolled device has one SQLite-backed `DeviceRoom` Durable Object. It owns:

- current connection epoch
- durable control and node sequence positions
- control-to-node outbox
- node-to-control inbox
- reconciliation state
- bounded receipt cache

Important state is stored before an acknowledgement is sent. Durable Object memory is a cache.

### Durable sequences

Control-to-node and node-to-control directions each use a persistent unsigned 64-bit sequence, serialized as a decimal string. Sequences continue across reconnects.

A duplicate sequence is valid only when message ID and payload digest match. Gaps stop application until replay resolves them.

### Separate delivery and admission

`transport.ack` proves durable transport custody. It does not prove operation admission.

A node journals an immutable operation and local policy decision before returning `operation.admission`. A run does not enter Working until the runtime or agent reports a real start.

### Local exact-once boundary

Every effectful operation has an operation ID, idempotency key, and request digest.

- same key and digest: replay the durable receipt
- same key and different digest: reject
- uncertain key: return uncertainty; never rerun automatically

Runtime providers expose an idempotent start boundary. Native processes are owned by a persistent local supervisor rather than an untracked shell spawn.

### Inbound custody before asynchronous ingestion

`DeviceRoom` stores a node frame in its durable inbox before acknowledging it. D1 and Queues projection happens after durable custody. Queue retries are deduplicated using Conduit event and receipt identity.

### Durable control-plane dispatch handoff

The operation journal, idempotency record, and a D1 dispatch-outbox row are committed together before the control plane invokes `DeviceRoom`. The dispatch row owns a stable message ID, operation correlation ID, payload digest, exact payload, target Device, and expiry.

Dispatch uses a bounded lease. Same-key/same-digest retries and a scheduled reconciler reclaim pending or expired-lease rows and submit the identical offer. `DeviceRoom` persists the offer before returning and treats the same message ID, correlation ID, and digest as an idempotent replay that returns the original transport sequence. A conflicting replay is rejected.

If the Worker fails after Durable Object custody but before the D1 offered transition, retry closes the ambiguous handoff without allocating another operation, message, or transport sequence. The offered or expired outbox transition and its operation-journal and idempotency projections commit in one D1 batch. The reconciler repairs terminal rows left with queued projections by an older deployment.

Connector concurrency is a `ConnectorLimiter` Durable Object lease keyed by operation ID. Acquire and release are idempotent for that operation; release cannot decrement another operation's slot. The lease expires at the operation expiry so a failure after acquire but before the D1 creation batch cannot hold capacity indefinitely. D1 records a release-projection marker after terminal expiry or receipt handling. If the Worker fails between the Durable Object release and that marker, reconciliation repeats the same operation-bound release safely. The per-Device Durable Object uses one alarm for due WebSocket-send retry; its alarm handler is idempotent and derives all work from SQLite-backed storage after hibernation.

### Reconciliation before new work

After authentication, a node sends a bounded reconciliation summary. The control plane responds with exact sequence and event ranges to replay, status requests, pending cancellations, and terminal-receipt confirmations.

New remote operation offers wait until initial reconciliation completes.

The public Worker forwards the WebSocket upgrade response without rebuilding away its `webSocket` endpoint. A reconnect summary whose control position is behind declares a control replay range. Node-origin `transport.replay_required` is accepted only for unacknowledged rows present in the Durable Object outbox. `DeviceRoom` validates one bounded contiguous chunk plus the high-sequence sentinel and commits a durable replay intent with request custody. Foreground, duplicate-request, and alarm paths resend the original sequence, message ID, correlation ID, payload, and digest on the current authenticated epoch. Repeated sentinel gaps advance ranges larger than one chunk. ACK compaction updates durable receipt tombstones, deletes covered replay intents, and removes live frames in one SQLite transaction. A received-but-unapplied replayed `operation.offer` is re-entered through the idempotent operation journal; this decision does not authorize automatic repetition of ambiguous `operation.input` or `operation.cancel` effects.

The authenticated Node retains `controlNextSequence - 1` as the preexisting frontier. Until reconciliation completes, strict contiguous replay may apply effectful frames only through that frontier. New effectful frames fail closed. Received-but-unapplied `operation.offer` duplicates are reprojected through the idempotent operation journal after restart; applied duplicates are only acknowledged.

While an authenticated socket is reconciling, new operation offers, input, cancellation, and approval effects remain in their producer outbox without a control transport sequence. Sequence allocation resumes after reconciliation completes. Offline delivery may allocate before the next handshake because that sequence is then included in the next authenticated frontier. The state check and new sequence allocation occur without an intervening asynchronous boundary inside the Durable Object turn.

### No automatic rerun from ambiguity

Recovery distinguishes:

- running: exact runtime identity and digest proven
- terminal: durable terminal receipt exists
- lost: runtime proven absent, no terminal receipt
- uncertain: effect state cannot be determined
- recovery required: observed runtime conflicts with durable authority state

Lost, uncertain, and recovery-required runs are not automatically replaced.

### Offline execution

An admitted run may continue while disconnected. New owner approval cannot be invented. New remote work cannot start. Normalized events and terminal receipts remain in the device outbox until acknowledged.

### Bounded storage

Receipts, security events, operation journals, and source/runtime commitments have priority over progress deltas and raw logs. If durable high-priority storage cannot be written, the node refuses new effectful work.

## Rejected alternatives

### Treat WebSocket delivery as operation success

Rejected because the node may fail policy or resource admission, or disconnect before starting the runtime.

### Dispatch device operations through Cloudflare Queues alone

Rejected because queue consumers do not represent one durable device connection and delivery is at least once. Queues remain suitable for downstream event indexing after Conduit identity has been persisted.

### Reset transport sequence on every reconnect

Rejected because replay and duplicate detection would depend on transient socket identity. Connection epoch fences sockets; durable sequence tracks messages.

### Keep unacknowledged frames only in Durable Object memory

Rejected because hibernation and eviction discard memory.

### Let the node resend an assignment as a new operation after restart

Rejected because a process, filesystem effect, or external call may already have happened. Recovery uses the original operation identity.

### Kill every runtime whose control-plane state differs

Rejected because stale shared state is not proof that a local runtime is unauthorized or safe to destroy. Conflicts enter recovery-required state.

## Consequences

- `DeviceRoom` needs a bounded SQLite schema and compaction rules.
- The control plane needs a D1 dispatch outbox and scheduled lease reconciler between operation commitment and `DeviceRoom` custody.
- The node needs a local transactional journal and persistent run supervisor.
- Control-plane read models are eventually updated from a durable per-device inbox.
- UI states distinguish queued, delivered, admitted, started, and terminal.
- Event replay can report an explicit gap when local retention has expired.
- Runtime-provider design must expose deterministic runtime identity and reconciliation.
- Transport tests require fake devices, fake Durable Object storage, and injected crash windows.
- Dispatch tests inject response loss after Durable Object persistence, evict the object, run a fresh reconciler, and prove the stable message ID occupies one outbound sequence.
- Projection tests reconstruct pre-invariant offered and expired crash images and prove reconciliation converges the outbox, journal, idempotency record, and concurrency-release marker.
- Limiter tests prove duplicate operation-bound release cannot decrement another operation's slot and an orphaned acquire stops counting at operation expiry.

## Contract

- `docs/NODE_PROTOCOL.md`
- `spec/schemas/node-protocol-v1.schema.json`
- `spec/examples/node-protocol/`
