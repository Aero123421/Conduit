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

### Reconciliation before new work

After authentication, a node sends a bounded reconciliation summary. The control plane responds with exact sequence and event ranges to replay, status requests, pending cancellations, and terminal-receipt confirmations.

New remote operation offers wait until initial reconciliation completes.

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
- The node needs a local transactional journal and persistent run supervisor.
- Control-plane read models are eventually updated from a durable per-device inbox.
- UI states distinguish queued, delivered, admitted, started, and terminal.
- Event replay can report an explicit gap when local retention has expired.
- Runtime-provider design must expose deterministic runtime identity and reconciliation.
- Transport tests require fake devices, fake Durable Object storage, and injected crash windows.

## Contract

- `docs/NODE_PROTOCOL.md`
- `spec/schemas/node-protocol-v1.schema.json`
- `spec/examples/node-protocol/`
