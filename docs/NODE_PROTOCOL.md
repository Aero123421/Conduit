# Node transport and reconciliation

## Scope

This contract covers the connection between the Cloudflare control plane and one enrolled `conduit-node` device.

It defines:

- authenticated outbound WebSocket connection
- version negotiation and connection fencing
- durable control-to-node and node-to-control delivery
- operation admission and idempotency
- normalized event replay
- disconnect behavior
- node restart reconciliation
- cancellation, input, and approval delivery
- bounded storage and backpressure

Device enrollment and key ownership are defined in `docs/AUTHORIZATION.md`.

## Cloudflare components

A device is routed to one SQLite-backed Durable Object named by the server-side device ID.

```text
HTTP API / scheduler
        │
        ▼
D1 intended state
        │
        ▼
DeviceRoom Durable Object
        │ hibernatable server WebSocket
        ▼
conduit-node
```

`DeviceRoom` is the per-device serialization point for connection epochs, transport sequences, durable outbox, durable inbox, and reconciliation.

D1 remains authoritative for shared assignment and run intent. Durable Object storage remains authoritative for messages that have been accepted for device delivery or accepted from a device but not yet projected into D1.

Cloudflare Queues may carry event-ingestion work after the Durable Object has persisted the inbound frame. Queue delivery is treated as at least once. Queue message identity is never used as the Conduit event identity.

Durable Object memory is a cache. Connection epochs, sequence positions, outbox rows, inbox rows, and pending reconciliation state are stored before the corresponding acknowledgement is sent.

## Transport

The node opens a WSS connection to the configured control-plane origin. No inbound device port is required.

The first release uses UTF-8 JSON text frames.

Limits:

- one JSON object per frame
- maximum encoded frame size: 65,536 bytes
- maximum string field: 32,768 UTF-8 bytes unless a smaller field limit is defined
- maximum event batch: 128 events and 60,000 encoded bytes
- binary files, raw logs, large command output, and artifacts use content references or separate bounded upload paths

A frame above the limit is rejected before JSON decoding where the runtime permits it. Oversized or malformed frames never become public adapter text.

The shared implementations enforce this boundary in Rust with `ValidatedDocument::<NodeProtocolV1>::from_slice` and in TypeScript with `parseWireDocumentText(schemaIds.nodeV1, textOrBytes)`. `parseWireDocument` operates on an already-decoded value and does not enforce encoded size.

## Protocol version

The initial version is:

```text
conduit.node/1
```

The node sends its supported versions in the authenticated hello. The control plane selects one exact version. There is no silent downgrade to an undocumented framing or command path.

An incompatible peer receives `protocol_version_unsupported` and the connection closes.

## IDs and counters

Identifiers are opaque and globally unique within a deployment.

Sequence and epoch values are unsigned 64-bit integers serialized as decimal strings. JSON numbers are not used for values that may exceed JavaScript's safe integer range.

The protocol uses four different counters:

| Counter | Scope | Persists across reconnect | Purpose |
|---|---|---:|---|
| connection epoch | device | yes | fences old sockets |
| control sequence | device, control-to-node | yes | ordered durable command delivery |
| node sequence | device, node-to-control | yes | ordered durable receipt and summary delivery |
| run event sequence | run | yes | replayable normalized observability events |

Transport sequence is not reused as run event sequence.

## Connection authentication

The challenge-response transcript and device-key rules are defined in `docs/AUTHORIZATION.md`.

After signature verification, `DeviceRoom` performs one storage transaction that:

1. increments the device connection epoch
2. stores the accepted key ID and connection metadata
3. records the selected protocol version and capability digest
4. marks previous connections fenced

Only after that transaction succeeds does the control plane send `transport.accepted`.

The accepted WebSocket attachment contains only bounded routing metadata needed after hibernation:

- device ID
- key ID
- connection epoch
- selected protocol version
- connection ID

Durable sequence and reconciliation state remain in Durable Object storage.

Messages from a fenced epoch are rejected. Closing an older socket is best effort; epoch validation is the authority check.

## Frame envelope

Every post-authentication frame uses this envelope:

```json
{
  "protocol": "conduit.node/1",
  "messageId": "nmsg_...",
  "deviceId": "dev_...",
  "connectionEpoch": "42",
  "direction": "node_to_control",
  "sequence": "918",
  "type": "operation.terminal",
  "correlationId": "op_...",
  "payloadDigest": "sha256-hex",
  "payload": {}
}
```

Required fields:

- protocol
- message ID
- device ID
- current connection epoch
- direction
- direction-specific durable sequence
- type
- SHA-256 digest of canonical payload
- bounded payload

`correlationId` is required for an operation, run, approval, input, or reconciliation exchange. Transport acknowledgements may omit it.

A sequence replay is accepted only when message ID and payload digest match the stored record. The same sequence with another message or digest is `sequence_conflict` and closes the connection.

A higher-than-expected sequence is not applied. The receiver returns `transport.replay_required` with the expected sequence. It does not skip an effectful message to process later frames.

A node-origin `transport.replay_required` may request only `control_to_node` sequences that are above the cumulative acknowledged position and no later than the Durable Object's stored control position. `expectedSequence` is the first requested sequence and `receivedSequence`, when present, is the inclusive end. The range is bounded and every sequence must still exist in the durable control outbox. `DeviceRoom` validates the complete range before accepting the request, then resends the stored frames with their original sequence, message ID, correlation ID, payload, and payload digest. Only the connection epoch is rebound to the authenticated replacement connection. An acknowledged, missing, conflicting, expired, or oversized range fails closed and is not recorded as an accepted node frame.

## Cumulative acknowledgement

Both directions use cumulative acknowledgements.

```json
{
  "type": "transport.ack",
  "payload": {
    "direction": "node_to_control",
    "throughSequence": "918"
  }
}
```

An acknowledgement means:

- the receiver has durably stored the frame or its application receipt
- every sequence through the acknowledged value has been accepted
- the sender may compact those transport-outbox rows according to retention policy

It does not mean that an offered operation was admitted, started, completed, or projected into every read model.

## Control-to-node delivery

A side-effecting remote request is created in this order:

1. authorize actor, client, connector policy, project, device, runtime, access scope, and approval policy
2. allocate operation ID and idempotency key
3. canonicalize the exact request and calculate its digest
4. atomically store intended operation state and a dispatch-outbox row in D1
5. claim the dispatch row with a bounded lease and submit the exact operation to `DeviceRoom`
6. store an outbound transport row in Durable Object storage using the dispatch row's stable message ID
7. atomically project the D1 dispatch row, operation journal, and idempotency record to offered only after `DeviceRoom` confirms durable custody
8. send the stored frame over the current WebSocket if the device is connected

Both custody boundaries persist before sending or acknowledging. A timeout or Worker failure between `DeviceRoom` custody and the D1 offered transition leaves the dispatch row retryable. An explicit same-key/same-digest request and the scheduled reconciler reuse the original operation ID, message ID, correlation ID, and payload digest. `DeviceRoom` returns the original transport sequence for that exact identity; a conflicting digest is rejected.

Dispatch attempts use expiring leases. An abandoned lease is reclaimable after Worker restart. The offered or expired outbox transition and its journal and idempotency projections execute in one D1 batch, so a Worker failure cannot commit a terminal outbox row while leaving the operation queued. The reconciler also repairs terminal rows written by deployments that predate this invariant.

Connector concurrency is represented by a Durable Object lease keyed by operation ID, class, and operation expiry. Acquire is idempotent for the same operation and release changes only that operation's active lease. D1 records `concurrency_released_at` as the release projection. A failure after Durable Object release but before that marker is safe because retry performs the same operation-bound release. A failure after acquire but before the D1 operation batch leaves an orphan lease that stops counting at operation expiry. Deterministic bounded backoff schedules ordinary retry, and operation expiry releases its lease exactly once without decrementing a different operation's slot. A dispatch failure never authorizes a new operation or a new message identity.

The Durable Object outbound row is persisted before any WebSocket send. A failed send remains queued in SQLite-backed storage. A single Durable Object alarm retries due rows idempotently; reconnect and hibernation reconstruct behavior from storage rather than isolate memory.

An offline device keeps queued messages in the Durable Object outbox until expiry, cancellation, or device revocation. A run is not shown as working merely because an offer was queued or transport-acknowledged.

## Operation offer

An `operation.offer` contains a versioned operation envelope:

- operation ID
- idempotency key
- actor principal
- OAuth or first-party client identity
- connector policy ID and revision
- target device
- project, session, assignment, and run IDs where applicable
- capability
- exact source-location and environment revisions
- runtime request
- access scope
- approval policy
- canonical arguments
- payload digest
- control-plane issue time
- server-side expiry
- bounded validity duration for node admission

The node validates the operation envelope before local admission. An offer is not executable authority merely because it arrived over an authenticated socket.

## Device-local operation journal

`conduit-node` journals every effectful operation before invoking a process, adapter, container, VM, filesystem write, or external API.

The journal stores:

- operation ID
- idempotency key
- request digest
- admitted immutable request manifest
- local policy revision
- source and runtime revisions
- state
- deterministic runtime or supervisor handle
- process identity, where applicable
- last run event sequence
- terminal receipt or explicit uncertainty
- journal version and integrity data

The journal is written with atomic replacement or a transactional embedded database. A memory-only marker is insufficient.

The minimum journal states are:

```text
reserved
admitted
starting
running
waiting_input
waiting_approval
finishing
completed
failed
cancelled
timed_out
lost
uncertain
recovery_required
rejected
expired
```

`reserved` means no external effect has been authorized to start. `admitted` means the immutable request and local policy decision are durable.

## Idempotency

When an operation arrives:

### New key

The node validates the request, reserves the key, evaluates local policy and resources, and returns an admission receipt.

### Existing key and same digest

The node replays the durable admission, status, or terminal receipt. It does not start another effect.

### Existing key and different digest

The node returns `idempotency_conflict`. No new effect starts.

### Existing uncertain key

The node returns the uncertainty record. It does not retry automatically.

Completed receipts remain available for a bounded retention period that is no shorter than the control-plane idempotency tombstone period.

## Admission

Node admission is separate from transport delivery.

The node sends `operation.admission` with one of:

- admitted
- rejected
- expired
- duplicate-replay
- uncertain

An admitted receipt binds:

- operation ID
- idempotency key
- request digest
- selected runtime provider
- effective local access scope
- effective approval policy
- local policy revision
- source-location revisions
- admission time observation
- admission receipt digest

The control plane marks a run as preparing only after a valid admitted receipt. It marks a run as working only after an agent or command start receipt or an observed running event.

## Effect start

Each runtime provider must offer an idempotent start boundary to `conduit-node`.

For native execution, a persistent local supervisor owns the child process. The supervisor reserves the run ID and spec digest before spawning, then records PID plus process-birth identity. A node-process crash must not make a still-running child anonymous.

Container and VM providers use a deterministic Conduit runtime ID and verify the existing object's specification digest before reuse.

A provider must not implement start as an untracked shell command.

## Node-to-control delivery

The node writes normalized frames to a durable local outbox before sending them.

On receipt, `DeviceRoom`:

1. validates device, epoch, sequence, message ID, and digest
2. stores the inbound row in SQLite-backed Durable Object storage
3. advances the durable received sequence in the same transaction
4. sends a cumulative acknowledgement
5. asynchronously projects the inbox row into D1 or an event-ingestion queue

Acknowledgement does not wait for every analytics index. It does require durable custody in the per-device inbox.

At-least-once queue delivery is deduplicated by Conduit event ID, run ID, and run event sequence.

## Run events

Each run has a persistent event sequence independent of transport connections.

A normalized event contains:

- run ID
- event ID
- run event sequence
- event schema version
- event type
- source component
- correlation and parent IDs
- evidence level
- sensitivity class
- device observation time
- bounded payload or content reference
- content digest

The event contract is defined by the trace schema. The node can batch consecutive events in `event.batch`.

The control plane applies a batch only when:

- event sequences are consecutive or known duplicates
- each duplicate has the same event ID and digest
- the batch stays within limits

A gap creates an event-range request. Later events are not silently renumbered.

## Event retention and gaps

The node retains normalized events according to device policy. Terminal receipts, admission receipts, approval commitments, security events, and change-set commitments have higher retention priority than progress deltas.

If the control plane requests an event range that no longer exists, the node sends `event.gap` with:

- missing range
- retention reason
- nearest retained sequences
- last available event-chain commitment
- whether terminal and verification receipts remain available

The run is marked `observability_incomplete`. The system does not invent replacement events.

## Reconciliation handshake

After connection authentication, the node sends a bounded `reconcile.summary` before accepting new remote work.

The summary contains:

- device ID
- connection epoch
- node boot ID
- node-journal generation
- capability digest
- last control sequence durably applied
- last node sequence acknowledged by the control plane, as observed by the node
- last node sequence still retained
- bounded active and nonterminal run summaries
- terminal receipts not yet confirmed by the control plane
- retained event ranges by run
- unresolved local journal records
- resource and storage health summary

When the device has more records than fit in one summary, it sends counts and cursors. It does not truncate without declaring truncation.

The control plane compares the summary with D1 intended state and `DeviceRoom` transport state, then sends `reconcile.plan`.

When `lastControlSequenceApplied` is behind the Durable Object position, the plan declares the inclusive control replay range. If the node observes the plan or another later frame before the missing range, it sends `transport.replay_required`; the Durable Object serves that range directly from SQLite-backed `outbound_frames`. A Worker restart, Durable Object eviction, WebSocket replacement, or lost pre-disconnect acknowledgement does not allocate new transport identities. Cumulative acknowledgement compacts the live outbox rows only after durable receipt tombstones have been updated.

The plan can request:

- replay control sequences
- replay node sequences
- replay run event ranges
- resend specific admission or terminal receipts
- status for named runtimes
- cancellation already requested while offline
- acknowledgement that a terminal receipt has been incorporated
- quarantine of a conflicting runtime

The node persists the plan before acting on effectful reconciliation steps.

The exchange ends with `reconcile.complete` containing the resulting sequence positions and unresolved items. New remote operation offers are held until initial reconciliation completes.

## Node restart

Each node process creates a new boot ID. The local journal generation changes only when the durable journal is migrated, repaired, restored, or replaced.

On restart, the node:

1. loads and validates the journal before accepting local or remote work
2. enumerates managed native supervisors, containers, VMs, and retained workspaces
3. compares each nonterminal journal record with the runtime provider
4. restores adapter or guest-agent connections where possible
5. records a typed recovery result
6. refuses new work if journal integrity or required storage cannot be established

Recovery outcomes:

### Running

The exact runtime handle exists, its specification digest matches, and liveness is proven. The node resumes event collection.

### Terminal

A durable terminal receipt exists. The node replays it even when the runtime has already been removed.

### Lost

The runtime is proven absent and no terminal receipt exists. The run is not rerun. Its workspace and available artifacts remain for inspection.

### Uncertain

The node cannot determine whether an external effect started or completed. Examples include ambiguous process identity, damaged journal state, unavailable runtime provider, or an unverified provider handle.

### Recovery required

The observed state conflicts with a durable terminal or authority record. Examples include a runtime still running after a terminal journal state, a different runtime digest under the same run ID, or an unresolvable controller transition.

An Agent subprocess cannot be resumed merely because its PID is still live. Resume requires an attachable provider I/O channel plus durable Adapter protocol phase, native session identity, active turn correlation, and event cursor. If any of those are unavailable after Node restart, the Node fences the exact recorded process identity and commits a schema-complete `recovery_required` terminal receipt. The receipt binds the original request digest and last durable event sequence and states that automatic replay did not occur.

`lost`, `uncertain`, and `recovery_required` require an explicit recovery action. None automatically create a replacement run.

## Disconnect behavior

After an operation is admitted, the node may continue it while the control plane is unreachable.

The node:

- continues the managed runtime according to local policy
- stores normalized events and raw logs locally
- queues agent messages and artifact metadata
- applies already received and valid approvals
- stops at a new approval boundary when no valid approval exists
- retains questions for later delivery
- writes terminal receipts locally

The node cannot invent owner approval, change a remote connector ceiling, or accept new remote assignments while disconnected.

A local UI or CLI may start a local scratch run. A scratch run has a device-generated local run ID, local actor record, local access decision, and ordinary trace. It is imported after reconnect as `origin=local_scratch`; it is not rewritten as a remotely authorized assignment.

## Input and follow-up

Remote user input is a typed operation with its own operation ID and idempotency key.

Input targets:

- exact run
- exact agent runtime session
- expected controller epoch
- expected agent state
- input mode such as answer, follow-up, steer, or queued instruction

A stale or terminal target rejects the input. Text posted to the board is not automatically injected into a running agent unless a structured input operation is created.

## Approval delivery

The node emits an approval request containing an exact operation commitment. The control plane resolves it according to `docs/AUTHORIZATION.md` and sends `operation.approval`.

The approval message binds:

- approval ID
- requester and client
- device and run
- operation digest
- source, runtime, and controller revisions
- decision
- approved reuse scope
- server expiry
- bounded validity duration

The node journals the approval receipt before applying it. A receipt for another digest, revision, or controller epoch is rejected.

If the connection is lost before the receipt is received, the run remains `waiting_approval` unless a prior approval already covers the exact operation.

## Agent server-request correlation

An Agent Adapter must answer every provider-initiated request that carries an ID. A supported approval request is bridged to the typed approval flow or receives a correlated explicit decline. A request for an unadvertised capability, including host-managed authentication refresh, client attestation, dynamic tools, or user input, receives a correlated fail-closed protocol error. Unknown request methods receive a correlated method-not-found error and a bounded visible Adapter error event. No provider request is left pending merely because Conduit does not implement it.

## Cancellation

Cancellation is an effectful operation, not a state label.

The flow is:

```text
cancel requested
  → cancel delivered
  → cancel admitted by node
  → runtime or agent cancellation attempted
  → terminal cancellation receipt or typed failure
```

The control plane does not mark a run cancelled merely because the request was queued or acknowledged.

Repeated cancellation with the same key and digest replays the first receipt. Cancellation targets the exact runtime and active agent turn where the adapter supports it.

If graceful cancellation fails, a separate force-stop operation may be offered according to policy. Force stop is not an automatic fallback hidden inside ordinary cancel.

## Presence and health

WebSocket presence is an observation, not device authority.

`DeviceRoom` uses hibernatable WebSocket auto-response for bounded ping/pong where possible. It does not use a permanent timer that prevents hibernation merely to update presence.

The UI distinguishes:

- connected
- recently observed
- disconnected
- reconciling
- degraded storage
- protocol incompatible
- revoked

A connected socket does not imply that sources, adapters, credentials, or runtimes are ready.

## Durable Object storage

The initial SQLite-backed `DeviceRoom` schema contains logical records equivalent to:

```text
connection_state
transport_positions
outbound_frames
inbound_frames
reconciliation_sessions
terminal_receipt_cache
```

The Durable Object stores only bounded control messages, receipts, summaries, and normalized event batches awaiting ingestion. It does not store VM disks, source files, full terminal logs, or unbounded provider output.

Acknowledged frames are compacted only after the required D1 or tombstone retention condition is met. Unacknowledged effectful operations and terminal receipts are never evicted because of ordinary age alone.

## Device-local storage pressure

Local data uses priority classes.

### P0: never silently discard

- operation journal
- admission receipts
- terminal receipts
- approvals and denials
- security events
- source and runtime commitments
- change-set and verification commitments

### P1: retain under normal policy

- assistant messages
- tool calls and results
- command summaries
- file and Git events
- test results
- artifact metadata

### P2: compactable

- streaming text deltas after a complete message exists
- repeated progress states
- high-frequency metrics
- duplicate provider status

### P3: separate raw retention

- terminal byte streams
- provider protocol bytes
- large command output
- screenshots and videos

If P0 storage cannot be committed, the node refuses new effectful work. It does not delete P0 records to keep accepting assignments. Existing runs are paused at a safe boundary where supported or marked degraded when pausing is unavailable.

## Control-plane backpressure

When the control plane cannot ingest more events:

- device transport acknowledgements stop before local custody can be released
- the node retains its outbox
- progress deltas may be coalesced locally
- terminal and admission receipts remain prioritized
- new run admission may be limited before storage becomes unsafe

The control plane reports a stable `ingestion_backpressure` state rather than showing stale progress as current.

## Stable errors

Initial transport and reconciliation errors:

```text
protocol_version_unsupported
device_not_enrolled
device_revoked
device_key_invalid
connection_epoch_stale
connection_fenced
frame_too_large
frame_malformed
payload_digest_mismatch
sequence_conflict
sequence_gap
replay_range_unavailable
operation_expired
operation_not_authorized
operation_rejected_local_policy
idempotency_conflict
runtime_identity_mismatch
journal_unavailable
journal_corrupt
storage_exhausted
observability_incomplete
reconciliation_required
ingestion_backpressure
```

Errors are bounded and do not include raw provider payloads, local canonical paths, credentials, or command output.

## Required deterministic tests

The protocol implementation must cover:

1. duplicate operation delivery before admission
2. duplicate operation delivery after completion
3. same idempotency key with another digest
4. connection replaced while an old socket sends events
5. node disconnect after runtime start but before admission receipt delivery
6. node completes while disconnected
7. control plane restarts or `DeviceRoom` hibernates with an active socket
8. node restarts with a running native supervisor
9. node restarts with a missing runtime and no terminal receipt
10. terminal receipt delivered twice through queue retry
11. event sequence gap and replay
12. requested event range already expired
13. approval requested immediately before disconnect
14. cancellation requested while the device is offline
15. P0 local storage exhaustion
16. malformed, oversized, unknown, and future-version frames followed by valid frames where recovery is allowed
17. stale connection epoch and mismatched sequence digest
18. local scratch run import after reconnect

The tests use fake control-plane and fake runtime providers before real Cloudflare and process integration.

## References

- Cloudflare Durable Object WebSockets: <https://developers.cloudflare.com/durable-objects/best-practices/websockets/>
- Durable Object lifecycle: <https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/>
- SQLite-backed Durable Object storage: <https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/>
- Cloudflare Queues delivery guarantees: <https://developers.cloudflare.com/queues/reference/delivery-guarantees/>
