# Node transport and reconciliation

## Scope

`conduit.node/1` carries control-plane work to an enrolled device and returns durable device records.

It covers:

- device challenge authentication
- connection fencing
- operation admission
- node-side exact-once records
- event replay
- runtime observations
- reconnect reconciliation
- flow control
- stable protocol errors

Project files, raw terminal output, VM disks, provider credentials, and large artifacts do not travel through this WebSocket protocol.

The machine-checkable contract is:

- `spec/schemas/node-transport-v1.schema.json`
- `spec/examples/node-transport/`

Authentication, enrollment, key rotation, connector policy, and Full Access rules are defined in `docs/AUTHORIZATION.md`.

## Protocol names

```text
WebSocket protocol       conduit.node/1
Operation contract       conduit.operation/1
Durable record contract  conduit.node-record/1
Normalized event body    conduit.event/1
```

The transport and operation versions are negotiated independently. A node that supports the WebSocket framing but not an operation kind rejects the operation with a typed admission error.

## Connection lifecycle

```text
connecting
  ↓
challenge
  ↓
authenticated
  ↓
reconciling
  ↓
ready
  ├─ draining
  └─ closed
```

A connection does not receive new operation offers until reconciliation completes and the control plane sends `connection.ready`.

### Handshake

1. The node opens an outbound WSS connection.
2. The node sends `device.hello`.
3. The control plane sends `device.challenge`.
4. The node signs the challenge transcript and sends `device.proof`.
5. The control plane verifies the active device key.
6. The control plane increments the device connection epoch and sends `device.accepted`.
7. Any older connection for that device is fenced.
8. The node and control plane reconcile durable state.
9. The control plane sends `connection.ready`.

The signed authentication transcript contains:

```text
conduit.device-auth.v1
public origin
connection ID
device ID
device key ID
client nonce
server nonce
selected protocol
server time
```

The transcript is encoded with RFC 8785 JSON Canonicalization Scheme, hashed with SHA-256, and signed with Ed25519.

Challenge freshness uses control-plane time. The node does not need an accurate wall clock to complete authentication.

### Connection epoch

Each accepted connection receives a monotonically increasing `connectionEpoch`.

Every authenticated frame contains:

- connection ID
- connection epoch
- per-direction sequence
- message ID
- send time

A frame from an older epoch is rejected before its payload is processed. Accepting a new epoch closes or fences every older socket for the device.

### Per-connection sequence

The node and control plane maintain independent outbound sequences.

- the first authenticated frame in each direction uses sequence `1`
- the sequence advances by exactly one
- a duplicate, gap, or regression closes the connection
- the sequence resets only when a new connection epoch is accepted

WebSocket ordering is not used as the only replay boundary. The explicit sequence detects stale connection handlers and implementation errors.

### Durable record sequence

`recordSeq` is different from the per-connection sequence.

- it is global to one device journal generation
- it survives reconnects and node restarts
- it is assigned transactionally before a durable record becomes visible
- it never resets during the life of a journal generation
- replayed records keep their original `recordSeq`

The control plane acknowledges the highest contiguous record sequence stored in the per-device durable ingress journal.

## Cloudflare routing

A per-device Durable Object owns the live WebSocket.

The Durable Object uses the WebSocket Hibernation API. Its in-memory fields are disposable. The WebSocket attachment stores only the bounded connection metadata needed after hibernation:

- device ID
- device key ID
- connection ID
- connection epoch
- selected protocol
- connection phase
- next expected sequence in each direction

The Durable Object uses SQLite-backed storage for:

- current connection epoch
- accepted ingress records that have not yet been materialized
- record sequence/hash conflict detection
- bounded delivery metadata

A node record is acknowledged only after the Durable Object has committed it to durable storage. D1 materialization may happen later. If D1 is unavailable, the record remains in the Durable Object ingress journal and the materializer retries.

The Durable Object does not become the authority for Project, Assignment, Run, or operation state. D1 keeps those shared records. The Device remains authoritative for local runtime observations.

Cloudflare Durable Object hibernation discards memory while retaining accepted WebSockets, so no correctness decision depends on an in-memory map.

References:

- <https://developers.cloudflare.com/durable-objects/best-practices/websockets/>
- <https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/>
- <https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/>

## Frame bounds

Initial defaults:

| Item | Limit |
|---|---:|
| Handshake frame | 32 KiB |
| Authenticated JSON frame | 512 KiB |
| Records per batch | 256 |
| Inline durable-record body | 64 KiB |
| In-flight record batches | 4 |
| Operation arguments | 256 KiB |
| Reconciliation operation summaries | 1,024 |
| Reconciliation runtime summaries | 256 |

The negotiated `device.accepted.transportLimits` may lower these values. It cannot raise a compiled node hard ceiling.

Large command output, raw provider events, videos, VM images, and artifacts use device-local chunk storage and a separate bounded transfer path. A transport record contains a digest and reference instead of the large body.

The first implementation does not require WebSocket compression. A later compression mode needs explicit decompressed-size limits and a protocol capability.

## Liveness

The Durable Object configures a hibernation auto-response for an exact small application heartbeat:

```text
CND1_PING
CND1_PONG
```

Heartbeat frames carry no authority and are not JSON protocol messages.

The default interval is 30 seconds and the timeout is 90 seconds. A timeout closes the local socket and reconnects with capped exponential backoff and jitter.

Application activity and record acknowledgements also count as liveness observations.

## Canonical digests and signatures

Conduit uses RFC 8785 JCS for signed and hashed JSON objects in this protocol. Values must be valid I-JSON. Floating-point values are not used in authority-bearing commitments.

### Operation offer

```text
payloadDigest = SHA-256(JCS(operation))
signature input =
  "conduit.operation-offer.v1\n" + payloadDigest
```

The control plane signs with the key pinned during device enrollment.

### Admission receipt

```text
receiptDigest = SHA-256(JCS(admission.core))
signature input =
  "conduit.operation-admission.v1\n" + receiptDigest
```

### Terminal receipt

```text
receiptDigest = SHA-256(JCS(terminal.core))
signature input =
  "conduit.operation-terminal.v1\n" + receiptDigest
```

### Reconciliation

`reconcile.state`, `reconcile.complete`, and `reconcile.plan` use the equivalent domain-separated digest shown in their examples.

Admission and terminal receipts are signed by the active device key. High-volume event records are not individually signed. They are protected by the authenticated current-epoch connection, per-frame ordering, durable record sequence, and record-body hash.

References:

- <https://www.rfc-editor.org/info/rfc8785/>
- <https://www.rfc-editor.org/info/rfc8032/>

## Operation offer

A side-effecting request is created in the control-plane operation ledger before delivery.

The offer binds:

- operation ID
- idempotency key
- operation kind
- actor and client identity
- connector-policy revision
- project- and device-policy revisions
- access scope
- approval mode or approval receipt
- selected device
- runtime kind
- Project, Session, Assignment, and Run when present
- exact Source Location revisions
- runtime and environment revisions
- arguments
- admission expiry
- execution deadline or maximum execution duration
- payload digest
- control-plane signature

`admissionExpiresAt` limits when a device may admit new work. It is not the result-acceptance deadline.

An operation can be admitted only on the current authenticated connection while the node has a valid estimate of control-plane time from that connection. Once admitted, it may continue during a network outage according to local policy.

## Node admission transaction

The node performs these steps before an external side effect:

1. validate the frame, epoch, sequence, operation schema, signature, target device, revisions, policy, and local resource limits
2. calculate the operation payload digest independently
3. check operation ID and idempotency bindings
4. allocate a stable execution ID
5. insert the operation journal row
6. bind the idempotency key to the payload digest
7. append a signed `operation.admission` record
8. commit all admission data in one local SQLite transaction
9. request runtime start using the stable execution ID

A request with the same operation ID, idempotency key, and digest does not create another execution. The node replays the existing records or appends an `operation.snapshot`.

A reused operation ID or idempotency key with another digest is rejected as `idempotency_conflict`. The conflicting body is not executed.

### Runtime start boundary

The runtime provider receives a stable `executionId`.

`RuntimeProvider.start(executionId, manifest)` must converge to one of:

```text
started          the execution exists and is identified
already_started  the same execution already exists
rejected         no external effect occurred
unknown          the provider cannot prove whether an effect occurred
```

A provider may not translate `unknown` into a new start. The operation becomes `uncertain` or `recovery_required`.

This boundary covers the crash window between recording launch intent and saving a process, container, or VM handle.

## Node journal

The first implementation uses SQLite in the node state directory.

Required logical tables:

```text
journal_meta
operation_admissions
idempotency_bindings
durable_records
runtime_bindings
reconciliation_conflicts
```

### `journal_meta`

Stores:

- journal generation
- next record sequence
- last control-plane-acknowledged record sequence
- schema version
- storage-pressure state

### `operation_admissions`

Stores:

- operation ID
- idempotency key
- payload digest
- signed control-plane offer commitment
- immutable admitted manifest
- execution ID
- current node state
- admission receipt
- terminal receipt when present
- timestamps
- retention class

### `durable_records`

Stores:

- record sequence
- record ID
- record type
- body hash
- bounded JSON body or local payload reference
- creation time
- cloud acknowledgement time

### Persistence rules

- admission reservation and admission record are one transaction
- state change and transition record are one transaction
- terminal state and signed terminal record are one transaction
- unacknowledged records are not evicted
- non-terminal and uncertain operation entries are not automatically evicted
- terminal receipts remain available for the configured replay window
- if safe compaction cannot keep the journal under its hard limit, new effectful admissions stop
- read-only diagnosis and record export remain available under storage pressure

The default terminal-receipt replay window is 30 days after completion. The control-plane idempotency tombstone must outlive the maximum node replay window and reconnect grace. The initial control-plane default is at least 45 days.

## Durable record delivery

The node sends contiguous `record.batch` messages.

The receiver validates:

- current connection epoch
- per-connection sequence
- first and last record sequence
- contiguous record order
- record ID
- record-body hash
- duplicate sequence/hash consistency
- frame and record bounds

A duplicate record with the same sequence and hash is accepted idempotently.

A duplicate sequence with another hash is a security and consistency fault. The current connection is fenced, the operation is not materialized, and the device requires review.

`record.ack.throughRecordSeq` means the control plane has durably stored every record through that sequence in the Device Durable Object ingress journal. It does not mean every record has already been indexed into D1.

The node may compact ordinary acknowledged event records according to retention policy. It retains operation receipts according to the operation journal rules.

## Reconciliation

Reconciliation runs after every accepted connection and before new work.

### Node state

`reconcile.state` includes:

- node instance and boot ID
- journal generation
- first available, last, and last acknowledged record sequence
- bounded non-terminal operation summaries
- bounded active-runtime observations
- count of local-only scratch runs
- truncation indicator
- signed summary digest

It contains opaque runtime IDs, not local paths, process command lines, credentials, or raw logs.

### Control-plane plan

The control plane compares:

- D1 expected operation state
- Durable Object ingress range
- node operation journal summaries
- runtime observations
- existing terminal receipts

`reconcile.plan` may request:

- record replay ranges
- operation snapshots
- re-offer of the same signed operation
- temporary hold on new work

The plan does not contain an unjournaled command to start, kill, or mutate a runtime. Effectful actions use normal signed operation offers with their own operation ID and idempotency binding.

### Completion

The node sends `reconcile.complete` after requested records and snapshots have been supplied.

The control plane sends `connection.ready` only when:

- the current epoch is still active
- required record ranges are durably accepted or explicitly reported unavailable
- queried operations have a snapshot or an unresolved reason
- no operation digest conflict exists
- the device is not revoked
- ingress flow control allows dispatch

If reconciliation is incomplete, the connection may remain available for health and record replay but does not receive new effectful work.

## Expected and observed state

The control plane keeps expected state. The node reports observed state.

Examples:

```text
Control plane: working
Node: runtime missing
Result: recovery_required
```

```text
Control plane: failed by delivery timeout
Node: signed completed receipt
Result: completed, with the earlier delivery problem retained as an incident
```

```text
Control plane: cancel requested
Node: completed before cancellation reached the runtime
Result: completed; cancellation remains recorded as requested but not effective
```

A synthetic control-plane timeout is not an authoritative terminal result after device admission.

The signed device terminal receipt is authoritative for the local execution outcome unless it conflicts with another valid receipt for the same operation and digest. Two different valid terminal receipts produce a consistency incident rather than selecting one silently.

## Operation time boundaries

Three deadlines are separate.

### Admission expiry

The device must not admit the operation after `admissionExpiresAt`.

### Execution deadline

The runtime and node policy bound how long admitted work may run. A disconnected device still enforces the locally admitted duration policy.

### Receipt acceptance retention

A matching signed terminal receipt remains acceptable after HTTP, MCP, dashboard, or delivery waits have expired. It is accepted until the durable operation and idempotency tombstone retention ends.

The invariant is:

```text
receipt acceptance retention
  >= maximum execution duration
   + maximum offline delivery grace
```

An admitted operation is never converted to a final `expired` result merely because the initial dispatch wait elapsed.

## Node restart

At startup the node:

1. opens and validates its journal
2. reads the current boot ID
3. enumerates runtime-provider instances managed by Conduit
4. resolves each runtime by stable execution ID
5. updates operation observations without inventing terminal success
6. starts the outbound connection
7. reconciles before accepting new remote work

Outcomes:

| Journal | Runtime observation | Result |
|---|---|---|
| admitted, no launch intent | absent | wait for same-operation re-offer after reconciliation |
| launching | same execution found | running |
| launching | provider proves no execution | same-operation re-offer may resume |
| launching | provider cannot prove | uncertain |
| running | same execution found | running |
| running | runtime proves terminal | append terminal record |
| running | missing without terminal proof | recovery_required |
| terminal | any stale runtime still present | recovery_required and explicit cleanup |
| no journal entry | managed runtime found | orphaned runtime; do not attach automatically |

The node never starts a second execution because a process handle was lost.

## Offline behavior

Once admission is committed, work may continue while disconnected.

The node:

- keeps running admitted work
- writes records and raw logs locally
- enforces execution and resource limits
- stops at a new approval boundary unless a valid prior authorization covers it
- signs and stores terminal receipts
- does not start queued cloud work that was never admitted

A remote approval cannot be completed while the control plane is unavailable. `never` approval continues inside the admitted authority. A future local approval mechanism needs a separate typed receipt; same-user IPC alone is not human presence.

Local-only Quick Command and Quick Agent Session runs may continue. They are not automatically inserted into a Project or uploaded. Import requires explicit owner action after reconnect.

## Revocation

A revoked device cannot establish a new connection.

If revocation occurs while connected:

- the current epoch is fenced
- no new work is delivered
- no later records are accepted through the revoked connection
- the owner may separately request managed-run termination before fencing

A control plane cannot force an offline device to stop. Local work may remain active. Results from a revoked device remain quarantined until the owner explicitly restores or re-enrolls the device.

## Flow control

The control plane may lower:

- in-flight batch count
- in-flight bytes
- dispatch concurrency

A zero in-flight allowance pauses record delivery without losing the connection.

The node keeps unacknowledged records durably. Under local storage pressure it prioritizes:

1. signed terminal receipts
2. admission receipts
3. approval requests
4. operation transitions
5. normalized events
6. verbose activity

It does not discard an unacknowledged authority record to preserve verbose logs.

## Protocol errors

Fatal errors close the connection after a bounded error frame when possible:

- epoch mismatch
- per-connection sequence mismatch
- message ID reuse with another body
- record sequence/hash conflict
- operation digest mismatch
- invalid signature
- unsupported protocol major
- oversized frame

Non-fatal errors may reject one operation:

- unsupported operation kind
- source revision mismatch
- local policy denial
- local resource limit
- runtime provider unavailable
- admission expiry

Error text is display data. Stable error codes drive behavior.

## Accident matrix

The executable test cases are listed in `spec/examples/node-transport/reconciliation-cases.json`.

| Case | Required result |
|---|---|
| same offer delivered twice | one execution; replay receipt |
| same idempotency key, new digest | reject conflict |
| disconnect after process start, before cloud receipt | replay admission and observed runtime; do not start again |
| terminal receipt produced while offline | accept after reconnect |
| control plane says working, runtime missing | recovery required |
| control plane says failed, runtime still live | expose divergence; do not kill or restart implicitly |
| approval requested while offline | wait |
| only part of record range arrived | replay missing range |
| old connection sends an event | reject by epoch |
| record sequence reused with another hash | fence connection |
| node journal cannot prove launch outcome | uncertain |
| journal capacity cannot safely compact | block new effectful admission |
| operation admission wait expired after admission | keep waiting for actual terminal receipt |
| local scratch work found | keep local until explicit import |

## Test plan

### Schema and fixtures

- validate every example against `node-transport-v1.schema.json`
- verify operation and receipt digests
- verify example Ed25519 signatures
- reject unknown fields
- reject unsafe integers
- reject invalid conditional result/error combinations
- reject non-contiguous record batches

### Fake control plane and node

- complete handshake and fencing
- hibernate and reconstruct WebSocket connection metadata
- duplicate operation offer
- idempotency drift
- record replay after disconnect
- D1 failure after Durable Object ingress commit
- Node restart at every launch boundary
- stale epoch event
- flow-control pause
- local journal storage pressure
- conflicting terminal receipts
- operation expiry before and after admission

### Linux receipt

The first live receipt uses:

- one local Wrangler/workerd control plane
- one real `conduit-node`
- isolated device state
- fake runtime provider first
- Native provider second
- process restart between admission and completion
- network interruption during work
- bounded fixture output without credentials or private reasoning

## Deferred

The following do not change `conduit.node/1` framing:

- raw log chunk upload protocol
- artifact upload protocol
- multi-node run migration
- peer-to-peer device transfer
- local offline passkey approval
- high-volume telemetry compression
- Windows and macOS runtime attestation details
