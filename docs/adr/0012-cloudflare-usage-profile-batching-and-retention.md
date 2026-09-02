# ADR 0012: Cloudflare usage profiles, batch custody, and bounded hot data

- Status: Accepted
- Date: 2026-09-02

## Context

The Linux vertical slice preserves transport, admission, execution, and terminal receipts, but several correct paths amplify Cloudflare Free usage. An unchanged Device health sample can create Durable Object rows, D1 rows, an application ACK, and an alarm. Normalized Agent events can become one Queue message and several D1 statements per event. Reconciliation and Source binding accept bounded arrays whose schema maxima exceed D1 per-invocation query and parameter ceilings. Authentication activity, live fanout, and idempotency records also accumulate writes or rows when no effectful work occurs.

Cost controls cannot weaken custody, exact digests, authorization, stale-epoch fencing, replay, approval, or immutable evidence. A Queue delivery or WebSocket ACK remains distinct from projection and execution.

## Decision

### Usage profiles

`CLOUDFLARE_USAGE_PROFILE` is explicitly `free` or `standard`; deployment templates default to `free`. Profiles choose batching intervals and bounds, semantic health checkpoints, event-ingestion transport, retention batch size, observability sampling, and the Cron backstop interval. They do not change authorization, approval, exact-target, idempotency-conflict, or security semantics.

The Free profile uses a five-minute Cron backstop, a 0.20 log sample, a 0.01 trace sample, and `durable_inbox` event custody. Staging and E2E configurations may use full sampling without changing production defaults.

### Device steady state

WebSocket protocol ping/pong is the transport keepalive and creates no application frame or durable row. `device.health` is semantic state: connection/reconciliation completion, a state or counter change, and fault or recovery emit immediately; an unchanged checkpoint is bounded at ten minutes on the Free Node profile. An unchanged checkpoint replays the exact durable health envelope (same message ID, sequence, digest, and observed timestamp) rather than allocating another Node outbox row. ACK-only control-frontier progress does not force a new health allocation; a non-ACK control application requests a fresh health rebase so the shared frontier is available without an ACK/health feedback loop. D1 `last_observed_at` is throttled independently from online connection state.

On one authenticated WebSocket, the Node records the greatest contiguous Node sequence successfully written to that socket. The generic durable-outbox flush sends only above that socket frontier; it does not retransmit an unacknowledged frame on each 100 ms poll. A new socket initializes the frontier from the peer's authenticated `nodeStoredThroughSequence`, so disconnect, process restart, and lost-custody recovery still replay every row the peer did not durably report. Explicit semantic-health checkpoints remain exact-envelope replays and do not allocate transport identity.

Application ACKs are cumulative and coalesced. ACK-only rows are distinguished from effectful control rows and compacted after the peer shares its applied control frontier. A DeviceRoom alarm exists only while durable work has a due time: retry, replay, coalesced ACK, event projection, or bounded retention. An inline-success path with no pending work deletes its alarm.

Transport exact rows compact into a bounded frontier and digest tombstone. A duplicate at or before the retained exact window is accepted only when the compacted commitment proves it; an unverifiable old duplicate returns `reconciliation_required` rather than being silently treated as exact.

### Batch-first normalized events

The Device-local trace remains lossless. The cloud path accumulates per Run until the first of a short time limit, 32 events, or 60,000 encoded bytes. Approval, terminal, error, tool boundary, command, file-effect, Change Set, and verification events force a priority flush. Adjacent visible assistant text deltas may be coalesced only with byte-for-byte reconstruction metadata. Each batch commits its source sequence range and range digest.

In `durable_inbox` mode, the DeviceRoom exact inbox is Queue-free custody and a bounded alarm bulk-commits events to D1 before advancing the projected frontier. In `queue` mode, one node `event.batch` is one sub-64 KiB Queue message. The consumer bulk-commits valid events, updates each Run trace index once, and isolates only the exact poison event as dead-letter/security evidence.

### D1 and subrequest ceilings

Production paths target at most 40 D1 statements or binding executions per Worker or Durable Object invocation and at most 90 bound parameters in one statement. The budget applies to the outer Queue consumer, Worker handler, scheduled handler, or Durable Object alarm, not merely to an inner helper. Queue delivery is capped at six messages per consumer invocation. DeviceRoom projects at most four D1-backed frames per alarm and rearms remaining custody. RetryScheduler spends a conservative whole-work reservation and performs at most one external work item per alarm. Schema maxima are not reduced to meet these targets. Source binding, reconciliation ranges and Run IDs, ingestion, and realtime claim/finalize use JSON table expansion, bounded set queries, and batch operations.

Usage instrumentation is opt-in local/test code. It records D1 statement and parameter counts plus result metadata, Durable Object RPC/messages/SQL/alarm counts, Queue chunks and retries, R2 operations and bytes, and Worker CPU/log/trace projections. It never writes a per-request production usage counter to D1.

### Retention classes

The following remain permanent or long-lived: Message revisions, important Assignment and Run transitions and terminal receipts, approval commitments and decisions, Change Sets, Reviews, Baselines and acceptances, artifact metadata, and security archive roots and manifests.

The following are short-lived hot data: exact transport rows and tombstones, unchanged health projection receipts, published realtime outbox rows, live fanout dedupe, consumed or expired authentication/OAuth challenges and tokens, completed enrollment transactions, effect/idempotency rows, limiter windows and leases, and high-volume normalized streaming deltas.

Short-lived records have an indexed expiry or explicit archival state. Cleanup deletes a small bounded page and schedules continuation only while backlog remains. The five-minute crash-gap backstop first probes for genuinely due rows; an empty system creates no RetryScheduler row, alarm, or D1 write. A DeviceRoom does not reserve an alarm merely because retained proof will expire in the future: activity detects due retention, hard row bounds remain active, and only due/over-bound cleanup is scheduled. Final messages, tool/state/error events, terminal receipts, Reviews, Baselines, and security evidence are never delta-coalesced or dropped.

`security_events` remains immutable and cannot be deleted by ordinary cleanup. A future capacity archive may write hash-chained compressed NDJSON segments to R2 Standard, commit the exact object digest, row range, and custody receipt to D1, and then prune only through a trigger that verifies the archive receipt. Critical events and segment roots remain in D1.

### Authentication, limiting, and live fanout

Browser and owner-CLI activity timestamps are touched no more than once per ten minutes; OAuth grant use is touched no more than once per hour. Revocation, status, policy-revision, audience, and scope checks still run on every request.

Connector rate state uses one compact retained budget row. Cardinality and mutation cost are distinct: each admitted read still updates that row so exact rate enforcement is preserved. Read-only requests do not create limiter idempotency rows, all-zero byte usage does not create a byte row, and effectful rate admission and concurrency acquisition share one Durable Object transaction. D1 effect records remain the durable effect authority. Expired idempotency and lease rows are pruned in bounded pages.

D1 is historical authority for Board state. BoardRoom keeps a bounded dedupe window and publishes event batches to active sockets. Its local fanout ring retains at most 2,048 rows, owns one alarm for the oldest expiry, and deletes at most 250 rows per alarm before rearming only while rows remain. Thus a quiet or closed Room converges without another publish. Realtime outbox rows are claimed in batches and published once per Session. Status events may coalesce only while pending for the same Session, record, and state family. Message, Approval, terminal, Review, Baseline, security, and failure events never coalesce. Clients fetch a bounded authoritative snapshot before applying buffered `(eventId, revision)` stream events.

### Demand-driven work and static assets

Immediate dispatch success schedules no additional worker. A failed operation, approval, or realtime delivery registers its exact next due time with one scheduler Durable Object alarm. The five-minute Cron is a crash-gap and expired-lease backstop, not the normal UX path.

Setup, Login, Device, and dashboard shells and JavaScript use Workers Static Assets with asset-first routing. API and authentication state remain Worker routes. A Worker Cache hit is not counted as a request-saving substitute for Static Assets.

## Rejected alternatives

### Reduce schema maxima

Rejected because it hides query fan-out and removes supported Sources or reconciliation evidence rather than batching them.

### Drop ACK, replay, or projection receipts

Rejected because delivery, custody, projection, admission, execution, and completion remain distinct facts.

### Treat Queue consumer batching as fewer Queue operations

Rejected because Queue operations are charged per message and 64 KiB chunk; node batches must remain intact through the producer boundary.

### Delete security events for capacity

Rejected because security evidence must remain immutable and archive custody must be committed before any authorized pruning.

## Consequences

- Free and Standard deployments share correctness and security contracts but have explicit cost knobs.
- DeviceRoom and ConnectorLimiter gain bounded local schema migrations and cleanup.
- Node event and health emission becomes stateful and batch-aware while the local trace remains lossless.
- D1 migrations classify hot rows and provide indexed cleanup.
- Budget tests become release gates alongside protocol, fault, security, and remote Cloudflare E2E tests.

## Contract

- `docs/CONTROL_PLANE.md`
- `docs/AUTHORIZATION.md`
- `docs/NODE_PROTOCOL.md`
- `docs/TRACE_FORMAT.md`
- `docs/CLOUDFLARE_FREE_TIER_BUDGET.md`
- `spec/schemas/node-protocol-v1.schema.json`
