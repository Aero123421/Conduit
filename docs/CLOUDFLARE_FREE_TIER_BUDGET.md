# Cloudflare Free tier budget

This document is the release budget for the Cloudflare control plane. It separates measured implementation counters from quota projections. Correctness, authorization, approval, exact-target control, replay, and immutable evidence do not vary by usage profile.

## Profile

The deployment template sets `CLOUDFLARE_USAGE_PROFILE=free`.

| Control | Free | Standard |
|---|---:|---:|
| Event ingestion | Durable inbox, no Queue | One node batch per Queue message |
| Event flush | 100 ms / 32 events / 60,000 bytes | 50 ms / 32 events / 60,000 bytes |
| Unchanged semantic health | 10 minutes | 5 minutes |
| D1 health touch | At most once per 15 minutes | At most once per 5 minutes |
| ACK coalescing | 100 ms / 32 frames | 50 ms / 32 frames |
| Realtime claim | 32 rows | 32 rows |
| Retention page | 250 rows | 500 rows |
| Cron backstop | Every 5 minutes | Every 5 minutes |
| Production logs | 0.20 head sample | Deployment-selected |
| Production traces | 0.01 head sample | Deployment-selected |

An unknown profile fails configuration parsing. Staging and isolated E2E may override sampling to `1.0`; production Free does not.

## Platform ceilings and release headroom

The release target is no more than 25% of each relevant daily Free allowance for 10 idle Devices plus one active eight-hour Agent Run.

| Resource | Platform Free allowance | Conduit release target |
|---|---:|---:|
| Worker requests | 100,000/day | 25,000/day |
| Worker CPU | 10 ms per HTTP/Cron invocation | p95 at most 8 ms |
| Worker subrequests | 50/invocation | At most 40 D1 statements/binding executions and reserved non-D1 headroom |
| D1 rows read | 5,000,000/day | 1,250,000/day |
| D1 rows written | 100,000/day | 25,000/day |
| D1 database | 500 MB | Bounded hot tables; alert before 125 MB |
| D1 bound parameters | 100/query | At most 90/query |
| SQLite Durable Object requests | 100,000/day | 25,000/day |
| SQLite Durable Object rows read | 5,000,000/day | 1,250,000/day |
| SQLite Durable Object rows written | 100,000/day | 25,000/day |
| Queues | 10,000 operations/day | At most 2,500/day; Free default is zero |
| Workers logs + trace spans | 200,000 events/day | At most 50,000/day, including post-2026-10-01 trace spans |

The current platform values are maintained in Cloudflare's official [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/), [D1 limits](https://developers.cloudflare.com/d1/platform/limits/), [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/), [Queues pricing](https://developers.cloudflare.com/queues/platform/pricing/), [R2 pricing](https://developers.cloudflare.com/r2/pricing/), [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/), and [Workers traces](https://developers.cloudflare.com/workers/observability/traces/) pages. Re-run the budget probe when those limits or the Wrangler compatibility date changes.

## Instrumentation

Production requests do not write usage counters to D1. Measurements use:

- an opt-in D1 proxy that records executed statements, binding calls, bound parameter counts, and returned `meta.rows_read` / `meta.rows_written`;
- DeviceRoom test counters for incoming application messages, SQL base-row mutations, `setAlarm`, alarm invocation, and hot-table rows;
- a Queue model that charges every 64 KiB chunk for write, read, successful delete, retry read, and dead-letter transfer;
- explicit R2 Class A/Class B and stored/served byte counters in local probes;
- Worker invocation, measured CPU time, sampled log-event, and trace-span projection;
- Cloudflare Analytics or GraphQL for isolated remote E2E confirmation.

`apps/control-plane/src/usage-instrumentation.ts` is not called by the production request path. Tests fail above 40 D1 statements or 90 parameters.

## Required simulations

The automated suite covers:

1. 1, 5, and 10 Devices for 24 hours of idle-equivalent time;
2. an eight-hour Run with 10,000 raw assistant deltas and 500 priority tool/state/error events;
3. 128 Sources, 512 retained event ranges, and 256 Runs;
4. 100 Board posts, 100 Assignment schedules, and 100 approvals;
5. offline Device, disconnect before ACK, Durable Object eviction, D1 response loss, and Queue retry/dead-letter;
6. zero, one, and five dashboard sockets converging on the same authoritative D1 snapshot;
7. cleanup interrupted and replayed at every durable boundary;
8. Wrangler deployment dry-run and isolated remote Cloudflare E2E.

The main assertions are:

- protocol ping/pong creates zero `device.health`, Durable Object SQL writes, and alarms;
- unchanged idle state writes at most 300 D1 rows and 1,000 Durable Object base rows per Device per day;
- a DeviceRoom without pending work normally invokes no alarm and never exceeds 10/day;
- ACK-only rows and every hot table reach a retention bound after 24 hours;
- coalesced assistant text reconstructs the exact visible bytes;
- `durable_inbox` uses zero Queue operations;
- Queue mode emits at most 400 messages / 1,200 normal operations for 10,000 raw deltas;
- Message, Approval, terminal receipt, Change Set, Review, Baseline, and security evidence are never dropped or status-coalesced.

## Node batching and fleet budget probe

The following Node values are measured by the Rust unit test, not inferred
from Cloudflare account analytics:

| Node probe | Measured result |
|---|---:|
| 10,000 visible assistant deltas | 313 batches |
| Largest canonical batch payload in that probe | 6,889 bytes |
| Visible text reconstruction | exact byte-for-byte match |
| Health policy probe | 3 emissions: initial, unchanged checkpoint, state change |
| Default Node unchanged-health checkpoint | 10 minutes |
| Unchanged checkpoint wire identity | exact envelope replay; 0 new Node sequence/outbox row |

The health probe uses a five-minute test checkpoint to exercise all three
emission causes. It is not an eight-hour volume measurement. The eight-hour
fleet model below uses the configured ten-minute Node checkpoint (49 active
health observations including the initial observation) and the fifteen-minute
Free-profile Control Plane projection throttle (33 active projections).

The DeviceRoom owner counter contract used by the estimate is: a fresh
semantic health projection is charged at the measured nine-row upper bound;
an unchanged exact-envelope replay is charged only the one-row marker update
at the fifteen-minute D1 checkpoint; and the replay path creates no ACK or
alarm. These are conservative local counters, not Cloudflare account usage.
For one idle Device this produces 145 application health observations (one
fresh frame plus 144 exact replays), 97 D1 health projections including the
initial frame, 195 D1 rows written including one connection touch, 113
Durable Object base-row mutations including connection custody, and zero alarm
invocations. Each is asserted independently against the review limits of 300
D1 rows, 1,000 Durable Object rows, and 10 alarms per idle Device per day.
Control ACKs can advance the Node's applied-control frontier without forcing a
new health allocation; a subsequent non-ACK control application, ordinary
receipt, or reconciliation frame carries the newer frontier.

`batching::tests::free_profile_fleet_budget_stays_below_quarter_daily_quotas`
is a conservative arithmetic assertion for each fleet of 1, 5, and 10 idle
Devices over 24 hours plus one active eight-hour Run. The active Run contains
the measured 10,000-delta workload and 500 priority events, so its upper-bound
batch count is `313 + 500 = 813`. It charges every application frame as one
Worker request and one Durable Object request, and six Durable Object row
reads. Idle health writes use the DeviceRoom counter contract above; active
health and event frames retain the nine-row Durable Object base-mutation upper
bound. D1 event work is charged at three row reads per write. These are
estimates for a quota gate, not remote usage measurements. Free `durable_inbox`
Queue usage is zero; the final column shows the alternate Queue mode's three
operations per batch.

| Idle Devices | Worker requests (estimate) | D1 rows read (estimate) | D1 rows written (estimate) | DO requests (estimate) | DO rows read (estimate) | DO rows written (estimate) | Free Queue ops | Queue-mode ops (estimate) | Logs + traces (estimate) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,301 | 34,737 | 11,579 | 1,301 | 6,058 | 7,879 | 0 | 2,439 | 2,480 |
| 5 | 1,893 | 37,077 | 12,359 | 1,893 | 9,570 | 8,331 | 0 | 2,439 | 2,603 |
| 10 | 2,633 | 40,002 | 13,334 | 2,633 | 13,960 | 8,896 | 0 | 2,439 | 2,759 |
| 25% daily target | 25,000 | 1,250,000 | 25,000 | 25,000 | 1,250,000 | 25,000 | 2,500 | 2,500 | 50,000 |

All rows in this table pass the corresponding 25% target. The model does not
claim that protocol Ping/Pong consumes application usage: those control frames
are excluded, as required by the transport contract. Raw trace bytes remain
Device-local and are therefore not counted as a Cloudflare R2 write.

## Retention

### Permanent or long-lived

- Message and revision
- important Assignment and Run state plus terminal receipt
- Approval commitment and decision
- Change Set, Review, Baseline, and acceptance
- Artifact metadata
- security archive root and manifest

### Short-lived hot data

- transport exact rows, compact tombstones, and replay receipts
- unchanged health projection receipts
- published realtime outbox and Board fanout dedupe
- consumed or expired browser/OAuth challenges, codes, tokens, and enrollment transactions
- effect/idempotency records
- limiter windows, idempotency, and released/expired leases
- coalescible normalized streaming deltas

Hot records carry an indexed expiry or archival state. Cleanup operates in pages of 100–500 and continues only while backlog exists. Raw trace remains Device-local. `security_events` remains immutable; any future archive-and-prune requires a verified hash-chained R2 Standard segment receipt before a restrictive database trigger permits pruning.

## Public endpoints and assets

Pending Dynamic Client Registration, enrollment, and authentication records have short expiry, global and source-hash caps, bounded cleanup, deduplication where the protocol permits, and exponential `Retry-After` for repeated polling. Operators with Cloudflare WAF/rate rules should additionally rate-limit `/oauth/register`, `/api/v1/device-enrollments`, and invalid enrollment polls by source and account risk score; the application limits remain required when WAF is unavailable.

Setup, Login, Device, and dashboard shells and JavaScript are Workers Static Assets. `assets.run_worker_first` must remain unset/false. Dynamic authentication and API paths have no matching asset and enter the Worker. Worker Cache is not counted as a request-saving replacement for Static Assets.

## R2 and CPU

Use R2 Standard. Do not lifecycle small archives into Infrequent Access. Archive objects are compressed NDJSON segments per Run/day with a signed manifest, not one object per event. An artifact/archive retry performs `head` and validates exact digest, metadata, and size before deciding whether another PUT is necessary.

CPU probes include MCP tool/schema construction, canonical JSON, and wire-schema validation after warm-up. Module-global immutable schema and tool metadata is reused; request and actor state remains invocation-local. The release gate is p95 at most 8 ms on the Node 22 CI runtime, leaving headroom below the Workers Free 10 ms HTTP/Cron limit.

## Measurement record

The before probe is pinned to PR head `885b44b`; the after probe uses this optimization change. Unless a row says `model`, each number is an observed local/Miniflare counter rather than an extrapolated price.

| Scenario | Before (`885b44b`) | After | Counter source |
|---|---:|---:|---|
| Unchanged idle Device over 24 hours | 2,880 newly allocated health frames; at least 5,760 D1 writes and about 23,000--26,000 DO base-row mutations (`model`) | 1 fresh frame + 144 exact replays; 195 D1 writes, 113 DO mutations, 0 alarms (`conservative asserted model`); one measured due replay used 1 D1 write, 1 DO marker mutation, 0 new ACK rows, and 0 alarms | Baseline 30-second source cadence + old frame mutation model; after Rust allocation probe and instrumented DeviceRoom |
| 10,000 visible assistant deltas | 10,000 cloud frames / Queue messages and 30,000 normal Queue operations (`model`) | 313 batches, maximum 6,889 bytes, exact visible reconstruction; 939 normal Queue operations (`deterministic chunk model`) or 0 in Free `durable_inbox` | Rust batch measurement + serialized Queue chunk accounting |
| 10 Browser session validations | 20 D1 statements / 10 rows written | 11 D1 statements / 1 row written | D1 result metadata |
| 10 OAuth access-token validations | 20 D1 statements / 10 rows written | 11 D1 statements / 1 row written | D1 result metadata |
| 100 read-only limiter admissions | 100 idempotency rows, 1 request-window row, 1 token row, 1 zero-byte row | 0 idempotency/window/token/zero-byte rows; 1 fixed compact budget row | Durable Object SQL row counts |
| 32 due realtime projections in one Session | 32 BoardRoom RPCs | 1 `publishBatch` RPC; 4 D1 statements, max 5 parameters | Miniflare publisher counter + D1 proxy metadata |
| Artifact retry after R2 PUT / lost D1 response | 0 HEAD / 2 PUT | 2 HEAD / 1 PUT | Instrumented Miniflare R2 binding |
| Warm MCP registration + canonical JSON + wire validation | median 2 ms / p95 2 ms / max 4 ms | median 2 ms / p95 2 ms / max 4 ms | 100-sample Miniflare CPU probe after 20 warmups |
| Bounded hot-data cleanup | absent | 16 D1 statements / max 3 parameters; continuation only with backlog | Miniflare D1 metadata and interrupted-replay test |
| Empty Cron backstop | 1,440 invocations/day | 288 invocations/day | Parsed deployment configuration |
| 100,000 production invocations | 100,000 sampled logs; 5,000 sampled traces before span multiplier | 20,000 logs; 1,000 sampled traces before span multiplier | Parsed deployment configuration |

Additional after-only release gates exercise the production bindings and fault paths:

| Gate | Measured after result |
|---|---:|
| Empty DeviceRoom fleet, 1 / 5 / 10 rooms | 0 application messages, 0 SQL base-row mutations, 0 alarms; respectively 3 / 15 / 30 read-only SQL statements |
| One Worker-route `event.batch` including handshake, custody, projection, and ACK | 261 DO SQL statements, 1 alarm invocation; the subsequent auto-response probe added 0 SQL writes and 0 alarms |
| Queue poison retry | 6 D1 statements/binding calls, max 6 parameters, 3 rows written; 1 message, 1 chunk, 1 retry, 4 modeled Queue operations; valid siblings committed and one poison item isolated |
| Committed D1 response loss and replay | 4 D1 statements/binding calls, max 6 parameters; exact final event and trace-index cardinality retained |
| 100 Board posts | 700 total D1 statements, max 7 per invocation, max 7 parameters |
| 100 Assignment schedules with 128-Source fixtures | 3,000 total D1 statements, max 30 per invocation, max 22 parameters |
| 100 approvals | 1,300 total D1 statements, max 13 per invocation, max 8 parameters |
| Combined 300 production API invocations | 5,000 statements/binding calls, max 30 per invocation, max 22 parameters |
| 32 realtime projections | 1 BoardRoom RPC, 4 D1 statements, max 5 parameters |
| R2 PUT-success / D1-response-loss retry | 2 HEAD, 1 PUT |
| Warm CPU probe | 100 samples; median 2 ms, p95 2 ms, max 4 ms |

The exact probes are `apps/control-plane/test/device-room-steady-state.test.ts`, `free-cost-probe.test.ts`, `cost-fault-scenarios.test.ts`, `realtime-batch-budget.test.ts`, `r2-budget.test.ts`, `retention.test.ts`, and `cpu-budget.test.ts`. Baseline copies were run in a detached `885b44b` worktree with the same Miniflare runtime and fixtures. Queue operations are calculated from the measured serialized byte lengths and retry count because Miniflare does not expose Cloudflare billing operations. The fleet table above remains explicitly estimated; it is not presented as Cloudflare account analytics.
