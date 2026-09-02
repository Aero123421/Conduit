# Control plane and devices

## Topology

The standard deployment uses a Cloudflare control plane and one or more outbound-connected devices.

```text
Browser / CLI / MCP
        │
        ▼
Cloudflare control plane
        │
        ├── conduit-node on Linux
        ├── conduit-node on Windows
        └── conduit-node on macOS
```

A device does not need an inbound port. The browser does not connect directly to a device for normal operation.

## Cloudflare responsibilities

The control plane owns:

- owner authentication and client authorization
- project, session, board, and context metadata
- project-agent definitions
- assignments and intended run configuration
- device registry and last observed presence
- connector permissions and rate-limit configuration
- shared run status and bounded summaries
- artifact metadata and optional uploaded artifacts
- observability indexes and aggregate reports

Expected components:

- Workers for HTTP APIs, dashboard backend, OAuth/MCP, and admission checks
- Workers Static Assets for Setup, Login, Device, and Dashboard shells; asset-first routing keeps those requests out of Worker execution
- D1 for durable collaboration and configuration records
- Durable Objects for live device routing, presence, realtime session fan-out, compact Connector budgets, and the singleton minimum-due retry alarm
- the DeviceRoom durable inbox for Free-profile normalized-event custody; Queue mode keeps one complete Node batch per asynchronous Queue message
- R2 only for explicitly uploaded artifacts, compressed log chunks, exports, or backups

Durable Object memory is never authoritative. Important state must survive hibernation and eviction in D1 or Durable Object storage. Per-connection metadata required after hibernation is attached to the WebSocket.

`CLOUDFLARE_USAGE_PROFILE` selects `free` or `standard` batching, unchanged-health checkpoints, ingestion transport, retention page sizes, sampling, and Cron backstop intervals. The profile does not change authorization, approval, stale-epoch fencing, idempotency conflicts, exact-target control, or evidence retention. Unknown profile values fail closed. The deployment template defaults to Free and its measured release gates are defined in `docs/CLOUDFLARE_FREE_TIER_BUDGET.md`.

References:

- <https://developers.cloudflare.com/durable-objects/best-practices/websockets/>
- <https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/>

## Device responsibilities

`conduit-node` owns:

- canonical source paths and filesystem identity
- source discovery and Git observations
- agent adapter discovery, version, and authentication observations
- command, process, PTY, container, and VM execution
- local policy enforcement
- local idempotency and run journal
- credential storage and projection
- raw command output and provider protocol logs
- local artifacts and retention
- resource and storage accounting
- runtime reconciliation after restart

A Cloudflare authorization decision cannot override a local denial or device resource limit.

## Data placement

| Data | Control plane | Device |
|---|---|---|
| Project and session metadata | authoritative | optional cache |
| Board messages | authoritative | queued outbound copies while offline |
| Assignment intent | authoritative | admitted copy and journal |
| Run desired configuration | authoritative | admitted immutable manifest |
| Run process/VM state | last observation | authoritative |
| Canonical local paths | opaque ID and display label only | authoritative |
| Source files and worktrees | no | authoritative |
| Agent credentials | no | authoritative |
| Raw provider events and command logs | index/reference or optional upload | authoritative |
| VM disks and container layers | no | authoritative |
| Change-set metadata | authoritative references | verified source data |
| Artifacts | metadata; optional R2 copy | authoritative until uploaded or exported |

## Admission and idempotency

Every side-effecting remote request contains:

- operation ID
- idempotency key
- actor and client identity
- target device
- project/session/assignment/run identifiers where applicable
- exact source-location and configuration revisions
- access scope and approval policy
- issue and expiry timestamps
- payload digest

The device journals admission before starting an external effect. A repeated request with the same key and digest replays its receipt. The same key with another digest is rejected. An admitted operation without authoritative completion evidence is never silently repeated.

## Offline behavior

After a run is admitted and journaled, a device may continue it without the control plane.

While disconnected, the device:

- continues existing processes, containers, and VMs according to local policy
- stores normalized events and raw logs locally
- records questions and approval requests but cannot invent approval
- stops at an approval boundary if no valid pre-authorization exists
- stores terminal receipts and artifacts locally

On reconnect, the device sends a bounded reconciliation summary followed by missing event ranges.

The control plane compares:

- intended run state
- device journal state
- runtime-provider state
- guest/agent process state
- terminal receipts

Ambiguous side effects produce `uncertain` or `recovery_required`, not an automatic rerun.

## New work while offline

Remote clients cannot start new work on a disconnected device. A local dashboard or CLI may start an explicitly local scratch run while the control plane is unavailable. Such a run receives a device-generated ID and is imported when connectivity returns.

Project collaboration changes require the control plane. The local UI must distinguish local scratch work from synchronized project work.

## Device selection

The scheduler filters devices by:

- required source locations
- operating system and architecture
- available agent adapter and supported version
- authentication status
- runtime-provider capability
- requested CPU, memory, storage, GPU, or attached hardware
- local policy and connector ceiling
- current capacity
- project-agent defaults

The scheduler may recommend a device. The admitted run records the exact selected device; it does not migrate implicitly after work starts.

## Rate limits

MCP and other external clients have an outer transport limit and an exact application limit.

Application limits are evaluated by client, principal, device, project, and operation class. They include request rate, weighted operation budget, concurrent commands, concurrent agents, VM starts, maximum runtime, log bytes, and response size.

The device enforces its own final concurrency, memory, storage, and runtime limits even if the control plane admits a request.
