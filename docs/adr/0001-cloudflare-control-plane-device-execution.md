# ADR 0001: Cloudflare control plane and device-local execution

- Status: Accepted
- Date: 2026-09-01

## Decision

The standard Conduit deployment uses a Cloudflare control plane. Every managed computer runs `conduit-node` and connects outbound.

Cloudflare stores collaboration and desired-work metadata. Devices remain authoritative for local files, canonical paths, credentials, processes, runtime instances, raw logs, and heavy artifacts not explicitly uploaded.

An admitted run may continue while disconnected. The device journals events and terminal receipts and reconciles after reconnect. New remote work cannot start on an offline device.

## Reasons

- no inbound port is required on personal computers or servers
- projects and boards remain available when any one device is offline
- multiple devices are peers rather than one user-managed parent computer
- local credentials and large runtime data do not need to be centralized
- Cloudflare already provides the required HTTP, WebSocket, durable metadata, queue, and optional object-storage primitives

## Consequences

- the system is not strongly consistent across control-plane intent and live device state during disconnection
- run state needs explicit reconciliation and an `uncertain` outcome
- control-plane timeouts cannot prove non-execution
- device-local journals and idempotency are required from the first executable version
- a future local-only control plane must implement the same application contracts rather than becoming a special device mode

## Rejected alternatives

### First registered computer as the permanent central hub

Rejected because another registered device would depend on that computer being online and reachable. Moving the hub would also become a user-visible operational task.

### Store project files and VM disks in Cloudflare

Rejected as the default because the data volume, latency, credential boundary, and local-hardware use do not match the product's normal execution path.

### Stop all runs when the control plane disconnects

Rejected because long-running local work should not fail due to dashboard or Internet availability. Approval boundaries still fail closed when no prior authorization exists.
