# Repository instructions

## Current phase

The repository is defining the product model and the first Linux vertical slice. Changes that alter the domain model, authority boundaries, runtime isolation, credential handling, node transport, durable operation behavior, or trace format require an ADR.

## Sources of truth

- `docs/DOMAIN_MODEL.md`: entity names and relationships
- `docs/CONTROL_PLANE.md`: Cloudflare and device responsibilities
- `docs/SOURCES_AND_WORKSPACES.md`: folders, repositories, locations, and run workspaces
- `docs/RUNTIME_AND_SECURITY.md`: runtime providers, access, approvals, and credentials
- `docs/AUTHORIZATION.md`: owner, browser, OAuth client, device, enrollment, connector ceiling, and rate-limit contracts
- `docs/NODE_PROTOCOL.md`: device connection, durable delivery, operation admission, offline behavior, and reconciliation
- `docs/TRACE_FORMAT.md`: immutable Run Manifest, Context Snapshot, normalized Event, local content, cursor, and retention contracts
- `docs/OBSERVABILITY.md`: debugging, reports, comparisons, and evaluation behavior
- `docs/MVP.md`: implementation order and acceptance criteria
- `spec/schemas/`: machine-checkable protocol and durable-record schemas

Do not introduce a second meaning for `Project`, `Session`, `Assignment`, `Run`, `Source`, or `Location`.

## Required properties

- Projects are optional.
- A run executes on exactly one device.
- Native execution is a supported product path, not a fallback.
- Container and VM execution use the same assignment and source model as native execution.
- Access scope and approval policy are separate settings.
- Full user and full device access may be configured without hidden denials.
- The device remains authoritative for local paths, credentials, processes, containers, VMs, and raw logs.
- Cloudflare remains authoritative for shared collaboration metadata and intended work.
- A device may continue an admitted run while disconnected and must reconcile on reconnect.
- Agent claims are not verification. Tests, diffs, artifacts, and receipts are recorded separately.
- Hidden model reasoning is never required for observability.
- Browser sessions, OAuth grants, device keys, local IPC identities, and agent-provider credentials remain separate.
- An MCP client cannot raise its own connector ceiling.
- Transport delivery, node admission, runtime start, and terminal completion are separate receipts.
- Ambiguous effectful work is never automatically repeated.
- A Run Manifest is immutable after commit; later facts are Events or Context Snapshots.
- Skill and instruction use must retain evidence level; inferred behavior is not reported as explicit invocation.

## Implementation rules

- Prefer typed commands and protocol adapters over shell-generated control paths.
- Store canonical local paths only on the device. Cloud records use opaque IDs and bounded display labels.
- Every side-effecting remote request needs an idempotency key and an exact target revision.
- Persist an operation or message before acknowledging custody of it.
- Use persistent per-device sequences across reconnects; connection epoch fences stale sockets.
- Never treat a WebSocket ACK or queue delivery as proof that an operation ran.
- Persist the Run Manifest before requesting Runtime start.
- Keep normalized Events bounded; use immutable Content Objects and raw Segments for larger data.
- Never expose a host container or VM-management socket inside an agent runtime.
- Never mount an entire user home directory only to reuse agent credentials.
- Unknown provider events remain visible as bounded adapter errors; do not silently discard them.
- Raw logs and content capture are opt-in, bounded, redactable, and independently permissioned.
- Keep Linux behavior complete before claiming equivalent Windows or macOS support.
- Require fresh passkey authentication before broadening device, connector, raw-log, credential, or full-access authority.
- Do not accept OAuth bearer tokens as device credentials or browser cookies at the MCP protected resource.
- Run `python scripts/validate_spec.py` after changing a schema or example.

## Documentation style

Write concrete behavior, state, constraints, and failure handling. Avoid product slogans, filler introductions, and claims that are not tied to an implemented or planned contract.
