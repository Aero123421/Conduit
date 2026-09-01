# Repository instructions

## Current phase

The repository is defining the product model and the first Linux vertical slice. Changes that alter the domain model, authority boundaries, runtime isolation, credential handling, node transport, durable operation behavior, or trace format require an ADR.

## Sources of truth

- `docs/DOMAIN_MODEL.md`: entity names and relationships
- `docs/CONTROL_PLANE.md`: Cloudflare and Device responsibilities
- `docs/SOURCES_AND_WORKSPACES.md`: folders, repositories, Locations, and Run Workspaces
- `docs/RUNTIME_AND_SECURITY.md`: Access Scope, Approval Policy, credentials, and local privilege boundaries
- `docs/RUNTIME_PROVIDER.md`: Runtime Provider lifecycle, capability, Workspace, Credential Projection, and reconciliation contracts
- `docs/AUTHORIZATION.md`: owner, browser, OAuth client, Device, enrollment, Connector ceiling, and rate-limit contracts
- `docs/NODE_PROTOCOL.md`: Device connection, durable delivery, operation admission, offline behavior, and reconciliation
- `docs/TRACE_FORMAT.md`: immutable Run Manifest, Context Snapshot, normalized Event, local content, cursor, and retention contracts
- `docs/OBSERVABILITY.md`: debugging, reports, comparisons, and evaluation behavior
- `docs/MVP.md`: implementation order and acceptance criteria
- `spec/schemas/`: machine-checkable protocol and durable-record schemas

Do not introduce a second meaning for `Project`, `Session`, `Assignment`, `Run`, `Source`, `Location`, or `Runtime`.

## Required properties

- Projects are optional.
- A Run executes on exactly one Device.
- Native execution is a supported product path, not a fallback.
- Container and VM execution use the same Assignment and Source model as Native execution.
- Access Scope and Approval Policy are separate settings.
- Full User and Full Device access may be configured without hidden denials.
- The Device remains authoritative for local paths, credentials, processes, Containers, VMs, and raw logs.
- Cloudflare remains authoritative for shared collaboration metadata and intended work.
- A Device may continue an admitted Run while disconnected and must reconcile on reconnect.
- Agent claims are not verification. Tests, diffs, Artifacts, and receipts are recorded separately.
- Hidden model reasoning is never required for observability.
- Browser sessions, OAuth grants, Device keys, local IPC identities, and Agent-provider credentials remain separate.
- An MCP client cannot raise its own Connector ceiling.
- Transport delivery, node admission, Runtime start, Agent prompt acceptance, and terminal completion are separate receipts.
- Ambiguous effectful work is never automatically repeated.
- A Run Manifest is immutable after commit; later facts are Events or Context Snapshots.
- Skill and instruction use must retain evidence level; inferred behavior is not reported as explicit invocation.
- Runtime capability claims come from effective receipts, not from Provider names or installed binaries.
- Container and VM management sockets are never exposed inside Agent Runtimes.

## Implementation rules

- Prefer typed commands and protocol adapters over shell-generated control paths.
- Store canonical local paths only on the Device. Cloud records use opaque IDs and bounded display labels.
- Every side-effecting remote request needs an idempotency key and an exact target revision.
- Persist an operation or Message before acknowledging custody of it.
- Use persistent per-Device sequences across reconnects; connection epoch fences stale sockets.
- Never treat a WebSocket ACK or Queue delivery as proof that an operation ran.
- Persist the Run Manifest before requesting Runtime start.
- Reserve deterministic Runtime identity and Spec digest before creating a process, Container, or VM.
- Keep normalized Events bounded; use immutable Content Objects and raw Segments for larger data.
- Never expose a host Container or VM-management socket inside an Agent Runtime.
- Never mount an entire user home directory only to reuse Agent credentials.
- Unknown provider Events remain visible as bounded adapter errors; do not silently discard them.
- Raw logs and content capture are opt-in, bounded, redactable, and independently permissioned.
- Keep Linux behavior complete before claiming equivalent Windows or macOS support.
- Require fresh Passkey authentication before broadening Device, Connector, raw-log, credential, or Full Access authority.
- Do not accept OAuth bearer tokens as Device credentials or browser cookies at the MCP protected resource.
- Do not silently replace a missing required Runtime capability with a weaker Provider.
- Collect required Workspace changes, Artifacts, and trace receipts before ordinary Runtime destruction.
- Run `python scripts/validate_spec.py` after changing a schema or example.

## Documentation style

Write concrete behavior, state, constraints, and failure handling. Avoid product slogans, filler introductions, and claims that are not tied to an implemented or planned contract.
