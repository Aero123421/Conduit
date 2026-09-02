# Repository instructions

## Current phase

The repository is defining the product model and the first Linux vertical slice. Changes that alter the domain model, authority boundaries, runtime isolation, credential handling, or trace format require an ADR.

## Sources of truth

- `docs/DOMAIN_MODEL.md`: entity names and relationships
- `docs/CONTROL_PLANE.md`: Cloudflare and device responsibilities
- `docs/SOURCES_AND_WORKSPACES.md`: folders, repositories, locations, and run workspaces
- `docs/RUNTIME_AND_SECURITY.md`: runtime providers, access, approvals, and credentials
- `docs/OBSERVABILITY.md`: run manifests, events, logs, and evaluations
- `docs/MVP.md`: implementation order and acceptance criteria

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

## Implementation rules

- Prefer typed commands and protocol adapters over shell-generated control paths.
- Store canonical local paths only on the device. Cloud records use opaque IDs and bounded display labels.
- Every side-effecting remote request needs an idempotency key and an exact target revision.
- Never expose a host container or VM-management socket inside an agent runtime.
- Never mount an entire user home directory only to reuse agent credentials.
- Unknown provider events remain visible as bounded adapter errors; do not silently discard them.
- Raw logs and content capture are opt-in, bounded, redactable, and independently permissioned.
- Keep Linux behavior complete before claiming equivalent Windows or macOS support.

## Documentation style

Write concrete behavior, state, constraints, and failure handling. Avoid product slogans, filler introductions, and claims that are not tied to an implemented or planned contract.
