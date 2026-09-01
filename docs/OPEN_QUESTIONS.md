# Open decisions

## Resolved contracts

### Authentication and authorization

The first-release identity, owner bootstrap, Passkey recovery, Device enrollment, MCP OAuth, Connector ceiling, Full Access, and rate-limit contracts are fixed in:

- `docs/AUTHORIZATION.md`
- `docs/adr/0006-separate-identities-and-server-side-connector-ceilings.md`
- `spec/schemas/auth-v1.schema.json`

Library selection, D1 migrations, endpoint implementation, and interoperability receipts remain implementation work. They must not change the identity separation or Connector-ceiling contract without a new ADR.

### Node transport and reconciliation

The handshake, persistent sequence model, operation admission, Device-local journal, Event replay, offline behavior, cancellation, approval delivery, Node restart, and reconciliation contracts are fixed in:

- `docs/NODE_PROTOCOL.md`
- `docs/adr/0007-durable-device-outbox-inbox-and-reconciliation.md`
- `spec/schemas/node-protocol-v1.schema.json`

The first implementation still needs concrete SQLite table layouts, compaction limits, Rust types, canonical JSON, and Cloudflare test harnesses. These choices must preserve the distinction between transport custody, operation admission, Runtime start, and terminal completion.

### Run Manifest and trace format

The immutable Run Manifest, Context Snapshot, normalized Event, evidence levels, instruction and Skill catalogs, content capture, local Segment storage, cursor, retention, verification, and OpenTelemetry export boundaries are fixed in:

- `docs/TRACE_FORMAT.md`
- `docs/OBSERVABILITY.md`
- `docs/adr/0008-immutable-manifest-and-local-content-custody.md`
- `spec/schemas/trace-v1.schema.json`

The Node protocol validates `event.batch` entries against Trace v1. Concrete SQLite migrations, raw-record binary encoding, Zstandard library selection, redaction implementation, and export code remain implementation work.

### Runtime Provider

The Native, Restricted Native, Container, and VM Provider boundary; lifecycle; deterministic Runtime identity; Capability Receipt; Workspace attachment; Credential Projection; resource and network reporting; collection; destruction; reconciliation; and local privilege boundaries are fixed in:

- `docs/RUNTIME_PROVIDER.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/adr/0009-runtime-provider-and-local-privilege-boundaries.md`
- `spec/schemas/runtime-v1.schema.json`

The first implementation still needs concrete Rust traits, the Linux Native supervisor, fake Providers, a Runtime Broker IPC, a Credential Broker, and storage reservation code. The Container and VM backends do not block the Native vertical slice.

## Blocks the first executable vertical slice

### Collaboration Session baseline and Change Set acceptance

Define exact Git branch and worktree behavior for:

- first Run in a Session
- proposed Change Set
- Reviewer Run
- fix Run on the proposal
- competing parallel proposals
- multi-Source integration
- Direct-mode divergence

The domain rules are fixed; exact Git commands and branch naming remain open.

### Codex Adapter import boundary

Identify what can be ported from OwnMesh and what must be rewritten. Prompt acceptance, continuation, cancellation, normalized Events, credential handling, and protocol-version evidence need explicit tests.

## Does not block the first vertical slice

### Control Plane data service split

D1 is the expected first store. Repository and service boundaries should allow a later PostgreSQL or local-Control-Plane implementation without defining a lowest-common-denominator schema now.

### Container backend

Docker and Podman remain candidates behind Runtime v1. Native and fake Providers can be implemented first.

### VM backend details

Incus with KVM/QEMU is the first Linux VM candidate. Storage driver, image-building workflow, Incus Project mapping, and Guest Agent transport can be decided before the VM vertical slice.

### Windows and macOS compute Providers

The Node protocol, Runtime schema, and domain model are portable. Equivalent isolation, process supervision, and Credential Projection do not block Linux work.

### Multi-user collaboration

The schema retains actor identity. Team roles, invitations, ownership transfer, and organizational policy are later work.

### Local-only Control Plane

Cloudflare is the standard first deployment. A local Control Plane Provider is a later compatibility target.

## Product decisions that need usability testing

- whether Project Agents appear above or beside running work in the right panel
- whether the UI calls execution records “Runs”, “Work”, or a translated user-facing term
- how much Assignment configuration appears inline with an `@` mention
- how Direct folder editing is explained without hiding risk or forcing a modal every time
- whether Questions and Additional Instructions use separate composers or one composer with an explicit mode
- default retention for completed Run Workspaces, raw logs, Containers, and VMs
- home-screen ordering of Needs attention, Working now, Projects, Scratch, and Devices

These should be tested with a stateful prototype rather than decided from static mockups alone.
