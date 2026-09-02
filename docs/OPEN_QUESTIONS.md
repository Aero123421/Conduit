# Open decisions

## Resolved contracts

### Authentication and authorization

The first-release identity, owner bootstrap, passkey recovery, device enrollment, MCP OAuth, connector ceiling, Full Access, and rate-limit contracts are fixed in:

- `docs/AUTHORIZATION.md`
- `docs/adr/0006-separate-identities-and-server-side-connector-ceilings.md`
- `spec/schemas/auth-v1.schema.json`

Library selection, D1 migrations, endpoint implementation, and interoperability receipts remain implementation work. They must not change the identity separation or connector-ceiling contract without a new ADR.

### Node transport and reconciliation

The handshake, persistent sequence model, operation admission, device-local journal, event replay, offline behavior, cancellation, approval delivery, node restart, and reconciliation contracts are fixed in:

- `docs/NODE_PROTOCOL.md`
- `docs/adr/0007-durable-device-outbox-inbox-and-reconciliation.md`
- `spec/schemas/node-protocol-v1.schema.json`

The first implementation still needs concrete SQLite table layouts, compaction limits, Rust types, canonical JSON, and Cloudflare test harnesses. These choices must preserve the distinction between transport custody, operation admission, runtime start, and terminal completion.

### Run Manifest and trace format

The immutable Run Manifest, Context Snapshot, normalized Event, evidence levels, instruction and Skill catalogs, content capture, local Segment storage, cursor, retention, verification, and OpenTelemetry export boundaries are fixed in:

- `docs/TRACE_FORMAT.md`
- `docs/OBSERVABILITY.md`
- `docs/adr/0008-immutable-manifest-and-local-content-custody.md`
- `spec/schemas/trace-v1.schema.json`

The node protocol now validates `event.batch` entries against Trace v1. Concrete SQLite migrations, raw-record binary encoding, Zstandard library selection, redaction implementation, and export code remain implementation work.

## Blocks the first executable vertical slice

### Collaboration-session baseline and change-set acceptance

Define exact Git branch/worktree behavior for:

- first run in a session
- proposed change set
- reviewer run
- fix run on the proposal
- competing parallel proposals
- multi-source integration
- direct-mode divergence

The domain rules are fixed; exact Git commands and branch naming remain open.

### Runtime-provider interface

Choose the Rust traits and process boundaries for native, restricted-native, container, and VM providers. Decide which operations belong in `conduit-node`, a privileged helper, and a guest agent.

### Codex adapter import boundary

Identify what can be ported from OwnMesh and what must be rewritten. Prompt acceptance, continuation, cancellation, normalized events, credential handling, and protocol-version evidence need explicit tests.

## Does not block the first vertical slice

### Control-plane data service split

D1 is the expected first store. Repository and service boundaries should allow a later PostgreSQL or local-control-plane implementation without defining a lowest-common-denominator schema now.

### Container backend

Docker and Podman are both candidates. The first RuntimeProvider contract can use fake providers and Native execution before selecting the production Container backend.

### VM backend details

Incus/KVM is the Linux default candidate. Storage driver, image-building workflow, Project mapping, and Guest Agent transport can be decided before the VM vertical slice.

### Windows and macOS compute providers

The node protocol and domain model must be portable. Equivalent runtime isolation and credential projection do not block Linux work.

### Multi-user collaboration

The schema should retain actor identity. Team roles, invitations, ownership transfer, and organizational policy are later work.

### Local-only control plane

Cloudflare is the standard first deployment. A local Control Plane provider is a later compatibility target.

## Product decisions that need usability testing

- whether Project Agents appear above or beside running work in the right panel
- whether the UI calls execution records “Runs”, “Work”, or a translated user-facing term
- how much Assignment configuration appears inline with an `@` mention
- how Direct folder editing is explained without hiding the risk or forcing a modal every time
- whether Questions and Additional Instructions use separate composers or one composer with an explicit mode
- default retention for completed Run Workspaces, raw logs, Containers, and VMs
- home-screen ordering of Needs attention, Working now, Projects, Scratch, and Devices

These should be tested with a stateful prototype rather than decided from static mockups alone.
