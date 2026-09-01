# Resolved contracts and remaining product decisions

## Resolved contracts

### Authentication and authorization

The first-release identity, owner bootstrap, Passkey recovery, Device enrollment, MCP OAuth, Connector ceiling, Full Access, and rate-limit contracts are fixed in:

- `docs/AUTHORIZATION.md`
- `docs/adr/0006-separate-identities-and-server-side-connector-ceilings.md`
- `spec/schemas/auth-v1.schema.json`

The Linux control plane implements these contracts with D1 migrations,
passkey/CSRF browser sessions, owner CLI tokens, Device Ed25519 identity, OAuth
2.1 + PKCE, immutable Connector Policy revisions and exact limiter receipts.
Changing the identity separation or Connector ceiling still requires a new ADR.

### Node transport and reconciliation

The handshake, persistent sequence model, operation admission, Device-local journal, Event replay, offline behavior, cancellation, approval delivery, Node restart, and reconciliation contracts are fixed in:

- `docs/NODE_PROTOCOL.md`
- `docs/adr/0007-durable-device-outbox-inbox-and-reconciliation.md`
- `spec/schemas/node-protocol-v1.schema.json`

The Linux Node and Worker implement the SQLite journal, bounded frames, JCS
digests, ACK/replay, connection epochs, event gaps and summary/plan/complete
reconciliation. Fault tests preserve the distinction between transport custody,
operation admission, Runtime start and terminal completion.

### Run Manifest and trace format

The immutable Run Manifest, Context Snapshot, normalized Event, evidence levels, instruction and Skill catalogs, content capture, local Segment storage, cursor, retention, verification, and OpenTelemetry export boundaries are fixed in:

- `docs/TRACE_FORMAT.md`
- `docs/OBSERVABILITY.md`
- `docs/adr/0008-immutable-manifest-and-local-content-custody.md`
- `spec/schemas/trace-v1.schema.json`

The Node protocol validates `event.batch` entries against Trace v1. The
Device-local store implements authenticated redaction, chained segments,
bounded cursors, partial recovery and OpenTelemetry export. Upload and retention
remain explicit policy decisions rather than an implicit cloud copy.

### Runtime Provider

The Native, Restricted Native, Container, and VM Provider boundary; lifecycle; deterministic Runtime identity; Capability Receipt; Workspace attachment; Credential Projection; resource and network reporting; collection; destruction; reconciliation; and local privilege boundaries are fixed in:

- `docs/RUNTIME_PROVIDER.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/adr/0009-runtime-provider-and-local-privilege-boundaries.md`
- `spec/schemas/runtime-v1.schema.json`

The Linux implementation provides the shared Rust trait, Native supervisor,
Restricted Native controls, Docker/Podman and Incus providers, encrypted
Credential Broker and quota/custody-aware storage. Capability receipts remain
truthful: a missing daemon, KVM, guest agent or enforcement mechanism is
reported as unavailable rather than simulated.

## Resolved implementation choices

### Collaboration Session baseline and Change Set acceptance

The workspace implementation fixes exact Git branch and worktree behavior for:

- first Run in a Session
- proposed Change Set
- Reviewer Run
- fix Run on the proposal
- competing parallel proposals
- multi-Source integration
- Direct-mode divergence

The accepted conventions are versioned in workspace receipts and protected by
repository identity, lease and compare-and-swap tests.

### Codex Adapter import boundary

The adapter boundary was rewritten around Conduit domain types. Prompt
acceptance, continuation, cancellation, normalized Events, credential handling
and protocol-version evidence have structured fixtures; live paid inference is
an explicit operator action.

## Does not block the first vertical slice

### Control Plane data service split

D1 is the expected first store. Repository and service boundaries should allow a later PostgreSQL or local-Control-Plane implementation without defining a lowest-common-denominator schema now.

### Container backend

Docker and Podman implement Runtime v1 behind the same typed provider boundary.
Daemon-backed conformance remains a host-specific live check.

### VM backend details

Incus with KVM/QEMU is the Linux VM provider. The selected image, storage
driver, Incus Project and guest transport are deployment configuration and are
recorded in capability/runtime receipts.

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
