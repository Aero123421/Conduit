# Open decisions

## Resolved contracts

### Authentication and authorization

The first-release identity, owner bootstrap, passkey recovery, device enrollment, MCP OAuth, connector ceiling, Full Access, and rate-limit contracts are fixed in:

- `docs/AUTHORIZATION.md`
- `docs/adr/0006-separate-identities-and-server-side-connector-ceilings.md`
- `spec/schemas/auth-v1.schema.json`

Library selection, D1 migrations, endpoint implementation, and interoperability receipts remain implementation work. They must not change the identity separation or connector-ceiling contract without a new ADR.

## Blocks the first executable vertical slice

### Node transport and reconciliation protocol

Define handshake message encoding, sequence numbers, operation admission, event replay, local journal format, and reconnect reconciliation.

Device identity, enrollment, challenge authentication, connection epochs, key rotation, and revocation are already defined by the authorization contract. The transport work must cover control-plane disconnect, node restart, duplicate admission, late terminal result, and device clock skew.

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

### Trace schema version 1

Freeze the first run manifest and event envelope before the Codex vertical slice. Decide local chunk format, compression, cursors, content redaction, and event commitments sent to Cloudflare.

## Does not block the first vertical slice

### Control-plane data service split

D1 is the expected first store. Repository/service boundaries should allow a later PostgreSQL or local-control-plane implementation without defining a lowest-common-denominator schema now.

### Container backend

Docker and Podman are both candidates. The first runtime-provider contract can use fake providers and native execution before selecting the production container backend.

### VM backend details

Incus/KVM is the Linux default candidate. Storage driver, image-building workflow, project mapping, and guest-agent transport can be decided before the VM vertical slice.

### Windows and macOS compute providers

The node protocol and domain model must be portable. Equivalent runtime isolation and credential projection do not block Linux work.

### Multi-user collaboration

The schema should retain actor identity. Team roles, invitations, ownership transfer, and organizational policy are later work.

### Local-only control plane

Cloudflare is the standard first deployment. A local control-plane provider is a later compatibility target.

## Product decisions that need usability testing

- whether project agents appear above or beside running work in the right panel
- whether the UI calls execution records “Runs”, “Work”, or a translated user-facing term
- how much assignment configuration appears inline with an `@` mention
- how direct-folder editing is explained without hiding the risk or forcing a modal every time
- whether Questions and Additional Instructions use separate composers or one composer with an explicit mode
- default retention for completed run workspaces, raw logs, containers, and VMs
- home-screen ordering of Needs attention, Working now, Projects, Scratch, and Devices

These should be tested with a stateful prototype rather than decided from static mockups alone.
