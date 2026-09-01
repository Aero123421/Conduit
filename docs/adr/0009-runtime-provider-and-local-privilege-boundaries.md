# ADR 0009: Runtime Provider and local privilege boundaries

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit must execute ordinary Commands and coding Agents in several environments:

- directly on a user's everyday computer
- under lighter host restrictions
- in a Container
- in a VM

Native execution is a primary product path. VM execution is not the product's universal runtime.

The same Assignment and Run model must work across providers without pretending that all providers offer the same isolation, resource enforcement, credential behavior, lifecycle, or recovery.

Some configurations require host elevation. Container and VM management sockets can grant broad host authority and must not be exposed inside an Agent Runtime.

## Decision

### Common Runtime Provider contract

Every provider implements versioned operations for:

- capability probe
- admission estimate
- prepare
- start
- inspect
- guest operation
- signal
- snapshot
- collect
- destroy
- reconciliation

The Provider receives typed, already-authorized Source attachments, Credential Projection descriptors, resource requests, network policy, lifecycle policy, and Launch Plan.

### Native is first class

Native runs under the signed-in user by default. Full User access is represented directly and does not claim filesystem or kernel isolation.

A persistent user-level supervisor owns process-tree identity and continues to provide recovery evidence after `conduit-node` restarts.

### Restricted Native is capability-based

Restricted Native can combine Landlock, namespaces, systemd resource control, seccomp, a dedicated identity, and network enforcement.

The Provider reports actual effective mechanisms. It does not market one preset as equivalent to a Container or VM when required controls are unavailable.

### Container and VM management boundary

A local Runtime Broker can hold Docker, Podman, Incus, or another provider connection and accepts only typed Conduit requests.

Provider management sockets are not mounted into Agent Runtimes.

Rootless Container operation is preferred where compatible, but rootless status alone is not a complete isolation or resource-enforcement claim.

Incus with KVM/QEMU is the first Linux VM candidate. The domain contract does not depend on Incus.

### Optional privileged helper

Host elevation uses a separate networkless local helper with a narrow typed protocol.

The helper:

- is installed or enabled locally
- does not accept arbitrary shell text
- does not accept arbitrary file paths or environment maps
- does not hold OAuth or Agent-provider credentials
- returns bounded operation and process receipts

Remote Full Device authority cannot install or enable the helper.

### Guest Agent

VM and selected Container implementations can use a Guest Agent for process supervision, Events, Artifacts, and filesystem operations.

The active Guest transport is reported. A provider-specific exec path can be used before a Conduit Guest Agent exists.

### Structured Agent I/O

Agent protocol framing is separate from process creation. The Node asks the
selected Runtime Provider for an interactive pipes boundary only after durable
admission and Runtime reservation. Restricted Native returns a process inside
its effective namespace/cgroup wrapper, Docker and Podman return an attached
container-main-process client, and Incus returns an attached `incus exec`
client after a per-VM agent probe. The Adapter layer may read and write the
child pipes but cannot construct provider commands or receive a management
socket.

Container and VM adapter executables are fixed by the Device-owned runtime
image contract (`/usr/local/bin/<adapter>`); a remote operation cannot select a
guest executable. Host executable digests are not reused as guest executable
claims. Incus records the host CLI session plus LaunchPlan digest separately
from guest process identity. Because current Incus exec receipts do not expose
a stable guest PID, guest process identity is reported degraded and restart
reconciliation fails closed rather than claiming attachment.

Read-only workspace flags remain part of the typed attachment through this
boundary. Container providers use read-only bind mounts, Incus uses named
per-Run disk devices with `readonly=true`, and Restricted Native requires an
effective read-only filesystem boundary. A Reviewer role is rejected by the
Node unless its Access Scope and every Source revision are read-only and the
provider is an enforcing Restricted Native, Container, or VM provider.

Exit of an attached Adapter client is not proof that a Container or VM Runtime
stopped. Before committing an ordinary Agent terminal receipt or completing a
cancel, the Node signals the owning Provider and confirms a stopped, failed, or
lost state; inspection failures leave cleanup unconfirmed and fail closed. On
Node restart, an Agent that lacks a durable attachable protocol session is not
replayed. The Node fences the exact recorded process identity, records whether
that fence was confirmed in the `recovery_required` receipt, and keeps an
unconfirmed or ambiguous fence explicit rather than claiming successful
cleanup.

### Runtime identity and idempotency

Every Runtime has a Conduit Runtime ID and immutable Spec digest. Provider objects carry or bind both values.

- same ID and digest: inspect or replay the durable receipt
- same ID and different digest: fail
- similar name without Conduit identity: external or recovery-required

Start is never an untracked shell command.

### Workspace custody

The Workspace Manager creates Direct, worktree, managed-copy, or read-only Run Workspaces before Provider preparation.

Providers expose only declared attachments and return the actual mechanism and consistency model.

### Credential custody

A Credential Broker produces opaque, Agent-specific projection descriptors. Providers never receive unrestricted access to a user's home or general credential store.

A full home-directory mount is not used merely to reuse an Agent login.

### Full Access

Full User, Full Device, and Never Ask remain valid.

- Native Full User: ordinary signed-in user authority
- Native Full Device: locally configured elevation path
- Container Full Access: root inside the Container, no undeclared host access
- VM Full Access: root or administrator inside the guest, no undeclared host access

The UI shows Runtime boundary and host authority separately.

### Truthful capability receipts

Capabilities are reported as supported, effective, degraded, or unavailable with evidence and reason codes.

Presence of a Provider binary or configuration setting does not prove that a limit, mount mode, network rule, Guest Agent, snapshot, or recovery path works.

## Rejected alternatives

### VM-only execution

Rejected because Conduit must work on everyday PCs with existing tools, credentials, GUI applications, devices, and folders. VM is one provider.

### Native only

Rejected because isolated parallel work, guest root, destructive experiments, environment reproducibility, and archivable machines need stronger boundaries.

### One provider interface made from arbitrary command strings

Rejected because it would move authorization and provider-specific parsing into model-controlled text and would not support reliable reconciliation.

### Mount Docker or Incus socket into the Agent environment

Rejected because it grants control over host-managed runtimes and defeats the isolation boundary.

### Run `conduit-node` as root

Rejected. Network-facing transport and broad host authority remain separate.

### Treat rootless Container as fully isolated

Rejected because mount exposure, kernel sharing, daemon setup, cgroup behavior, network enforcement, and device access remain separate concerns.

### Automatically fall back to a weaker Runtime

Rejected. Missing required capability fails admission. A user or policy can explicitly choose a weaker provider.

### Destroy Runtime after Agent completion without collection

Rejected because uncommitted Workspace changes, raw traces, login state, or Artifacts may still be held only by the Runtime.

## Consequences

- Runtime lifecycle and Run lifecycle remain separate.
- Provider code needs deterministic identity, durable receipts, and fake-provider tests.
- Linux Native is implemented before Container and VM.
- Device setup can add Container, VM, and privileged-helper capability later.
- Dashboard states must show Runtime kind, effective isolation, access scope, and approval mode together.
- Agent Adapter code cannot call Docker, Podman, Incus, or host elevation directly.
- Interactive Agent protocol pipes are created by Runtime Providers; protocol
  normalization does not acquire provider authority.
- Storage and collection checks can block Runtime destruction.
- Windows and macOS Providers can implement the same contract without claiming feature parity.

## Contract

- `docs/RUNTIME_PROVIDER.md`
- `spec/schemas/runtime-v1.schema.json`
- `spec/examples/runtime/`
