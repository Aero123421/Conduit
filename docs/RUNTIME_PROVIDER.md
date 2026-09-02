# Runtime Provider contract

## Scope

A Runtime Provider turns one admitted Run into a managed execution environment on one Device.

The first contract covers:

- Native
- Restricted Native
- Container
- VM

Project and Scratch Runs use the same interface. A Project is not required.

The provider does not decide Assignment authority, Source identity, Project policy, or Agent behavior. It receives already-authorized, revision-bound inputs and returns observed capabilities and lifecycle receipts.

## Components

### `conduit-node`

User-level Device service.

Responsibilities:

- Cloudflare node transport
- operation admission
- local policy
- Run journal
- Source Location resolution
- Run Workspace creation
- Runtime Provider selection
- Agent Adapter orchestration
- normalized Events
- Artifact and trace custody

`conduit-node` does not run as root.

### Native supervisor

Persistent user-level process supervision used by Native and Restricted Native.

Responsibilities:

- reserve deterministic Runtime ID before spawn
- launch exact argv without shell reconstruction
- retain process-tree identity across node restart
- capture stdout, stderr, exit, signals, and resource observations
- graceful and forced stop
- reconcile PID plus process-birth identity

The supervisor can be a service owned by `conduit-node` or a separate local process. Its durable identity is part of the contract.

### Runtime broker

Optional local-only service for Container and VM backends.

Responsibilities:

- hold Docker, Podman, Incus, or another management connection
- accept typed Runtime requests from `conduit-node`
- reject arbitrary provider API calls
- persist provider operation and object identity
- return bounded receipts

The provider management socket is never mounted or forwarded into an Agent Runtime.

### Privileged helper

Optional networkless root service for host-level elevation.

Responsibilities are deliberately narrow:

- elevated Native process launch from a typed, pre-authorized spec
- process-tree signal and termination
- selected host-administration operations defined by versioned capability
- ownership and permission repair for Conduit-managed paths

It does not accept arbitrary shell text, arbitrary environment maps, arbitrary
file paths, OAuth tokens, Cloudflare connections, or a provider-management
socket. The Linux `privileged-native` Provider talks to it over an authenticated
per-UID `SOCK_SEQPACKET` connection. Effectful calls carry a one-use signed
ticket for `prepare`, `start`, `input`, `resize_pty`, `pause`, `resume`,
`graceful_stop`, or `force_stop`. Read-only inspect/stream replay still requires
the authenticated peer and an exact Runtime handle.

Prepare binds the immutable local execution plan and passed descriptor manifest,
then returns durable `admitted` and `prepared` receipts. Start creates a
deterministically named transient systemd service through the fixed exec worker
and returns distinct `unit_created` and `running` receipts. Controls bind Runtime,
unit, Invocation ID, controller epoch, expected helper state revision, Runtime
handle digest, and control-request digest. The Provider preserves the entire
helper receipt chain; it does not translate root evidence into an unsigned
generic Provider claim.

After helper or Node restart, reconciliation compares the root journal with the
systemd unit, Invocation ID, cgroup, PID/process-birth identity, stream cursors,
and last signed receipt. A matching object may be reattached only when Adapter
protocol custody is also recoverable. Otherwise the Runtime is retained under
explicit `recovery_required` custody and no prompt, start, or effectful control
is repeated automatically.

Installing or enabling the helper is a local Device setup action. Remote MCP authority cannot install it.

### Guest Agent

Optional service inside a VM and, where useful, inside a Container.

Responsibilities:

- guest liveness
- exact command and Agent launch
- process-tree supervision
- Event and raw-stream forwarding
- guest filesystem and Artifact operations
- guest resource and environment observations

The provider reports whether Guest Agent communication uses provider exec, vsock, virtio serial, a private Unix socket, or another transport. It does not label unauthenticated network SSH as a trusted Guest Agent channel.

## Provider interface

The Rust interface exposes typed requests and receipts equivalent to:

```rust
pub trait RuntimeProvider: Send + Sync {
    fn provider_id(&self) -> RuntimeProviderId;

    async fn probe(
        &self,
        context: ProbeContext,
    ) -> Result<CapabilityReceipt, RuntimeError>;

    async fn estimate(
        &self,
        request: RuntimeRequest,
    ) -> Result<AdmissionEstimate, RuntimeError>;

    async fn prepare(
        &self,
        request: RuntimeRequest,
        workspace: RunWorkspaceDescriptor,
        credentials: Vec<CredentialProjectionDescriptor>,
    ) -> Result<PreparedRuntimeReceipt, RuntimeError>;

    async fn start(
        &self,
        prepared: PreparedRuntimeHandle,
        launch: LaunchPlan,
    ) -> Result<RuntimeStateReceipt, RuntimeError>;

    async fn inspect(
        &self,
        handle: RuntimeHandle,
    ) -> Result<RuntimeStateReceipt, RuntimeError>;

    async fn exec(
        &self,
        handle: RuntimeHandle,
        operation: GuestOperation,
    ) -> Result<GuestOperationReceipt, RuntimeError>;

    async fn signal(
        &self,
        handle: RuntimeHandle,
        signal: RuntimeSignal,
    ) -> Result<RuntimeStateReceipt, RuntimeError>;

    async fn snapshot(
        &self,
        handle: RuntimeHandle,
        request: SnapshotRequest,
    ) -> Result<SnapshotReceipt, RuntimeError>;

    async fn collect(
        &self,
        handle: RuntimeHandle,
        request: CollectionRequest,
    ) -> Result<CollectionReceipt, RuntimeError>;

    async fn destroy(
        &self,
        handle: RuntimeHandle,
        request: DestroyRequest,
    ) -> Result<DestroyReceipt, RuntimeError>;

    async fn reconcile(
        &self,
        records: Vec<ExpectedRuntimeRecord>,
    ) -> Result<Vec<RuntimeReconciliationReceipt>, RuntimeError>;
}
```

The concrete Rust shape may split read-only and effectful traits. The versioned request and receipt schemas remain the public contract.

## Lifecycle

Runtime lifecycle states:

```text
planned
  → preparing
  → prepared
  → starting
  → running
      ├─ paused
      ├─ stopping
      ├─ stopped
      ├─ failed
      ├─ lost
      ├─ uncertain
      └─ recovery_required

prepared / stopped / failed
  → destroying
  → destroyed
```

`completed` is a Run or operation result, not a Runtime lifecycle state. A stopped Runtime can belong to a failed, cancelled, or completed Run.

A provider cannot return `running` before it has durable Runtime identity and proven liveness.

## Deterministic identity

Each Runtime has:

- Runtime ID generated by Conduit
- Run ID
- provider ID
- immutable Runtime Spec digest
- provider-object ID
- provider-object identity digest
- creation and observed timestamps
- generation

Provider object names are derived from the Runtime ID, not from user-controlled Project or Agent names.

Examples:

```text
Native cgroup/service   conduit-run-<runtime-id>
Container               conduit-<runtime-id>
Incus instance          conduit-<runtime-id>
```

The provider stores the Runtime ID and Spec digest in provider metadata or local journal before start.

### Existing object

If `prepare` or `start` finds an existing object:

- same Runtime ID and same Spec digest: inspect and replay the durable receipt
- same Runtime ID and different Spec digest: `runtime_identity_mismatch`
- object exists but Conduit metadata is missing: quarantine or recovery required

It never silently reuses a similarly named external object.

## Runtime request

A Runtime request contains:

- schema version
- Runtime ID and Run ID
- requested kind and provider selector
- configuration revision
- required capabilities
- Run Workspace attachments
- Credential Projection handles
- launch target
- CPU, memory, PID, GPU, and storage requests
- network mode
- environment identity or image
- lifecycle and retention policy
- access and approval commitments
- request digest

Provider-specific options live in a bounded typed extension selected by Provider ID. An arbitrary map of Docker, QEMU, or Incus flags is not accepted from an MCP client or Agent.

## Capability receipt

Provider support is not one boolean.

Each capability has:

- capability ID
- state: supported, effective, degraded, or unavailable
- evidence source
- observation time
- provider and host version
- notes and stable reason code

Initial capabilities:

### Lifecycle

- prepare
- start
- inspect
- graceful stop
- force stop
- pause
- resume
- snapshot
- archive
- restore
- destroy
- reconcile after node restart

### Workspace

- direct host path
- read-only mount
- read-write mount
- managed copy
- device-local volume
- snapshot or copy-on-write clone
- multiple Source attachments
- file ownership mapping

### Execution

- exact argv
- environment projection
- PTY
- stdin
- process-tree tracking
- guest exec
- desktop or GUI
- browser automation support
- nested Container runtime

### Isolation

- distinct operating-system identity
- filesystem restriction
- process namespace
- mount namespace
- user namespace
- network namespace
- seccomp or equivalent syscall filtering
- Landlock or equivalent access restriction
- Container boundary
- VM boundary
- host management socket absent

### Resources

- CPU limit
- memory limit
- PID limit
- storage quota
- I/O limit
- GPU attachment
- metrics

### Network

- open Internet
- offline
- restricted egress
- explicit LAN access
- port publication
- private Project network

### Privilege

- guest root
- host user
- host elevation through helper
- full host administrator

A capability receipt is truthful for the selected host and provider version. Detection of a binary alone does not establish an effective capability.

## Admission estimate

`estimate` is read-only and can report:

- provider availability
- required downloads or image build
- expected hot-storage bytes
- expected archive-storage bytes
- CPU, memory, GPU, and PID availability
- Source projection feasibility
- Credential Projection feasibility
- required local setup
- expected startup class

It does not reserve resources or create provider objects.

The UI labels the result as an estimate.

## Prepare

`prepare` performs durable admission steps before start:

1. validate Runtime request digest and policy revisions
2. verify Provider capability requirements
3. reserve hot-storage and Runtime identity
4. verify Run Workspace attachments
5. create copy, mount, Container, VM, or Native supervision record as needed
6. materialize only approved Credential Projections
7. apply network and resource configuration
8. write provider metadata and local journal
9. return `PreparedRuntimeReceipt`

The receipt contains:

- Runtime ID and Spec digest
- Provider ID and version
- provider-object identity digest
- effective Capability Receipt
- Workspace attachment receipts
- Credential Projection receipts without secret values
- reserved-resource observation
- security warnings
- prepared state digest

No Agent process is started during prepare.

## Start

`start` takes a prepared handle and an immutable Launch Plan.

The Launch Plan contains:

- exact executable identity
- argv
- working-directory reference
- bounded environment overlay or Credential Projection references
- stdio and PTY mode
- Agent Adapter ID where applicable
- process limits
- requested user or guest identity
- launch digest

The provider verifies that the prepared Spec digest and Launch Plan digest match the Run Manifest.

Start receipts distinguish:

- launch accepted
- process or guest command created
- Runtime liveness proven
- Agent prompt accepted, which belongs to the Adapter layer

The provider does not convert a successful `docker start`, Incus operation, or process spawn into Agent prompt acceptance.

## Run Workspace attachment

The Workspace Manager prepares a Run Workspace before the Provider mounts or exposes it.

Each attachment contains:

- Source ID and Location revision
- Workspace mode
- opaque host path reference
- requested guest path
- read-only or read-write mode
- ownership mapping
- content or base-commit digest
- cleanup policy

Provider behavior:

### Native

Uses the resolved Run Workspace path directly. Worktree and managed-copy isolation happened before Runtime prepare.

### Restricted Native

Exposes only paths admitted by the selected restriction mechanism. If a required read-only or denied path cannot be enforced, prepare fails rather than claiming filesystem restriction.

### Container

Creates explicit mounts. Read-only Sources use a read-only mount flag. Write access is not assumed from a default bind mount.

### VM

Uses an explicitly reported mechanism such as virtiofs, 9p, provider disk, managed copy, or synchronized volume. The receipt states whether host changes are immediate or require collection.

A Provider never receives an unbounded “mount this host path” instruction from an Agent.

## Credential Projection

Credentials are prepared by a Credential Broker. The Runtime Provider receives opaque projection descriptors, not unrestricted access to a credential store.

Projection types:

- native host credential use
- read-only file projection
- ephemeral file
- environment variable injection
- private Agent socket
- guest credential volume
- login-required placeholder

Each receipt states:

- credential profile ID and revision
- target Adapter
- projection type
- target path or environment-key reference
- read-only or writable behavior
- lifetime
- whether changes can be persisted
- evidence of successful projection

Rules:

- no entire home-directory mount for credential reuse
- no credential plaintext in Runtime receipt, Event, Board Message, D1, or ordinary logs
- Agent-specific credentials are not projected into unrelated Agent Runtimes
- a Runtime cannot request a Credential Profile outside the Assignment and Device policy
- writable login state is stored in a dedicated managed volume where required
- Runtime destruction follows Credential Projection retention policy

## Native Provider

Native is a first-class Runtime.

### Identity and supervision

The user-level supervisor launches exact argv without a shell. On Linux it records:

- PID
- process birth identity
- process-group or cgroup identity
- executable identity
- launch digest

A systemd transient service or scope can provide cgroup placement and resource control when available. Support is reported from the effective unit and cgroup state, not from the presence of `systemd-run` alone.

### Access modes

- `selected_sources` and `project_full` can use Direct, worktree, or managed copy paths
- `full_user` runs with the `conduit-node` user's ordinary authority
- `full_device` requires a configured elevation path when ordinary user authority is insufficient

Native Full Access is not described as isolated.

### Resource control

CPU, memory, PID, and I/O limits are effective only when the selected supervisor and host cgroup configuration enforce them. Unsupported limits return degraded or unavailable capability.

### Stop and recovery

Graceful stop targets the recorded process tree. Forced stop is a separate typed action.

After node restart, the Provider verifies PID plus process birth, executable or cgroup identity, and launch digest. PID existence alone is insufficient.

## Restricted Native Provider

Restricted Native composes host mechanisms and returns their actual evidence.

Linux candidates:

- dedicated user or transient identity
- Landlock restrictions
- mount and user namespaces
- bubblewrap or equivalent launcher
- seccomp
- systemd transient unit and cgroup limits
- network namespace or explicit egress filter

Landlock can add unprivileged restrictions to filesystem and supported network access, but availability and handled rights depend on the running kernel ABI. Conduit records the effective ABI and ruleset. It does not claim denied operations that the kernel ABI cannot mediate.

Restricted Native presets are versioned. A preset can require:

```text
filesystem restriction: required
network isolation: required
separate user: optional
cgroup memory limit: required
```

If a required feature is missing, the Runtime fails admission. An optional missing feature is visible as degraded.

Restricted Native is not automatically equivalent to a Container or VM boundary.

## Container Provider

The first Container backends can be Docker and Podman behind one Provider contract.

### Control boundary

`conduit-node` or the local Runtime broker owns the provider connection. The Agent Container never receives:

- Docker socket
- Podman service socket
- Containerd socket
- Incus socket
- host privileged-helper socket

A Container that needs a nested Container environment uses an explicitly configured inner daemon or another isolated build mechanism. It does not control the host daemon.

### Rootless and rootful

Rootless operation is preferred where compatible. The Capability Receipt records:

- daemon rootless state
- user-namespace mapping
- cgroup driver and version
- effective CPU, memory, and PID limits
- storage driver
- network implementation

Rootless status is not a complete isolation claim. Resource controls that are ignored by the host configuration are reported unavailable.

### Mounts

Only Run Workspace and approved managed volumes are mounted.

- Reviewer Source mounts default read-only
- writable mounts are explicit
- host root, home, credential directories, and provider sockets are not implicitly mounted
- mount source identity and flags are part of the Spec digest

### Container identity

Labels or annotations include Runtime ID, Run ID, Spec digest, and Conduit generation. Reconciliation verifies all fields before reuse.

## VM Provider

Incus with KVM/QEMU is the first Linux VM candidate behind the generic contract.

### Isolation

VM Full Access means root or administrator inside the guest. It does not imply host access.

Host files enter the guest only through declared Workspace attachments or Credential Projections.

### Instance and project

The Provider uses server-generated instance names and a Conduit-managed Incus Project or equivalent isolation boundary. CPU, memory, storage, VM count, network, and allowed Device types are configured and verified where the backend supports them.

### Guest communication

The first Incus implementation can use `incus-agent` for command execution without exposing an inbound guest network listener. A future `conduit-guestd` can provide richer Agent Adapter and Event behavior.

The Capability Receipt states the active mechanism.

### Initialization

Image and cloud-init inputs are versioned and hashed. A VM is not `prepared` until the expected guest or provider exec path is available, or the receipt explicitly reports that guest initialization is pending.

### Workspace modes

Supported mechanisms can include:

- read-only or read-write virtiofs
- 9p
- managed block volume
- managed copy or synchronization

The Provider reports consistency and collection behavior. A copied Workspace is not presented as a live mount.

### Snapshot and archive

Snapshot, export, and archive are distinct operations.

A snapshot receipt contains Source Workspace and environment digests. An archive receipt records storage class, bytes, object digest, and restore requirements.

The Provider does not destroy a VM that holds uncollected changes or Artifacts unless an explicit discard operation authorizes it.

## Network policy

Runtime network modes:

### Open

Internet access follows host or guest routing. Access to host management endpoints and provider sockets remains denied by Runtime construction.

### Restricted

Only approved domains, IP ranges, protocols, or Project services are intended. The Capability Receipt identifies the actual enforcement mechanism.

DNS-only filtering is not presented as complete egress enforcement.

### Offline

No external network path is available. Loopback and explicitly declared local Runtime services can remain available.

### LAN explicit

Internet or selected egress plus listed LAN targets. LAN access is not implied by Open Internet.

Port publication is a separate typed request. Provider defaults do not publish Agent services to the host or Internet.

## Resource admission

Requested resources are limits or reservations according to Provider capability.

The receipt distinguishes:

- requested
- reserved
- hard limit
- soft limit
- observed
- unsupported

Storage admission includes:

- Workspace copy or worktree estimate
- Runtime writable layer
- image or template download
- Credential volume
- trace and raw-log budget
- archive estimate

If hot storage cannot safely hold R0 journal and trace data, start is denied even when the Provider could create a Runtime object.

## Metrics

Provider metrics can include:

- CPU time and usage
- memory current, peak, and limit
- PID count
- disk and filesystem bytes
- I/O bytes
- network bytes
- GPU utilization and memory where available
- Runtime uptime

Metric absence is reported as unavailable. Unsupported metrics are not filled with zero.

High-frequency metrics use R2 retention and can be aggregated before upload.

## Pause and resume

Pause support is Provider-specific.

- Native pause may use process-tree stop signals or cgroup freezer when available
- Container pause uses provider support
- VM pause can mean CPU suspension and is not the same as disk snapshot

A Provider reports whether timers, network, and guest state continue while paused.

An unsupported pause returns `capability_unavailable`. It does not terminate and recreate the Runtime silently.

## Snapshot, archive, and restore

These are separate capabilities.

### Snapshot

Fast local state capture used for restart or branching.

### Archive

Move or export retained state to configured archive storage. May be slower and require restore before use.

### Restore

Create a usable Runtime or environment from a Snapshot or Archive. The receipt records whether the restored Runtime preserves Runtime ID or creates a new generation.

Source Workspace state, Runtime disk state, Agent-native session state, and Credential volumes are separate attachments. A VM disk alone is not the whole Collaboration Session.

## Collect

Before destroy or retention transition, the Provider can collect:

- Workspace changes
- Change Set inputs
- visible Agent output
- normalized Events and raw Segment closure
- Artifacts
- environment changes
- guest diagnostics

Collection produces immutable receipts. Failure to collect required content blocks ordinary destroy.

## Destroy

Destroy request modes:

- normal: refuse when required changes or Artifacts are uncollected
- discard: destroy after explicit discard authority
- quarantine: detach from scheduling but retain object for recovery

Destroy does not delete Project Source Locations, accepted Change Sets, Board Messages, R0 receipts, or Credential Profiles.

## Reconciliation

On node restart or Provider reconnect, Conduit lists managed provider objects and compares them with local journal records.

For each expected Runtime:

### Running

Object exists, metadata and Spec digest match, and liveness is proven.

### Stopped

Object exists and is terminal or stopped under the expected Spec.

### Lost

Object is proven absent and no terminal or destroy receipt exists.

### Uncertain

Provider cannot determine object or process state.

### Recovery required

Object exists under the Runtime ID but metadata, Spec digest, ownership, generation, or authority conflicts.

### External

Provider object is not owned by Conduit. It is ignored unless a deliberate import flow exists.

Reconciliation does not adopt an unknown object by name and does not start a replacement Runtime automatically.

## Full Access

Full Access remains an explicit product mode.

### Native `full_user`

Agent receives the ordinary signed-in user authority. No filesystem isolation is claimed.

### Native `full_device`

Agent can use configured host elevation. The implemented Linux path requires
the optional privileged helper, a Control Plane-approved helper installation,
an exact signed ticket, matching root-owned policy, systemd process custody,
and a helper-signed receipt chain verified independently by Node and Control
Plane. Missing or mismatched evidence is a fail-closed capability error; Native
`full_user` is not substituted.

### Container Full Access

Agent can be root inside the Container and unrestricted inside its mounted workspace. It still does not receive host provider sockets or undeclared host paths.

### VM Full Access

Agent can be root or administrator inside the VM. It still does not receive undeclared host access.

### Never Ask

When effective approval mode is `never`, actions within the admitted authority proceed without Conduit approval prompts. Provider, operating-system, local policy, and unsupported-capability errors remain visible failures.

## Capability claims by Runtime kind

Initial expected claims:

| Capability | Native | Restricted Native | Container | VM |
|---|---|---|---|---|
| existing host tools | direct | selected | image/mount dependent | guest dependent |
| host user credentials | adapter dependent | projection dependent | projection | projection |
| full host user access | yes | no by preset | no | no |
| host administrator access | optional helper | no by preset | no | no |
| root inside environment | host-dependent | no by preset | optional | optional |
| filesystem isolation | no | mechanism-dependent | mount/namespace | VM/mount |
| independent kernel | no | no | no | yes |
| fast startup | highest | high | medium | lower |
| snapshot | workspace/provider only | workspace/provider only | backend-dependent | backend-dependent |

This table is an expectation, not a runtime receipt. UI claims come from the effective receipt.

## Stable errors

```text
provider_unavailable
provider_version_unsupported
provider_capability_missing
runtime_identity_mismatch
runtime_object_external
runtime_state_conflict
runtime_lost
runtime_uncertain
runtime_recovery_required
workspace_attachment_failed
workspace_mode_unsupported
credential_projection_failed
credential_projection_not_allowed
network_mode_unsupported
resource_limit_unsupported
resource_exhausted
hot_storage_insufficient
archive_storage_unavailable
launch_plan_mismatch
process_identity_mismatch
guest_agent_unavailable
guest_exec_unavailable
pause_unsupported
snapshot_unsupported
collection_required
destroy_blocked
privileged_helper_unavailable
privileged_operation_not_allowed
```

Errors contain bounded reason codes and receipts. They do not expose credential values, raw provider responses, or private host paths.

## Required deterministic tests

1. prepare and start replay with same Runtime ID and Spec digest
2. same Runtime ID with another digest
3. node crash before provider object creation
4. provider object created before prepared receipt persistence
5. node crash after process spawn but before running receipt
6. native PID reused by another process
7. Native resource limit requested but not enforceable
8. Restricted Native required Landlock or network capability unavailable
9. Container read-only mount remains read-only
10. Agent cannot access host provider socket
11. rootless Container limit silently ignored by backend
12. VM boots without Guest Agent
13. Workspace copy differs from expected base digest
14. Credential Projection expires during Run
15. graceful stop fails and force stop is separately requested
16. snapshot unsupported
17. archive storage unavailable
18. destroy attempted with uncollected changes
19. provider object exists with conflicting metadata
20. node restart reconciliation across Native, fake Container, and fake VM
21. Full User + Never Ask Native receipt shows no isolation claim
22. VM root receipt does not imply host Full Access

## References

- Linux Landlock: <https://docs.kernel.org/userspace-api/landlock.html>
- systemd-run transient units: <https://www.freedesktop.org/software/systemd/man/systemd-run.html>
- systemd execution environment: <https://www.freedesktop.org/software/systemd/man/systemd.exec.html>
- Docker Rootless mode: <https://docs.docker.com/engine/security/rootless/>
- Docker bind mounts: <https://docs.docker.com/engine/storage/bind-mounts/>
- Docker resource constraints: <https://docs.docker.com/engine/containers/resource_constraints/>
- Incus instance creation: <https://linuxcontainers.org/incus/docs/main/howto/instances_create/>
- Incus instance exec: <https://linuxcontainers.org/incus/docs/main/instance-exec/>
- Incus cloud-init: <https://linuxcontainers.org/incus/docs/main/cloud-init/>
