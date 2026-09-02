# Runtime and security model

`docs/RUNTIME_PROVIDER.md` defines Runtime lifecycle, Provider requests, receipts, Workspace attachments, Credential Projections, and reconciliation. This document defines the authority boundary around those operations.

## Access scope and Runtime boundary are separate

Access Scope says which target the Run may affect.

Runtime kind says where the Agent or Command executes.

Examples:

```text
Native + full_user
The Agent receives the signed-in user's ordinary host authority.
```

```text
VM + full_device
The Agent receives administrator authority inside the guest. It does not receive host administrator authority.
```

```text
Container + project_full
The Agent can modify declared Project Sources mounted read-write. It does not receive undeclared host paths or the host Container socket.
```

The UI and receipts always show both values.

## Access scopes

### `read_only`

The Run can inspect admitted Sources and metadata. Effectful operations are rejected unless separately admitted by a Custom policy.

### `selected_sources`

The Run can operate on selected Source bindings according to each read-only or read-write attachment.

### `project_full`

The Run can use all Project Sources, Project-managed services, and Project policy capabilities.

### `full_user`

The Run can use the ordinary authority of the selected host or guest user.

For Native, this is the signed-in host user's authority. For Container or VM, this is authority inside the Runtime boundary.

### `full_device`

The Run can use device-administration authority available through a locally configured elevation mechanism.

For Native, this can reach the host. For VM, “device” refers to the guest unless a separate host operation is explicitly authorized.

### `custom`

A typed policy selects Sources, paths, executables, capabilities, network targets, Runtime kinds, and expiry.

Custom policy is not an arbitrary shell or provider configuration map.

## Approval policies

Approval policy is evaluated independently from Access Scope.

- `always`: ask before each effectful operation
- `outside_scope`: ask when an operation exceeds the ordinary sub-scope but remains under the admitted maximum
- `risk_classes`: ask for configured risk classes
- `never`: do not ask for operations already inside effective authority

`full_user + never` and `full_device + never` are valid.

Unsupported platform capabilities, local policy denials, missing elevation, stale revisions, and resource failures remain errors. They are not hidden approval prompts.

## Effective authority

The effective authority is the intersection of:

1. human principal state
2. calling client and current Connector Policy
3. Project Agent and Assignment settings
4. Project policy
5. Device policy
6. Runtime Provider capabilities
7. operating-system or guest authority
8. exact approval receipt where required

A narrower layer can deny. A broader layer cannot force another layer to exceed its policy or capability.

The exact actor, client, Device, Run, Source Location, Runtime Spec, arguments, revisions, expiry, and idempotency key are bound into the operation commitment.

## Owner-controlled Full Access

Broadening an MCP Connector to `full_user`, `full_device`, or `never` requires fresh owner Passkey authentication as defined in `docs/AUTHORIZATION.md`.

The Connector cannot raise its own ceiling.

Native host elevation is installed or enabled locally. A remote Connector cannot deploy the privileged helper.

## Local services

### `conduit-node`

Runs as the signed-in user. It owns Cloudflare transport, policy, Run journal, Workspace preparation, Runtime selection, Adapter orchestration, and local evidence.

### Native supervisor

Owns exact process-tree identity for user-level Native Runs.

### Runtime broker

Optionally owns Docker, Podman, Incus, or another management connection. It accepts typed local requests and never exposes the provider socket to an Agent Runtime.

### Privileged helper

Optional networkless root service with a narrow typed protocol. It does not accept arbitrary shell text, arbitrary environment maps, OAuth tokens, or Agent credentials.

### Guest Agent

Optional service inside a VM or Container. It has no implicit host authority.

## Credential boundaries

Credential handling uses Agent-specific Credential Profiles and Projections.

Supported projection forms include:

- use of existing Native host login
- read-only credential file
- ephemeral file
- environment injection
- private Agent socket
- guest credential volume
- login-required state

Rules:

- do not mount an entire home directory only to reuse authentication
- do not project unrelated Agent credentials
- do not return credential plaintext in Board Messages, D1, ordinary Events, Runtime receipts, or MCP results
- store writable login state in a dedicated managed location where required
- record source type, revision, target Adapter, lifetime, and evidence without secret content

## Native execution

Native is a primary product path.

It provides direct access to existing tools, ordinary user credentials, local folders, GUI applications, and attached hardware.

Ordinary Native does not claim:

- filesystem isolation
- process namespace isolation
- network isolation
- Container boundary
- VM boundary

Restricted Native is a separate Provider. It reports only mechanisms proven effective on the current host.

## Container execution

Container execution does not receive host Runtime-management sockets.

Only declared Run Workspace attachments and Credential Projections enter the Container.

Root inside a Container is not host administrator authority.

Rootless status alone is not treated as a complete security claim. Mounts, kernel sharing, network enforcement, devices, and resource controls remain separate capabilities.

## VM execution

VM execution is a separate guest operating system.

Root or administrator inside the guest does not imply host access.

A Collaboration Session, Source, or Credential Profile is not stored only inside a VM disk. Workspace, Runtime state, Agent session state, Artifacts, traces, and credentials remain separate attachments with independent retention.

## Provider sockets and host control APIs

The following are denied inside Agent Runtimes unless a future, separately reviewed capability explicitly requires one:

- Docker socket
- Podman service socket
- Containerd socket
- Incus socket
- QEMU management socket
- Conduit Runtime Broker socket
- Conduit privileged-helper socket

An Agent that needs nested Container builds uses a configured guest-local or isolated build mechanism.

## Network modes

### `open`

Internet access follows the selected Runtime's routing. Open Internet does not imply access to private LAN targets or host management APIs.

### `restricted`

Only declared destinations are intended. The Capability Receipt states the enforcement mechanism and limitations.

DNS filtering alone is not reported as complete egress control.

### `offline`

No external path is admitted. Loopback and explicitly declared internal services can remain available.

### `lan_explicit`

Only listed LAN targets are added to the ordinary network policy.

Port publication is a separate typed operation. A Provider does not publish Agent services by default.

## Resource and storage admission

CPU, memory, PID, storage, GPU, and I/O settings distinguish:

- requested
- reserved
- hard limit
- soft limit
- observed
- unsupported

A Provider cannot claim a hard limit when the current host or backend does not enforce it.

A Runtime is not started when the Node cannot safely persist R0 Run journal and trace records, even if the backend could create the process, Container, or VM.

## Approval receipts

An approval binds:

- approver and requester
- calling client
- Device, Run, and operation
- normalized operation arguments
- Source Location and Runtime revisions
- controller epoch
- payload digest
- expiry
- bounded reuse scope

Board text is not an approval receipt.

## Runtime cleanup

Agent completion does not automatically authorize Runtime destruction.

Before ordinary destruction, Conduit collects required:

- Workspace changes
- Change Set inputs
- visible Agent output
- terminal and verification receipts
- finalized traces
- Artifacts
- environment-change metadata

An explicit discard operation can authorize loss of uncollected Runtime data. It does not delete accepted Project data, Board Messages, or R0 receipts.

## Audit limitation under host administration

A Native process with full host administrator authority can modify local logs, Node software, credentials, and policy files.

Local evidence is therefore operational evidence, not an unconditional tamper-proof record.

Stronger evidence requires sending hash-chain commitments to another Device or the Control Plane before local administrator-level software can rewrite history.

## Ordinary personal computers

A Device can install Conduit in Desktop mode without Container, VM, or elevation support.

Device setup reports:

- effective service identity
- Agent Adapter installation and authentication state
- available Runtime Providers and effective capabilities
- Source Locations
- storage roots and capacity
- local resource ceilings
- elevation state
- network exposure
- current Control Plane identity

Container, VM, and host-elevation capability can be added later.

## Normative references

- Authentication and Connector authority: `docs/AUTHORIZATION.md`
- Node operation admission: `docs/NODE_PROTOCOL.md`
- Runtime lifecycle and receipts: `docs/RUNTIME_PROVIDER.md`
- Source and Run Workspace custody: `docs/SOURCES_AND_WORKSPACES.md`
- Run evidence and raw content: `docs/TRACE_FORMAT.md`
