# Runtime and security model

## Runtime provider contract

Every runtime provider implements the same product-level operations:

- capability discovery
- admission estimate
- create or bind runtime
- expose run workspace
- project credentials and environment
- start typed command or agent adapter
- stream normalized events
- query liveness and resource use
- stop, kill, pause, and resume where supported
- collect artifacts and terminal receipt
- archive or destroy retained state
- reconcile after node restart

Provider-specific capabilities are explicit. The scheduler does not infer VM-equivalent isolation from a container or restricted process.

## Native provider

Native execution starts a process under a selected host identity.

It supports:

- direct use of existing tools and user credentials
- local folders and attached hardware
- low startup latency
- optional elevation through a separate local path

Native execution does not claim filesystem or network isolation unless a restricted-native provider is selected.

## Restricted-native provider

This provider adds operating-system restrictions around a native process while retaining host tools where possible.

Linux candidates include a dedicated user, Landlock, mount namespaces, bubblewrap, systemd scopes, cgroups, and network namespaces. The implemented restriction set must be reported as evidence, not summarized as “sandboxed” without qualification.

Windows and macOS may expose different capabilities. Unsupported restrictions remain visible.

## Container provider

The container provider creates a managed container with explicit mounts, network policy, resource limits, credentials, and lifecycle.

Rules:

- the agent does not receive the host container-runtime socket
- host paths are not mounted unless they are part of the run workspace or explicit configuration
- the selected image and digest are recorded
- nested container builds require an explicit mechanism; they do not reuse the host control socket by default
- Docker and Podman may be implemented behind the same contract with truthful capability differences

## VM provider

The Linux reference VM provider is expected to use Incus with KVM/QEMU. Incus details remain behind the provider interface.

VM use cases include:

- root access inside an isolated guest
- guest-local Docker or other system services
- high-risk dependency installation
- browser and GUI automation
- retained development machines
- quick disposable machines without a project

A VM can be created from a versioned project environment, a generic image, or a retained snapshot. A collaboration session is not itself a VM.

Incus projects, resource limits, storage pools, snapshots, and backups are useful implementation primitives:

- <https://linuxcontainers.org/incus/docs/main/reference/projects/>
- <https://linuxcontainers.org/incus/docs/main/reference/storage_drivers/>
- <https://linuxcontainers.org/incus/docs/main/howto/instances_backup/>

## Access scope

Access scope is an admitted capability boundary.

### Read only

The run can inspect selected sources and allowed metadata. No file, process, repository, or external side effect is admitted unless separately named.

### Selected sources

The run can operate on the chosen source bindings according to each binding's read/write mode.

### Project full access

The run can use all project sources, project-managed runtimes, declared project services, and allowed network endpoints.

### Full user access

The run can use everything available to the selected host user, subject only to actual operating-system permissions and explicit runtime boundary.

### Full device access

The run may use device administration or root/Administrator paths when the device has a configured elevation mechanism. This is a valid product mode.

### Custom

A typed policy combines source bindings, paths, executables, operation classes, network rules, devices, runtimes, and expiry.

## Approval policy

Approval policy is evaluated separately from access scope.

- `always`: ask before every effectful operation
- `outside_scope`: ask when an operation exceeds the ordinary sub-scope but remains below the configured maximum
- `risk_classes`: ask only for configured classes such as external publish, secret access, destructive deletion, elevation, or production deployment
- `never`: do not request human approval for admitted actions

An access scope can be broad with strict approvals or narrow with no approvals.

The UI and receipts record both values. There is no hidden product-wide denial after the user explicitly configures full access and `never`, except for an unavailable platform capability or a higher-level client/device ceiling.

## Authority layers

Effective authority is the intersection of:

1. actor and client authorization
2. MCP or API connector ceiling
3. project-agent and assignment configuration
4. project policy
5. selected device policy
6. runtime-provider capability
7. operating-system permissions
8. exact approval receipt, when required

A lower layer can deny. A higher layer cannot force a device to exceed its local policy or operating-system capability.

## Approval receipts

A valid approval binds:

- approver identity
- requesting actor and client
- device
- run and operation ID
- operation type and normalized arguments
- source/location/runtime revisions
- payload digest
- expiry
- one-time or bounded reuse scope

Board messages are display and collaboration records. They are never parsed as approval receipts.

## Credentials

Credentials remain device-local unless the user explicitly exports them.

Supported patterns:

- use existing host credentials for native execution
- project an adapter-specific credential subset into a container or VM
- authenticate inside a retained project or agent credential volume
- inject a configured secret through a write-only broker

Rules:

- never mount an entire home directory solely for authentication
- isolate credentials by provider and intended run scope where possible
- do not emit secrets into control-plane metadata, normal traces, board messages, or artifacts
- record credential source type and status, not secret content
- treat “binary installed” separately from “authenticated” and “adapter ready”

## Ordinary personal computers

A device can install Conduit in desktop mode without enabling containers or VMs.

The default node process runs as the signed-in user. Enabling elevation, container management, VM management, or system persistence is a separate device setup step with an explicit local receipt.

The device settings screen reports:

- effective service identity
- installed agent adapters
- authentication state
- available runtime providers
- configured storage roots
- resource limits
- elevation mechanism
- network exposure
- connected control-plane identity

## Host administration warning

A process with full host administration can modify local logs, node binaries, credentials, and policy files. Strong audit evidence therefore requires streaming signed or chained event commitments to another device or the control plane before the administrator-level process can rewrite them. Local logs alone are operational evidence, not tamper-proof proof.

## Network policy

Runtime network modes include:

- open internet
- restricted destinations
- offline
- explicit LAN access

Host control APIs, container/VM sockets, and cloud metadata endpoints are denied by default in isolated runtimes. Full native access follows the selected user's actual network access when configured.
