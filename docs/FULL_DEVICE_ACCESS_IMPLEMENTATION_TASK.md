# Full Device Access implementation task

This branch carries the complete Linux host-elevation implementation for Conduit.

- Base branch: `main`
- Task branch: `task/full-device-access`
- Tracking issue: `#20`
- Platform: Linux only
- Final dashboard layout and visual design: excluded
- Do not open a replacement pull request.
- Do not merge the pull request.
- Implement, test, document, push, update the pull-request body, and mark the pull request ready for review.

## Completion boundary

Implement `full_device` as real Linux host-administrator authority without running `conduit-node` as root and without turning the privileged boundary into a generic remote root shell API.

The current unconditional `full_device_capability_unavailable` rejection is correct until every required boundary in this document is effective. Do not remove that rejection first and fill in the security controls later. The Node may advertise and admit Native host `full_device` only after it has verified:

1. an installed and enabled local privileged helper;
2. a matching root-owned helper policy revision;
3. a registered helper installation identity and active receipt-verification key;
4. a valid privilege ticket for the exact operation or control request;
5. an exact Runtime and launch-plan digest;
6. all Connector, Project Agent, Assignment, Device, Runtime, Access Scope, Approval, and risk-class ceilings;
7. durable helper admission before the first root side effect;
8. a signed helper receipt for every state transition that is projected as elevated execution evidence.

This is not a skeleton task. Do not finish with only a protocol, fake daemon, installer stub, unit file, or isolated library. The Control Plane, Node, Runtime Provider, Agent Adapter I/O, helper, packaging, update, recovery, and Linux live E2E must be connected.

## Required reading

Read before changing code:

- `AGENTS.md`
- `docs/AUTHORIZATION.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/RUNTIME_PROVIDER.md`
- `docs/NODE_PROTOCOL.md`
- `docs/TRACE_FORMAT.md`
- `docs/LINUX_OPERATIONS.md`
- `docs/LINUX_E2E.md`
- `docs/SOURCES_AND_WORKSPACES.md`
- every ADR under `docs/adr/`
- the auth, node, runtime, trace, and Change Set schemas and examples
- the merged implementation and review history of PR `#19`
- Issues `#4`, `#7`, and `#20`

Inspect the current implementations rather than designing beside them:

- `crates/conduit-node/src/lib.rs`
- `crates/conduit-node/src/service.rs`
- `crates/conduit-node/src/local.rs`
- `crates/conduit-node/src/transport.rs`
- `crates/conduit-node-store/`
- `crates/conduit-runtime/src/lib.rs`
- `crates/conduit-runtime/src/native.rs`
- `crates/conduit-adapters/src/process.rs`
- `apps/control-plane/src/`
- `apps/control-plane/migrations/`
- `installers/`
- `packaging/systemd/`
- `scripts/test-packaging.sh`

## Current state

The merged implementation deliberately fails closed:

- `LocalPolicy::evaluate()` rejects `accessScope=full_device`.
- the lower Node admission layer also rejects `full_device`.
- the Native provider and process supervisor run with the signed-in user's ordinary authority.
- there is no packaged root helper binary, root-owned helper configuration, system service, helper journal, privilege-ticket issuer, or helper-signed receipt path.
- `full_user` is implemented and must remain a separate user-level authority.
- Container and VM root are Runtime-local and must not be confused with Native host administrator authority.

Do not reinterpret a root process inside a Container or VM as Native host `full_device`. Do not route Container or VM management sockets into an Agent Runtime.

## Product semantics

### Native `full_user`

The process has the ordinary authority of the Device user running `conduit-node`. It must never be silently upgraded through the helper.

### Native `full_device`

The approved process has host UID 0 and the effective Linux administrator authority exposed by the selected host. Once an unrestricted elevated Agent session is admitted, the Agent can affect the host broadly. Conduit must not claim that this mode is filesystem-isolated or tamper-proof.

### Container or VM authority

Root inside a Container or VM remains root inside that Runtime boundary. It does not receive host administrator authority from this helper. Host-elevation for provider administration is a separate future typed capability, not an implicit side effect of `full_device` inside a guest.

### Approval semantics

Access Scope and Approval Policy remain independent.

For a one-shot elevated command, the approval binds the complete exact launch plan.

For an elevated structured Agent session:

- `never` may launch only when every server-side ceiling permits it and a separate root-owned local policy flag permits it;
- `always`, `outside_scope`, and `risk_classes` require an Adapter with a proven pre-execution approval bridge for the affected request class;
- if the Adapter cannot enforce that boundary before execution, reject with a typed reason such as `full_device_approval_enforcement_unavailable`;
- an Adapter-mediated approval bridge is not represented as kernel syscall mediation;
- after an unrestricted root Agent is launched, the helper cannot truthfully claim to approve every syscall or subprocess unless an actual enforcement mechanism exists.

Pi or ACP support that currently fails closed must remain fail closed until its interactive approval response is connected and tested. Do not mark it effective because the process can be launched.

## Security goal

A compromised remote client, ordinary Board participant, same-user process, `full_user` Agent, stale Node process, or replayed transport frame must not be able to mint new root authority.

The unprivileged Node is a courier and orchestrator, not the root authorization source. A root action requires an exact ticket issued by an authorized issuer and accepted by a root-owned local policy.

The privileged helper is part of the Device trust base. Compromise of the helper or a running root Agent can compromise the host. Document this honestly.

## Explicit non-goals

Do not implement any of the following:

- running the entire `conduit-node` as root;
- a setuid `conduit-node`;
- a wildcard `NOPASSWD` sudoers rule;
- an HTTP, TCP, QUIC, or externally reachable helper listener;
- a helper RPC accepting an arbitrary shell command string;
- a helper RPC accepting unrestricted systemd unit properties;
- a helper RPC accepting arbitrary Docker, Podman, Incus, QEMU, or D-Bus calls;
- a generic `write_file(path, bytes)` or `run_as_root(command)` RPC;
- returning root credentials, helper private keys, OAuth tokens, Agent credentials, or secret file contents;
- trusting a user-owned configuration file as the root policy;
- treating a same-UID Unix-socket connection by itself as human approval;
- treating a WebSocket ACK, Queue delivery, helper socket write, or systemd method return as proof that the target Agent accepted a prompt;
- silently re-running a root effect after an uncertain crash;
- final Dashboard visual design.

## Threat model

Add a concrete threat model to the implementation documentation and tests. At minimum cover:

1. a remote MCP client with a narrower Connector ceiling;
2. a stolen or stale OAuth token;
3. a compromised Device user process;
4. a `full_user` Agent that can read and change ordinary user files;
5. a malicious same-UID process connecting to the helper socket;
6. a stale Node process after update or restart;
7. a replayed privilege ticket;
8. a ticket copied to another Device or helper installation;
9. a changed Runtime Spec or launch plan after approval;
10. a symlink or executable replacement race;
11. a forged helper receipt;
12. a helper restart during launch;
13. a Node restart while an elevated process is alive;
14. a Control Plane retry after losing a response;
15. a root Agent modifying local Conduit logs, policy, binaries, or credentials;
16. local storage exhaustion and SQLite failure;
17. Control Plane privilege-signing-key rotation or compromise;
18. downgrade to an older helper or protocol;
19. unexpected, duplicated, truncated, or forged file descriptors;
20. a local user attempting to enable elevation without a root setup action.

State which threats are prevented, detected, limited, or inherent to administrator-level execution.

## Required architecture

The implementation must preserve these components and trust boundaries.

```text
Browser / MCP / local owner
        |
        | ordinary Conduit operation + approval
        v
Cloudflare Control Plane
        |
        | signed privilege ticket for exact plan digest
        v
conduit-node (ordinary Device user)
        |
        | AF_UNIX SOCK_SEQPACKET, peer credentials,
        | device proof, exact ticket, bounded typed request
        v
conduit-privileged-helper (root, networkless, socket activated)
        |
        | root-owned durable journal
        | systemd system D-Bus / fixed root-owned exec worker
        v
conduit-elevated-<runtime-id>.service / cgroup
        |
        v
exact elevated command or structured Agent process
```

The concrete crate layout may change if the boundaries remain clear. A recommended layout is:

```text
crates/conduit-privileged-protocol/
crates/conduit-privileged-helper/
crates/conduit-runtime/src/privileged.rs
apps/control-plane/src/privilege-*.ts
spec/schemas/privileged-helper-v1.schema.json
spec/examples/privileged-helper/
```

Do not duplicate existing domain types when the auth, node, runtime, trace, or operation schemas already define them.

## Workstream coordination

Use parallel subagents and independent Git worktrees, with one coordinator owning shared schema changes and final integration.

Suggested workstreams:

1. `full-device/protocol-schema`
2. `full-device/helper-journal`
3. `full-device/systemd-runtime`
4. `full-device/node-adapter`
5. `full-device/control-plane`
6. `full-device/cli-packaging`
7. `full-device/security-tests`

Rules:

- shared wire/schema changes land through the coordinator first;
- do not create competing ticket, receipt, Runtime, or approval types;
- do not weaken existing fail-closed behavior to make another worktree pass;
- each workstream runs its focused tests before integration;
- continuously integrate `task/full-device-access` into worktrees;
- no workstream may claim completion from mocks alone;
- do not open additional implementation PRs;
- preserve all Cloudflare Free-profile budget gates.

## Workstream 1 — privileged protocol and schemas

Create one versioned local helper protocol and the public Control Plane ticket/receipt contracts.

### Local transport

Use AF_UNIX `SOCK_SEQPACKET` on Linux so one request is one bounded record. Use systemd socket activation for the production listener.

Required properties:

- maximum encoded packet size: 65,536 bytes before JSON parsing;
- canonical JSON and SHA-256 commitments using the repository's existing RFC 8785 implementation;
- monotonically scoped request IDs and idempotency keys;
- explicit protocol version negotiation;
- peer UID, PID, and process-start observation through kernel credentials;
- `SO_PEERCRED` and/or per-message `SCM_CREDENTIALS` validation;
- `SO_PASSCRED` when per-message credentials are used;
- `MSG_CMSG_CLOEXEC` for received descriptors;
- reject `MSG_TRUNC`, `MSG_CTRUNC`, unexpected ancillary messages, wrong FD counts, and wrong FD types;
- set close-on-exec on every helper and received descriptor;
- bounded active connections, outstanding requests, descriptors, stream chunks, and response size;
- no fallback to a world-readable stream socket or localhost TCP.

The socket should be rooted under a root-owned runtime directory, for example:

```text
/run/conduit/privileged/<uid>.sock
```

The target Device user may own the socket endpoint with mode `0600`; the parent directory remains root-owned. The helper must still validate peer credentials and cryptographic authority.

### Connection authentication

Define a challenge-response handshake. Bind at least:

- protocol version;
- helper installation ID;
- Device ID;
- expected UID;
- peer PID and observed process-start identity;
- Node boot ID;
- helper nonce;
- client nonce;
- timestamp and expiry.

Use the existing Device signing identity or a distinct registered local client identity. Do not treat possession of a user-writable file alone as root authorization. The handshake authenticates the courier; it does not replace the privilege ticket.

### Local protocol operations

The final names may differ, but the protocol must cover typed equivalents of:

```text
helper.hello
helper.challenge
helper.proof
helper.accepted
capability.probe
runtime.prepare
runtime.start
runtime.inspect
runtime.stream.read
runtime.stream.write
runtime.pty.resize
runtime.signal
runtime.stop
runtime.kill
runtime.pause
runtime.resume
runtime.reconcile
runtime.receipt.get
helper.policy.attest
helper.key.rotate
```

Every effectful request carries or references an exact privilege ticket. Read-only inspection still requires authenticated peer identity and an exact Runtime handle.

### Descriptor protocol

Large or secret material must not be embedded in ordinary JSON. When a descriptor is needed, carry a typed descriptor manifest in the packet and the exact number of FDs through `SCM_RIGHTS`.

For credential or content memfds:

- verify regular memfd semantics where available;
- verify expected size and digest;
- require immutable seals before use where supported;
- reject writable aliases and unexpected seek state;
- never serialize secret bytes into journal rows, receipts, Events, or logs.

Do not add descriptor passing merely for novelty. If a value is small, public, and safe in bounded JSON, keep the protocol simpler.

### Privilege ticket schema

Add a versioned signed ticket, for example `conduit.privilege-ticket/1`. It must bind at least:

```text
schemaVersion
ticketId
issuerKind
issuerKeyId
audience
publicOrigin
helperInstallationId
helperPolicyRevision
helperPolicyDigest
deviceId
deviceKeyId
expectedUid
operationId
assignmentId when present
runId
runtimeId
operationRequestDigest
runManifestDigest
runtimeSpecDigest
localExecutionPlanDigest
launchPlanDigest or controlDigest
accessScope = full_device
approvalMode
requiredApprovalRiskClasses
connectorPolicy ID/revision when applicable
project-agent/config revisions when applicable
device-policy revision
controllerEpoch
issuedAt
expiresAt
one-time nonce
maximum use count
```

Do not put canonical local paths, plaintext credentials, raw prompts, or secret environment values in the ticket. Bind their exact local plan by digest and expose only a bounded redacted summary where owner approval requires it.

Use a dedicated privilege-ticket signing key. Do not reuse OAuth bearer secrets, bootstrap secrets, recovery codes, Device private keys, or helper receipt keys. Algorithm and key ID are versioned. Prefer the repository's already proven Ed25519/JCS/SHA-256 primitives; do not invent custom cryptography.

A ticket is valid only for the exact helper installation, Device, UID, operation, Runtime, plan, controller epoch, and policy revisions. First durable admission must occur before expiry. A retry after durable admission may replay the existing receipt even after ticket expiry; it may not create a second execution.

### Local execution plan

Define a canonical local plan that binds the fields the Control Plane deliberately does not store:

- exact resolved executable identity;
- argv as an array, never reconstructed command text;
- exact cwd identity;
- Runtime ID and systemd unit identity;
- Workspace attachment identities and access modes;
- Adapter ID/version and executable identity where applicable;
- environment-key names and value digests, not secret values;
- Credential Projection descriptors and digests;
- I/O mode and PTY settings;
- CPU, memory, PID, storage, I/O, GPU, timeout, and network requests;
- root identity request;
- expected helper and exec-worker versions.

The Node signs the local plan commitment with the Device key when requesting a remote privilege ticket. The Control Plane verifies that the ticket request belongs to the exact admitted operation and active Device connection before signing the ticket.

### Helper receipt schema

Every helper admission, start, control transition, and terminal state must produce a signed receipt. Bind at least:

- helper installation ID, policy revision, key ID, version;
- ticket ID and ticket digest;
- operation, Run, Runtime, and request digests;
- local execution-plan and launch/control digests;
- actual UID/GID and supplementary-group policy;
- systemd unit, invocation ID, cgroup identity, and generation;
- target PID and process-birth observation or pidfd-backed identity when available;
- effective resource and network evidence;
- state and exact transition;
- exit code or signal where terminal;
- observed timestamps;
- stream custody/cursor evidence;
- receipt digest and signature.

A helper signature proves that the registered helper key produced the receipt. It does not make a host controlled by a root Agent tamper-proof. Preserve this limitation in the public evidence model.

### Invalid fixtures

Add fixtures for malformed IDs, duplicate risk classes, wrong key ID, wrong audience, wrong origin, wrong helper, wrong UID, wrong Device, wrong operation, stale controller epoch, expired ticket, future ticket, changed plan digest, unsupported version, oversize packet, unexpected FD manifest, signature failure, and idempotency conflict.

Validate all fixtures in Rust, TypeScript, and the repository's schema validator. Generated code drift must fail CI.

## Workstream 2 — helper identity, root-owned policy, and journal

Implement `conduit-privileged-helper` as a root service. It must never connect to Cloudflare or another network endpoint.

### Installation identity

On local root setup, generate a unique helper installation ID and a root-owned signing key. Store private material only in a root-owned state directory such as:

```text
/var/lib/conduit/privileged-helper/<installation-id>/
```

Required permissions:

- root-owned parent directories;
- no symlink traversal;
- directory mode no broader than `0700` for secret state;
- private key and SQLite files no broader than `0600`;
- atomic creation and update;
- explicit fsync behavior for authority and terminal receipts.

The receipt public key is registered with the Control Plane through a fresh-owner-Passkey flow. The Control Plane stores the public key, helper installation ID, Device binding, policy revision/digest, status, and key history.

### Root-owned local policy

Create a root-owned policy file, for example:

```text
/etc/conduit/privileged-helper.d/<uid>.json
```

The policy must include versioned, validated fields for:

- enabled/disabled state;
- expected UID and Device ID;
- helper installation ID;
- accepted Control Plane origin and privilege-ticket key IDs;
- helper policy revision and digest;
- allowed operation families;
- allowed provider and Adapter classes;
- maximum duration and resource ceilings;
- registered launch profiles and/or unrestricted-exec opt-in;
- whether `full_device + never` is locally allowed;
- whether persistent elevated Agent sessions are locally allowed;
- whether local offline authorization is enabled;
- receipt retention and active-run shutdown policy.

Broadening this file requires a local root action. A user-level config file cannot broaden it. Narrowing takes effect immediately.

`full_device + never` must require a separate, conspicuous root-owned boolean or equivalent policy state. Enabling ordinary `full_device` must not accidentally enable `never`.

If unrestricted elevated command/Agent launch is supported, require a separate root-owned opt-in. The default may be registered launch profiles only. Once unrestricted mode is explicitly enabled and all other layers authorize it, do not add undocumented hidden path or executable denials.

### Pinned Control Plane keys

Pin the privilege-ticket verification key set in root-owned configuration. Key rotation must be versioned and explicit.

Support either:

- a rotation statement signed by an already pinned key and accepted by local root policy; or
- an explicit local root update command that displays old/new fingerprints.

Never fetch and trust a replacement key from the network inside the helper.

### Durable journal

Use a root-owned SQLite journal with migrations and bounded retention. It must record, before side effects:

- accepted ticket identity and digest;
- idempotency key and request digest;
- operation/Run/Runtime identity;
- execution-plan digest;
- intended unit/generation;
- state and state revision;
- start/control attempt state;
- systemd invocation and process identity observations;
- stream custody cursors;
- terminal and signed receipt metadata.

Required behavior:

- same idempotency identity plus same digest replays the first durable result;
- same identity plus a different digest is rejected;
- a consumed one-time ticket cannot start another Runtime;
- storage failure before admission causes no root side effect;
- response loss after admission replays the durable receipt;
- an uncertain start is never retried as a new start;
- journal schema downgrade is refused;
- corruption is surfaced as `recovery_required` or a stronger fail-closed state;
- active/nonterminal authority rows are not deleted for quota relief;
- secret descriptor contents never enter SQLite.

Define explicit states such as:

```text
received
validated
admitted
unit_starting
running
paused
stopping
stopped
failed
uncertain
recovery_required
terminal
```

Names may differ, but crash boundaries must be representable.

### Helper capability probe

Return a signed, bounded capability receipt containing:

- helper version and protocol versions;
- installation ID and policy revision/digest;
- enabled status;
- systemd system-manager reachability;
- socket and peer-credential enforcement;
- transient-unit support;
- cgroup and freeze/pause support;
- pidfd/openat2/execveat support;
- PTY and stream support;
- receipt-signing-key fingerprint;
- local `never` and unrestricted-launch opt-in states without exposing secrets;
- stable unavailable/degraded reason codes.

Binary presence alone is not effective capability. The Node advertises Native host `full_device` only after verifying this signed probe and matching it to Control Plane registration.

## Workstream 3 — elevated process and systemd custody

Implement a dedicated `PrivilegedNativeProvider` or equivalent. Use `RuntimeKind::Native` with a distinct provider identity such as `privileged-native`.

### Fixed exec worker

Do not send arbitrary unit properties or target commands directly to systemd. A recommended design is:

1. helper validates and durably admits the signed ticket and local plan;
2. helper writes a root-owned immutable/MACed execution record;
3. helper asks the system systemd manager to start a transient unit whose executable is a fixed root-owned Conduit exec worker;
4. the exec worker revalidates the root-owned record, safely opens the target executable/cwd, sets up I/O, and executes the exact target;
5. the worker remains as supervisor when necessary to preserve stream and terminal custody.

The helper/worker binary path and every ancestor must be root-owned and not group/world writable.

### Systemd integration

Use the system D-Bus transient-unit API or another typed systemd API. Do not construct a `systemd-run` shell command.

Unit names are server-derived only, for example:

```text
conduit-elevated-<runtime-id>.service
```

Validate the Runtime ID before deriving the unit name.

Construct a fixed allowlisted property set. At minimum use and verify where supported:

- root service identity;
- `KillMode=control-group`;
- cgroup identity and systemd invocation identity;
- bounded stop timeout;
- Runtime maximum duration;
- CPU, memory, PID/task, and I/O properties when requested and effective;
- restart disabled unless a separately designed exact replay policy exists;
- no arbitrary dependencies, environment files, bind mounts, capabilities, or unit directives from remote input.

The privileged helper service itself is hardened and networkless. The elevated target unit intentionally represents full host authority and must not be mislabeled as sandboxed. If the target unit applies restrictions, report the exact restrictions in the capability receipt.

### Executable and cwd safety

Prevent time-of-check/time-of-use replacement:

- resolve and open executable/cwd through safe descriptor-relative operations;
- use `openat2` constraints such as no magic links/no symlink escape where applicable;
- verify expected device/inode, type, ownership policy, size, and digest;
- execute an already verified object with `execveat`/`fexecve` or an equivalently race-safe mechanism;
- do not validate a path and later execute it by an unverified string;
- handle symlinked CLI entry points explicitly rather than accidentally trusting a changed target;
- bind script content and interpreter identity for shebang executables, or reject unsupported script launch with a truthful reason;
- test executable, interpreter, cwd, and parent-directory replacement races.

Full Device means broad authority after launch. These checks protect the privilege boundary from launching something other than the approved plan; they are not a hidden filesystem sandbox for the running root Agent.

### Environment

Start from a minimal known environment. Define a versioned allowlist for non-secret keys.

Reject or explicitly mediate dangerous loader/interpreter injection variables, including relevant forms of:

```text
LD_*
DYLD_*
GCONV_PATH
BASH_ENV
ENV
PYTHONPATH
PYTHONHOME
NODE_OPTIONS
RUBYOPT
PERL5OPT
```

Use a fixed or root-policy-controlled `PATH`. Do not inherit the helper's environment.

Set a managed Runtime home by default rather than using `/root`. Agent-specific credentials use Credential Projections. Do not serialize credentials in the helper request or ticket.

### Credential Projections

Connect the existing Credential Broker boundary.

- project only credentials admitted by Assignment, Adapter, Device policy, and root policy;
- use bounded sealed descriptors or root-owned managed files;
- record only IDs, revisions, target keys/paths, size, digest, lifetime, and custody evidence;
- do not copy the entire user home;
- do not put plaintext in logs, SQLite, D1, Board, Trace, or receipts;
- writable provider state uses an explicit managed volume and retention policy;
- cleanup never removes accepted Project data or required evidence.

A root Agent can technically read host credentials because it has administrator authority. Do not claim that credential projections provide secrecy from a malicious root Agent; they prevent accidental broad projection and leakage through Conduit records.

### I/O and structured Agent support

Refactor the current concrete `std::process::Child` coupling where necessary. The Runtime/Adapter boundary must support both:

- a locally owned user-level child; and
- a helper/systemd-managed elevated process with bounded stdin/stdout/stderr or PTY access.

Preserve:

- streaming assistant output;
- structured protocol record boundaries;
- stdin/follow-up input;
- PTY resize;
- cancellation;
- pause/resume;
- timeout;
- raw-stream custody and normalized Event generation;
- terminal receipt ordering.

Do not fake a `Child` for an external process. Introduce a typed managed-process/I/O abstraction and keep lifecycle authority in the Runtime Provider.

Prefer durable root-owned stream spools with cursors so response loss and reconnect can replay bytes without allocating a second process. If exact structured-session reattachment after Node restart cannot be proven, preserve the process identity and converge to explicit `recovery_required`; never resend the prompt or start another root Agent automatically.

### Process control

Control requests target Runtime ID, unit/invocation identity, controller epoch, state revision, and digest. They never target an arbitrary caller-supplied PID.

Use systemd unit/cgroup controls for normal process-tree operations. When a direct signal is unavoidable, use pidfd-based signaling where supported to avoid PID-reuse races. Verify process birth and cgroup/unit identity before fallback signaling.

Implement and test:

- inspect;
- graceful stop;
- force stop;
- pause/freeze;
- resume/thaw;
- timeout;
- input/follow-up;
- PTY resize;
- terminal collection;
- helper restart reconciliation;
- Node restart reconciliation.

A missing unit after an admitted uncertain start is not proof that the command never ran. Mark the effect uncertain/recovery-required instead of starting again.

## Workstream 4 — privilege-ticket issuance and Control Plane verification

Add the Control Plane records and services needed to issue exact tickets and verify helper evidence.

### D1 migration

Add the next migration after the current schema version. Suggested records include:

```text
device_privilege_installations
privilege_installation_keys
privilege_policy_attestations
privilege_ticket_requests
privilege_ticket_issuance
privilege_receipt_projections
privilege_key_revisions
```

Use the existing schema-version and migration-test infrastructure. The exact table layout may differ.

Store only bounded public metadata, digests, state, revisions, public keys, and security evidence. Do not store root private keys, local canonical paths, plaintext credentials, or raw execution plans.

### Helper registration

The registration flow must require:

1. local root helper setup and generation of installation identity/key;
2. Device-authenticated submission of the public attestation;
3. Owner review of Device, UID, origin, helper fingerprint, policy digest, and capabilities;
4. fresh Passkey authentication;
5. activation of the exact helper key and policy revision.

A remote client cannot install or enable the helper. Registration only tells the Control Plane which locally installed helper it may trust.

Root-policy broadening changes the attestation digest and places the installation into a state requiring Owner confirmation before broader tickets are issued. Narrowing/revocation takes effect immediately.

### Ticket request

The Node builds the exact local execution-plan digest after resolving Device-local data. It sends a Device-signed ticket request through a dedicated typed route/frame.

The Control Plane verifies:

- active Owner/Device/helper registration;
- exact admitted operation and request digest;
- exact Run Manifest and Runtime Spec;
- current Connector and grant revisions;
- Project Agent, Assignment, Project, and Device ceilings;
- effective Access Scope and Approval Policy;
- authoritative required risk classes;
- fresh approval receipt where required;
- helper policy revision/digest;
- Device signature and current connection epoch;
- bounded redacted owner-visible summary;
- ticket issuance idempotency and expiry.

Only then sign the ticket.

The same request ID and digest replays the same issuance result. A conflicting digest is rejected. Losing the HTTP/WS response must not mint a second ticket with broader authority.

### Approval binding

For one-shot commands, bind approval to the exact local plan digest.

For structured Agents, verify Adapter approval capability before ticket issuance. Do not claim `always` or `risk_classes` is effective for a root Agent if the Adapter cannot provide a pre-execution request/response bridge for the relevant action.

`full_device + never` requires all of:

- Owner or Connector permission;
- Project Agent and Assignment permission;
- Device user-level policy permission;
- active helper registration;
- root-owned helper policy opt-in;
- Adapter/runtime capability;
- empty or satisfied mandatory risk-class set.

### Receipt verification

The Node and Control Plane verify helper signatures and exact bindings before projecting elevated states.

A Native host `full_device` Run cannot become `running`, `completed`, `failed`, `cancelled`, or `ready_for_review` from an unsigned ordinary Node claim alone. It must carry the required helper receipt chain.

Verify:

- helper key active for the observed timestamp;
- installation, Device, UID, operation, Run, Runtime, controller epoch, ticket, and plan digests;
- monotonic state revision;
- legal transition;
- exact terminal identity;
- no cross-Device or cross-Run reuse.

Project only bounded receipt metadata. Detailed local paths and stream content remain Device-local.

### Key rotation and revocation

Implement:

- privilege-ticket signing key rotation with overlapping verification window;
- helper receipt-key rotation with explicit installation/key history;
- helper disable/revoke;
- Device revoke interaction;
- ticket issuance refusal after revoke;
- exact handling of already admitted elevated Runs.

Revocation cannot force an offline root process to stop. Distinguish remote authority revocation from local process termination. When online, offer a separately signed stop request.

### Cloudflare usage

Do not add polling or periodic ticket writes.

- issue records only on helper registration/policy change/ticket/receipt events;
- report helper capability in semantic Device health only when changed and at the existing bounded checkpoint;
- preserve the Free profile's event batching, D1 statement/parameter budgets, retention, static assets, and no-idle-alarm properties;
- add usage assertions for helper idle state and ticket/receipt flows.

## Workstream 5 — Node and Runtime integration

### Admission

Replace the unconditional `full_device` rejection with conditional capability-based admission only after the complete helper path exists.

The Node must evaluate both:

- existing user-owned local Device policy; and
- root-owned helper policy and signed capability attestation.

A broader Control Plane decision cannot override either local deny.

Required stable errors include exact equivalents of:

```text
full_device_capability_unavailable
privileged_helper_not_installed
privileged_helper_disabled
privileged_helper_registration_missing
privileged_helper_policy_mismatch
privileged_helper_protocol_unsupported
privilege_ticket_required
privilege_ticket_invalid
privilege_ticket_expired
privilege_ticket_replayed
privilege_ticket_conflict
full_device_never_local_opt_in_required
full_device_approval_enforcement_unavailable
privileged_runtime_recovery_required
```

Preserve existing public error bounding and secret redaction.

### Provider selection

- Native host `full_device` selects `PrivilegedNativeProvider` explicitly.
- Native `full_user` continues to select the ordinary Native provider.
- Restricted Native does not silently become root.
- Container/VM guest authority does not select the host helper.
- missing helper capability is an admission error, not fallback to `full_user`.

Persist the selected provider, helper installation ID, helper policy revision, ticket ID/digest, and receipt key ID in the immutable/local Run evidence before root start.

### Runtime and Agent state

Keep these receipts separate:

```text
operation admitted
privilege ticket issued
helper durably admitted
systemd unit created
root liveness proven
Agent protocol initialized
Agent prompt accepted
Agent settled
workspace collected
helper terminal signed
Node terminal submitted
Control Plane terminal accepted
```

Do not collapse them into one `running` boolean.

### Follow-up and control

Every effectful control delivered to an existing elevated Runtime is exact-target and privilege-authorized. Input/steer, stop, kill, pause, resume, and PTY control use a control ticket or an equivalent signed capability specific to that action.

Read-only stream replay may use the authenticated session and existing Runtime custody without minting broad new authority.

### Restart and reconciliation

On Node start:

1. connect to helper and verify installation/key/policy;
2. read nonterminal elevated Runtime custody from Node journal;
3. ask helper to reconcile exact Runtime/unit identities;
4. compare helper signed state, systemd state, Node state, and Control Plane expected state;
5. reattach stream cursors where provably safe;
6. otherwise mark structured Agent state `recovery_required`;
7. never start a replacement root process automatically.

On helper start, perform the equivalent root-journal/systemd reconciliation before admitting new work.

## Workstream 6 — local setup, CLI, systemd, packaging, and update

### Root package

Build and install a root-owned helper package. A recommended layout is:

```text
/usr/libexec/conduit/conduit-privileged-helper
/usr/libexec/conduit/conduit-privileged-exec   # if split
/usr/lib/systemd/system/conduit-privileged-helper@.socket
/usr/lib/systemd/system/conduit-privileged-helper@.service
/etc/conduit/privileged-helper.d/
/var/lib/conduit/privileged-helper/
/run/conduit/privileged/
```

The exact prefix may be configurable for packaging tests, but production root binaries must not execute from a user-writable directory.

### Systemd socket/service

Use a templated per-UID socket/service or an equivalently isolated design.

The socket unit should use AF_UNIX sequential packets, a root-owned parent directory, target-user endpoint ownership, and restrictive mode.

Harden the helper service where compatible with its duties. At minimum investigate and test:

- `PrivateNetwork=yes`;
- `RestrictAddressFamilies=AF_UNIX`;
- no IP listener;
- `NoNewPrivileges=yes` for the helper service itself where compatible;
- root-owned read-only executable/config paths;
- writable paths limited to helper state/runtime directories;
- protected kernel tunables/modules/control groups where compatible;
- locked personality and native syscall architecture;
- bounded file descriptors, tasks, memory, and restart behavior;
- explicit system D-Bus access required for transient units.

Do not copy hardening options without verifying the helper still works. Record effective `systemd-analyze security` evidence without claiming that a score proves correctness.

The elevated target unit is intentionally broad host authority. Do not apply helper-service hardening to it in a way that contradicts Full Device semantics without reporting the restriction.

### Installer

Add root-specific install/update/uninstall flows, for example:

```text
installers/install-privileged.sh
installers/update-privileged.sh
installers/uninstall-privileged.sh
```

Requirements:

- explicit local `sudo`/root action;
- no remote automatic installation;
- verify root-owned paths and reject symlinks;
- install binaries atomically with root ownership and fixed modes;
- install and daemon-reload systemd units;
- generate keys/config only through the setup command;
- never print private keys or secret ticket material;
- transactional update with rollback;
- helper/Node protocol compatibility check before activation;
- refuse downgrade across incompatible journal/protocol versions;
- do not destroy active elevated Runtime custody during update;
- uninstall refuses while active Runs exist unless an explicit terminate/discard option is provided;
- preserve root journal and keys by default on uninstall, with a separate destructive purge action;
- support `DESTDIR` packaging tests without invoking live systemd.

Do not add a broad sudoers entry.

### Local authorization/setup UX

Expose CLI operations such as:

```text
conduit privileged status
conduit privileged prepare
conduit privileged doctor
conduit privileged registration-bundle
```

Provide a root-owned setup/admin command for:

```text
enable
disable
approve policy revision
allow/disallow full_device + never
allow/disallow unrestricted elevated launch
rotate receipt key
rotate pinned Control Plane key
stop active elevated Runs
uninstall/purge
```

Names may differ. The privilege-changing command must run from a root-owned installed binary, not a mutable checkout or user-owned script.

If polkit is used, identify the subject with PID, PID start time, and UID, and obtain the UID from Unix peer credentials. Do not authorize by a bare PID. A `sudo`-based explicit local setup path is acceptable and should remain available for headless Linux.

### Browser and API setup

Final visual design is excluded. Add only the typed API and minimal unstyled browser flow needed to:

- review helper installation fingerprint, UID, Device, origin, policy digest, and capabilities;
- perform fresh Passkey authentication;
- approve/revoke the helper registration;
- approve broader helper-policy attestation;
- display enabled/disabled/mismatch/recovery-required state.

Provide realistic fixtures and bounded composite snapshot fields for the future Dashboard. Do not design the final screen.

### Doctor and diagnostics

`conduit doctor` and `conduit privileged doctor` must report, without secrets:

- helper binary/unit/socket installation;
- root ownership and mode checks;
- active systemd unit versions;
- helper protocol compatibility;
- helper installation ID and public-key fingerprint;
- root/user policy revisions and digest agreement;
- Control Plane registration state;
- effective `full_device`, `full_device + never`, structured-approval, PTY, pause, and recovery capabilities;
- systemd/pidfd/openat2/execveat support;
- active elevated Runtime count and recovery state;
- stable remediation codes.

## Workstream 7 — observability and evidence

Extend Run Manifest and normalized Events without collecting hidden reasoning.

Record:

- helper installation/key/policy identities and revisions;
- ticket issuance/request digest and approval evidence;
- helper admission/start/control/terminal receipt digests;
- actual UID/GID evidence;
- systemd unit/invocation/cgroup identity;
- capability state and degradation reason;
- process and stream custody transitions;
- restart/reconciliation decisions;
- whether approval is exact-command, Adapter-mediated, or unavailable;
- root-owned local opt-in state as a boolean/capability, not secret config content.

Do not upload canonical local paths, helper private state, raw root logs, or secret environment values as ordinary metadata.

Raw elevated logs follow the existing opt-in, bounded, redactable content policy. The helper must not log ticket bodies, credentials, secret FDs, or complete environment maps.

Document that a root Agent can modify local Node/helper software and local evidence. Stronger evidence comes from commitments already delivered to the Control Plane or another Device; do not call local logs tamper-proof.

## Security and correctness tests

### Protocol tests

Test at least:

- valid handshake and capability probe;
- wrong UID/PID/start identity;
- wrong Device/helper installation;
- stale Node boot or controller epoch;
- malformed, truncated, oversized, duplicate, and unknown packets;
- wrong number/type of ancillary FDs;
- `MSG_CTRUNC`/`MSG_TRUNC` handling;
- missing close-on-exec;
- signature/key/audience/origin failure;
- ticket expiry/future timestamp;
- nonce replay;
- same idempotency key with same/different digest;
- protocol downgrade;
- policy revision/digest mismatch.

### Path and launch tests

Test:

- symlink executable;
- executable replaced between plan and start;
- shebang script and interpreter replacement;
- cwd replacement;
- magic-link and `/proc` traversal;
- user-writable helper/worker path rejection;
- environment injection variables;
- argument preservation including spaces, Unicode, empty arguments, and leading dashes;
- no shell reconstruction;
- root-owned managed HOME and Credential Projection cleanup.

### Authorization tests

Build a matrix covering:

- full_user vs full_device;
- Owner browser, local CLI, read-only MCP, full-device MCP;
- Connector ceiling narrower than Assignment;
- Project Agent/Assignment deny;
- Device user policy deny;
- root helper policy deny;
- helper disabled/revoked/mismatched;
- `never` allowed server-side but denied locally;
- `never` allowed locally but denied server-side;
- mandatory risk classes;
- Adapter with/without enforceable approval bridge;
- ticket copied across Project/Run/Device/helper;
- remote attempt to install or enable helper.

### Crash/fault tests

Inject crashes or response loss at every important boundary:

1. before helper journal admission;
2. after admission before execution record;
3. after execution record before systemd request;
4. after systemd request before method response;
5. after unit creation before liveness receipt;
6. after liveness before Node response;
7. after root process exits before terminal receipt;
8. after signed receipt before Node custody;
9. after Node custody before Control Plane projection;
10. helper restart while process lives;
11. Node restart while process lives;
12. Control Plane/Device disconnect;
13. SQLite full/corrupt/I/O failure;
14. systemd restart or unit disappearance;
15. duplicate control request;
16. helper update during active Run.

Assert exact-once start. Any case that cannot prove whether a root effect occurred converges to `uncertain` or `recovery_required` and never auto-starts a replacement.

### Process lifecycle tests

Test:

- exact root UID/GID observation;
- process-tree/cgroup containment;
- stdin/stdout/stderr streaming;
- PTY and resize;
- graceful/forced stop;
- pause/resume;
- timeout;
- child/grandchild cleanup;
- terminal exit/signal receipt;
- stream replay by cursor;
- explicit persistent Agent session and follow-up input;
- structured Adapter settlement;
- restart reconciliation;
- cleanup and active-run uninstall refusal.

### Control Plane tests

Test:

- clean migration through the new schema version;
- helper registration with fresh Passkey;
- stale/non-fresh session rejection;
- policy broadening confirmation and narrowing immediacy;
- ticket issuance idempotency and conflict;
- receipt signature and transition verification;
- cross-Device/cross-Run negative cases;
- revocation and key rotation;
- no raw path/secret in D1 rows or public errors;
- Free-profile D1 statement/parameter/write budgets;
- zero idle helper writes/alarms/polls.

## Linux live E2E

Normal CI may use a fake systemd manager and temporary rootless helper backend for deterministic tests. That is not sufficient for completion.

Add an explicit live script, for example:

```text
scripts/e2e-full-device-live.sh
```

Run it on `sahur-pc` with a real system systemd manager and local root authorization. It must use isolated test directories and leave the host clean.

The live test must prove all of the following:

1. build release binaries from the exact PR head;
2. install the root package from a root-owned staging path;
3. create and register a helper installation identity;
4. exercise the fresh-Passkey/registration boundary through the real Control Plane when credentials are available, or an explicitly isolated cryptographic test deployment;
5. verify an ordinary `full_user` command reports the Device user's UID and does not contact the helper;
6. run an exact `full_device` command and prove UID 0;
7. create a root-owned marker only inside a dedicated temporary E2E directory, then clean it through an independently authorized operation;
8. verify the signed helper admission/start/terminal receipts at Node and Control Plane boundaries;
9. verify exact argv without shell reconstruction;
10. exercise stdout/stderr/stdin;
11. exercise PTY and resize;
12. exercise pause/resume, graceful cancel, force stop, and timeout;
13. run a fake or local structured Codex-compatible Agent protocol as root through the same Runtime/Adapter path without paid inference;
14. prove Agent prompt acceptance remains separate from root process liveness;
15. restart `conduit-node` during an active elevated process and reconcile without duplicate start;
16. restart the helper during an active elevated process and reconcile;
17. simulate lost response after systemd start and prove receipt replay/no duplicate;
18. prove `full_device + never` fails until both the server-side policy and root-owned local flag are enabled;
19. prove a same-user client without a valid exact ticket cannot elevate;
20. prove a remote MCP/Control Plane request cannot install or enable the helper;
21. prove update and rollback preserve active custody;
22. prove uninstall refuses active Runs and succeeds after explicit termination;
23. verify no helper IP sockets are opened;
24. record bounded `systemd-analyze security` and effective capability evidence;
25. remove E2E units, sockets, configuration, keys, journals, marker files, and temporary Control Plane resources according to the test cleanup policy.

Never run destructive tests against ordinary `/etc`, package databases, network configuration, user data, or production services. Use a dedicated temporary root-owned test root and fixed harmless executables.

If `sudo`, systemd, or required host capabilities are unavailable, report the live test as blocked. Do not replace it with a fake success and do not mark the PR ready for review as a completed Full Device implementation.

## CI and verification

Keep Linux-only CI. Preserve all existing jobs and add focused jobs where useful.

Required commands at completion:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
pnpm install --frozen-lockfile
pnpm --filter @conduit/schema check:wire
pnpm -r typecheck
pnpm -r test
pnpm -r build
python scripts/validate_spec.py
./scripts/test-packaging.sh
./scripts/check-all.sh
```

Add deterministic helper protocol, journal, systemd-backend, ticket, receipt, Node, Adapter, Control Plane, migration, packaging, update, and fault tests.

Do not put the privileged live test on every ordinary push if it requires mutable machine setup. Keep a reproducible script and record the exact host/kernel/systemd/helper/commit evidence in the PR. A self-hosted or manually dispatched protected workflow is acceptable if no untrusted fork can execute root code on the runner.

## Documentation and ADRs

Add:

- `docs/FULL_DEVICE_ACCESS.md`
- `docs/adr/0013-privileged-helper-and-signed-elevation-tickets.md`

Update at least:

- `docs/AUTHORIZATION.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/RUNTIME_PROVIDER.md`
- `docs/NODE_PROTOCOL.md`
- `docs/TRACE_FORMAT.md`
- `docs/LINUX_OPERATIONS.md`
- `docs/LINUX_E2E.md`
- `crates/conduit-node/README.md`
- relevant installer/package documentation

The ADR must record:

- why `conduit-node` remains unprivileged;
- why signed exact tickets and root-owned local policy are both required;
- why AF_UNIX `SOCK_SEQPACKET` and peer credentials are used;
- why the helper is networkless;
- why systemd transient units/fixed exec worker own elevated process custody;
- how one-shot commands differ from unrestricted root Agent sessions;
- which approval modes are enforceable for structured Agents;
- restart and uncertain-effect rules;
- key rotation and revocation;
- audit limitations after granting host root;
- rejected alternatives such as setuid Node, wildcard sudoers, generic root shell RPC, and provider-socket exposure.

## Completion report

Before removing Draft status, update the PR body with factual evidence, not planned work.

Include:

1. implemented architecture and changed trust boundaries;
2. protocol/schema versions and migrations;
3. helper/systemd/install/update details;
4. supported command and Agent paths;
5. Approval-mode enforcement matrix by Adapter;
6. effective capability matrix;
7. root local-policy examples without secrets;
8. unit/contract/integration/fault test counts;
9. packaging and upgrade/rollback results;
10. exact Linux live E2E commit, host prerequisites, commands, and receipts;
11. Cloudflare Free-profile before/after budget impact;
12. explicit gaps or blocked live tests;
13. security limitations of a running root Agent;
14. cleanup evidence from the live test.

A feature is not `Complete` if it exists only as a schema, fake backend, fixture, unavailable capability, or unrun live path.

## Final acceptance checklist

The PR may be marked ready for review only when every statement below is true:

- `conduit-node` still runs as the ordinary user;
- helper is root-owned, networkless, socket activated, and packaged;
- remote clients cannot install, enable, or reconfigure it;
- Native `full_user` never invokes it;
- Native host `full_device` cannot run without an exact signed ticket and matching root policy;
- `full_device + never` requires separate server and root-local opt-ins;
- helper admission is durable before side effects;
- start and controls are idempotent and digest-bound;
- target launch is exact and race-safe, with no shell reconstruction by the helper;
- root process lifecycle and I/O are connected to Runtime and Agent abstractions;
- helper/Node restart cannot duplicate an effect;
- uncertainty is explicit and never auto-retried;
- helper receipts are signed and verified before elevated state is projected;
- Control Plane stores no local paths or secrets;
- Adapter approval claims match actual enforceability;
- normal CI is green;
- packaging/update/rollback/uninstall tests are green;
- the `sahur-pc` live root E2E is green and cleaned up;
- the PR body reflects actual evidence;
- the PR remains unmerged for review.
