# ADR 0013: Networkless privileged helper and signed elevation tickets

- Status: Accepted
- Date: 2026-09-03

## Context

Native `full_device` grants host administrator authority. Running
`conduit-node` as root would combine Internet transport, OAuth-derived work,
Agent protocol parsing, local workspace custody, credentials, and host
administration in one process. A wildcard sudo rule or generic root command RPC
would have the same authority-confusion problem. The existing user Node must
remain unable to remove a root-owned local denial.

The Control Plane can authorize intended work but cannot inspect a Device-local
executable or path safely. Conversely, a local helper cannot reconstruct the
Connector, Project Agent, Assignment, approval, and revocation decisions held
by the Control Plane. Both authorities are required at the start boundary.

## Decision

### Separate root service

`conduit-node` remains an ordinary user service. Native host `full_device`
selects a distinct `privileged-native` Provider backed by an optional root-owned
helper. The helper has no IP network namespace, accepts only
`conduit.privileged/1` packets over a per-UID AF_UNIX `SOCK_SEQPACKET` socket,
and verifies Unix peer credentials plus a Device-key challenge. Packet and
ancillary-data boundaries are preserved; truncated packets, unexpected FDs,
and missing close-on-exec fail closed.

`SOCK_SEQPACKET` is used because a ticket, execution plan, and descriptor
manifest must be accepted or rejected as one bounded record. Stream framing
ambiguity is excluded at this privilege boundary. Peer credentials identify
the kernel-observed UID/PID; a signed challenge also binds PID birth, Node boot,
Device, installation, nonces, and time.

### Two-key authorization

Every elevated effect requires both:

1. an exact, short-lived, one-use Ed25519 ticket issued by the Control Plane;
2. a matching root-owned policy under `/etc/conduit/privileged-helper.d/`.

The ticket binds the Device, helper installation and key, UID, operation, Run,
Runtime, immutable Run Manifest and Runtime Spec, local execution-plan digest,
controller epoch, all policy revisions, access and approval settings, risk
classes, ceilings, validity, and nonce. The helper keeps pinned Control Plane
public keys. It never fetches trust material from the network. The Node cannot
broaden either ticket or root policy.

`full_device + never` additionally requires distinct server-side and
root-local opt-ins. One-shot commands bind approval to the exact local plan.
Structured Agents may use `always`, `outside_scope`, or `risk_classes` only when
their Adapter provides the tested pre-execution approval bridge for the
relevant action. An Adapter name is not evidence of enforcement.

### Durable admission and process custody

The helper writes a root-owned SQLite admission record and consumes the ticket
before any external effect. Same idempotency identity and digest replays the
stored receipt; another digest conflicts. A crash window that cannot prove
whether systemd accepted a start converges to `uncertain` or
`recovery_required`, never to an automatic second start.

After admission the helper writes a root-owned execution record. It asks the
system systemd manager through a typed D-Bus call to start a transient unit
whose executable is the fixed root-owned Conduit exec worker. Remote input
cannot supply arbitrary unit properties. The unit name derives only from the
validated Runtime ID, uses `KillMode=control-group`, has restart disabled, and
applies only allowlisted resource properties.

The exec worker revalidates the execution record. Executable, interpreter, cwd,
and relevant ancestors are opened and compared by descriptor identity and
digest; supported launches execute the verified object without returning to an
unverified path string. Shell reconstruction is never used. Environment starts
from a fixed allowlist and rejects loader/interpreter injection variables.

Systemd unit, Invocation ID, cgroup, controller epoch, Runtime handle digest,
PID birth, and state revision form process custody. Controls target that exact
custody, never an arbitrary PID. Ordinary controls use systemd unit/cgroup
operations; pidfd is used for a direct signal when supported.

The WebSocket connection epoch and Runtime controller epoch are separate
authorities. A reconnect advances only the courier epoch used to authenticate
and fence transport frames. Every effectful control request carries the exact
Runtime controller epoch from durable custody; the Control Plane verifies it
against the immutable control operation and current Runtime or Agent custody,
then copies that epoch into the helper ticket. It never substitutes the current
WebSocket epoch. This permits control after a Node reconnect without widening
the target or authorizing a replacement Runtime.

### Signed evidence and projection

The helper has a root-owned receipt key. Capability, admission, start, control,
and terminal receipts are RFC 8785 canonical JSON signed with Ed25519. Receipt
chains bind the ticket and plan or exact control, monotonic state revision,
previous receipt digest, effective UID/GID, systemd identity, stream cursors,
and terminal status.

The Node verifies the active helper key and exact bindings before recording an
elevated transition. The Control Plane independently verifies the same chain.
A privileged Runtime is never polled through the ordinary unauthenticated
provider inspection method. The Node uses bounded-cadence helper inspection,
records every monotonic helper-signed observation, and permits signed stable
`running` or `paused` observations without treating them as a new effect.
A Native host `full_device` Run cannot become running, terminal, or
ready-for-review from an ordinary Node claim alone. D1 retains bounded public
metadata and digests, never local canonical paths, private keys, credential
plaintext, or the raw plan.

The Device-signed policy attestation also forms a monotonic chain. A changed
policy must increase its revision and name the exact active policy digest as
`previousPolicyDigest`; an exact replay must reproduce its original
predecessor. The Node persists only the last Control Plane-accepted revision,
digest, and predecessor in its local journal. The Control Plane registration
result returns those exact values, and a fresh result is durably delivered for
each connection epoch so a restarted Node cannot activate issuer keys from an
uncorrelated or stale policy response.

### One-shot and retained Agent sessions

A one-shot command ends with its root process. A structured root Agent may be
retained only when the Assignment, ticket, root policy, Adapter capability, and
lease all permit it. Provider settlement remains separate from root liveness.
Follow-up and every effectful control require an exact action ticket. If a Node
restart cannot prove structured I/O and protocol reattachment, the process is
not replaced and the Agent enters `privileged_runtime_recovery_required`.

### Keys, revocation, and offline work

Ticket issuer and helper receipt keys rotate through explicit revisions with a
bounded overlap for verification. Broadening a helper policy requires fresh
Owner Passkey approval; narrowing and revocation prevent new tickets
immediately. Revocation cannot prove that an offline root process stopped. A
separately signed stop action is required when connectivity returns.

The initial disabled root policy may attest an empty ticket-key allowlist. This
is the only bootstrap state in which no issuer key is pinned: it cannot accept
a privilege ticket because the helper is disabled and there is no matching
issuer. Pinning the first issuer and enabling the helper remain separate,
explicit local-root mutations and produce a new signed policy revision.

### Installation and update

Only explicit local root commands can install, enable, configure, rotate, stop,
uninstall, or purge the helper. A browser, MCP client, Device frame, or Agent
cannot do so. Updates verify protocol and journal compatibility before
activation, preserve active systemd custody, and roll back atomically on failed
health. Uninstall refuses active Runs by default and preserves keys and journal;
purge is a separate destructive local action.

Helper-service hardening must preserve the capabilities used by its fail-closed
path checks. In particular, the packaged service does not enable
`RestrictSUIDSGID`: systemd 255 applies that option with a syscall filter which
causes required `openat2` probes to return `ENOSYS` even when the kernel supports
the syscall. The live root E2E verifies the effective sandbox, absence of helper
IP sockets, and signed capability evidence instead of inferring correctness from
the hardening option name or `systemd-analyze security` score.

## Security limitation

A running root Agent can alter host software and local evidence. Helper signing
prevents an unprivileged Node from inventing receipts; it does not make evidence
tamper-proof against an already-authorized malicious root process. Evidence
committed to the Control Plane before local modification is stronger, and this
limitation is always reported.

## Rejected alternatives

### Run `conduit-node` as root or setuid

Rejected because it combines remote protocol and Agent parsing with ambient
administrator authority.

### Wildcard sudoers entry or generic root shell RPC

Rejected because neither binds exact immutable work, local policy, expiry,
idempotency, process custody, or a signed result.

### Let the Agent access the helper or provider-management socket

Rejected because it bypasses Node admission and exposes a reusable authority
channel inside the Runtime.

### Trust a helper binary probe or Node assertion

Rejected because installed software is not effective capability and an
unprivileged Node cannot attest root-owned policy or root process state.

### Automatically restart after an ambiguous effect

Rejected because the first root process or filesystem effect may already have
occurred.

## Consequences

- Full Device stays fail-closed unless the entire ticket, policy, journal,
  systemd, receipt, Node verification, and Control Plane verification path is
  effective.
- Helper and Node journals are independent authorities and must reconcile.
- Each Adapter advertises only approval modes it actually enforces.
- Packaging and Linux live tests become release evidence for this capability.
- The Cloudflare path is event driven; helper idle state creates no poll,
  periodic D1 write, Queue message, or Durable Object alarm.

## Contract

- `docs/FULL_DEVICE_ACCESS.md`
- `docs/AUTHORIZATION.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/RUNTIME_PROVIDER.md`
- `docs/NODE_PROTOCOL.md`
- `docs/TRACE_FORMAT.md`
- `spec/schemas/privileged-helper-v1.schema.json`
