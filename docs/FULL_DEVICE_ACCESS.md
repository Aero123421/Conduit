# Linux Full Device Access

Native host `full_device` is an optional, explicit Linux capability. The normal
Node remains the logged-in user's service. Elevation uses a separately installed
root helper and a fixed root exec worker; it is never a fallback for
`full_user`, Restricted Native, Container, or VM execution.

## Required authority chain

An elevated start is admitted only when all of these exact records agree:

1. current Owner, caller, grant, Connector Policy, Project Agent, Assignment,
   Project, and Device ceilings;
2. immutable operation, Run Manifest, Runtime Spec, source and approval
   commitments;
3. Device-signed ticket request containing the Device-local execution-plan
   digest;
4. active Owner-approved helper installation, receipt key, policy attestation,
   and current Device connection epoch;
5. Control Plane Ed25519 privilege ticket for one exact operation;
6. user-owned Device policy;
7. root-owned local policy and its independent `never` and unrestricted-launch
   flags;
8. helper durable admission before the systemd request;
9. helper-signed admission, running, control, and terminal receipt chain;
10. independent Node and Control Plane receipt verification.

Failure at any layer returns a stable denial. No layer may silently choose
ordinary Native or reduce `full_device` to `full_user`.

## Local data boundaries

The Control Plane stores public keys, bounded labels and summaries, revisions,
digests, ticket ciphertext-free canonical records, and verified receipt
metadata. The Device holds canonical paths and the exact plan. Root-owned
policy, private receipt key, admission journal, execution records, and stream
spools stay under the helper state directory. Credential plaintext travels only
through admitted sealed descriptors or root-owned managed files and does not
enter tickets, D1, journals, or logs.

The helper socket is per UID and accepts sequential packets. Kernel peer
credentials and a Device-key proof are both required. The helper has no IP
network access and cannot call Cloudflare.

## Lifecycle receipts

The following remain distinct: operation admission, ticket issuance, helper
durable admission, systemd unit creation, root liveness, Agent initialization,
prompt acceptance, Agent settlement, workspace collection, helper terminal,
Node terminal submission, and Control Plane acceptance. A transport ACK proves
none of the later transitions.

Start and controls are separate. Input, PTY resize, pause, resume, graceful
stop, force stop, and reconciliation target the exact Runtime, unit,
Invocation ID, controller epoch, expected state revision, and handle digest.
Read-only stream replay uses cursor custody and does not mint broad authority.

## Approval capability

Exact commands support a one-shot plan approval. Structured Agents require a
tested pre-execution Adapter bridge. Effective `never` additionally requires an
empty/satisfied mandatory risk-class set and explicit server and root-local
opt-ins. Missing enforcement returns
`full_device_approval_enforcement_unavailable`; it is not described as Never
Ask.

## Restart and uncertainty

On helper restart, the root journal is compared with systemd unit, Invocation
ID, cgroup and process identity before new admission. On Node restart, the Node
first verifies helper installation, key and policy, then reconciles every
nonterminal privileged Runtime. Matching stream and Adapter custody may attach;
otherwise the existing process is preserved or explicitly stopped by a new
authorized control and the Agent becomes
`privileged_runtime_recovery_required`. No ambiguous prompt or root process is
automatically repeated.

## Operations

Production layout and commands are documented in `docs/LINUX_OPERATIONS.md`.
Root setup is always an explicit local action. Browser helper registration only
approves which already-installed local key and policy the Control Plane may
trust; it cannot install, enable, or reconfigure the service.

Capability is reported from a verified signed probe, not executable presence.
The probe includes helper/protocol version, installation and key fingerprint,
policy revision/digest, systemd reachability, peer credential enforcement,
transient units, cgroup/freeze, pidfd/openat2/execveat, PTY/stream replay, and
the two local opt-ins.

## Protocol and test vectors

The helper wire contract is `spec/schemas/privileged-helper-v1.schema.json`;
the public registration, ticket-request/result, and receipt frames are in
`spec/schemas/node-protocol-v1.schema.json`. Canonical valid shapes are kept in
`spec/examples/privileged-helper/` and
`spec/examples/node-protocol/privilege-installation-attestation.json`. They use
synthetic IDs, hosts, keys, digests, process values, and signatures and contain
no contributor or deployment data.

Rust contract tests cover canonical claim validation, wrong key/audience/origin,
helper/UID/Device/operation/epoch binding, expiration and future issuance,
digest mutation, unsupported versions, signature failure, packet and FD bounds,
and journal idempotency conflicts. The schema validator and generated
TypeScript validators separately reject malformed wire shapes and generated
code drift. These deterministic checks are not substitutes for the protected
real-root/systemd live test described in `docs/LINUX_E2E.md`.

## Threat model and verification map

`Prevented` means the request is rejected before a new root effect. `Detected`
means custody converges to a signed terminal, uncertain, or recovery-required
record. `Limited` means the design reduces reusable authority but cannot remove
the stated host-admin consequence. `Inherent` is an explicit consequence of an
already authorized root Agent.

| Threat | Treatment | Enforced and exercised by |
|---|---|---|
| Narrow remote MCP Connector | Prevented | Connector/Assignment/Device ceilings and Control Plane cross-project and privilege-ticket tests |
| Stolen or stale OAuth token | Prevented/limited | grant revision, expiry, revocation, fresh-Passkey and CSRF/replay tests |
| Compromised Device-user process | Limited | root policy, pinned issuer, one-use exact ticket, peer plus Device proof; it cannot edit root authority |
| `full_user` Agent attempts elevation | Prevented | explicit provider selection and the live helper-disabled Full User case |
| Malicious same-UID helper client | Prevented | challenge transcript, Device signature, exact ticket and peer process-birth checks |
| Stale Node after restart/update | Prevented/detected | controller-epoch fencing, helper reconciliation, signed recovery receipt and restart tests |
| Replayed ticket | Prevented | root-journal one-use admission and exact same-digest receipt replay tests |
| Ticket copied to another Device/helper | Prevented | installation, key, Device, UID and public-origin binding tests |
| Plan changed after approval | Prevented | Runtime Spec, local plan, launch/control and immutable operation digest tests |
| Executable/cwd/symlink/interpreter race | Prevented | descriptor-relative identity/digest validation and helper worker replacement tests |
| Forged helper receipt | Prevented | active helper-key signature, receipt chain and Node/Control Plane binding tests |
| Helper restart during launch | Detected | durable boundary fault injection, journal/systemd reconcile and no-duplicate-start tests |
| Node restart with live root process | Detected/limited | helper-signed reconcile, same Invocation attach where safe, otherwise `recovery_required`; no respawn |
| Lost Control Plane response and retry | Prevented | request/idempotency uniqueness and DeviceRoom replay tests |
| Root Agent tampers with local software/evidence | Inherent | disclosed below; previously projected remote commitments remain the stronger evidence |
| Storage exhaustion or SQLite failure | Prevented/detected | pre-effect durable admission and crash/storage fault tests |
| Ticket signing-key rotation or compromise | Limited | Owner-activated revisions, overlap/revocation and explicit locally pinned replacement fingerprint |
| Helper/protocol downgrade | Prevented | package compatibility probe, schema version checks and rollback tests |
| Unexpected, duplicated, truncated or forged FDs | Prevented | `SOCK_SEQPACKET` ancillary bounds and sealed descriptor manifest tests |
| User enables elevation without root setup | Prevented | root-owned package/policy commands and remote MCP/HTTP administration-denial tests |

The live script covers only the cases it reports in its bounded result artifact.
The table also cites deterministic protocol/fault tests; it does not relabel
those tests as live host evidence.

## Audit limitation

Host root is intentionally broad authority. A root Agent can alter Node/helper
software, credentials, and local records. Signed receipts prove what the trusted
helper committed at the time; they do not make later local state tamper-proof.
Canonical paths, raw streams, prompts, credentials, and host identifiers are
excluded from public evidence.
