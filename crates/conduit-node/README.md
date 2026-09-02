# conduit-node

Linux user service for Device-local operation admission and execution.

The service exposes a mode-0600 Unix socket and verifies `SO_PEERCRED` before
decoding a bounded request. `health` checks the local journal; `doctor` performs
live Provider probes. The control-plane client accepts only `wss:` endpoints,
uses bounded DNS/address/connect/handshake time, performs the
`device.hello`/challenge/proof/accepted exchange, and fences every frame by the
persisted connection epoch.

Transport custody and operation state are independent. Incoming frames are
stored before an ACK can be emitted. An admitted operation is stored before a
Provider is called. Reconciliation plans are stored before their effectful
steps, and remote work remains disabled until reconciliation completes.

Run locally:

```text
cargo run -p conduit-node -- serve --data-dir /absolute/device/data --socket /absolute/runtime/node.sock
```

With no flags, `serve` uses `$XDG_DATA_HOME/conduit`,
`$XDG_RUNTIME_DIR/conduit/node.sock`, and
`$XDG_CONFIG_HOME/conduit/launch-profiles.json` (with the documented HOME
fallbacks for data and config). The IPC parent directory must already be owned
by the service user and mode 0700; symlinked path components are rejected.

Remote work additionally requires an owner-only launch profile file containing
a positive, Device-local policy revision and explicit allowlists for capability,
provider, access scope, approval mode, and launch profile. Connector policy
revision is retained in the immutable offer but never substitutes for this local
decision. `full_user` combined with `never` requires a separate explicit
local-policy opt-in. `full_device` fails closed with
`full_device_capability_unavailable` unless the packaged root helper, signed
capability and registration bundle, active Control Plane registration, exact
privilege ticket, root-owned policy, durable helper journal, systemd custody,
and helper receipt-verification path all match. It never falls back to
`full_user`.

The optional Linux path is enabled only when both
`--privileged-socket /run/conduit/privileged/<uid>.sock` and
`--privileged-registration-bundle <root-helper-export.json>` are supplied. At
startup the Node performs the Device-key challenge/proof handshake, verifies
the helper-signed capability and receipt key, and submits the Device-signed
registration attestation. It does not advertise effective `full_device` until
the correlated `privilege.registration_result` is active. Prepare, start, Agent
input, PTY resize, pause, resume, stop, and kill each obtain their own exact
ticket. The complete helper receipt chain is persisted and projected; a generic
unsigned Node state claim cannot substitute for it.

On restart, privileged reconciliation checks root journal, systemd unit,
Invocation ID, process identity, state revision and receipt chain before
reattaching. If exact Agent/stream custody cannot be restored, the Node records
`privileged_runtime_recovery_required` and does not respawn or replay the
prompt. Setup, registration, policy enabling, key rotation, update, rollback,
uninstall, and live-root verification commands are documented in
`docs/LINUX_OPERATIONS.md` and `docs/LINUX_E2E.md`.

Docker, Podman, Incus, KVM, bubblewrap, and systemd user scopes are diagnosed
but never installed or globally configured by the network-facing service.
Enrollment and key rotation produce signed Device-local requests; external
confirmation remains a separate prerequisite.

Locations are registered over the owner-authenticated local socket and their
canonical paths are retained only in the mode-0600 Device-local Source
registry. Remote Source revisions are revalidated against that registry on
every use. Git read-only/direct/worktree modes and bounded managed copies
produce durable custody records before Runtime start. Worktree leases are
locked and journaled so restart reconciliation cannot silently create a second
writer.

`agent.run.start` selects only a structured `conduit-adapters` profile. The
adapter ID must also appear in the Device-local policy `launchProfiles`
allowlist. The Linux provider bridge runs the same bounded protocol driver in
Native, Restricted Native, Docker/Podman, and Incus/KVM. Container and VM
images must provide the selected adapter at the fixed Device-owned guest path;
missing guest execution capability fails closed. Reviewer operations require a
read-only Access Scope, read-only Source revisions, and an enforcing non-Native
provider. Visible normalized adapter events are committed to the Device-local trace store and
event journal. Hidden reasoning, raw stderr, and credentials are not captured.
Input, follow-up, steer, close, cancel, and launch-time native-session resume use
typed adapter operations and fail closed when the selected protocol does not
support the requested control. Settlement defaults to `close_on_settle`, which
archives/closes a long-lived adapter and releases its Runtime. An explicitly
requested persistent session instead enters durable `waiting_input` under a
bounded Device lease and idle timeout.

Agy uses its documented headless stream contract: prompts are NDJSON `user`
events on stdin, output is `init`/`step_update`/`result` NDJSON, and resume uses
the emitted conversation ID. Prompts are never placed in process arguments.
