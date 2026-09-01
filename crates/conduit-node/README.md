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
decision. `full_user` or `full_device` combined with `never` requires a separate
explicit local-policy opt-in.

The initial CLI intentionally has no enrollment or provider-setup mutation.
Docker, Podman, Incus, KVM, bubblewrap, and systemd user scopes are diagnosed
but never installed or globally configured by the network-facing service.
Agent protocol adapters and opaque Location/workspace resolution are not linked
in this crate revision. `agent.run.start` and offers with unresolved Source
revisions therefore receive durable `operation.admission` rejections rather
than being passed to a generic executable.
