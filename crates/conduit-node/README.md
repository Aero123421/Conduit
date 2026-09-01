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
cargo run -p conduit-node -- --data-dir /absolute/device/data --socket /absolute/runtime/node.sock
```

The initial CLI intentionally has no enrollment or provider-setup mutation.
Docker, Podman, Incus, KVM, bubblewrap, and systemd user scopes are diagnosed
but never installed or globally configured by the network-facing service.
