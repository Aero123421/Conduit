# Node transport fixtures

Every JSON frame in this directory validates against `../../schemas/node-transport-v1.schema.json`.

The signatures are deterministic verification fixtures. They do not use deployment keys.

```text
Control-plane Ed25519 public key
iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w

Device Ed25519 public key
gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q
```

Digest rules are defined in `docs/NODE_TRANSPORT.md`.

The fixtures intentionally use only strings, integers, booleans, arrays, and objects in the RFC 8785 I-JSON subset.

`reconciliation-cases.json` is a behavior matrix for fake-node and fake-control-plane tests. It is not a wire frame.
