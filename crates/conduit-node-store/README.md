# conduit-node-store

Device-local SQLite custody and file storage.

- SQLite runs in WAL mode with `synchronous=FULL`, foreign keys, migrations,
  busy bounds, and a startup integrity check.
- Operation idempotency keys are unique. Same-key/same-digest delivery replays
  the durable record; a changed digest conflicts; uncertainty never retries.
- Directional transport and per-Run event sequences remain persistent across
  connections and Node restarts.
- Device identity is Ed25519 in a regular mode-0600 file.
- Credential profiles use XChaCha20-Poly1305 with metadata as associated data,
  remain Adapter-bound, and expose no secret-bearing `Debug` representation.
- Storage profiles enforce quotas, pins, collection, credential, and final-copy
  custody gates.
- Content objects use SHA-256 paths and atomic local publication.

`open_read_only` supports diagnostics and always refuses new custody. SQLite
corruption, read-only operation, and disk-full conditions map to distinct
fail-closed errors.
