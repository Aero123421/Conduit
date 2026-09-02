# Linux operations

This guide covers the non-visual Linux product. The Cloudflare control plane
stores shared metadata and routing state. Canonical paths, provider credentials,
active process state, workspace contents, VM disks, and raw trace content remain
on the Device unless an explicit artifact policy uploads a bounded object.

## Supported toolchain

- Rust 1.92
- Node.js 22.12
- pnpm 9.15 through Corepack
- Wrangler and Cloudflare package versions pinned by
  `apps/control-plane/package.json`

Run the complete repository gate from the repository root:

```sh
./scripts/check-all.sh
```

This includes locked Rust and pnpm builds, schema and generated-file drift,
secret-pattern checks, metadata validation, and the packaging smoke test.
Hardware- or account-dependent live tests are separate and must print a reason
when a prerequisite is absent:

```sh
./scripts/e2e-linux.sh
```

## Local control plane

Install the locked workspace and create the local D1 database:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @conduit/control-plane types:check
corepack pnpm --filter @conduit/control-plane migrate:local
corepack pnpm --filter @conduit/control-plane test
corepack pnpm --filter @conduit/control-plane dev
```

Wrangler persists local D1, Durable Object, R2, and Queue state under its ignored
development directory. Delete that state only when intentionally starting a new
local deployment; it is not an upgrade mechanism.

For loopback development, configure the public origin, OAuth issuer, and
WebAuthn RP consistently. Production requires one exact HTTPS origin. Do not put
bootstrap material, token peppers, receipt keys, OAuth tokens, Device private
keys, or provider credentials in `wrangler.jsonc`, Git, URLs, fixtures, or
ordinary logs.

## Cloudflare deployment

Provision a D1 database, R2 artifact bucket, ingestion Queue, dead-letter Queue,
and the three Durable Object bindings named in `wrangler.jsonc`. Replace the
template database ID and public origin values for the deployment. Generate each
secret independently and install it through Wrangler:

```sh
corepack pnpm --filter @conduit/control-plane exec wrangler secret put BOOTSTRAP_VERIFIER
corepack pnpm --filter @conduit/control-plane exec wrangler secret put TOKEN_PEPPER
corepack pnpm --filter @conduit/control-plane exec wrangler secret put RECEIPT_SIGNING_KEY
```

`BOOTSTRAP_VERIFIER` is the lowercase SHA-256 verifier of a separately retained
256-bit bootstrap secret. The other two values contain at least 256 bits of
random material. Apply D1 migrations before deploying the Worker:

```sh
corepack pnpm --filter @conduit/control-plane exec wrangler d1 migrations apply conduit-control-plane --remote
corepack pnpm --filter @conduit/control-plane deploy:check
corepack pnpm --filter @conduit/control-plane exec wrangler deploy
```

The dry run is a build check, not evidence of a successful remote deployment.
After deployment, verify `/healthz`, complete owner bootstrap from the exact
configured origin, and run the authenticated API/MCP smoke tests. Retain the D1
migration output with release evidence.

## Node installation

Native Desktop operation does not require Docker, Podman, or Incus.

```sh
cargo build --locked --release --bin conduit --bin conduit-node
./installers/install.sh --start
```

The installer places the two binaries below the selected absolute prefix,
creates owner-only XDG directories, installs a systemd user unit, and leaves
configuration and data intact during uninstall. Use `--prefix /absolute/path`
to select another prefix. The default service is a user service and never opens
an inbound network port.

The service invokes the implemented Node interface directly: `conduit-node
serve --data-dir ... --socket ... --launch-profiles ...`. Installation writes
an owner-only `~/.config/conduit/node.env` with the effective XDG paths. Start
from `packaging/conduit-node.env.example` when editing it; this is systemd
EnvironmentFile syntax, not TOML or shell syntax. `CONDUIT_CONTROL_URL` and
`CONDUIT_DEVICE_ID` must either both be absent or both be set. The Node requires
`wss://` for remote transport, including development endpoints.

Useful service commands are:

```sh
systemctl --user status conduit-node.service
journalctl --user -u conduit-node.service --since today
systemctl --user restart conduit-node.service
conduit --output json doctor
conduit --output json device doctor
```

Doctor output distinguishes `effective`, `degraded`, and `unavailable`. An
installed executable alone is not effective evidence. Provider and Agent live
protocol probes remain opt-in where they could consume paid inference.

### Privileged helper package

Native host `full_device` does not run `conduit-node` as root. It uses the
separate `conduit-privileged-helper` system service and the fixed
`conduit-privileged-exec` worker. The helper is socket activated per Device UID
at `/run/conduit/privileged/<uid>.sock`; the endpoint is owned by that UID with
mode `0600`, while its parent remains root-owned. The helper service has a
private network namespace and permits only `AF_UNIX`. Elevated target units are
separate transient system units and intentionally represent broad host
authority.

Build both binaries from the reviewed commit:

```sh
cargo build --locked --release \
  --bin conduit-privileged-helper \
  --bin conduit-privileged-exec
```

The root installer refuses binaries, unit templates, or target ancestors that
are symlinked, non-root-owned, or writable by group/other. Consequently, do not
run a privileged installer directly from a mutable checkout. Copy the two
release binaries, the four `installers/*privileged*.sh` files, and the two
`packaging/systemd/conduit-privileged-helper@.*` units to a root-owned,
mode-`0700` staging directory first. Invoke the staged installer locally as
root with `CONDUIT_BUILD_DIR` pointing to its root-owned binary directory.

Installation places the binaries below `/usr/libexec/conduit`, installs the
system units, creates only empty root custody directories, and reloads systemd.
It does not generate a key, create a policy, enable a socket, or grant Full
Device authority. Identity and policy changes use the installed root-owned
binary:

```sh
sudo /usr/libexec/conduit/conduit-privileged-helper admin prepare \
  --uid "$(id -u)" --device-id dev_... --public-origin https://example.invalid \
  --output json
sudo /usr/libexec/conduit/conduit-privileged-helper admin enable \
  --uid "$(id -u)" --output json
sudo systemctl enable --now "conduit-privileged-helper@$(id -u).socket"
```

`prepare` output is a bounded public registration bundle; it never contains the
receipt private key. Registration, fresh-Passkey approval, active ticket key,
matching root policy, and a valid signed capability probe are still required
before the Node may advertise `full_device`. Enabling the helper does not enable
`full_device + never` or unrestricted elevated launch. Those remain separate
root-local policy actions.

Disable new privileged work without terminating already-admitted Runtimes:

```sh
sudo /usr/libexec/conduit/conduit-privileged-helper admin disable \
  --uid "$(id -u)" --output json
```

The result reports whether prior admissions are still running. Add the explicit
`--stop-active` option only when those Runtimes should be stopped; the result
then reports the before/after custody counts and signed terminal-receipt count.

Receipt-key rotation is bound to the currently observed key and refuses any
nonterminal Runtime custody:

```sh
sudo /usr/libexec/conduit/conduit-privileged-helper admin rotate-receipt-key \
  --uid "$(id -u)" --expected-current-key-id hkey_... --output json
```

Rotation retains a bounded root-owned public-key history, increments the root
policy revision, and emits a new public registration bundle. Restart the helper
and complete the fresh-owner registration flow before relying on the new key.
Root policy changes fence a running helper immediately; broader or narrower
policy becomes usable only after a service restart.

Use `admin package-status --output json` before maintenance. The updater calls
the candidate's read-only `admin package-check` against the installed journal
and exec worker, then probes the installed files again before committing. It
rejects protocol or journal downgrade. With active elevated Runtime custody it
may atomically install a compatible package, but it does not restart the running
helper or target units. Use `--activate-uid <uid>` only when the reported active
count is zero.

Uninstall fails closed when active elevated Runtime custody exists. The explicit
`--terminate-active` action first requires terminal helper custody. Ordinary
uninstall removes binaries and units but preserves root policy, keys, journal,
and update evidence. Destructive removal additionally requires both `--purge`
and `--confirm-purge DELETE-CONDUIT-PRIVILEGED-STATE`.

`DESTDIR` install/update/uninstall never invoke systemd. Run
`scripts/test-privileged-packaging.sh` for deterministic layout, symlink,
compatibility, active-custody, rollback, preservation, and purge tests.

## Enrollment and identities

Owner browser sessions, MCP OAuth grants, Device keys, and provider credentials
are separate identities. Enrollment generates the Ed25519 private key locally,
sends only the public key and proof, and requires fresh owner approval of the
display code and fingerprint. The private key must remain in an owner-only
Device directory.

Key rotation requires proof by both the current and replacement keys and fences
old connection epochs. Revoking a Device invalidates its keys and active
transport. Recovery sessions can replace passkeys and revoke access, but cannot
read Projects or execute commands.

## Runtime setup

Provider admission is local and fail-closed. The Device validates the registered
Location, immutable operation commitment, local policy revision, provider
capabilities, access scope, approval mode, resource limits, and credential
projection before starting work.

### Native

Native runs as the service user with an exact executable and argument vector,
process-group custody, bounded environment projection, and timeout/cancellation
reconciliation. Full User is an explicit policy choice, not an implicit
fallback. Native host Full Device uses the separately packaged root helper and
fixed exec worker described above. Admission remains fail closed until the
signed probe, owner-approved registration, exact one-use ticket, root policy,
durable journal, systemd unit and verified helper receipt chain are all
effective; missing evidence never selects Full User instead.

### Restricted Native

Install `bubblewrap` and ensure user systemd scopes/cgroup v2 and any configured
Landlock support are available. The provider reports the controls it actually
applied. If a requested control cannot be applied, admission is degraded or
rejected according to the local policy; it is never reported as isolated merely
because a prerequisite executable exists.

### Containers

Docker and Podman are probed independently. Configure the service user for the
chosen daemon without projecting its management socket into an Agent container.
Conduit applies declared CPU, memory, PID, storage, network, and workspace
attachments and validates the resulting provider object before reporting it
running. Entire-home mounts and aliases of management sockets are rejected.

### Incus/KVM

Install and initialize Incus/KVM explicitly using the distribution's operator
documentation. Conduit does not repartition disks, create storage pools, change
global bridges, or select destructive defaults. Before enabling VM operations,
use `incus info`, `incus storage list`, `incus network list`, and `conduit doctor`
to confirm the intended project, pool, bridge, `/dev/kvm`, and guest-agent path.
Offline mode must be evidenced by an absent/disabled NIC; secure boot alone is
not offline isolation.

Snapshot, archive, restore, and destroy require matching provider identity and
custody receipts. If Incus is missing or inaccessible, Quick VM is accurately
`unavailable`; that does not prevent Native use.

## Storage and credentials

The Node maintains distinct hot, archive, backup, and cache roots. Paths must be
absolute, owner-controlled, and non-overlapping where configured. Quotas are
checked against recorded and observed size/free-space evidence. Pinning,
credential presence, uncollected changes, and final-copy custody prevent
cleanup. Moving or restoring an object is journaled so a restart can reconcile
the filesystem and database.

Credential profiles use an encryption key separate from the Device signing key.
Only metadata and evidence enter traces. Each Adapter declares the projections
it supports: native login state, read-only file, ephemeral file, bounded
environment variable, broker socket, guest volume, or login-required. A
projection is scoped to one operation and has an explicit cleanup receipt. The
whole home directory is never copied as a credential shortcut.

## Backup, restore, and upgrade

Create and verify a Device-local backup before an upgrade:

```sh
conduit --output json backup create --data '{}'
conduit --output json backup verify --data '{"backupId":"backup_..."}'
```

A backup is written only below the active, owner-only `backup` storage root. Its
signed schema-v1 manifest binds the Device identity, Backup ID, fixed database
basename, byte length, SHA-256 digest, and journal generation. The SQLite copy
includes versioned Node metadata, migration state, encrypted credential records,
and custody metadata. Credential key files, workspace contents, Git objects, VM
disks, and raw content are separate custody objects and are not implied by the
journal manifest. The manifest never records clear credentials.

Restore is an explicit staged operation. While the current Node is healthy, run
`backup restore` with the verified Backup ID; it copies the signed manifest and
database to owner-only pending paths and returns `pending_restart` with
`applied: false`. Restart the user service to apply it. Startup re-verifies the
Device signature, manifest schema, fixed basename, size, digest, ownership and
SQLite integrity before replacing anything. It preserves the current database,
WAL and SHM as a rollback generation, opens/migrates the candidate, and restores
the former generation atomically if candidate startup fails. A failed check
leaves the old state authoritative.

For a binary upgrade, retain the previous binaries until the new Node has opened
its databases, completed migrations, reconciled active records, and returned a
healthy local IPC receipt. On failure, stop the new binary, restore the database
backup if a migration committed, restore the old binaries, and restart. Never
downgrade a database by copying an older binary over a newer schema.

Use the transactional updater for an installed Node:

```sh
cargo build --locked --release --bin conduit --bin conduit-node
./installers/update.sh
```

If the service is live, the updater first requires successful `backup create`
and `backup verify` CLI receipts. A missing or unavailable backup capability
aborts before the service is stopped. It then stops the service and opens a
disposable copy of the Node data with the candidate binary; failure to open,
migrate, or serve IPC is a schema-compatibility failure and leaves live data
untouched. Candidate binaries and the unit replace their predecessors with
same-directory renames. The updater restarts the service and requires an
installed-CLI IPC receipt before committing.

If migration or startup fails after replacement, the updater stops the
candidate, preserves its failed data, restores the pre-update data copy,
binaries, unit, and generated configuration, and health-checks the old service.
Verified backups remain below the configured Node `backup` storage root and the
updater records the returned manifest path in its owner-only transaction
evidence. Transaction receipts, previous binaries, rollback data, and any
failed data are below `$XDG_STATE_HOME/conduit/upgrades`. The updater rejects a
candidate with a lower semantic version. There is no force-downgrade switch:
restore a backup whose schema is explicitly compatible with the target release.

`installers/uninstall.sh` stops and disables the user service and removes only
the two binaries and managed unit. XDG configuration, data, state, cache,
backups, and update evidence remain in place for recovery or explicit operator
removal.

Control-plane backup uses D1 export plus binding/deployment metadata. R2 object
backup is a separate custody decision. Durable Object inbox/outbox state is not
reconstructed by pretending D1 is its backup; export/recovery procedures must
account for outstanding Device reconciliation.

## Recovery and diagnostics

After a Node restart, every admitted operation, process/container/VM, workspace
lease, outbound frame, and pending terminal receipt is reconciled against its
durable identity. Missing or ambiguous effectful work becomes `uncertain`,
`lost`, or `recovery_required`; it is never automatically executed again.

When transport is unavailable, admitted local work continues and events remain
in the bounded local outbox. Reconnect establishes a strictly newer epoch,
exchanges a summary/plan/complete sequence, replays durable ranges, and gates new
remote work until reconciliation completes.

For incident collection, retain owner-only copies of doctor output, service
status, schema versions, public capability receipts, and normalized error codes.
Do not attach raw databases, provider credential stores, canonical paths, raw
logs, prompts, or hidden reasoning to public issues.

## MCP connection

The MCP endpoint is Streamable HTTP at `/mcp`. Clients first read the OAuth
protected-resource metadata, use Authorization Code with PKCE S256 and the exact
resource value, and receive a grant bound to the current Connector Policy
revision. Redirect URIs are exact-match and HTTPS except for registered loopback
clients.

Connector ceilings cover Devices, Projects, operation families, Runtime kinds,
maximum access, approval permissiveness, raw content, artifact uploads,
concurrency, duration, response/log bytes, VM rates, and weighted budgets. The
Device then applies its own resource and local-policy limits. Long operations
return handles; clients poll bounded status tools instead of holding one request
for an entire Run.

Pausing, revoking, changing a Connector Policy, refresh-token reuse, or recovery
forces the documented reauthorization state. There is no arbitrary-URL fetch
tool and credentials are never returned by an MCP tool.
