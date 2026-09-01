# Linux end-to-end verification

This runbook is the reproducible acceptance record for the non-visual Linux
product. It separates deterministic local evidence from live checks that need a
Cloudflare account, passkey, provider daemon, VM host, or paid Agent account. A
skip is not evidence that a provider works.

## Automated local suite

Run from the repository root with Rust 1.92, Node.js 22.12 and pnpm 9.15:

```sh
corepack pnpm install --frozen-lockfile
./scripts/e2e-linux.sh
```

The script runs the Rust `e2e_linux` target and the Miniflare Control Plane E2E
suite. The complete gate, including unit/contract/fault, schema drift, packaging
and installed-binary start/IPC/stop tests, is:

```sh
./scripts/check-all.sh
```

Deterministic fixtures never invoke paid inference. Adapter live checks must be
started explicitly by an operator who has inspected the selected model and
account.

## Acceptance scenario map

1. **Local Control Plane and Node:** Miniflare creates D1, Durable Objects, R2
   and Queue bindings; the Rust E2E starts a real Node IPC service. For an
   interactive run, start `pnpm --filter @conduit/control-plane dev`, then
   `conduit-node serve` with an owner-only launch-policy file.
2. **Enroll `sahur-pc`:** the Device ceremony tests generate an Ed25519 key,
   prove the complete JCS transcript and retain the private key locally. A live
   run additionally needs a real passkey and owner approval at the configured
   origin.
3. **Multi-Source Project:** API/schema tests cover Project, Source and opaque
   Location records. Node workspace tests bind each Location revision to its
   Device-local canonical path and reject stale or changed filesystem identity.
4. **Codex Builder:** Adapter discovery and fixture conformance cover the exact
   Codex executable/protocol identity. Creating the Project Agent is a normal
   revisioned API operation and does not launch a process.
5. **Ordinary Board Message:** the Miniflare test posts a message with no
   structured mentions and proves the Assignment count does not increase.
6. **Structured assignment:** the same test commits the Message, structured
   mention and draft Assignment atomically and verifies idempotent replay.
7. **Codex isolated worktree:** workspace tests create a unique locked Run
   branch/worktree, preserve the dirty primary tree, capture exact Git state and
   produce an immutable Change Set. Paid Codex inference is an opt-in live
   extension; fixture protocol tests cover prompt/event/terminal normalization.
8. **Completion is not acceptance:** collaboration and Change Set tests prove an
   Agent terminal event cannot mutate the Session Baseline.
9. **Explicit acceptance/materialization:** prepare/CAS/finalize tests bind the
   exact Change Set, review, Baseline vector, Location, Device and custody
   receipts; competing or stale acceptance fails.
10. **Offline continuation/reconnect:** transport tests persist admission before
    acknowledgement, continue the supervised local process, replay retained
    envelopes and complete summary/plan/complete reconciliation without a
    second execution.
11. **Quick Command:** Rust E2E executes a projectless Native command once and
    validates its durable terminal receipt.
12. **Quick Agent Session:** structured Adapter fixtures exercise projectless
    launch and event normalization without paid inference. A live Agent command
    requires the vendor CLI to be logged in.
13. **Container limits:** Docker/Podman provider conformance validates typed
    command construction, CPU/memory/PID/storage/network bounds and rejects
    management-socket or whole-home mounts. The opt-in live test uses an already
    local image, offline networking, exact argv, bounded collection and
    custody-gated destroy; it never pulls an image.
14. **Quick VM lifecycle:** Incus conformance covers metadata-bound prepare
    validation, inspect, stop, archive/import restore, reconciliation and
    custody-gated destroy command/receipt semantics. Guest start, snapshot
    digest custody and output collection remain accurately unavailable until a
    versioned guest-process identity/custody contract exists. Run provider-live
    checks only after `conduit doctor` reports Incus, KVM, storage and offline
    network prerequisites effective.
15. **`full_user + never` and `full_device + never`:** local-policy tests require
    those exact combinations to be explicitly enabled and retain admission and
    audit receipts. The Device-local deny remains final.
16. **MCP parity and ceilings:** Miniflare negotiates the strict modern MCP
    envelope over authenticated HTTP, lists the typed long-operation tools and
    invokes a read tool through OAuth resource binding, immutable policy
    revision and the exact limiter. Separate admission tests prove typed owner
    operations return handles instead of holding the request open.
17. **Run/Skill/Instruction reports:** observability tests persist normalized
    visible events, HMAC-redacted content, discovery/load/outcome evidence and
    distinguish explicit, observed, inferred and unknown strength.
18. **Backup/restore:** packaging and Node-store tests create a digest manifest,
    verify it before restore, preserve the pre-restore state and reopen the
    migrated database. Remote Control Plane backup remains an operator D1/R2
    export because local tests have no Cloudflare account.
19. **Node restart:** Rust E2E reopens the journal and inspects actual provider,
    process and spec identity. It resumes custody of matching work and marks
    missing or ambiguous effects `lost`, `recovery_required` or `uncertain`
    without respawning them.
20. **All Agent adapters:** Codex, Claude Code, OpenCode and Pi use versioned
    protocol fixtures and bounded process conformance. Agy is intentionally
    `unavailable` until an independently verified structured CLI exists. Live
    checks are opt-in and never count a missing executable or login as support.

## Live evidence record

Record these separately for each host and deployment:

- date, Conduit commit, OS/kernel and Node/Runtime capability receipt;
- Cloudflare deployment identifier and migration versions, without secrets;
- provider executable and version identity;
- whether the test was run, skipped, degraded or failed, with its reason code;
- resulting operation, Run, Runtime, Change Set and custody receipt IDs;
- paid Agent/model/effort only when the operator explicitly authorized use.

Do not attach Device databases, canonical private paths, credentials, raw
prompts, hidden reasoning or unredacted logs to public evidence.
