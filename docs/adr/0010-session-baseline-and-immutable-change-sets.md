# ADR 0010: Session baseline vector and immutable Change Sets

- Status: Proposed
- Date: 2026-09-01

## Context

One Collaboration Session can include several Sources and several Agents.

A typical flow is:

```text
Codex implements
Claude reviews
Codex fixes
Human accepts
```

If all participants share one mutable branch or folder, concurrent edits, review staleness, direct-mode user changes, and crash recovery become ambiguous.

A Session can span multiple Git repositories and non-Git folders. Git cannot provide one atomic commit across repositories. Cloudflare D1 and Device-local Git refs also cannot commit one transaction together.

Agent completion is not proof that a proposal is ready or accepted.

## Decision

### Baseline vector

A Collaboration Session has immutable Baseline Revisions.

Each revision is a vector of exact Git commits or managed-folder snapshots, one per Source.

The active Baseline changes only through an explicit acceptance operation.

### Run Workspace isolation

Each writable managed Run receives its own Workspace and lease.

Git uses unique linked worktrees and unique Run branches by default. Non-Git folders use managed copies or snapshots. Direct mode remains available and is labeled as weaker isolation.

### Immutable Change Set

A Run produces an immutable Change Set containing Source Changes, parent Baseline, provenance, custody, verification, and application order.

A Fix Run produces another Change Set that supersedes its parent. It does not mutate the reviewed proposal.

### Review binding

A Review binds one exact Change Set digest. A Review does not carry silently to another digest.

Reviewer Sources are read-only when the selected Runtime can enforce it. Missing required read-only enforcement fails admission.

### Draft versus proposed

A Git Workspace with uncommitted or conflicted state can produce a draft, but not a proposed Change Set eligible for Baseline acceptance.

Conduit does not create a hidden commit while presenting the work as uncommitted.

### Baseline acceptance

Acceptance uses a prepared Device receipt followed by a D1 compare-and-swap and Device finalization.

The Control Plane commits the new Baseline Revision in one D1 transaction across all Source states. Device refs and snapshots finalize idempotently afterward.

A disconnect can leave materialization pending without losing the accepted Baseline decision.

### Source application

Updating a user's branch, Direct folder, remote ref, or another Device Location is separate from Session Baseline acceptance.

Merge, rebase, cherry-pick, push, and force operations are not hidden inside acceptance.

### Custody

Accepted metadata is insufficient when Git objects or folder snapshots exist only on an unavailable Device.

Project policy requires explicit custody receipts such as Device refs, local archives, remote refs, replicated Devices, or R2 Artifacts.

### Direct mode

Direct mode is valid. It records initial and final state and holds a Conduit writer lease, but cannot prevent the user or another program from editing the folder.

Unattributable changes mark the Workspace diverged and prevent automatic isolated acceptance.

## Rejected alternatives

### One shared Session branch

Rejected because simultaneous or sequential Agents would mutate the same branch and make review targets unstable.

### Treat the Agent branch as the accepted state

Rejected because Agent completion, verification, review, custody, and human acceptance are separate decisions.

### Automatically merge a proposed branch on acceptance

Rejected because the Session Baseline is not necessarily the user's target branch, and multi-Source proposals have no single Git transaction.

### Store only patch files

Rejected because commits, trees, parent structure, LFS and submodule state, review targets, and repository object custody need stronger identities.

### Automatically stash a user's dirty working tree

Rejected because it changes ordinary-PC state and can obscure local work.

### Automatically rebase stale proposals

Rejected because rebasing changes commit identity and review evidence. An explicit Integrator or replay Run creates another Change Set.

### Use D1 metadata as proof that code remains recoverable

Rejected because Cloudflare does not hold ordinary Source objects or managed snapshots by default.

### Delete Run worktrees after Agent completion

Rejected because collection, review, custody, and recovery can still require them.

## Consequences

- Session UI shows active Baseline, proposals, reviews, and materialization separately.
- Git operations need a Device-local Workspace Manager and journal.
- Worktree creation, locks, refs, status, cleanup, and reconciliation use stable Git interfaces.
- Multi-Source acceptance is atomic in shared metadata but can be materialization-pending on a Device.
- Reviewer and Fix Runs have explicit parent Change Set identity.
- Direct mode remains useful but carries weaker attribution.
- Source application and remote push require separate operations and approvals.
- Change Set custody must be monitored after acceptance.

## Contract

- `docs/SESSION_BASELINE_AND_CHANGESETS.md`
- `spec/schemas/changeset-v1.schema.json`
- `spec/examples/changeset/`
