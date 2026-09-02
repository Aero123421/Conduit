# Collaboration Session baseline and Change Sets

## Scope

This contract defines how a Collaboration Session carries code and file state across:

- an Implementer Run
- a Reviewer Run
- a Fix Run
- competing parallel proposals
- an Integrator Run
- multiple Git repositories
- non-Git managed folders
- Direct editing on an ordinary computer

It separates:

- accepted Session state
- one Run's mutable Workspace
- an immutable proposed Change Set
- review and verification
- applying accepted work to a user's branch or folder

A Collaboration Session is not a shared mutable folder and is not a VM disk.

## Entities

### Baseline Revision

Immutable accepted state for one Collaboration Session.

A Baseline Revision contains one entry per bound Source. It can mix Git and managed-folder Sources.

For Git:

- Source ID
- repository identity digest
- accepted commit
- tree digest
- source-custody receipts

For a managed folder:

- Source ID
- accepted snapshot ID
- file-manifest digest
- source-custody receipts

A Baseline Revision also records:

- revision number
- predecessor revision
- accepted Change Set
- accepting principal and client
- acceptance operation and receipt
- acceptance time
- status of materialization on each Device Location

The first Baseline Revision is created when the Session binds its initial Sources.

### Run Workspace

Mutable, Device-local working state created for one Run.

A Run Workspace is bound to:

- Run ID
- one Device
- one Baseline Revision or parent Change Set
- exact Source Location revisions
- workspace mode per Source
- Runtime attachment receipts
- exclusive writer or read-only lease

### Change Set

Immutable proposal assembled from one Run Workspace.

A Change Set contains one Source Change per changed Source and references unchanged Sources through its parent state.

It can be:

- draft
- proposed
- under_review
- changes_requested
- approved
- accepted
- rejected
- withdrawn
- superseded
- stale
- conflicted

`accepted` means the Collaboration Session Baseline advanced to this exact Change Set.

It does not mean that a user's branch was merged, pushed, deployed, or that a non-Git original folder was overwritten.

### Review

Immutable review bound to one exact Change Set digest.

A later Change Set created by a Fix Run requires a new review or an explicit policy allowing carry-forward of named checks. An old review never silently applies to changed content.

### Source application

Separate operation that materializes an accepted Change Set into:

- a user's local branch
- a remote branch
- a Direct folder
- another Device Location

Baseline acceptance and Source application are not one operation.

## Session state

A Session keeps:

```text
accepted Baseline Revision
candidate Change Sets
review records
verification records
materialization status by Location
```

It does not keep one continuously running Agent process or one mandatory shared branch.

## Initial Baseline

When a Session is created with Sources, Conduit resolves each selected Location.

### Git Source

The initial baseline uses an exact commit.

The user or caller selects:

- current `HEAD`
- another local ref
- an explicit commit

An uncommitted working tree is not silently included.

If the selected Location is dirty, the UI shows:

```text
Baseline commit
<commit>

Local changes not included
<bounded status summary>
```

Options:

- continue from the commit and leave local changes untouched
- commit local changes manually
- create a separate managed snapshot operation
- cancel

Conduit does not automatically stash, reset, clean, or commit the user's working tree while creating a Session.

### Managed-folder Source

Conduit creates a bounded manifest or versioned snapshot according to Source policy.

The snapshot records:

- included and excluded paths
- file type
- size
- content digest
- executable bit or platform mode where relevant
- symlink or reparse-point state
- hardlink and mount observations where supported
- snapshot policy and limits

The first baseline is not considered durable until its required custody receipt exists.

## Baseline Vector

A Baseline Revision is a vector rather than one commit.

Example:

```text
Baseline Revision 7

frontend   commit a18c2d...
backend    commit 76fa10...
infra      commit c832b1...
design     snapshot snap_...
```

The digest covers the ordered Source IDs and state digests.

A Run starts from the complete vector, even when its Assignment permits changes to only one Source.

## Git repository identity

A Source repository identity is not determined by folder name.

Evidence can include:

- object-format algorithm
- normalized configured remote identities
- initial root or known-history commitment
- repository-format version
- partial-clone and shallow state
- explicit owner confirmation

Remote URL is evidence, not sole authority. Forks and mirrors can be linked or separated by explicit user choice.

## Git observation

Machine parsing uses stable Git interfaces.

- Worktree inventory uses `git worktree list --porcelain -z` where supported.
- Working-state capture uses `git status --porcelain=v2 -z --branch`.
- Refs and commits use exact object IDs.
- Diff and commit ranges are generated with explicit base and head objects.
- User aliases and color output are disabled for managed Git operations.

The exact Git version and object format are recorded.

## Isolated worktree mode

Worktree is the default writable mode for a Git Source in a managed Run.

### Creation

For each writable Git Source:

1. verify repository identity and required objects
2. verify exact base commit from the selected Baseline or parent Change Set
3. reserve Run Workspace and branch identity in the local journal
4. create a linked worktree under a Device-managed storage root
5. create a unique branch for the Run
6. lock the worktree with a Conduit reason
7. record worktree administrative identity and initial status

Generated branch form:

```text
conduit/run/<short-run-id>/<source-slug>
```

The full Run ID and Source ID remain in Conduit metadata. Branch text is a convenience, not authority.

Each Run receives a unique branch. Conduit does not try to check out one branch simultaneously in multiple linked worktrees.

A generated branch collision is an error. Conduit does not reuse it by name.

### Conduit refs

Device-local refs preserve immutable proposal and accepted heads:

```text
refs/conduit/runs/<run-id>/<source-id>/head
refs/conduit/changesets/<change-set-id>/<source-id>/head
refs/conduit/sessions/<session-id>/<source-id>/accepted
refs/conduit/acceptance-prepares/<operation-id>/<source-id>
```

Refs are updated with expected-old-value compare-and-swap semantics.

User branches are not updated by Baseline acceptance.

### Worktree lifecycle

Run worktrees are managed through Git worktree commands. The directory is not deleted behind Git's administrative state.

Rules:

- active or retained worktrees remain locked
- ordinary cleanup refuses dirty or uncollected worktrees
- force removal requires explicit discard authority
- `git worktree prune` is not used as the primary Conduit cleanup operation
- reconciliation compares local journal, `git worktree list --porcelain`, filesystem identity, branch, and Conduit refs
- a missing directory or stale administrative record becomes recovery state
- a worktree on removable or archive storage remains locked while absent

`git gc` can prune stale worktree administrative records according to Git configuration, so locks and Conduit's own journal remain part of custody.

## Read-only Reviewer Workspace

A Reviewer receives an exact Change Set digest and Source heads.

For Git Sources, the Reviewer Workspace is created from detached heads or separate unique branches and exposed read-only through the selected Runtime where enforcement is available.

The Reviewer can:

- inspect commits and diffs
- read files
- run approved tests in an expendable writable test area
- write a Review record and Artifacts

The Reviewer does not mutate the proposal branch by default.

If the selected Runtime cannot enforce Source read-only behavior, a required read-only capability fails admission. The system does not rely only on a Reviewer role label.

A Reviewer that must propose code changes creates another Assignment and Change Set.

## Direct mode

Direct mode exposes the original Location to the Run.

It is valid and is required for ordinary-PC and Full Access use.

It has weaker attribution and isolation.

### Preflight

Conduit records:

- exact `HEAD`
- branch and upstream
- index and working-tree status
- bounded untracked-file summary
- status digest
- existing locks or operations
- Location revision

A Conduit exclusive-writer lease prevents another Conduit writer from using the same Location. It cannot prevent the user, IDE, hook, background process, or unrelated program from changing the folder.

### Divergence

During and after the Run, Conduit checks:

- branch and `HEAD` movement
- index changes
- worktree status
- reflog observations where available
- unexpected file changes

If changes cannot be attributed to the Run, the Workspace becomes `diverged`.

A diverged Direct Workspace can still produce a draft Change Set and evidence, but it cannot be automatically accepted as isolated work.

The UI states that the original folder was modified directly.

### Dirty start

Dirty Direct state is allowed only when policy permits it and is included in the Run Manifest.

Conduit does not claim that changes after the Run started belong solely to the Agent.

It does not stash, reset, clean, or discard pre-existing changes automatically.

## Managed-copy mode

Managed-copy mode is used for non-Git Sources and can be selected for Git Sources when linked worktrees are unsuitable.

The Workspace Manager creates a versioned copy or copy-on-write snapshot under managed storage.

The receipt records:

- source snapshot digest
- copy mechanism
- included and excluded paths
- ownership and mode handling
- hardlink and symlink policy
- consistency model
- bytes and storage class

The copy is compared against its start snapshot to create a file-operation manifest.

## Draft Change Set

A Run can produce a draft while its Workspace is dirty or incomplete.

A draft can contain:

- observed changed-file summary
- bounded diff or patch Artifacts
- uncommitted state digest
- tests and Agent report
- unresolved conflicts
- missing Source Changes

A draft cannot advance the Session Baseline.

For a Git Source to enter `proposed`, it must have:

- immutable base commit
- immutable head commit
- no unmerged index entries
- clean tracked worktree and index relative to head
- retained Conduit ref for the head
- commit and tree objects present
- Source Change digest

Untracked files must be either:

- committed
- captured as declared Artifacts
- explicitly excluded
- listed as unresolved, which keeps the Change Set draft

Conduit does not create a hidden commit while presenting the Workspace as uncommitted. A future explicit checkpoint operation can create a visible system-authored commit.

## Git Source Change

A proposed Git Source Change records:

- Source ID and repository identity
- originating Location and Device
- base commit and tree
- head commit and tree
- merge base observation
- ordered commit IDs in the proposal range
- parent structure and merge commits
- diff-stat summary
- diff and patch commitments
- changed paths and rename observations under bounds
- submodule gitlink changes
- LFS state
- shallow or partial-clone state
- verification references
- object-custody receipts

The proposal does not rewrite commits to create a linear history.

## Managed-folder Source Change

A managed-folder Source Change records:

- base snapshot and manifest
- result snapshot and manifest
- created, modified, deleted, renamed, and type-changed paths
- before and after content digests
- mode and symlink changes
- conflict and unavailable-content state
- Artifact and verification references
- object-custody receipts

A managed-folder Change Set is accepted into a new managed baseline snapshot. Applying it to an original Direct folder is separate.

## Change Set identity

A Change Set is immutable.

Its digest covers:

- Change Set ID and parent relationships
- Session and parent Baseline Revision
- producing Run and Assignment
- ordered Source Changes
- unchanged Source state references
- required verification policy
- Artifact commitments
- provenance and custody receipts

A Fix Run creates a new Change Set with:

```text
supersedes: <old-change-set>
parents: [<old-change-set>]
```

The old proposal remains available.

## Multi-Source Change Set

One Run can change multiple Sources on one Device.

The Change Set contains separate commits or snapshots per Source and one logical application order.

Example:

```text
Change Set

1. backend schema commit
2. frontend API client commit
3. deployment configuration commit
```

There is no cross-repository atomic Git commit.

Conduit gives the logical bundle one digest, performs Session acceptance with a Baseline-vector compare-and-swap, and reports materialization per Source.

## Change Set custody

A Change Set cannot be accepted when its immutable Git objects or managed snapshots have no required custody.

Initial custody classes:

- Device ref: retained under `refs/conduit/...`
- Device archive: Git bundle, object pack, or managed snapshot under archive storage
- Remote ref: explicit push to an allowed remote ref
- Replicated Device: verified copy on another enrolled Device
- R2 Artifact: optional encrypted bundle or snapshot upload

Project policy defines the minimum.

The Linux single-Device MVP can accept with one healthy Device ref and local archive receipt. The UI shows that loss of the Device can make the baseline unavailable until restored.

Metadata in D1 does not prove that Git objects or folder snapshots still exist.

## Review

A Review binds:

- Review ID
- Change Set ID and digest
- Reviewer Agent or human
- Source Change digests
- reviewed verification state
- findings
- verdict
- evidence references
- review time

Verdicts:

- approved
- changes_requested
- rejected
- unable_to_review

Findings have stable IDs and severities.

A Review becomes stale when the target Change Set digest changes or is superseded. It remains historical evidence.

## Fix Run

A Fix Run starts from the exact heads or snapshots of a proposed Change Set, not from the old Session Baseline.

For Git Sources:

- create unique worktrees from proposal heads
- create new Run branches
- retain parent Change Set IDs
- apply no implicit rebase

The resulting Change Set supersedes its parent.

If the accepted Session Baseline advanced meanwhile, the new proposal is marked stale relative to the current Baseline. It is not automatically rebased.

## Parallel proposals

Two Runs can start from one Baseline Revision and produce separate Change Sets.

Accepting one advances the Session Baseline. Other proposals remain available but become stale unless their Source states are still identical to the new Baseline for every affected Source.

Options:

- reject or withdraw
- compare
- create an Integrator Run
- create an explicit rebase or replay Run

Baseline acceptance does not silently cherry-pick or merge competing proposals.

## Integrator Run

An Integrator Assignment selects:

- current Baseline Revision
- one or more Change Sets
- explicit integration order
- conflict policy
- required verification

It receives isolated writable Workspaces and produces another Change Set.

The Integrator result is reviewed and accepted normally.

## Submodules

Submodule state is explicit.

Setup policy:

- none: keep gitlinks, do not initialize working trees
- recorded: initialize exact recorded commits
- recursive_recorded: initialize recursively at exact recorded commits

Network fetching is subject to Runtime Network Policy and Source policy.

Missing submodule objects fail required setup. Conduit does not silently use another commit.

A changed submodule can be represented as:

- a separate Source Change for the submodule repository
- a superproject gitlink change
- both, linked by dependency

Submodule working-tree changes that are not committed keep the Change Set draft.

## Git LFS

LFS behavior is explicit:

- required content
- pointer-only
- skip smudge

The selected mode and LFS object availability are recorded.

A Run that requires full LFS content fails setup when objects are unavailable and network policy does not allow retrieval.

Change Set custody distinguishes Git pointer objects from retained LFS objects.

## Sparse, partial, shallow, and alternates

The Source receipt records:

- sparse-checkout patterns and mode
- partial-clone filter
- shallow boundaries
- object alternates

A Run can preserve the Source mode or request an explicit materialization policy.

Required objects must be proven present before proposal or acceptance. A Change Set whose history or content is unavailable remains draft or degraded.

Conduit does not assume that another Device can reconstruct an accepted proposal from a remote when the necessary objects were never pushed.

## Hooks and configuration

Managed Git commands use an explicit environment and disable user aliases.

Repository hooks can affect checkout, commit, merge, and other operations. Conduit records hook availability and command outcomes.

The MVP does not globally disable repository hooks because Project workflows may depend on them. Security-sensitive operations use typed commands and exact object verification after the hook completes.

A Project can later select a hook policy:

- repository hooks
- approved hooks only
- disabled managed environment

## Acceptance

Acceptance uses a prepared, durable two-phase flow because the Control Plane Baseline and Device-local Git refs cannot be changed in one transaction.

### Prepare on Device

1. verify Change Set digest and state
2. verify expected Session Baseline Revision
3. verify Source Location and repository identity
4. verify all required objects or snapshots and custody policy
5. create acceptance-preparation refs or snapshot references
6. journal the preparation under the acceptance operation ID
7. return a prepared receipt

### Commit in Control Plane

One D1 transaction:

1. compare expected current Baseline Revision
2. create the next immutable Baseline Revision
3. mark the exact Change Set accepted
4. record the prepared Device receipt and custody state
5. mark competing affected proposals stale where applicable

If compare-and-swap fails, no Baseline advances.

### Finalize on Device

After Control Plane commit:

1. move or update Session accepted refs with expected-old-value checks
2. retain Change Set refs
3. remove preparation refs
4. persist materialization receipt
5. acknowledge completion

If the Device disconnects after D1 commit, reconciliation resends finalization. The accepted Baseline remains committed but its Location is shown as materialization pending.

If D1 commit fails, Conduit aborts the Device preparation and removes only preparation refs after durable abort receipt.

## Acceptance checks

A Change Set is acceptable only when:

- state is proposed or approved according to policy
- parent Baseline matches expected current Baseline
- no required Source Change is draft or conflicted
- required verification passes
- required Review verdicts are current
- custody policy passes
- Source objects and snapshots remain available
- acceptance operation and policy revisions are current

Agent completion is not an acceptance check by itself.

## Apply to user branch

Applying accepted work to a user's branch is separate.

Initial modes:

### Fast-forward

Allowed only when the target ref equals the expected old commit and accepted head descends from it.

### Create branch

Create or update a new user-visible branch with expected-old-value checks.

### Integrate

Merge, rebase, or cherry-pick is performed through an explicit Integrator Run or a future typed Git operation. It is not hidden inside acceptance.

### Push

Push is an external effect with explicit remote, refspec, expected remote state, force policy, and approval.

Force push is not implied by Full Project access.

## Apply to Direct or managed folder

For non-Git or Direct folders, application:

1. verifies expected target snapshot or manifest
2. previews operations and conflicts
3. writes through the Device custody layer
4. journals each commit boundary
5. records resulting snapshot and receipt

Unexpected target changes cause conflict. Conduit does not overwrite them silently.

## Cleanup and retention

After Change Set collection:

- Run branch can be deleted after retained Change Set refs and custody receipts exist
- linked worktree can be removed when clean and unlocked
- retained Change Set ref remains according to Project retention
- accepted ref remains while Baseline Revision is retained
- archived worktree is tracked by storage metadata
- raw Runtime can be destroyed independently after required collection

Cleanup uses operation IDs and idempotency.

A missing worktree directory does not delete Change Set refs. A missing ref or object changes custody health and can require recovery.

## Reconciliation

On Node restart, Conduit compares:

- Run journal
- Runtime records
- Run Workspace records
- Git worktree porcelain inventory
- branch and Conduit refs
- filesystem paths and identities
- Change Set and acceptance journals
- managed snapshots

Outcomes:

- healthy
- dirty
- diverged
- missing worktree
- stale Git administration
- ref conflict
- object missing
- acceptance pending
- recovery required

It does not run `git worktree prune` or delete branches as an automatic repair for ambiguous state.

## Stable errors

```text
repository_identity_mismatch
repository_object_missing
repository_shallow_boundary
repository_partial_object_missing
worktree_branch_in_use
worktree_path_conflict
worktree_admin_stale
worktree_missing
workspace_dirty
workspace_diverged
workspace_conflicted
workspace_read_only_unavailable
source_location_stale
submodule_object_missing
lfs_object_missing
changeset_draft
changeset_stale
changeset_conflicted
changeset_digest_mismatch
review_stale
verification_required
custody_insufficient
baseline_revision_conflict
acceptance_prepare_failed
acceptance_finalize_pending
application_target_changed
push_remote_changed
cleanup_blocked
```

Errors are bounded. Private canonical paths and file content remain Device-local unless policy permits export.

## Required deterministic tests

1. clean Git Source creates isolated worktree from exact Baseline commit
2. dirty main working tree remains untouched
3. generated branch already exists
4. same branch cannot be reused by another linked worktree
5. Agent leaves tracked or untracked changes uncommitted
6. proposed Git Change Set has clean committed head
7. Reviewer cannot write to required read-only Source
8. Reviewer approves one digest and Fix Run supersedes it
9. two proposals start from one Baseline and one is accepted
10. stale proposal is not implicitly rebased
11. multi-Source Change Set acceptance updates Baseline vector in one D1 transaction
12. Device disconnects after acceptance prepare
13. Device disconnects after D1 commit before ref finalization
14. acceptance CAS fails and preparation aborts
15. accepted commit object disappears
16. Direct mode changes concurrently with user edit
17. dirty Direct start remains visible
18. managed-copy folder creates file-operation manifest
19. non-Git target changes before application
20. submodule commit missing
21. required LFS object missing
22. sparse or partial clone lacks required object
23. worktree directory removed outside Conduit
24. stale Git administrative record exists
25. ordinary cleanup refuses dirty Workspace
26. explicit discard removes worktree but preserves R0 receipts
27. apply fast-forward detects changed target ref
28. push detects changed remote ref

## References

- Git worktree: <https://git-scm.com/docs/git-worktree>
- Git status porcelain v2: <https://git-scm.com/docs/git-status>
- Git update-ref: <https://git-scm.com/docs/git-update-ref>
- Git diff: <https://git-scm.com/docs/git-diff>
- Git submodules: <https://git-scm.com/docs/gitsubmodules>
- Git LFS: <https://git-lfs.com/>
