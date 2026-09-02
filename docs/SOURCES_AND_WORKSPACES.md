# Sources and run workspaces

## Source and location

A project references logical sources. Device paths are locations of those sources.

```text
Project: Conduit

Source: conduit
├── Location: linux-desktop / ~/src/Conduit
└── Location: ubuntu-server / /srv/repos/Conduit

Source: ownmesh
└── Location: linux-desktop / ~/src/OwnMesh
```

The control plane stores source identity and opaque location IDs. The device stores canonical paths and validates the filesystem object each time a location is used.

## Source types

The first implementation supports:

- Git repository
- normal folder

Later source types may include datasets, managed volumes, artifact collections, or remote repositories without a persistent local checkout.

## Git identity

A Git source records:

- normalized remote identities, when present
- repository object-format information
- default branch observation
- local repository identifier

Two clones may be proposed as locations of the same source. The user can keep them separate. Forks, mirrors, and repositories without remotes are not merged automatically from path or directory name alone.

## Non-Git identity

Normal folders remain separate sources unless the user explicitly relates them. Similar names or contents are insufficient evidence of identity.

## Primary source

A project may select one primary source. It provides defaults for:

- initial working directory
- Git actions
- repository instruction discovery
- new collaboration sessions

A project may have no primary source.

## One run, one device

A run executes on one device. Every required read-write source must have a usable location on that device or be materialized there through an explicit clone, transfer, or managed-copy operation.

A run does not transparently edit folders on another device. Read-only remote retrieval may be added later as an explicit source adapter.

## Workspace modes

Each source binding in a run uses one mode.

### Direct

The run uses the selected location itself. Changes are immediately visible in the user's folder. This is required for ordinary native use and explicit full-access workflows.

Properties:

- no isolation from existing local edits
- no automatic rollback guarantee
- source state is observed before and after the run
- concurrent writers require an explicit override or lease policy

### Git worktree

A managed worktree and branch are created for the run.

Properties:

- preferred safe mode for Git sources
- separate working tree per writer
- base commit is fixed in the workspace snapshot
- commits, patches, and uncommitted changes are captured in the change set

Worktrees are a storage optimization and isolation mechanism; the domain model must also support a managed clone when worktrees are unavailable.

Reference: <https://developers.openai.com/codex/environments/git-worktrees>

### Managed copy

The device copies a non-Git source or a Git source that cannot use a worktree into managed storage. A pre-run manifest and post-run delta are recorded.

Properties:

- the original folder is not modified until an apply operation is approved or explicitly configured
- large folders require size and file-count admission checks
- special files, links, permissions, and filesystem metadata need a declared policy

### Read only

The run can inspect the source but cannot modify the exposed copy. Reviewer and research roles use this by default.

## Workspace snapshot

Before starting an agent, the device creates a snapshot manifest.

For Git sources:

- repository identity
- location revision
- HEAD commit
- branch and upstream observations
- dirty-state summary
- submodule revisions where supported
- sparse-checkout and worktree mode

For normal folders:

- location revision
- declared copy/direct mode
- bounded file manifest or explicit `manifest_unavailable`
- excluded paths
- total observed size and file count

The snapshot also records project context, collaboration-session revision, environment revision, access policy, agent configuration, instruction manifest, and skill catalog revision.

## Change set

A run change set is source-specific and can cover multiple sources on the same device.

For each source it records:

- base workspace snapshot
- resulting commit references
- patch or changed-file summary
- uncommitted changes
- generated and deleted files
- verification evidence
- unresolved conflicts or incomplete writes

A multi-source change set also records application order and cross-source dependencies when known.

## Collaboration-session baseline

A collaboration session may maintain an accepted baseline per source. This is a logical revision set, not a continuously running VM or one shared mutable directory.

Rules:

1. A run starts from an immutable workspace snapshot derived from the accepted baseline or an explicitly selected revision.
2. A run produces a proposed change set.
3. Agent completion does not advance the baseline.
4. A human action, accepted automation rule, or configured direct mode advances the baseline.
5. Reviewer runs read the proposed change set without mutating it by default.
6. A fix run can start from the proposed change set or the previous accepted baseline; the choice is recorded.
7. Parallel proposed change sets remain independent until an integration run or merge action combines them.

In direct mode, the physical folder can change before the control-plane baseline is updated. The UI must show this divergence rather than pretending the run was isolated.

## Concurrency

- A managed worktree or copy has one writer lease per run.
- Direct locations have a configurable writer policy: exclusive, warn, or allow.
- Reviewer roles are read-only unless a separate patch-proposal workspace is requested.
- Multiple agents are never assumed to coordinate safely merely because they run in separate VMs; the exposed source workspace must also be separate.

## VM and container mounts

A container or VM receives the run workspace, not an unrestricted host filesystem, unless direct mode was selected.

Stable guest paths use source aliases:

```text
/workspace/primary
/workspace/sources/ownmesh
/workspace/sources/design-notes
```

The runtime does not receive the host Docker, Podman, Incus, or hypervisor management socket. Nested container use belongs inside the VM or to a separately designed provider contract.
