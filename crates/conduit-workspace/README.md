# conduit-workspace

Device-local implementation of Sources, Locations, Run Workspaces, Session Baseline vectors, and immutable Change Sets.

Canonical paths exist only in `DeviceLocationRegistry` and are revalidated against Unix filesystem identity on every resolution. Shareable `LocationRecord` values contain only opaque IDs, revisions, and bounded display paths.

Managed Git uses stable Git interfaces. Repository observation covers object format, remotes, dirty/conflicted/detached state, ahead/behind state, shallow and partial clones, sparse checkout, submodules, LFS, alternates, and missing objects. `WorktreeManager` durably reserves a unique Run branch and lease before `git worktree add`, locks active worktrees, and refuses cleanup without clean state and healthy custody.

Managed folders use bounded, content-addressed manifests. Acceptance is prepare/CAS/finalize; `MaterializationRequest` and `PushRequest` remain separate effect and approval boundaries.

The `wire_v1` module is the schema-exact serde boundary for
`changeset-v1.schema.json`. It represents Baseline, Run Workspace, Change Set,
Review, acceptance, custody, and materialization records without changing the
acceptance service's established operational API.

The crate remains in the existing root workspace; this wire-boundary addition does not alter workspace registration.
