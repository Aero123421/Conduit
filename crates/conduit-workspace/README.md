# conduit-workspace

Device-local implementation of Sources, Locations, Run Workspaces, Session Baseline vectors, and immutable Change Sets.

Canonical paths exist only in `DeviceLocationRegistry` and are revalidated against Unix filesystem identity on every resolution. Shareable `LocationRecord` values contain only opaque IDs, revisions, and bounded display paths.

Managed Git uses stable Git interfaces. Repository observation covers object format, remotes, dirty/conflicted/detached state, ahead/behind state, shallow and partial clones, sparse checkout, submodules, LFS, alternates, and missing objects. `WorktreeManager` durably reserves a unique Run branch and lease before `git worktree add`, locks active worktrees, and refuses cleanup without clean state and healthy custody.

Managed folders use bounded, content-addressed manifests. Acceptance is prepare/CAS/finalize; `MaterializationRequest` and `PushRequest` remain separate effect and approval boundaries.

Integration must add these crates to the repository lockfile. This workstream intentionally does not edit the root `Cargo.toml` or `Cargo.lock`.

