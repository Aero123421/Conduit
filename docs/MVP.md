# Initial implementation plan

## Foundation gate

Before product code is accepted, the repository must contain reviewed definitions for:

- Project, Collaboration Session, Message, Project Agent, Assignment, Run
- Source, Location, Run Workspace, Workspace Snapshot, Change Set
- control-plane and device authority
- runtime-provider contract
- access scope and approval policy
- run manifest and normalized event envelope

Open decisions may remain, but code must not introduce conflicting terms.

## Vertical slice 1: Linux native assignment

Target path:

```text
Cloudflare dashboard
→ register one Linux device
→ add an existing Git folder as a source
→ create a project and collaboration session
→ add a Codex project agent
→ post a structured @ assignment
→ create an isolated worktree or use direct mode
→ start Codex natively
→ stream bounded status to the board
→ collect diff, command, test, and terminal receipts
→ show the run in the right panel
→ stop or accept the result
```

Required product behavior:

- single owner authentication
- one Cloudflare deployment
- outbound device connection
- device-local source registry
- project with multiple sources on the same Linux device
- projectless Quick Command and Quick Agent Session
- native runtime provider
- Codex adapter only
- direct and Git-worktree workspace modes
- selected-source, full-project, full-user, and full-device access configuration
- `never` approval policy
- local command/agent journal and reconnect reconciliation
- basic run manifest and normalized trace
- raw log remains device-local

Acceptance criteria:

- duplicate remote admission does not start a second agent
- control-plane disconnect does not stop an admitted run
- node restart reports a truthful recovered, lost, uncertain, or terminal state
- an agent message alone cannot mark verification complete
- a run can be stopped from the dashboard
- a direct-mode run visibly reports that it can modify the original folder
- a worktree-mode run leaves the original working tree untouched
- full-user and full-device configuration have no undocumented product denial
- the UI shows device, runtime, access, approval, model, effort, base commit, and current phase
- all trace events remain bounded and cursor-readable

## Vertical slice 2: multiple devices and MCP

- register multiple Linux devices
- represent one Git source at multiple device locations
- explicit and policy-assisted device selection
- Quick Command on a selected device
- MCP gateway using the same application service as the dashboard
- per-connector permission ceiling
- weighted rate limits, concurrency limits, runtime limits, and log-byte limits
- emergency pause for connector execution
- device-local final resource limits

Acceptance criteria:

- the scheduler never selects a device without the required source location or adapter capability
- non-Git folders are not assumed identical across devices
- MCP cannot exceed its configured permission ceiling even when the project agent is broader
- transport throttling is not treated as the exact usage ledger

## Vertical slice 3: container and VM providers

- managed Docker/Podman provider
- Linux Incus/KVM provider
- Quick Container and Quick VM
- project environment revisions
- run workspace mounting
- fast, archive, and backup storage roots
- VM/container resource settings
- pause, snapshot, archive, restore, and destroy flows where supported
- guest-local agent adapter execution

Acceptance criteria:

- agent runtimes never receive the host runtime-management socket
- VM root access does not imply host access
- storage exhaustion prevents new admission without deleting active or uncollected work
- destruction is blocked while uncollected source changes or required artifacts remain
- provider capability differences are visible

## Vertical slice 4: additional agents and roles

- Claude Code
- OpenCode
- Pi
- Agy
- reviewer, tester, implementer, and integrator role presets
- read-only review runs
- cross-agent assignment proposals
- deterministic automation limits

Acceptance criteria:

- each adapter has versioned protocol fixtures and truthful capability states
- an AI-created mention proposes a new assignment unless a bounded automation rule permits automatic dispatch
- reviewer defaults cannot write the proposed change set
- all adapters map into the same normalized run event model without hiding unknown events

## Vertical slice 5: Observatory and evaluations

- run and trace explorer
- failure classification
- agent/model/device/runtime comparisons
- instruction manifest viewer
- skill evidence viewer
- matched evaluation cases
- candidate instruction/skill revisions
- canary and rollback records

Acceptance criteria:

- reports distinguish explicit, observed, inferred, and unknown evidence
- comparisons retain model, environment, base revision, and policy confounders
- Conduit proposes repository changes through reviewable diffs
- raw logs require separate permission and byte budget

## Later work

- optimized Windows and macOS compute nodes
- multi-user ownership and roles
- entirely local control plane
- remote cloud runtime providers
- GPU and attached-device scheduling
- desktop takeover and browser/GUI evidence
- task board and external issue synchronization

These are not prerequisites for the first Linux-native vertical slice.
