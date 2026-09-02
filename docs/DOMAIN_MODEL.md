# Domain model

## Naming

The following names are reserved. Runtime-provider or vendor concepts must use qualified names instead of reusing them.

### Project

A long-lived grouping of sources, collaboration sessions, shared context, project agents, defaults, and retention policy. A project is optional.

### Collaboration Session

A project board thread with messages, assignments, participants, context references, and an optional accepted workspace baseline. It is called `CollaborationSession` in code. It is not a process, VM, MCP session, or vendor-native agent session.

### Message

An immutable board post with an author, origin, body, attachments, and structured mentions. Editing creates a revision. Quoted text and code blocks do not create assignments.

### Project Agent

A saved project member configuration. It references an agent adapter and default role, model, effort, device policy, runtime policy, source permissions, network policy, and verification policy. It does not imply a running process.

### Assignment

A durable unit of requested work. It is created from a structured mention, a form, an automation rule, CLI, API, or MCP call. An assignment can have multiple runs due to retry, alternative agents, comparison, or recovery.

### Run

One admitted execution of an assignment or scratch request. A run has exactly one device, one runtime instance, one access scope, one approval policy, and zero or one agent adapter. A command-only run has no agent adapter.

### Agent Runtime Session

The local process and vendor-native session used inside a run. It is called `AgentRuntimeSession` in code. It may be replaced without replacing the collaboration session or assignment.

### Device

A registered computer. The product entity is `Device`; the installed service is `conduit-node`.

### Runtime Instance

The execution boundary created by a runtime provider. It may be the host user process, restricted process, container, or VM.

### Source

A logical repository or folder known to a project. A source is independent from the path of any one copy.

### Location

A device-local realization of a source. The canonical path and filesystem identity remain on the device. A source can have multiple locations on different devices.

### Run Workspace

The concrete files exposed to a run. It is built from one or more source locations using direct, worktree, managed-copy, or read-only mode.

### Workspace Snapshot

The immutable description of the source state used to start a run. For Git it contains repository identity and commit. For non-Git folders it contains a bounded manifest or explicit unknown state.

### Change Set

The observed output of a run across one or more sources. It contains base snapshots, commits or patches, changed-file metadata, non-Git deltas, artifacts, and verification evidence. A change set is not accepted into a collaboration session merely because an agent reports completion.

### Artifact

A retained output such as a diff, commit reference, test result, report, screenshot, video, build, package, or exported log range.

### Approval

A typed decision for one exact requested operation. Chat messages such as “OK” are not approvals.

## Relationships

```text
Project
├── Source
│   └── Location (per Device)
├── ProjectAgent
├── ProjectContext
└── CollaborationSession
    ├── Message
    │   └── Assignment
    │       └── Run
    │           ├── RuntimeInstance
    │           ├── AgentRuntimeSession
    │           ├── RunWorkspace
    │           ├── Trace
    │           └── ChangeSet / Artifact
    └── AcceptedWorkspaceBaseline
```

Scratch requests create runs without a project or collaboration session. Promotion creates a project and links the retained scratch records; it does not rewrite their original identity.

## Assignment states

- `draft`
- `queued`
- `active`
- `waiting_input`
- `waiting_approval`
- `ready_for_review`
- `accepted`
- `rejected`
- `cancelled`
- `failed`

Assignment state is derived from its runs and human decisions. It must not be set directly from an agent message.

## Run states

Internal states:

- `created`
- `admitted`
- `queued`
- `offered`
- `claimed`
- `preparing_workspace`
- `provisioning_runtime`
- `starting_agent`
- `prompt_accepted`
- `working`
- `waiting_input`
- `waiting_approval`
- `finishing`
- `ready_for_review`
- `completed`
- `paused`
- `cancelled`
- `failed`
- `lost`
- `uncertain`

The UI may group these into Assigned, Preparing, Working, Needs you, Ready for review, Done, Paused, Failed, and Recovery needed.

## Authority

- The control plane is authoritative for projects, collaboration sessions, messages, assignments, intended run configuration, connector policy, and shared context.
- The selected device is authoritative for local source paths, source identity observations, process state, runtime state, credentials, raw logs, and local artifacts not uploaded elsewhere.
- A terminal run requires a device receipt or reconciliation evidence. A control-plane timeout alone cannot prove that local work did not execute.
- Accepted workspace baselines and change-set decisions are control-plane records that reference device-verified source revisions.
