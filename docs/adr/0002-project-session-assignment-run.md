# ADR 0002: Separate collaboration, assignment, and execution records

- Status: Accepted
- Date: 2026-09-01

## Decision

Conduit uses distinct entities for Project, Collaboration Session, Message, Project Agent, Assignment, Run, and Agent Runtime Session.

A structured `@` mention creates an Assignment. The scheduler creates a Run. The device starts an Agent Runtime Session inside that Run. Agent output returns as messages, activity, and artifacts.

An assignment may have multiple runs. A collaboration session remains after every runtime process or VM has stopped.

## Reasons

- one requested task may be retried with another model, device, or runtime
- a vendor-native session can fail without losing the board or requested work
- project agents need to remain visible while idle
- agent-reported completion and verified acceptance are different events
- collaboration sessions, MCP sessions, VM sessions, and CLI sessions otherwise become ambiguous in code and UI

## Consequences

- the UI right panel displays active Runs, not “active sessions”
- code uses `CollaborationSession` and `AgentRuntimeSession` explicitly
- task-board cards may reference assignments but are not their source of truth
- messages cannot directly mutate run state without a typed command
- provider adapters map vendor events into Run events rather than becoming the domain model

## Rejected alternatives

### One session entity for board, process, and VM

Rejected because lifecycle, retention, authority, and failure semantics are different.

### Treat every `@name` string as immediate execution

Rejected because quoted text, code, edits, and AI-generated mentions can accidentally or recursively start work. The client stores a structured mention and the control plane admits an assignment.

### One run per assignment forever

Rejected because retry, comparison, recovery, and alternative-agent workflows require multiple immutable execution records.
