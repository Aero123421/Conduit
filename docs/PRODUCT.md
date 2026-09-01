# Product behavior

## Main paths

### Project work

A project groups sources, shared context, collaboration sessions, project agents, defaults, and retention policy. A project can contain folders from one or more registered devices. A single run still executes on one selected device.

### Scratch work

The home screen exposes:

- Quick Command
- Quick Agent Session
- Quick Container
- Quick VM

Scratch work does not require a project. It can later be promoted into a project with its messages, run history, workspace references, and retained artifacts.

### Board assignment

A normal board post does not start an agent. Selecting or typing a project-agent mention creates a structured assignment attached to the message.

An assignment identifies:

- the assignee
- the requested result
- completion conditions
- selected sources
- preferred device and runtime
- model and effort overrides
- access scope
- approval policy
- context references

The scheduler creates a run from the assignment. The run reports admission, preparation, agent startup, work, questions, approvals, verification, and termination independently from the agent's prose.

### Direct device operations

The dashboard, CLI, and optional MCP gateway can execute typed commands and device operations without an AI agent. Connector-specific rate limits and permission ceilings apply to MCP calls.

## Project agents

A project agent is a saved role, not a continuously running process. Examples:

- Codex Builder
- Claude Reviewer
- Pi Tester

A project agent stores defaults for adapter, model, effort, device selection, runtime, source access, network access, and completion checks. Each assignment may override allowed fields.

## Runtime choices

- Native: run under the selected host user
- Restricted native: use operating-system restrictions around a native process
- Container: use a managed container without access to the host runtime socket
- VM: use a managed virtual machine

Native execution is expected on ordinary personal computers. Container and VM support can be enabled per device.

## Access and approval

Access scope answers what the run may reach. Approval policy answers when a human must confirm.

Supported access presets:

- read only
- selected sources
- project full access
- full user access
- full device access
- custom

Supported approval presets:

- ask for every effect
- ask outside the selected scope
- ask for selected risk classes
- never ask

Full device access with no approvals is a valid explicit configuration. The UI must display the effective user, elevation capability, runtime boundary, target device, and connector ceiling before the run starts.

## Multiple devices

Each registered device reports available sources, agent adapters, authentication state, runtime providers, storage, resources, and current runs. Device selection may be explicit or policy-driven. Data is not copied between devices unless a transfer or clone operation is selected.

## Observatory

Every run produces a manifest and normalized event stream. The Observatory supports:

- run and failure inspection
- agent, model, device, and runtime comparison
- instruction-loading evidence
- skill discovery, loading, use, and outcome evidence
- test and artifact verification
- version comparisons for AGENTS.md, skills, adapters, and environment definitions

The first implementation must collect the required evidence even before comparison and evaluation screens are complete.

## Initial users and deployment

The first release is single-owner and Cloudflare-backed. The control plane is reachable from the browser and registered devices connect outbound. Multi-user roles and an entirely local control plane are later work.
