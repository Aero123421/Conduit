# Observability and evaluation

## Purpose

The event model must support operational debugging and later comparison of agents, models, runtimes, instructions, skills, devices, and environment revisions. Collection begins with the first executable vertical slice.

## Run manifest

Every run stores an immutable manifest before agent startup.

Required fields:

- run, assignment, project, and collaboration-session IDs
- actor, client, and project-agent IDs
- device ID and node version
- operating system, architecture, and relevant resource observations
- runtime provider, provider version, image or environment revision
- access scope and approval policy
- agent adapter, adapter version, executable identity, model, and effort
- source locations and workspace snapshots
- project-context and board revisions
- environment and tool-catalog revisions
- instruction manifest
- skill catalog manifest
- credential source type and bounded status
- idempotency key and operation digest
- capture and redaction policy

Secret values, full environment dumps, and raw credential paths are excluded.

## Instruction manifest

The node or agent adapter records instruction discovery before or during startup.

For every discovered instruction file:

- type, such as AGENTS.md, AGENTS.override.md, CLAUDE.md, or adapter-specific equivalent
- opaque device-local path reference and bounded display path
- content hash
- size
- precedence order
- loaded, skipped, unsupported, or truncated state
- applied scope

Where the provider does not expose authoritative loading evidence, the evidence level is recorded as observed discovery, inferred, or unknown.

Codex uses layered AGENTS.md guidance, so discovery order and truncation must be retained rather than only recording that an AGENTS.md file existed.

Reference: <https://developers.openai.com/codex/agent-configuration/agents-md>

## Skill manifest

For each available skill:

- stable skill ID
- name and description hash
- source and version
- SKILL.md hash
- referenced scripts/resources hashes where practical
- eligible agent adapters
- discovery scope

Run evidence distinguishes:

- discovered
- eligible
- triggered
- loaded
- script or resource used
- behavior consistent with the skill
- unknown

Only explicit adapter events or observed file/script access count as strong use evidence. Similar behavior alone is an inference.

Skills may package instructions, resources, and scripts; Conduit does not assume that every adapter exposes the same invocation event.

Reference: <https://developers.openai.com/codex/build-skills>

## Normalized event envelope

Every event contains:

- event ID
- run ID
- device-local monotonic sequence
- device timestamp and control-plane receive timestamp
- event type and schema version
- source component
- correlation and parent span IDs where applicable
- evidence level
- sensitivity class
- bounded payload or payload reference
- content hash

Primary event families:

- `assignment.*`
- `run.*`
- `workspace.*`
- `runtime.*`
- `agent.*`
- `context.*`
- `instruction.*`
- `skill.*`
- `subagent.*`
- `tool.*`
- `command.*`
- `file.*`
- `git.*`
- `test.*`
- `approval.*`
- `artifact.*`
- `verification.*`
- `adapter_error`
- `policy.*`
- `resource.*`

Unknown provider events become bounded `adapter_error` or `agent.provider_event_unknown` records. Later valid events continue processing.

## Traces, logs, and metrics

- Trace: causal structure of assignment, run, agent turns, tool calls, commands, tests, approvals, and artifacts
- Log: ordered diagnostic records and output streams
- Metric: duration, count, bytes, resource use, token/use information where available, queue time, approval wait, failure rate, and storage use

The internal schema is versioned and can be exported to OpenTelemetry. OpenTelemetry semantic conventions are used where stable and applicable; provider-private details remain namespaced because GenAI conventions continue to evolve.

References:

- <https://opentelemetry.io/docs/specs/semconv/>
- <https://opentelemetry.io/blog/2026/genai-observability/>

## Content capture

Default normalized traces store bounded summaries and hashes, not every prompt, completion, file body, or command output.

Capture levels:

- metadata only
- normalized messages and summaries
- command/output ranges
- raw provider protocol
- export bundle

Each level has separate permission, retention, byte budget, and redaction policy. Hidden chain-of-thought is never a required field and is suppressed if a provider exposes private reasoning events.

## Local and control-plane storage

The device retains raw and high-volume data in chunked local storage. The control plane stores indexes, summaries, event commitments, and optional uploaded chunks.

A trace page can be fetched through the node by cursor. MCP never receives an unbounded run log in one response.

## Verification

Agent prose and observed evidence are separate.

A run can report:

- agent-reported completion
- files actually changed
- commits actually created
- commands actually executed
- tests actually observed
- artifacts actually retained
- checks still unverified

Assignment acceptance can require configured checks before the control plane marks it accepted.

## Skill and instruction evaluation

A comparison must record confounders:

- task or benchmark case
- base source revisions
- project context revision
- environment revision
- agent adapter and version
- model and effort
- access/approval policy
- device/runtime class
- instruction and skill versions

Reports distinguish correlation from controlled comparison. “Runs using this skill succeeded more often” is not presented as causal evidence unless matched or repeated evaluation supports it.

Useful outcomes include:

- verified success
- human correction required
- policy violation
- test failure
- time to prompt acceptance
- time to first meaningful action
- total runtime
- tool and command errors
- retries and abandoned approaches
- token or provider usage when available
- artifact quality checks

## Improvement workflow

1. Select production traces, failed runs, or curated cases.
2. Classify the failure at runtime, adapter, context, instruction, skill, model, policy, or verification level.
3. Create a candidate AGENTS.md, skill, adapter, or context-compiler revision.
4. Replay or rerun matched cases in isolated workspaces.
5. Compare outcomes and regressions.
6. Review the diff and evidence.
7. Promote to selected projects or a canary group.
8. Retain the previous revision for rollback.

Conduit may propose changes. It does not silently rewrite repository instructions or skills from its own analysis.
