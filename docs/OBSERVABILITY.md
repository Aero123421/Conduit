# Observability and evaluation

`docs/TRACE_FORMAT.md` is the record and storage contract. This document defines how Conduit uses those records for debugging, comparison, and improvement.

## Required questions

For any Run, Conduit should be able to answer:

- what was requested
- which Device, Runtime, adapter, executable, model, and effort were used
- which Source revisions and workspace mode were exposed
- which access and approval policies were effective
- which Project, Session, and Board revisions entered the context
- which instruction and Skill packages were available
- what loading or use evidence exists
- which Tools, Commands, Files, Git changes, tests, and Artifacts were observed
- what the Agent claimed
- which claims were independently verified
- what evidence is missing, redacted, corrupt, or expired

It must not require hidden model reasoning.

## Run view

A Run view is assembled from:

- immutable Run Manifest
- Context Snapshots
- normalized device Events
- control-plane Assignment, approval, and Board records
- Change Set and Artifact metadata
- verification checks
- evidence-gap state

The UI does not dump raw Event JSON by default.

### Summary

- current and terminal state
- Device and Runtime
- Agent, model, and effort
- access and approval modes
- Source and base revisions
- elapsed working, waiting, and verification durations
- Change Set and verification state

### Activity

A causal timeline of:

- Runtime and Agent startup
- prompt admission
- visible messages
- Tools and Commands
- File and Git observations
- tests
- approvals
- subagents
- Artifacts
- cancellation and recovery

Repeated progress and streaming deltas are grouped.

### Evidence

Agent claims and observed evidence are shown separately.

Example:

```text
Agent claim
Tests pass

Observed
pnpm test exited 1
required-tests verification failed
```

### Raw data

Raw terminal and provider streams require separate permission. Reads are bounded by cursor, byte budget, and retention policy.

## Failure classification

A failed or degraded Run can have multiple classified causes.

Initial classes:

- assignment or context
- source or workspace
- runtime provisioning
- resource admission
- authentication
- adapter protocol
- model or provider
- Tool or Command
- policy or approval
- instruction conflict or truncation
- Skill routing or procedure
- test or verification
- Device disconnect or recovery
- storage or trace integrity
- unknown

The classifier records evidence and confidence. It does not collapse every failure into “Agent error”.

## Instruction reports

Instruction reporting separates:

- discovery
- provider selection
- loading evidence
- precedence and shadowing
- truncation
- relevance
- adherence
- violation
- inability to determine

A file that existed but was irrelevant to the Run is excluded from adherence-rate denominators.

Stable rule identifiers such as `AG-TEST-001` allow a verifier to link an outcome to a specific rule. Without identifiers, reporting remains file- or section-level.

Useful findings include:

- instruction discovered but not loaded
- file exceeded configured provider limit
- lower directory overrode a root rule
- two instructions conflict
- rule is not machine-verifiable
- rule applies often but is frequently violated
- rule consumes context on Runs where it is never relevant
- procedure should move from persistent guidance into a Skill
- hard safety requirement should move from guidance into policy or a Hook

Conduit proposes edits and shows evidence. It does not silently rewrite `AGENTS.md`, `CLAUDE.md`, or other repository guidance.

## Skill reports

Skill reporting separates:

1. present in catalog
2. eligible for adapter and task
3. triggered
4. `SKILL.md` loaded
5. bundled script or resource used
6. procedure followed
7. verification outcome
8. efficiency and regressions

Evidence levels from `docs/TRACE_FORMAT.md` remain visible. Inferred behavior is not counted as explicit Skill use.

Useful findings include:

- relevant Skill not triggered
- Skill triggered for unrelated work
- Skill loaded but required script not used
- procedure step skipped
- procedure followed but verification still failed
- new version improves success but increases runtime or usage
- description change improves trigger precision
- Skill conflicts with Project guidance

## Agent and model comparison

Reports can compare:

- Agent adapter and version
- model and effort
- Device and Runtime class
- Native, Container, and VM execution
- context-compiler revision
- instruction-catalog revision
- Skill-catalog revision
- verification policy

Every report lists unmatched confounders.

Production comparisons are labeled observational. They do not claim that one Skill, instruction, model, or Runtime caused an outcome unless the evaluation design supports that claim.

## Evaluation cases

An Evaluation Case defines:

- input Assignment or prompt
- Source snapshots
- Project and Session context
- Runtime and environment revision
- Agent, model, and effort constraints
- access and approval policy
- instruction and Skill variants
- required checks
- scoring rules
- repetition and timeout policy

Each variant runs in a clean workspace. Reusing a previous provider session is disallowed unless session reuse is the subject of the evaluation.

## Checks and scores

Checks are versioned and retain their evidence.

Examples:

- expected file exists
- schema validates
- required tests pass
- forbidden path untouched
- no secret in Artifact
- requested operation not performed
- expected Skill script observed
- instruction rule followed
- review findings resolved

A score can combine checks, but raw check outcomes remain available. A score does not replace terminal and verification receipts.

## Improvement flow

1. Select failed production Runs or curated Evaluation Cases.
2. Confirm trace completeness and confounders.
3. Classify the failure.
4. Create a candidate instruction, Skill, adapter, Context Compiler, policy, or environment revision.
5. Run matched variants in isolated workspaces.
6. Compare verification, regressions, duration, usage, and human correction.
7. Review the candidate diff and evidence.
8. Apply to selected Projects or a canary group.
9. Retain the previous revision for rollback.

## Observatory sections

The later dashboard can expose:

```text
Overview
Runs
Failures
Agents
Models
Instructions
Skills
Devices
Runtimes
Evals
Storage
```

The record format does not depend on these screen names.

## Derived metrics

Initial metrics:

- admission latency
- workspace preparation duration
- Runtime startup duration
- Agent-open and prompt-acceptance duration
- time to first visible message
- time to first meaningful Tool or Command action
- working, approval-wait, input-wait, and verification duration
- total runtime
- Tool and Command counts and failures
- changed files and commits
- test and verification outcomes
- retry and abandoned-attempt counts
- human corrections
- Agent usage when explicitly available
- CPU, memory, GPU, storage, and retained bytes

Unknown usage remains unknown unless a report explicitly labels an estimate.

## MCP access

MCP tools return summaries and bounded pages.

Planned operation families:

```text
observability.search_runs
observability.get_run_summary
observability.get_trace_page
observability.search_events
observability.failure_report
observability.instruction_report
observability.skill_report
observability.compare_runs
observability.start_eval
observability.get_eval_result
observability.propose_change
```

Raw content, export, Evaluation execution, and configuration writes use separate OAuth scopes, Connector Policy permissions, and byte or concurrency limits.

## Export

Conduit can export retained data to OpenTelemetry and offline Evaluation bundles.

Export records:

- source Conduit schema version
- exporter version
- target convention version
- omitted or downgraded fields
- capture and redaction policies

Export cannot recover content that was never captured.

## References

- Trace contract: `docs/TRACE_FORMAT.md`
- Agent Skills: <https://agentskills.io/specification>
- Skill evaluation: <https://agentskills.io/skill-creation/evaluating-skills>
- Codex AGENTS.md: <https://developers.openai.com/codex/agent-configuration/agents-md>
- Codex Skills: <https://developers.openai.com/codex/build-skills>
- OpenTelemetry semantic conventions: <https://opentelemetry.io/docs/specs/semconv/>
