# ADR 0005: Run evidence is collected before observability UI

- Status: Accepted
- Date: 2026-09-01

## Decision

Every executable Run writes an immutable Run Manifest and a versioned normalized event stream from the first vertical slice.

The manifest includes agent, model, effort, device, runtime, source snapshots, context revisions, instruction discovery, skill catalog, access, approval, adapter version, and capture policy.

High-volume raw logs remain device-local by default. The control plane stores bounded indexes, summaries, and event commitments. Raw content can be uploaded or fetched only through a separate permission and retention policy.

## Reasons

- instruction and skill effectiveness cannot be reconstructed after a run if loading evidence was never recorded
- agent output alone cannot prove that files, tests, or commits exist
- comparison across models or runtimes is invalid without base revision and environment controls
- provider protocols differ and change, so Conduit needs one stable internal vocabulary
- storing all prompts, file bodies, and terminal output centrally would create unnecessary cost and privacy exposure

## Consequences

- the first Codex path includes trace collection even if the Observatory UI is minimal
- evidence levels distinguish explicit, observed, inferred, and unknown
- unknown provider events remain visible and bounded
- hidden model reasoning is not part of the contract
- event and manifest schemas require migrations and compatibility fixtures
- later OpenTelemetry export maps from the internal schema instead of defining domain behavior

## Rejected alternatives

### Add logs after the execution product works

Rejected because the missing instruction, skill, environment, and adapter evidence cannot be recovered from old runs.

### Store only terminal text

Rejected because terminal output does not represent model turns, board instructions, file changes, approvals, subagents, or verified artifacts reliably.

### Store the complete provider protocol and derive everything later

Rejected because raw formats contain sensitive or private fields, differ by provider, can be unbounded, and do not guarantee future compatibility.

### Treat skill use as true when behavior resembles the skill

Rejected because this confuses inference with observed loading or invocation and produces misleading effectiveness reports.
