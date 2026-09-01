# ADR 0008: Immutable Run Manifest and local content custody

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit must later answer questions such as:

- which executable, model, effort, Device, Runtime, Source revision, and policy produced a result
- whether an instruction or Skill was discovered, loaded, or only inferred from behavior
- whether an agent's claim matches observed Commands, Files, Git state, tests, and Artifacts
- whether a result changed after an AGENTS.md, Skill, adapter, or environment revision
- what evidence is missing because capture was disabled, redacted, corrupt, or expired

Most provider output can contain Project content, Command output, local paths, or credentials. VM disks, raw protocol logs, screenshots, and terminal streams are too large for D1 and should not be required for normal Board operation.

A mutable “current run metadata” record would make later comparison unreliable because source, instructions, policies, and adapter versions could be overwritten after the run started.

## Decision

### Immutable start boundary

Each admitted run commits one Run Manifest after local preflight and before runtime start.

The Manifest contains the exact authority-bound and comparison-relevant inputs known at that boundary. A later incompatible change creates another run instead of editing the Manifest.

### Context per input

Initial prompts, answers, follow-ups, steering instructions, and resume operations create immutable Context Snapshots. A new Board Message does not enter an active agent context until a typed input operation creates a snapshot.

### Device-origin normalized stream

Each Device assigns one persistent sequence to normalized events for a Run. Events use evidence levels, sensitivity classes, retention classes, payload digests, and an ordered hash chain.

Control-plane collaboration and audit records remain separate. A merged UI timeline does not claim a total order across independent clocks.

### Evidence levels

The schema distinguishes:

- explicit provider or Conduit evidence
- observed local activity
- inferred interpretation
- unknown evidence

Inferred Skill use is not reported as explicit invocation. Filesystem discovery is not proof that a model followed an instruction.

### Claims and verification

Agent prose is stored as a claim. File state, Git commits, Command exits, test reports, independent verification, and human acceptance are separate records.

An Assignment can require named verification checks. It is not accepted because a model wrote “done”.

### Content custody

Normalized bounded events are stored in a local SQLite trace store. Large or separately permissioned content is stored as immutable Content Objects. Raw terminal and provider protocol streams use compressed Segments.

The control plane stores Manifest metadata and digest, selected normalized evidence, current Run state, receipt commitments, gaps, and indexes. The Device retains the authoritative complete local stream until retention or explicit upload changes custody.

### Capture policy

Visible messages, Tool arguments, Tool results, Command output, File diffs, raw provider protocol, and screenshots have independent capture modes and byte budgets.

Secret plaintext is not written to normalized events. Raw local streams are separately permissioned and are not required for normalized operation.

Provider-private reasoning is neither requested nor normalized into public messages. A provider event can be suppressed with metadata-only evidence.

### Adapter request custody and restart

Every provider-initiated request with a correlation ID is completed by the Adapter. Approval requests are either bridged to a durable typed Conduit approval or explicitly declined; unadvertised and unknown requests receive correlated fail-closed errors. A Node restart may reattach an Agent only when provider I/O, protocol phase, native session, active turn, and cursor custody are all durable. Otherwise the exact process identity is fenced and a durable `recovery_required` terminal receipt is committed without automatic replay.

The Adapter receives the effective Approval Policy separately from Access
Scope and an explicit indication of whether the typed approval bridge owns
provider requests. ACP `session/request_permission` requests are cancelled
immediately when that bridge is unavailable. Under effective `never`, the
Adapter may select only an `allow_once` option already offered by the ACP
server; it never selects `allow_always` because that would broaden reuse
authority. Pi `select`, `confirm`, `input`, and `editor` extension dialogs are
never inferred from `never`: an unavailable bridge receives a correlated
cancel response. Only `agent_settled`, not the lower-level `agent_end`, is a Pi
terminal receipt because retry, compaction, or queued input may still follow.

Codex app-server client requests are tracked in a bounded map keyed by the
exact JSON-RPC request ID. Each entry also records the method and expected
response shape. A wrong, duplicate, stale, or out-of-order response cannot
consume another request. Turn notifications are accepted only for the active
turn ID. Every method in the locally generated `ServerRequest` union receives
either its typed response or a correlated fail-closed response; unknown methods
receive a same-ID method-not-found response.

A notification may complete a Codex turn before the correlated `turn/start`
response arrives. The pending request retains that completed turn ID until the
response is consumed. An exact delayed response is observational only and
cannot resurrect the turn; a mismatched response terminally fails correlation.

Provider request IDs are process-scoped across approval and fail-closed request
categories. After a terminal response, the Adapter retains a bounded,
non-evicting tombstone containing the normalized ID, method, canonical
parameters digest, and exact response bytes. Exact duplicate requests replay
those bytes. Reusing a settled ID with another commitment produces a visible
Adapter error and terminally fails the Adapter without a contradictory second
response. Capacity exhaustion terminally fails the Adapter rather than evicting
an ID.

The effective Access Scope is translated into an explicit Codex sandbox policy
at thread and turn start. Read-only becomes `readOnly`; Restricted Native,
Container, and VM use `externalSandbox` because the Node enforces the boundary;
selected/workspace Native access uses `workspaceWrite`; and configured Full
User or Full Device Native access uses `dangerFullAccess`. Approval Policy is a
separate parameter. Empty-risk `never` is pre-authorized, `always` uses Codex
`untrusted`, and outside-scope or risk-class modes conservatively use
`on-request`. A non-empty immutable or Device-local required-risk set forces
provider callbacks to remain observable. The current conservative classifier
can pre-authorize only a known effect whose class is disjoint from that set;
unknown effects prompt.

Only one interactive Codex approval may be pending for an Agent. A duplicate
pending ID does not receive a second terminal response; another fresh ID is
declined and tombstoned. The Node transactionally
journals the request commitment and `waiting_approval` transition before it can
queue the transport frame. The frame has a deterministic message ID; re-queue
after a crash is idempotent. Resolution is journaled as the exact provider
response before child I/O, then marked applied after the write succeeds. A
write failure is retried from the journal. Expiry produces one same-ID decline;
a late receipt cannot create a second response. The local approval journal
enforces one durable row per operation/provider-request ID pair.

The approval controller epoch is the generation of the Agent controller, not
the Device WebSocket connection epoch. Ordinary reconnect increments only the
transport epoch and does not invalidate a pending approval. Replacing the Agent
controller requires a new operation/run in the current non-attachable
implementation, so its generation remains `1`. A future same-run attach path
must persist and increment this generation before it may claim receipt fencing.

The control plane takes durable custody of `operation.approval_request` before
acknowledging the Node sequence and projects it idempotently into D1. Invalid or
stale requests are security-event deadletters so they cannot poison replay;
the Node-side deadline still settles the provider request. Browser or MCP
resolution commits the decision, approval dispatch outbox row, and idempotency
effect completion in one D1 batch. A dispatch state of `offered` proves only
DeviceRoom durable custody, not Node application or provider settlement.

### Local storage

Normalized events and sequence advancement commit transactionally in SQLite. Inline event payloads are bounded. Larger content uses immutable references.

Raw Segments are length-prefixed, finalized under size/time/terminal limits, optionally compressed with Zstandard, content-addressed, and committed before partial files are removed.

R0 authority and recovery data has priority over progress deltas and raw logs. Failure to persist R0 data stops admission of new effectful work.

### Schema independence from OpenTelemetry

Conduit stores its own versioned records. An exporter maps retained fields to a selected OpenTelemetry semantic-convention version.

OpenTelemetry changes do not rewrite durable Conduit history or cause uncaptured prompt or output content to appear in exports.

## Rejected alternatives

### Store every prompt, completion, file body, and terminal stream in Cloudflare

Rejected because it creates unnecessary content exposure, cost, and retention risk. Normal Board and verification behavior uses bounded normalized evidence.

### Keep only final agent messages and Git diffs

Rejected because adapter failures, instruction loading, Tool use, policy decisions, test execution, and recovery cannot be diagnosed from final output alone.

### Infer Skill use from a successful-looking result

Rejected because similar behavior does not establish that a Skill was triggered or loaded.

### Treat AGENTS.md presence as loading proof

Rejected because provider discovery order, scope, limits, truncation, and actual loading can differ.

### Make OpenTelemetry the internal schema

Rejected because GenAI conventions and provider coverage continue to change. Conduit needs stable product records and explicit evidence semantics.

### Store normalized events only in memory until upload

Rejected because a Node or network failure would erase the evidence needed for reconciliation and later evaluation.

### Mutate the Run Manifest as new facts arrive

Rejected because comparison would no longer identify the exact start conditions. Later facts are events or Context Snapshots.

## Consequences

- Node startup requires a local trace database and Content Object directory.
- Runtime start depends on successful Manifest persistence.
- Adapters emit evidence without claiming more certainty than their protocol supports.
- Provider-initiated requests never remain pending without a correlated response.
- Non-attachable Agent processes become durable `recovery_required` outcomes after restart and are never silently rerun.
- Instruction and Skill reports require catalog identities and content digests.
- The Node protocol Event Batch references `trace-v1.schema.json`.
- Device storage settings need retention and capacity controls before long-running use.
- Schema validation and fixture tests run in CI.
- Observatory can be built later without changing what the first Runs record.

## Contract

- `docs/TRACE_FORMAT.md`
- `spec/schemas/trace-v1.schema.json`
- `spec/examples/trace/`
