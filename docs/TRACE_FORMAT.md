# Run manifest and trace format

## Scope

This contract defines the evidence retained for every command or agent run.

It covers:

- immutable run configuration
- source, runtime, adapter, instruction, and skill identities
- ordered normalized events
- evidence strength
- content capture and redaction
- local storage, chunking, cursors, and corruption handling
- control-plane indexing and optional upload
- verification and later evaluation
- OpenTelemetry export

Collection begins with the first executable Linux Native run. The dashboard and evaluation screens may be implemented later.

## Records

A run produces five record classes.

### Run manifest

One immutable record written after node admission and before runtime or agent start.

The manifest records what was authorized and the exact local inputs known at the start boundary. Later observations do not mutate it.

### Context snapshot

One immutable record for each initial prompt, follow-up, steer, or resumed turn.

It records the selected Project and Board revisions, references, content digests, and compilation policy. Prompt text is not required in the trace.

### Normalized event

An ordered, bounded device-origin event. Events record observed activity and provider output without requiring vendor-private protocol data.

### Content object

An immutable local object referenced by a manifest or event when content is too large, binary, separately permissioned, or retained under another policy.

### Segment descriptor

Metadata for a finalized compressed group of raw stream records or exportable normalized events.

## Immutable run manifest

The manifest is committed before any runtime start request.

If an executable, source revision, runtime configuration, access decision, or other authority-bound field changes after the manifest is committed, the run does not silently update the manifest. It fails preflight or creates a new run.

Fields are grouped below.

### Identity

- manifest schema version
- manifest ID and digest
- run ID
- assignment ID, when present
- project and collaboration-session IDs, when present
- operation ID and request digest
- idempotency key digest, not the plaintext key where a digest is sufficient
- actor principal
- calling client
- Project Agent, when present
- creation and admission timestamps

### Device

- device ID
- device display label
- node version
- node protocol version
- operating system and architecture
- node boot ID
- capability digest
- selected local policy revision
- configured storage profile revision

### Runtime

- runtime kind and provider ID
- provider version and capability receipt digest
- runtime configuration revision
- selected host identity or guest identity class
- requested CPU, memory, GPU, storage, and network mode
- effective isolation claims as individual capabilities
- environment image, template, or snapshot digest where applicable

The manifest does not write “sandboxed” as a boolean. It records evidence such as filesystem restriction, process-user separation, network namespace, container boundary, VM boundary, elevation availability, and host socket exposure.

### Authority

- requested and effective access scope
- requested and effective approval mode
- Connector Policy ID and revision
- Project policy revision
- Device policy revision
- approved risk classes or pre-authorizations
- operation expiry and admitted validity duration

### Sources

For each Source binding:

- Source ID
- Location ID and revision
- workspace mode: direct, worktree, managed copy, or read-only
- repository identity, when Git is present
- base commit
- branch and upstream observations
- initial dirty-state digest and bounded summary
- submodule, LFS, sparse-checkout, or partial-clone observations
- filesystem snapshot or explicit unknown state for non-Git folders
- bounded display path and opaque device-local path reference

Canonical paths remain device-local.

### Agent adapter

When an agent is used:

- adapter ID and adapter contract version
- adapter implementation version
- executable identity
- wrapper and interpreter identities where applicable
- detected CLI version
- requested model and effort
- effective model and effort, when known before start
- authentication state and evidence source
- supported capability receipt
- launch-plan digest
- tool-catalog digest
- provider-native session mode requested

Executable identity may include file identity, file hash, package identity, and canonical device-local reference. The trace does not expose a private absolute path to the control plane.

### Project and Board context

- Project Context revision
- Collaboration Session revision
- Assignment Message revision
- selected Board message IDs
- selected Artifact and Change Set IDs
- Context Compiler version and configuration digest
- context size and item counts
- capture policy for compiled context

### Instruction catalog

The manifest records files Conduit discovered before agent start. Actual provider loading remains a later event unless the adapter has authoritative pre-start evidence.

For each item:

- instruction ID
- kind, such as `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, or adapter-specific equivalent
- opaque path reference and bounded display path
- content digest
- byte length
- discovery source
- directory scope
- precedence index
- adapter eligibility
- initial state: discovered, skipped, unsupported, missing, or unknown
- evidence level

The manifest also records:

- configured discovery filenames
- configured per-file or aggregate byte limits
- discovered total bytes
- discovery errors

For Codex, discovery order matters because guidance is layered and loaded when the run or session starts. Conduit retains the order and truncation evidence rather than only a boolean stating that an `AGENTS.md` existed. citeturn890288search1turn890288search28turn890288search31

### Skill catalog

For each available skill:

- stable Skill ID
- parsed Skill name
- description digest
- `SKILL.md` digest and byte length
- source and version metadata
- compatibility metadata digest
- hashes of referenced scripts, references, templates, or resources where practical
- discovery scope
- eligible adapters
- eligibility state for this run, when determined before start
- catalog position or precedence

The Agent Skills format requires a `SKILL.md` with `name` and `description` metadata and can bundle scripts and other resources. Conduit records the skill as a versioned package rather than treating its name as sufficient identity. citeturn890288search0turn890288search4turn890288search20

### Capture and retention

- capture-policy ID and revision
- redaction-policy ID and revision
- retention-policy ID and revision
- permitted content classes
- permitted local raw streams
- permitted uploads
- maximum inline payload
- maximum object and segment sizes

### Evaluation tags

Optional fields:

- benchmark or case ID
- experiment ID
- variant ID
- replicate number
- expected checks
- comparison group

These are explicit experiment labels. Conduit does not infer a controlled experiment from ordinary production runs.

## Context snapshot

Each user or orchestrator input that may change agent behavior gets a Context Snapshot.

Required fields:

- Context Snapshot ID and digest
- run ID
- turn or input operation ID
- input mode: initial, answer, follow-up, steer, resume, or queued instruction
- expected controller epoch
- Project Context revision
- Collaboration Session revision
- selected message and artifact references
- instruction and skill catalog digests
- Context Compiler version
- ordered item manifest
- compiled byte and token estimates where available
- capture and redaction policy
- final compiled-content digest

Each item states:

- item type
- source record ID and revision
- precedence
- content digest
- byte length
- included, summarized, referenced, omitted, or unavailable
- omission or summarization reason
- sensitivity class

The compiled prompt body is retained only when capture policy permits it. Its digest is always retained when compilation succeeded.

A later Board message is not automatically part of a running agent's context. It appears only in a new Context Snapshot created by a typed input operation.

## Event producer and order

The normalized event stream in `conduit.node/1` is device-origin and has one persistent sequence per run.

The device allocates the sequence before committing the event. Sequence values are unsigned 64-bit integers serialized as decimal strings.

Control-plane audit and collaboration events remain separate records. The UI may merge them by causal references and timestamps but does not claim one total order across device and control-plane clocks.

Device event order is authoritative for local activity. Wall-clock timestamps are observations, not ordering authority.

## Event envelope

Every event contains:

- schema version
- event ID
- run ID
- device ID
- device event sequence
- event type
- source component
- observed wall-clock time
- optional monotonic time since node boot
- node boot ID
- correlation ID
- parent event or span ID
- trace ID and span ID where applicable
- evidence level
- sensitivity class
- retention class
- payload or content reference
- payload digest
- previous chain hash
- event chain hash

The control plane adds ingestion metadata outside the committed device event:

- receive time
- ingestion attempt
- DeviceRoom sequence
- queue-delivery identity
- D1 projection state

Control-plane receive data does not change the device event digest.

## Evidence levels

### Explicit

A documented provider or Conduit component emitted an unambiguous record.

Examples:

- Codex returned a correlated `turn/start` response
- the test process exited zero
- Git returned a commit ID
- an adapter emitted a documented Skill invocation event

### Observed

Conduit observed a concrete local action or state but the provider did not label its intent.

Examples:

- the agent process opened a `SKILL.md`
- a skill script executable was invoked
- a file changed
- a process existed with a matching birth identity

### Inferred

Conduit derived a likely interpretation from incomplete evidence.

Examples:

- behavior resembled a Skill procedure
- a provider event likely represented a subagent but lacked a documented identifier

Inferred evidence is never promoted to explicit use in reports.

### Unknown

The adapter or environment does not provide enough evidence.

Unknown is retained rather than converted to false.

## Sensitivity classes

- `public`: safe for ordinary exported examples
- `metadata`: identifiers, versions, counts, hashes, and bounded labels
- `project_content`: visible messages, diffs, filenames, test text, and source-derived content
- `raw_log`: terminal or provider protocol content
- `credential_reference`: non-secret reference to a credential source or status
- `secret`: material detected or declared secret; never placed in normal events

A `secret` payload is not serialized into an event. The event contains a redaction record and, where safe, a non-reversible digest generated with a deployment-specific keyed hash.

## Retention classes

### R0: authority and recovery

- Run Manifest and Context Snapshot digests
- operation admission and terminal receipts
- approvals and denials
- security and policy decisions
- source and runtime commitments
- Change Set and verification commitments
- explicit uncertainty and recovery records

R0 is not silently discarded while the associated run identity or control-plane idempotency tombstone is retained.

### R1: normalized evidence

- completed visible agent messages
- tool calls and results
- command summaries
- file and Git events
- test results
- Artifact metadata
- instruction and Skill evidence

### R2: compactable progress

- streaming text deltas after a complete visible message exists
- repeated status notifications
- high-frequency resource samples
- duplicate provider progress

### R3: separately controlled raw content

- raw terminal streams
- raw provider protocol
- full command output
- full prompts or completions
- screenshots, video, and large binary evidence

R3 uses separate permission, storage, retention, and export paths.

## Core event registry

The first schema permits namespaced future events, but these core types have fixed meaning.

### Run and workspace

- `run.admitted`
- `run.phase_changed`
- `run.waiting_input`
- `run.waiting_approval`
- `run.cancel_requested`
- `run.terminal`
- `workspace.preparation_started`
- `workspace.prepared`
- `workspace.conflict`

### Runtime

- `runtime.start_requested`
- `runtime.started`
- `runtime.liveness_changed`
- `runtime.pause_requested`
- `runtime.paused`
- `runtime.stop_requested`
- `runtime.stopped`
- `runtime.resource_sample`
- `runtime.recovery_result`

### Agent and context

- `agent.open_requested`
- `agent.opened`
- `agent.prompt_submitted`
- `agent.prompt_accepted`
- `agent.message_delta`
- `agent.message_completed`
- `agent.usage`
- `agent.warning`
- `agent.error`
- `agent.cancel_requested`
- `agent.cancelled`
- `agent.provider_event_unknown`
- `context.snapshot_created`
- `context.item_omitted`

### Instructions

- `instruction.discovered`
- `instruction.loaded`
- `instruction.skipped`
- `instruction.truncated`
- `instruction.effective_set`
- `instruction.violation_observed`

A provider's claimed loading event can be explicit. Filesystem discovery alone is observed discovery, not proof that the model used the instruction.

### Skills

- `skill.discovered`
- `skill.eligible`
- `skill.triggered`
- `skill.loaded`
- `skill.resource_accessed`
- `skill.script_started`
- `skill.script_completed`
- `skill.behavior_inferred`

Skill activation quality depends heavily on the `description` used for routing. Conduit retains the description digest and distinguishes discovery, triggering, and output quality so that description changes can be evaluated separately. citeturn890288search17turn890288search23

### Subagents

- `subagent.started`
- `subagent.phase_changed`
- `subagent.message_completed`
- `subagent.terminal`

A vendor thread or subprocess is not labeled a subagent without explicit or observed evidence.

### Tools and commands

- `tool.started`
- `tool.completed`
- `tool.failed`
- `command.started`
- `command.output_available`
- `command.completed`
- `command.failed`

Tool arguments and command output follow capture and redaction policy. The exact execution commitment is retained even when visible arguments are redacted.

### Files, Git, and tests

- `file.created`
- `file.modified`
- `file.deleted`
- `file.renamed`
- `git.state_observed`
- `git.commit_created`
- `git.branch_changed`
- `git.diff_observed`
- `test.started`
- `test.completed`

File content is not required in the event. Path references, change type, before/after digests, sizes, and Artifact references are sufficient for metadata-only capture.

### Approval, policy, and artifacts

- `approval.requested`
- `approval.resolved`
- `policy.decision`
- `policy.denied`
- `artifact.created`
- `artifact.uploaded`
- `verification.started`
- `verification.completed`
- `adapter_error`

## Agent messages

Visible assistant output has two event forms.

`agent.message_delta` is R2 and may be compacted after a complete message is available.

`agent.message_completed` contains:

- provider message ID, when available
- role
- bounded visible text or content reference
- visible-content digest
- finish status
- provider event evidence
- Board Message ID when published

Provider-private reasoning is not mapped into visible messages, tool text, or synthetic summaries. If an adapter suppresses a private provider event, it may record a metadata-only count and provider event type without content.

## Tool and command correlation

A Tool Call, Command, and provider event can represent the same causal operation. Conduit keeps separate IDs and links them.

Example:

```text
tool_call_id    tool_...
command_id      cmd_...
provider_id     vendor call ID
parent_span_id  agent turn span
```

A tool result does not prove a file or external effect occurred. File, Git, test, and Artifact observations remain separate evidence.

## Agent claims and verification

An agent can report completion, a test result, or a changed file. Such text is a claim.

Conduit records separately:

- agent-reported claims
- observed filesystem and Git state
- observed commands and exits
- retained test reports
- independent verification checks
- human acceptance

`verification.completed` contains named checks with:

- check ID and version
- target digest
- outcome: pass, fail, error, skipped, or unknown
- evidence references
- verifier identity
- observed time

Assignment acceptance policy references verification checks. It does not parse success from prose.

## Instruction effectiveness

Instruction reports require both relevance and evidence.

For each rule or file, Conduit can report:

- discovered
- selected by provider discovery rules
- loaded with explicit or observed evidence
- truncated or shadowed
- relevant to a run according to a labeled evaluation or rule detector
- followed
- violated
- unable to determine

A file that was discovered but not relevant is not counted as a successful or failed instruction.

When instruction files contain stable rule identifiers such as `AG-TEST-001`, Conduit can link a check directly to a rule. Without identifiers, comparison remains file- or section-level.

## Skill effectiveness

Skill reports preserve these separate questions:

1. Was the Skill present in the catalog?
2. Was it eligible for the adapter and task?
3. Was it triggered?
4. Was `SKILL.md` loaded?
5. Was a bundled script or resource used?
6. Was the documented procedure followed?
7. Did verification improve?
8. Did runtime, token use, retries, or errors change?

Only explicit provider events or observed resource access are strong use evidence. Similar output is inference.

Controlled Skill evaluation uses clean runs with matched source, context, environment, adapter, model, effort, access, and verification. The Agent Skills guidance likewise recommends clean contexts for eval runs so prior state does not contaminate the result. citeturn890288search23

## Event digest and chain

Conduit uses RFC 8785 JSON Canonicalization Scheme for JSON digests.

`payloadDigest` is SHA-256 of canonical payload JSON or the referenced plaintext content.

`eventDigest` is SHA-256 of the canonical event core excluding:

- `eventDigest`
- `previousChainHash`
- `chainHash`
- control-plane ingestion metadata

The event chain is:

```text
chain[0] = SHA256("conduit.event-chain.v1\n" + manifestDigest)
chain[n] = SHA256(
  "conduit.event-chain.v1\n" +
  chain[n-1] + "\n" +
  eventDigest[n]
)
```

A chain proves ordered device commitment, not that a full-access administrator could not alter local software before an event was generated.

The node periodically sends event-range commitments to the control plane. Stronger tamper evidence requires those commitments to leave the device before a full-host administrator can rewrite local data.

## Normalized event storage

The first node implementation stores normalized events in SQLite.

Logical tables:

```text
run_manifest
context_snapshot
run_event
content_object
raw_segment
trace_cursor_generation
retention_state
```

Writing an event and advancing the run's last committed sequence is one transaction.

Requirements:

- WAL or another crash-safe transactional mode
- foreign keys and uniqueness on `(run_id, sequence)` and event ID
- duplicate event accepted only when digest matches
- event JSON bounded to 65,536 bytes
- inline payload bounded to 8,192 bytes
- content above the inline limit stored by immutable reference
- terminal receipt and event-chain state committed together
- schema migrations versioned and fail closed when incompatible

A database integrity failure affecting R0 records prevents new effectful work. A recoverable R2 index failure may degrade observability without claiming complete traces.

## Content objects

A Content Object descriptor records:

- object ID
- owning run
- content kind
- sensitivity and retention class
- compression
- uncompressed and stored byte lengths
- plaintext SHA-256
- stored-object SHA-256
- encryption and redaction metadata
- storage provider and opaque locator
- creation and expiry times

The initial maximum uncompressed Content Object is 8 MiB. Larger output is split into ordered objects or retained as an Artifact.

Default compression is Zstandard for text, JSON, and raw streams when compression reduces size. Already compressed media may remain uncompressed.

Objects are immutable. Replacing content creates another object ID.

## Raw stream segments

Raw terminal and provider protocol streams are not stored as event payloads.

The node writes length-prefixed raw records into an active segment. Each record contains stream ID, local sequence, monotonic time, direction, byte length, and bytes.

A segment finalizes when any configured limit is reached, including:

- 4 MiB uncompressed data
- 60 seconds of activity
- run terminal state
- explicit flush

Finalization:

1. flush and synchronize the active file
2. calculate plaintext digest
3. compress where configured
4. calculate stored-object digest
5. atomically publish the final object
6. commit the Segment Descriptor in SQLite
7. remove the partial file only after the descriptor is durable

A crash can leave a `.partial` segment. Recovery validates complete records, truncates only an incomplete final record, finalizes the valid prefix, and records a gap if bytes were lost.

Raw protocol records use a different stream from terminal bytes. Access to one does not imply access to the other.

## Cursor paging

Trace and log APIs return bounded pages.

The cursor is opaque to clients and binds:

- device ID
- run ID
- stream or event provider
- next sequence or byte position
- store generation
- query filters
- capture-policy revision

The node signs or MACs the cursor. A cursor cannot be substituted across runs, streams, or filter sets.

A stale store generation returns `cursor_stale` with the nearest safe restart position. It does not restart at the beginning without telling the client.

Page limits apply to:

- record count
- decoded JSON bytes
- referenced content bytes
- response bytes

MCP and dashboard callers never receive an unbounded trace in one response.

## Corruption and missing data

Conduit reports evidence loss explicitly.

Possible states:

- complete
- content_redacted
- raw_not_captured
- retention_gap
- segment_corrupt
- event_chain_mismatch
- local_store_unavailable
- upload_incomplete

A corrupted R3 raw segment does not erase normalized R0/R1 evidence. A corrupted R0 manifest or terminal receipt places the run and node journal in recovery-required state.

When an event sequence range is unavailable, the node sends `event.gap` as defined in `docs/NODE_PROTOCOL.md`.

## Redaction

Redaction occurs before normalized payload persistence and before upload.

Redaction inputs include:

- declared secret fields from typed operations
- adapter-specific credential patterns
- configured path and environment-key rules
- known token formats
- user-defined patterns

The raw local stream may exist under a separate permission and retention policy. Normalized events do not depend on keeping raw secret content.

A redaction record contains:

- redaction rule ID and version
- field or content class
- replacement category
- optional keyed digest
- evidence level

The redaction log never contains the removed plaintext.

## Cloud placement

The control plane stores:

- Run Manifest metadata and digest
- Context Snapshot metadata and digest
- latest run phase and terminal receipt
- selected R0/R1 normalized events needed for Board, approvals, Artifacts, and verification
- event-range commitments and gap state
- indexes for search and reports
- optional uploaded object descriptors

The device stores the authoritative complete normalized stream and local raw content until retention or explicit export changes custody.

High-frequency R2 events are aggregated before D1 storage. Optional R1/R3 objects may be uploaded to R2 under a separate permission and byte budget.

Cloudflare Queues can ingest normalized event batches after `DeviceRoom` has durable custody. Queue retry does not create another Conduit event.

## OpenTelemetry export

The internal schema does not depend on OpenTelemetry.

An exporter maps Conduit records to current semantic conventions where compatible:

- one Run or Agent Turn can map to a trace or span hierarchy
- model request and usage fields map to `gen_ai.*` attributes where stable
- Tool and Command operations map to child spans or events
- approvals and handoffs use Conduit namespaced attributes when no stable convention exists
- content export remains opt-in

OpenTelemetry's GenAI conventions are evolving and have moved between specification locations. Keeping a versioned Conduit schema avoids changing durable local records whenever export conventions move. citeturn890288search2turn890288search3turn890288search15turn890288search22

The export records:

- Conduit schema version
- exporter version
- OpenTelemetry semantic-convention version
- fields omitted or downgraded

Export does not add content that the Conduit capture policy did not retain.

## Minimum metrics

Derived metrics include:

- assignment-to-admission duration
- admission-to-runtime-start duration
- agent-open and prompt-acceptance duration
- time to first visible message
- time to first meaningful Tool or Command action
- working, approval-wait, input-wait, and verification durations
- total runtime
- Tool and Command counts and failure counts
- file and Git change counts
- test outcomes
- retry and abandoned-attempt counts
- provider token or usage data when explicitly available
- local and uploaded bytes by retention class
- CPU, memory, GPU, and storage observations where supported

Missing provider usage remains unknown. It is not estimated from message text unless the report is clearly labeled estimated.

## Comparison safeguards

A comparison groups runs only after recording:

- assignment or benchmark case
- source snapshot and base commit
- Project and Session context revisions
- runtime and environment revision
- device and resource class
- adapter and executable version
- model and effort
- access and approval policies
- instruction and Skill catalog digests
- verification policy

Ordinary production correlation is labeled observational. A causal claim requires a controlled or matched evaluation design.

## Required deterministic tests

1. manifest committed before runtime start
2. executable or source revision changes after preflight
3. duplicate event sequence with same digest
4. duplicate event sequence with different digest
5. event gap and later valid range
6. event payload above inline limit
7. object above maximum split into ordered references
8. crash during raw segment append
9. crash between segment publish and SQLite descriptor commit
10. corrupted compressed segment
11. cursor substitution across runs
12. stale cursor after retention compaction
13. secret in Tool arguments and Command output
14. unknown provider event followed by valid provider events
15. private-reasoning provider event suppression
16. instruction discovered but not provably loaded
17. instruction truncation and precedence
18. Skill discovered, triggered, loaded, resource used, and inferred-only cases
19. agent claims tests passed but observed test failed
20. Node disconnect before event commitment upload
21. Queue delivers the same event batch twice
22. OpenTelemetry exporter omits unretained content

## References

- Agent Skills specification: <https://agentskills.io/specification>
- Agent Skills evaluation: <https://agentskills.io/skill-creation/evaluating-skills>
- Codex AGENTS.md discovery: <https://developers.openai.com/codex/agent-configuration/agents-md>
- Codex Skills: <https://developers.openai.com/codex/build-skills>
- OpenTelemetry semantic conventions: <https://opentelemetry.io/docs/specs/semconv/>
- OpenTelemetry GenAI observability: <https://opentelemetry.io/blog/2026/genai-observability/>
