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

## Record classes

A run produces five record classes.

### Run Manifest

One immutable record written after node admission and before runtime or agent start.

It records what was authorized and the exact local inputs known at the start boundary. Later observations do not mutate it.

### Context Snapshot

One immutable record for each initial prompt, answer, follow-up, steer, or resumed turn.

It records the selected Project and Board revisions, references, content digests, and compilation policy. Prompt text is not required in the trace.

### Normalized Event

An ordered, bounded device-origin event. Events record observed activity and provider output without requiring vendor-private protocol data.

### Content Object

An immutable local object referenced when content is too large, binary, separately permissioned, or retained under another policy.

### Segment Descriptor

Metadata for a finalized compressed group of raw stream records or exportable normalized events.

## Immutable Run Manifest

The manifest is committed before any runtime start request.

If an executable, source revision, runtime configuration, access decision, or other authority-bound field changes after commit, the run fails preflight or a new run is created. The manifest is not silently amended.

### Identity

- schema version
- Manifest ID and digest
- Run ID
- Assignment ID, when present
- Project and Collaboration Session IDs, when present
- operation ID and request digest
- idempotency-key digest
- actor principal and calling client
- Project Agent, when present
- creation and admission timestamps

### Device

- Device ID and bounded display label
- node version and node-protocol version
- operating system and architecture
- node boot ID
- capability digest
- local-policy revision
- storage-profile revision

### Runtime

- runtime kind and provider ID
- provider version and capability-receipt digest
- runtime-configuration revision
- selected host or guest identity class
- requested CPU, memory, GPU, storage, and network mode
- effective isolation capabilities
- image, template, or snapshot digest where applicable

The manifest does not use one `sandboxed` boolean. It records individual capabilities such as:

- distinct operating-system identity
- filesystem restriction
- process namespace
- network isolation
- container boundary
- VM boundary
- elevation availability
- host control-socket exposure

### Authority

For Native host `full_device`, immutable/local authority evidence additionally
binds the helper installation ID, helper policy revision and digest, privilege
ticket ID/digest and issuer key ID, receipt key ID, local execution-plan digest,
controller epoch, exact privileged operation, control-request digest when
applicable, and approval-enforcement mode. Cloud evidence contains opaque IDs,
digests, bounded state and timestamps only. Canonical local paths, argv content,
environment values, credential bytes, prompt text, and raw elevated streams
remain Device-local under their existing sensitivity and opt-in rules.

The following are distinct evidence boundaries and are not collapsed into one
"started" event: Device operation admission, ticket issuance, helper durable
admission, plan preparation, systemd unit creation, root liveness, Agent prompt
acceptance, each effectful control, helper terminal observation, Node terminal
submission, and Control Plane receipt acceptance. Helper receipts are Ed25519
signed and chained by monotonic state revision and previous-receipt digest. The
Node and Control Plane retain their independent verification results.

- requested and effective access scope
- requested and effective approval mode
- Connector Policy ID and revision
- Project-policy revision
- Device-policy revision
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
- submodule, LFS, sparse-checkout, and partial-clone observations
- filesystem snapshot or explicit unknown state for non-Git folders
- bounded display path and opaque device-local path reference

Canonical paths remain device-local.

### Agent Adapter

When an agent is used:

- Adapter ID and contract version
- adapter implementation version
- executable identity
- wrapper and interpreter identities where applicable
- detected CLI version
- requested model and effort
- effective model and effort, when known before start
- authentication state and evidence source
- supported-capability receipt
- launch-plan digest
- tool-catalog digest
- provider-native session mode requested

Executable identity can include file identity, file hash, package identity, and an opaque device-local path reference. A private absolute path is not sent to the control plane.

### Project and Board context

- Project Context revision
- Collaboration Session revision
- Assignment Message revision
- selected Board Message IDs
- selected Artifact and Change Set IDs
- Context Compiler version and configuration digest
- context size and item counts
- context capture policy

### Instruction catalog

The manifest records instruction files discovered before agent start. Actual provider loading is a later event unless the adapter has authoritative pre-start evidence.

For each item:

- instruction ID
- kind such as `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, or an adapter-specific equivalent
- opaque path reference and bounded display path
- content digest and byte length
- discovery source
- directory scope
- precedence index
- adapter eligibility
- initial state: discovered, skipped, unsupported, missing, or unknown
- evidence level

The manifest also records:

- configured discovery filenames
- configured per-file and aggregate byte limits
- discovered total bytes
- discovery errors

For Codex, discovery order and truncation are retained because guidance is layered when a run or session starts.

### Skill catalog

For each available Skill:

- stable Skill ID
- parsed name
- description digest
- `SKILL.md` digest and byte length
- source and version metadata
- compatibility-metadata digest
- hashes of referenced scripts, references, templates, or resources where practical
- discovery scope
- eligible adapters
- eligibility state for the run, when determined before start
- catalog position or precedence

A Skill is identified by package content and version, not only by its name.

### Capture and retention

- capture-policy ID and revision
- redaction-policy ID and revision
- retention-policy ID and revision
- permitted content classes
- permitted local raw streams
- permitted uploads
- maximum inline payload
- maximum Content Object and Segment sizes

### Evaluation tags

Optional fields:

- benchmark or case ID
- experiment ID
- variant ID
- replicate number
- expected checks
- comparison group

These are explicit labels. Ordinary production runs are not presented as controlled experiments.

## Context Snapshot

Each input that may change agent behavior gets a Context Snapshot.

Required fields:

- Context Snapshot ID and digest
- Run ID
- turn or input operation ID
- mode: initial, answer, follow-up, steer, resume, or queued instruction
- expected controller epoch
- Project Context revision
- Collaboration Session revision
- selected Message and Artifact references
- instruction- and Skill-catalog digests
- Context Compiler version
- ordered item manifest
- compiled byte and token estimates where available
- capture and redaction policies
- final compiled-content digest

Each item states:

- item type
- source record ID and revision
- precedence
- content digest and byte length
- included, summarized, referenced, omitted, or unavailable
- omission or summarization reason
- sensitivity class

The compiled prompt body is retained only when policy permits it. Its digest is retained when compilation succeeds.

A later Board Message is not automatically injected into a running agent. It appears only in a new Context Snapshot created by a typed input operation.

## Event producer and order

The normalized event stream in `conduit.node/1` is device-origin and has one persistent sequence per Run.

The device allocates a sequence before committing the event. Sequence values are unsigned 64-bit integers serialized as decimal strings.

Control-plane audit and collaboration events remain separate. The UI can merge them by causal references and timestamps but does not claim one total order across device and control-plane clocks.

Device sequence is authoritative for local activity. Wall-clock timestamps are observations.

## Cloud event batches

The Device commits every normalized event to its local Run stream before
attempting cloud delivery. It may then coalesce adjacent progress events into
one transport `event.batch` using a 100ms, 32-event, or 60,000-byte limit,
whichever occurs first. Approval, terminal, error, tool, command, file-effect,
Change Set, and verification events flush immediately. Coalescing is only a
transport optimization: normalized event IDs, event sequences, event digests,
and chain hashes remain individually present in the batch.

An `event.batch` carries `fromSequence`/`throughSequence` and the explicit
`sourceSequenceRange` with the same inclusive values. Its `sourceRangeDigest`
commits the Run ID, range, and ordered `(sequence, eventDigest)` list. A
receiver can therefore verify that a retry or replay covers the exact local
source range without treating a Queue message ID as event identity. The full
encoded frame stays below the 64KiB transport limit.

Visible assistant text deltas remain byte-for-byte reconstructible by
concatenating their visible text in source-sequence order. The local raw
provider stream is written independently as lossless length-prefixed records;
cloud batching, normalization, redaction, or Queue retry cannot alter that
Device-local evidence.

## Event envelope

Every event contains:

- schema version
- Event ID
- Run ID
- Device ID
- device event sequence
- event type
- source component
- observed wall-clock time
- optional monotonic time since node boot
- node boot ID
- correlation ID
- parent Event or Span ID
- Trace ID and Span ID where applicable
- evidence level
- sensitivity class
- retention class
- payload or Content Object reference
- payload digest
- previous chain hash
- event-chain hash

The control plane adds ingestion metadata outside the committed device event:

- receive time
- ingestion attempt
- DeviceRoom sequence
- Queue-delivery identity
- D1 projection state

Ingestion metadata does not change the device Event digest.

## Evidence levels

### Explicit

A documented provider or Conduit component emitted an unambiguous record.

Examples:

- Codex returned a correlated prompt-admission response
- a test process exited zero
- Git returned a commit ID
- an adapter emitted a documented Skill invocation event

### Observed

Conduit observed a concrete local action or state, but the provider did not label its intent.

Examples:

- the agent process opened a `SKILL.md`
- a Skill script executable ran
- a file changed
- a process existed with a matching birth identity

### Inferred

Conduit derived a likely interpretation from incomplete evidence.

Examples:

- behavior resembled a Skill procedure
- a provider event likely represented a subagent without a documented identifier

Inferred evidence is never reported as explicit use.

### Unknown

The adapter or environment did not expose enough evidence.

Unknown is retained rather than converted to false.

## Sensitivity classes

- `public`: safe for ordinary exported examples
- `metadata`: identifiers, versions, counts, hashes, and bounded labels
- `project_content`: visible messages, diffs, filenames, test text, and source-derived content
- `raw_log`: terminal or provider-protocol content
- `credential_reference`: a non-secret reference to credential source or status
- `secret`: detected or declared secret material

A `secret` payload is not serialized into a normalized event. The event contains a redaction record and, where useful, a non-reversible keyed digest.

## Retention classes

### R0: authority and recovery

- Run Manifest and Context Snapshot digests
- operation admission and terminal receipts
- approvals and denials
- security and policy decisions
- source and runtime commitments
- Change Set and verification commitments
- uncertainty and recovery records
- helper registration and root-policy attestation digests
- privilege-ticket issuance and one-use admission commitments
- helper-signed admission, start, control, and terminal receipt-chain metadata

R0 is not silently discarded while the associated Run identity or control-plane idempotency tombstone is retained.

### R1: normalized evidence

- completed visible agent messages
- Tool Calls and results
- Command summaries
- File and Git events
- test results
- Artifact metadata
- instruction and Skill evidence

### R2: compactable progress

- streaming text deltas after a complete message exists
- repeated status notifications
- high-frequency resource samples
- duplicate provider progress

### R3: separately controlled raw content

- raw terminal streams
- raw provider protocol
- full Command output
- full prompts or completions
- screenshots, video, and large binary evidence

R3 has separate permission, storage, retention, and export paths.

## Core Event registry

The schema permits namespaced future Events. These core names have fixed meaning.

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

Filesystem discovery is not proof that a model used the instruction.

### Skills

- `skill.discovered`
- `skill.eligible`
- `skill.triggered`
- `skill.loaded`
- `skill.resource_accessed`
- `skill.script_started`
- `skill.script_completed`
- `skill.behavior_inferred`

Discovery, routing, loading, procedure adherence, and output quality are measured separately.

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

Tool arguments and Command output follow capture and redaction policy. The exact execution commitment is retained even when visible arguments are redacted.

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

File content is not required in the Event. Path references, change type, before/after digests, sizes, and Artifact references are sufficient for metadata-only capture.

### Approval, policy, and Artifacts

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

Visible assistant output has two Event forms.

`agent.message_delta` is R2 and can be compacted after a complete message is available.

`agent.message_completed` contains:

- provider Message ID, when available
- role
- bounded visible text or Content Object reference
- visible-content digest
- finish status
- provider-event evidence
- Board Message ID when published

Provider-private reasoning is not mapped into visible messages, Tool text, or synthetic summaries. An adapter can record a metadata-only suppression count and provider Event type without content.

## Tool and Command correlation

A Tool Call, Command, and provider Event can represent the same causal operation. Conduit keeps separate IDs and links them.

```text
tool_call_id    tool_...
command_id      cmd_...
provider_id     vendor call ID
parent_span_id  Agent Turn span
```

A Tool result does not prove a File or external effect occurred. File, Git, test, and Artifact observations remain separate evidence.

## Agent claims and verification

Agent prose is a claim. Observed evidence is stored separately.

Conduit distinguishes:

- agent-reported claims
- observed filesystem and Git state
- observed Commands and exits
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

Instruction reports can record:

- discovered
- selected by provider discovery rules
- loaded with explicit or observed evidence
- truncated or shadowed
- relevant to a labeled evaluation or rule detector
- followed
- violated
- unable to determine

A discovered but irrelevant file is not counted as successful or failed guidance.

Stable rule identifiers such as `AG-TEST-001` allow checks to link directly to a rule. Without identifiers, comparison remains file- or section-level.

## Skill effectiveness

Skill reports preserve these separate questions:

1. Was the Skill present?
2. Was it eligible for the adapter and task?
3. Was it triggered?
4. Was `SKILL.md` loaded?
5. Was a bundled script or resource used?
6. Was the documented procedure followed?
7. Did verification improve?
8. Did runtime, usage, retries, or errors change?

Only explicit provider Events or observed resource access are strong use evidence. Similar output is inference.

Controlled evaluation uses clean Runs with matched source, context, environment, adapter, model, effort, access, and verification.

## Event digest and chain

Conduit uses RFC 8785 JSON Canonicalization Scheme for JSON digests.

`spec/fixtures/canonical-json-v1.json` is the cross-language parity fixture for canonical UTF-8 text and SHA-256 output. Rust and TypeScript implementations must produce its exact canonical text before a digest is accepted as compatible.

`payloadDigest` is SHA-256 of canonical payload JSON or referenced plaintext content.

`eventDigest` is SHA-256 of canonical Event core excluding:

- `eventDigest`
- `previousChainHash`
- `chainHash`
- control-plane ingestion metadata

The chain is:

```text
chain[0] = SHA256("conduit.event-chain.v1\n" + manifestDigest)
chain[n] = SHA256(
  "conduit.event-chain.v1\n" +
  chain[n-1] + "\n" +
  eventDigest[n]
)
```

This proves ordered device commitment. It does not prove that a full-host administrator could not modify local software before an Event was generated.

The node periodically sends Event-range commitments to the control plane. Stronger tamper evidence requires commitments to leave the Device before a full-host administrator can rewrite local data.

## Normalized Event storage

The first node implementation stores normalized Events in SQLite.

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

Writing an Event and advancing the Run's last committed sequence is one transaction.

Requirements:

- WAL or another crash-safe transactional mode
- foreign keys and uniqueness on `(run_id, sequence)` and Event ID
- duplicate accepted only when digest matches
- Event JSON bounded to 65,536 bytes
- inline payload bounded to 8,192 bytes
- larger content stored by immutable reference
- terminal receipt and chain state committed together
- schema migrations versioned and fail closed when incompatible

A database integrity failure affecting R0 records prevents new effectful work. A recoverable R2 index failure can degrade observability without claiming a complete trace.

## Content Objects

A descriptor records:

- Object ID and owning Run
- content kind
- sensitivity and retention class
- compression
- uncompressed and stored byte lengths
- plaintext and stored-object SHA-256
- encryption and redaction metadata
- storage provider and opaque locator
- creation and expiry times

The initial maximum uncompressed Content Object is 8 MiB. Larger output is split into ordered Objects or retained as an Artifact.

Default compression is Zstandard for text, JSON, and raw streams when it reduces size. Already compressed media can remain uncompressed.

Objects are immutable. Replacing content creates another Object ID.

## Raw stream Segments

Raw terminal and provider-protocol streams are not Event payloads.

The node writes length-prefixed records into an active Segment. Each record contains Stream ID, local sequence, monotonic time, direction, byte length, and bytes.

A Segment finalizes when any configured limit is reached, including:

- 4 MiB uncompressed data
- 60 seconds of activity
- Run terminal state
- explicit flush

Finalization:

1. flush and synchronize the active file
2. calculate plaintext digest
3. compress where configured
4. calculate stored-object digest
5. atomically publish the final object
6. commit the Segment Descriptor in SQLite
7. remove the partial file after the descriptor is durable

A crash can leave a `.partial` Segment. Recovery validates complete records, truncates only an incomplete final record, finalizes the valid prefix, and records a gap if bytes were lost.

Raw provider protocol and terminal bytes use different Streams. Access to one does not imply access to the other.

## Cursor paging

Trace and log APIs return bounded pages.

The opaque cursor binds:

- Device ID
- Run ID
- Stream or Event provider
- next sequence or byte position
- store generation
- query filters
- capture-policy revision

The node signs or MACs the cursor. It cannot be substituted across Runs, Streams, or filter sets.

A stale store generation returns `cursor_stale` with the nearest safe restart position. It does not restart at the beginning silently.

Page limits apply to:

- record count
- decoded JSON bytes
- referenced-content bytes
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

A corrupted R3 Segment does not erase normalized R0/R1 evidence. A corrupted R0 Manifest or terminal receipt places the Run and node journal in recovery-required state.

When an Event sequence range is unavailable, the node sends `event.gap` as defined in `docs/NODE_PROTOCOL.md`.

## Redaction

Redaction occurs before normalized payload persistence and before upload.

Inputs include:

- declared secret fields from typed operations
- adapter-specific credential patterns
- configured path and environment-key rules
- known token formats
- user-defined patterns

The raw local Stream can exist under a separate permission and retention policy. Normalized Events do not depend on keeping raw secret content.

A redaction record contains:

- rule ID and version
- field or content class
- replacement category
- optional keyed digest
- evidence level

It never contains removed plaintext.

## Cloud placement

The control plane stores:

- Run Manifest metadata and digest
- Context Snapshot metadata and digest
- latest Run phase and terminal receipt
- selected R0/R1 Events needed for Board, approvals, Artifacts, and verification
- Event-range commitments and gap state
- search and report indexes
- optional uploaded Object descriptors

The Device stores the authoritative complete normalized Stream and local raw content until retention or explicit export changes custody.

High-frequency R2 Events are aggregated before D1 storage. Optional R1/R3 Objects can be uploaded to R2 under a separate permission and byte budget. The
batch range and digest are retained with the cloud ingestion receipt even when
the normalized events are later compacted under retention policy.

Cloudflare Queues can ingest normalized Event batches after `DeviceRoom` has durable custody. Queue retry does not create another Conduit Event.

## OpenTelemetry export

The internal schema does not depend on OpenTelemetry.

An exporter maps Conduit records to current conventions where compatible:

- a Run or Agent Turn can map to a Trace or Span hierarchy
- model request and usage fields map to stable `gen_ai.*` attributes
- Tool and Command operations map to child Spans or Events
- approvals and handoffs use Conduit-namespaced attributes where no stable convention exists
- content export remains opt-in

The exporter records:

- Conduit schema version
- exporter version
- OpenTelemetry semantic-convention version
- fields omitted or downgraded

Export does not add content that the Conduit capture policy did not retain.

## Minimum metrics

Derived metrics include:

- Assignment-to-admission duration
- admission-to-runtime-start duration
- Agent-open and prompt-acceptance duration
- time to first visible Message
- time to first meaningful Tool or Command action
- working, approval-wait, input-wait, and verification durations
- total runtime
- Tool and Command counts and failure counts
- File and Git change counts
- test outcomes
- retry and abandoned-attempt counts
- provider token or usage data when explicitly available
- local and uploaded bytes by retention class
- CPU, memory, GPU, and storage observations where supported

Missing provider usage remains unknown. It is not estimated from Message text unless labeled estimated.

## Comparison safeguards

A comparison records:

- Assignment or benchmark case
- source snapshot and base commit
- Project and Session context revisions
- runtime and environment revision
- Device and resource class
- Adapter and executable version
- model and effort
- access and approval policies
- instruction and Skill catalog digests
- verification policy

Production correlation is labeled observational. A causal claim requires a controlled or matched evaluation design.

## Required deterministic tests

1. Manifest committed before runtime start
2. executable or source revision changes after preflight
3. duplicate Event sequence with same digest
4. duplicate Event sequence with different digest
5. Event gap and later valid range
6. Event payload above inline limit
7. Object above maximum split into ordered references
8. crash during raw Segment append
9. crash between Segment publish and SQLite descriptor commit
10. corrupted compressed Segment
11. cursor substitution across Runs
12. stale cursor after retention compaction
13. secret in Tool arguments and Command output
14. unknown provider Event followed by valid provider Events
15. private-reasoning Event suppression
16. instruction discovered but not provably loaded
17. instruction truncation and precedence
18. Skill discovered, triggered, loaded, resource used, and inferred-only cases
19. Agent claims tests passed but observed test failed
20. Node disconnect before Event commitment upload
21. Queue delivers the same Event batch twice
22. OpenTelemetry exporter omits unretained content

## References

- Agent Skills specification: <https://agentskills.io/specification>
- Agent Skills evaluation: <https://agentskills.io/skill-creation/evaluating-skills>
- Codex AGENTS.md discovery: <https://developers.openai.com/codex/agent-configuration/agents-md>
- Codex Skills: <https://developers.openai.com/codex/build-skills>
- OpenTelemetry semantic conventions: <https://opentelemetry.io/docs/specs/semconv/>
- OpenTelemetry GenAI observability: <https://opentelemetry.io/blog/2026/genai-observability/>
