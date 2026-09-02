# ADR 0011: Integrated assignment execution, exact-target control, and Agent Session leases

- Status: Proposed
- Date: 2026-09-02

## Context

The first Linux slice already has separate libraries for board collaboration, Context Snapshots, Runtime Providers, Agent adapters, workspace capture, verification, and Session Baselines. A library contract does not establish a product path. The Control Plane must durably bind an Assignment to exact authority and configuration revisions, the Device must execute that committed request, and the resulting proposal must return through verification and review before a Session Baseline can change.

Start requests and controls also have different effect boundaries. A start reserves a new deterministic Runtime identity. Input, cancellation, pause, resume, snapshot, restore, stop, and destroy address existing custody and must never be interpreted as another start.

Codex app-server, Pi RPC, and ACP peers can keep one process alive across turns. Provider process lifetime therefore cannot be used as the completion signal for every Assignment Run.

Finally, a normal user service cannot enforce `full_device`. The packaged privileged-helper unit named a binary that was not implemented.

## Decision

### Assignment binding and durable scheduling

A structured Board mention that requests an Assignment stores an immutable binding to:

- the exact Project Agent and configuration revision
- model and effort selection
- target Device revision
- Runtime kind, Provider, and configuration revision
- Access Scope and Approval Policy
- exact Source and Location revisions
- the Context Compiler input and resulting Context Snapshot digest
- the parent Session Baseline revision

The Board transaction commits the Message, mention, Assignment, and binding before publishing realtime state. A durable scheduler may then create one Run, Agent Session lease, operation journal entry, and dispatch-outbox entry. Scheduler replay uses the Assignment identity and binding digest; it cannot create another Run for the same binding.

The Context Snapshot is immutable. Its identity and digest are part of the Run Manifest before Runtime start.

### Proposal, verification, and acceptance

After the task settles, the Device captures the exact Workspace state before ordinary Runtime destruction. It returns immutable Source Change custody and verification receipts bound to the Run Manifest and parent Baseline. The Control Plane verifies the submission digest before storing an immutable Change Set and transitions the Assignment to `ready_for_review` only when required checks are satisfied.

A Review binds one Change Set digest. Acceptance requires an approved Review, an eligible Change Set, the expected Collaboration Session revision, and the expected parent Baseline revision and digest. One D1 transaction stores the next immutable Baseline revision and compare-and-swaps the Session pointer. Materializing the accepted state to user folders, branches, or remotes remains a separate Device operation.

### Start and control are separate commands

An `operation.offer` is the only frame that may reserve and start a new Runtime.

An existing-target control operation stores:

- a new control operation ID and idempotency key
- the target Run and, where applicable, Runtime
- the original start operation ID and request digest
- target Device and controller epoch
- expected shared and Device-local state revisions
- a target-custody digest
- the exact typed command and bounded arguments

Input, steer, follow-up, explicit close, and cancellation use `operation.input` or `operation.cancel`. Runtime pause, resume, stop, snapshot, restore, and destroy use `runtime.control`. They are delivered through the same durable dispatch outbox but never through the start adapter.

The Device journals control custody before applying the effect. Exact duplicate commands replay a durable receipt. A reused idempotency key, target digest, controller epoch, or expected revision conflict is rejected. An effect left ambiguous by a crash is not automatically repeated.

### Node-to-Control Plane projection

`operation.admission`, `operation.status`, `operation.terminal`, and `device.health` are Device-authenticated projections, not independent authority.

The Control Plane accepts a projection only when Device ID, operation ID, request digest, Run custody, connection epoch, and monotonic node sequence match stored authority. Each message identity and digest has one idempotent projection receipt. Exact duplicates replay the projection result; reordered state, stale epochs, conflicting digests, and invalid transitions are retained as bounded security evidence and do not advance shared state.

Admission and status update Operation, Run, Assignment, Agent Session, and Device read models in one bounded projection. Rejection and all terminal states release operation-bound connector concurrency idempotently. Board realtime events are emitted only after the D1 transition commits.

### Assignment Run and Agent Session lifecycle

An Assignment Run represents one task against one immutable Run Manifest. An Agent Session represents the reusable provider conversation and Runtime custody.

Each start chooses one explicit settlement policy:

- `close_on_settle`: capture and verify the Workspace, close or archive the provider session, terminalize the Run, and release Runtime and concurrency custody
- `waiting_input`: terminal provider settlement changes the Agent Session to `waiting_input` under a bounded lease while retaining the process; a follow-up creates a new task transition against that same session

Follow-up requires the exact Agent Session revision and controller epoch. Explicit close terminates the lease and process after collection. Cancel affects the active task and is fail-closed when no active task exists. Idle lease expiry closes the session and produces a terminal timeout receipt. A process exit is evidence about Runtime custody, but protocol settlement is the task completion signal.

### Full Device is unavailable without a helper

Until a privileged helper implements its documented socket, peer-credential, exact-commitment, allowlist, expiry, replay-prevention, audit, installation, update, and removal contracts, `full_device` admission returns `capability_unavailable`.

No package or Feature Matrix entry may advertise a helper or effective `full_device` enforcement while that binary is absent. `full_user` remains distinct and supported where local policy permits it.

## Rejected alternatives

### Infer an Assignment configuration at dispatch time

Rejected because later Project Agent, Device, Runtime, or Source edits would silently change intended work.

### Send controls as another operation offer

Rejected because the Node start path reserves a Runtime and can create another process.

### Treat a WebSocket ACK as shared Run progress

Rejected because delivery, admission, Runtime start, Agent prompt acceptance, settlement, and terminal collection are separate receipts.

### Wait for every Agent process to exit

Rejected because multi-turn Agent servers are intentionally long-lived.

### Report `full_device` when only the user service is running

Rejected because the effective authority is no broader than `full_user` and cannot enforce access to root-owned objects.

## Consequences

- The Control Plane gains immutable Assignment binding, Context Snapshot, Agent Session, Change Set, Review, Baseline, control-dispatch, projection-receipt, and Device-health records.
- The Node protocol gains a typed Runtime control frame and request-digest-bound status projections.
- The local journal gains an exact-once boundary for existing-target controls.
- Board state reflects committed Device receipts rather than transport delivery.
- Runtime collection happens before ordinary destruction, and verification remains distinct from Agent claims.
- Tests must cover scheduler replay, control retry, process-count stability, projection duplicates and stale frames, long-lived provider settlement, Baseline CAS, and fail-closed `full_device` admission.

## Contract

- `docs/DOMAIN_MODEL.md`
- `docs/NODE_PROTOCOL.md`
- `docs/RUNTIME_AND_SECURITY.md`
- `docs/RUNTIME_PROVIDER.md`
- `docs/SESSION_BASELINE_AND_CHANGESETS.md`
- `spec/schemas/node-protocol-v1.schema.json`
- `spec/schemas/trace-v1.schema.json`
- `spec/schemas/changeset-v1.schema.json`
