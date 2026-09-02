# ADR 0011: Stateful Codex app-server adapter

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit needs to run Codex as a Project Agent on a selected device and Runtime
Provider. A Codex assignment may outlive the browser or MCP caller, receive
follow-up input, wait for approval, be cancelled, and be resumed after the
supervised process is restarted.

The Codex app-server protocol is stateful. It has initialization, thread, turn,
server-request, notification, and item lifecycles. Writing a prompt to stdin and
treating a live child process as accepted is not sufficient.

OwnMesh contains useful Codex protocol work, but its current design audit
identified behaviors that must not be copied:

- turn admission can be reported before the correlated `turn/start` response
- active cancellation state can be reconstructed from a bounded output tail
- typed continuation is not a complete public adapter surface
- protocol readiness cannot produce a durable compatible receipt
- server-request coverage is not exhaustive

Conduit also permits `full_user`, `full_device`, and `never` approval. The
adapter therefore needs a real policy bridge rather than unconditional denial
or blind provider approval.

## Decision

### Transport

Version 1 uses one supervised `codex app-server --listen stdio://` child per
Conduit agent runtime session.

Experimental app-server WebSocket and experimental API methods are disabled.

### State

The adapter retains:

- exact executable and interpreter receipt
- provider thread ID in device-local custody
- opaque Conduit native-session handle
- active turn ID and status
- pending provider request IDs
- normalized event cursor
- model and effort capability receipt
- protocol conformance receipt

One adapter session has at most one active turn.

### Admission

`agent.open` waits for the correlated `thread/start` or `thread/resume`
response.

`agent.send` waits for the correlated immediate `turn/start` response. The Run
enters `Working` only after that response is validated. Model completion remains
asynchronous.

### Control

`agent.steer` sends `turn/steer` with the retained active turn as
`expectedTurnId`.

`agent.cancel` sends `turn/interrupt` using retained control state. Cancellation
is terminal only after bounded terminal convergence is observed.

Provider log scanning is not an authority path.

### Resume

The provider thread ID remains on the device and is referenced remotely through
an opaque handle.

Idle threads may be resumed in a new child. Loss of a child during an active
turn without a terminal receipt becomes `recovery_required`; Conduit does not
re-run the prompt automatically.

### Approvals

Conduit Access Scope and Approval Mode are authoritative.

Known Codex approval and input requests are converted to typed Conduit requests.
A response is bound to the exact normalized action digest and provider request
ID.

Version 1 uses one-shot `accept`, `decline`, or `cancel` responses. It does not
allow Codex to mutate Conduit policy through session-wide approval or policy
amendment responses.

Unknown server requests receive a correlated safe failure.

### Capability discovery

The adapter uses stable protocol methods, including `model/list` and
`skills/list`, when available.

Unsupported model or effort selections fail explicitly. They do not fall back
silently.

Protocol readiness is established by a non-inference conformance probe and
stored against the exact executable hash, version, environment digest, adapter
contract, and upstream source revision.

### Events

Codex events are mapped to Conduit's bounded normalized vocabulary. Private
reasoning and user-message echoes are excluded from normal replay.

Raw provider frames remain device-local and require separate authorization.

## Rejected alternatives

### Invoke `codex exec` for every assignment

Rejected because Conduit needs retained thread state, typed steering,
cancellation, approval requests, normalized streaming, and resume.

### Reuse one app-server process for every Project Agent

Rejected for version 1. It increases failure coupling, credential exposure,
pending-request routing complexity, and state recovery complexity. Multiplexing
can be reconsidered after the single-session contract is proven.

### Treat successful process spawn as prompt admission

Rejected because the provider can reject `turn/start` immediately while the
child remains alive.

### Find active turns from the latest log records

Rejected because logs are diagnostic storage, may be truncated, and can contain
a terminal turn after the latest start record.

### Auto-approve every Codex request in Full Access mode

Rejected. Full Access removes intended restrictions only inside the admitted
authority. Unknown or unmappable provider requests remain fail-closed.

### Deny every provider request

Rejected because Conduit supports explicit approval modes and full-access
operation. A typed bridge is required.

### Expose provider thread IDs as remote session IDs

Rejected. Provider identifiers remain device-local implementation data and
cannot be supplied as arbitrary remote authority.

### Enable experimental API methods

Rejected for version 1. Stable methods cover the first vertical slice, and
experimental schemas may change without compatibility guarantees.

## Consequences

- The adapter is a state machine, not a line-oriented prompt wrapper.
- Device-local storage needs an opaque-handle-to-thread mapping.
- The Run state machine must distinguish admission, working, cancellation
  request, terminal completion, and recovery required.
- Approval requests can pause a turn while the app-server request remains
  pending; they require bounded expiry and one correlated response.
- The adapter fixture suite must track the current generated app-server schemas.
- Exact executable upgrades invalidate protocol evidence.
- A Linux live receipt is still required before the first implementation claims
  operational readiness.

## Contract

- `docs/CODEX_ADAPTER.md`
- `spec/schemas/codex-adapter-v1.schema.json`
- `spec/examples/codex-adapter/`
