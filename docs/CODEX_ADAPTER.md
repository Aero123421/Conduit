# Codex adapter

## Scope

This contract covers the first Conduit adapter for the Codex CLI.

The adapter starts `codex app-server` as a supervised local child and translates
between the Codex app-server protocol and Conduit's Run, approval, event, and
artifact contracts.

The first implementation uses only the stable stdio transport:

```text
codex app-server --listen stdio://
```

The experimental app-server WebSocket transport and experimental API methods
are not enabled.

Verified upstream source on 2026-09-01:

- repository commit: `2b7c279735d0d096cf7b34fe98938f46792f4d4f`
- app-server README blob: `4acc629c967e77917c45be7d3f1c1b776825f6a0`
- [app-server README](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md)
- [generated protocol schemas](https://github.com/openai/codex/tree/main/codex-rs/app-server-protocol/schema/json)

The generated schemas and README are the vendor contract. Conduit fixtures
pin the exact upstream revision used during review.

## Process boundary

Version 1 uses one supervised app-server process for one Conduit agent runtime
session.

The process owns one active Codex thread and at most one active turn. Conduit
does not multiplex unrelated Runs through the same child in version 1.

Detection and launch use the same executable receipt:

- exact resolved executable
- executable SHA-256
- parsed Codex version
- resolved shebang interpreter, when present
- deterministic child `PATH`
- launch argv
- child environment digest

Shell startup files are not sourced. A detected wrapper whose interpreter
cannot be resolved is `adapter_degraded`, not ready.

Provider credentials stay on the device. They are not copied to the control
plane, Board, normalized Trace, or fixture set.

## Status

Binary presence, protocol compatibility, authentication, and live execution
are separate observations.

| State | Meaning |
| --- | --- |
| `not_installed` | No launchable Codex executable was found. |
| `installed` | The exact binary and interpreter are launchable. Protocol and authentication are not proven. |
| `needs_login` | Codex explicitly reported that authentication is required. |
| `authenticated` | A documented Codex result proved current authentication. Protocol readiness is tracked separately. |
| `adapter_degraded` | The executable, interpreter, version, or protocol contract cannot be used safely. |
| `ready` | The exact executable has a compatible protocol receipt and sufficient authentication evidence for the requested operation. |
| `running` | A supervised app-server child and retained adapter state are live. |

`codex --version` cannot prove authentication or protocol compatibility.

## Protocol-only test

A protocol test must not perform a hidden paid inference.

The test:

1. starts the pinned app-server executable
2. sends `initialize` as the first request
3. validates the correlated response
4. sends `initialized`
5. exercises stable read-only protocol requests such as `model/list` where
   available
6. closes the process
7. stores a bounded conformance receipt

An authentication error from a stable read-only request may establish
`needs_login` while still proving that the protocol framing and request method
are compatible.

The receipt is bound to:

- executable SHA-256
- Codex version
- deterministic child environment digest
- Conduit adapter contract version
- upstream app-server source revision
- conformance case revision

Replacing or upgrading the executable invalidates the receipt.

## Initialization

`initialize` is always the first app-server request. Conduit supplies bounded
client metadata and:

```json
{
  "capabilities": {
    "experimentalApi": false
  }
}
```

After a successful response, Conduit sends `initialized`.

A second `initialize` request is an adapter error. The adapter does not reset a
live session implicitly.

Provider request and notification records are LF-delimited JSON. The protocol
is JSON-RPC-like but does not include the `jsonrpc` field.

## Model and effort selection

The adapter uses `model/list` for the model catalog and each model's supported
reasoning efforts.

A requested model or effort that is absent from the current capability receipt
returns a typed error. The adapter does not silently switch to another model or
effort.

The effective model and effort are recorded in the Run Manifest and open/turn
receipts.

## Agent session lifecycle

Conduit exposes this stable adapter surface:

```text
adapter.discover
adapter.status
agent.open
agent.send
agent.steer
agent.state
agent.cancel
agent.replay
agent.close
```

`agent.follow_up` is represented by `agent.send` after the prior turn is
terminal. Resume is a capability of `agent.open`.

### Open

A new session performs:

```text
spawn app-server
initialize
initialized
thread/start
```

A resumed session performs:

```text
spawn app-server
initialize
initialized
thread/resume
```

`agent.open` does not create a hidden model turn.

The correlated `thread/start` or `thread/resume` response must be validated
before the session becomes `idle`.

The provider thread ID is kept in the device-local adapter record. Remote
surfaces use an opaque Conduit native-session handle.

### Send

`agent.send` is accepted only when the session is `idle`.

The adapter:

1. persists the pending request and expected session state
2. sends `turn/start`
3. waits for the immediate correlated response
4. validates the returned thread and turn identity
5. stores the active turn
6. returns a turn-admission receipt
7. streams completion asynchronously

The Run does not become `Working` merely because the request bytes were written
or the child is still alive.

A JSON-RPC error, wrong response ID, EOF, malformed response, or admission
timeout fails admission. Later model failure is a terminal normalized event,
not an admission rollback.

### Steer

`agent.steer` maps to `turn/steer`.

The request includes the retained active turn ID as `expectedTurnId`. If the
active turn changed or became terminal, Conduit returns a conflict and does not
send input to another turn.

### Cancel

`agent.cancel` maps to `turn/interrupt`.

The adapter uses retained active `(thread ID, turn ID, status)` state. It does
not search provider logs for the latest `turn/started` event.

Cancellation has two observations:

1. the correlated `turn/interrupt` response
2. bounded convergence to a terminal interrupted turn

If the interrupt response is received but terminal convergence cannot be
proved, the session becomes `cancel_requested` or `recovery_required`. It is
not reported as cancelled.

### State

`agent.state` returns retained device-local control state:

- session phase
- opaque native-session handle
- active opaque turn handle
- pending provider request count
- normalized event cursor
- last terminal receipt or stable error

### Replay

`agent.replay` returns cursor-paged normalized events.

Raw app-server records are a separate device-local diagnostic stream with
independent authorization, retention, and byte limits.

### Close

Closing stops the supervised child and records a terminal process receipt.

Closing does not archive or delete the Codex thread automatically. Provider
thread archival is a separate typed operation.

## Resume and process loss

An idle persisted thread may be resumed in a new app-server child through
`thread/resume`.

The device resolves the opaque native-session handle to the provider thread ID.
Remote callers cannot supply an arbitrary provider ID or local path.

If the app-server process disappears while a turn is active and no terminal
receipt exists, version 1 marks the Run `recovery_required`. It does not
silently submit the same prompt again.

A later implementation may prove more recovery states using `thread/read`, but
absence of proof remains ambiguous.

## Session state machine

```text
created
  -> process_starting
  -> initializing
  -> thread_opening
  -> idle

idle
  -> turn_admitting
  -> working
  -> finishing
  -> idle

working
  -> waiting_input
  -> working

working
  -> waiting_approval
  -> working

working
  -> cancelling
  -> idle
  |  cancel_requested
  |  recovery_required

any non-terminal state
  -> failed
  |  closed
```

Only a correlated protocol response or retained terminal observation advances a
control state. Display text is not state authority.

## Approval policy and sandbox policy

Conduit Access Scope and Approval Mode remain the authority. Codex policy fields
are a provider-level enforcement layer, not the source of truth.

The adapter maps the admitted scope to the narrowest supported Codex sandbox:

| Conduit scope | Required provider boundary |
| --- | --- |
| `read_only` | Read-only filesystem and no unapproved mutation. |
| `selected_sources` | Write access only to the admitted source roots. |
| `project_full` | Write access to all admitted project roots. |
| `full_user` | User-level unrestricted access only when device and runtime policy permit it. |
| `full_device` | Device-level authority only when the runtime and configured elevation path support it. |

For `never`, the adapter requests the provider's no-prompt approval behavior
only inside the already admitted authority.

For approval modes that can require confirmation, the adapter uses an
on-request provider policy and bridges typed requests to Conduit.

A vendor approval prompt cannot broaden the admitted Conduit authority.

## Server-request handling

Every supported server-initiated request carrying an ID receives exactly one
correlated response.

| Codex request | Conduit behavior |
| --- | --- |
| `item/commandExecution/requestApproval` | Normalize argv, cwd, risk, and turn identity; evaluate exact Conduit authority. |
| `item/fileChange/requestApproval` | Normalize file-change identity and affected paths; evaluate exact authority. |
| `item/permissions/requestApproval` | Return only the exact permission subset admitted by Conduit, or decline. |
| `item/tool/requestUserInput` | Create a bounded Board input request and wait for a correlated response or timeout. |
| `mcpServer/elicitation/request` | Unsupported in version 1 unless a separately registered bridge owns the request; otherwise cancel/fail safely. |
| `item/tool/call` | Unsupported unless a Conduit dynamic-tool registry explicitly advertised the tool. |
| `account/chatgptAuthTokens/refresh` | Never returns provider account credentials; fail safely. |
| `attestation/generate` | Unsupported without a separate attestation contract; fail safely. |
| legacy execution or patch approval | Decline or cancel within the claimed compatibility range. |
| unknown future request | Emit `adapter_error` and return a correlated safe failure. |

Unknown requests are never left pending silently.

### Approval decisions

The initial bridge emits only one-shot decisions:

```text
accept
decline
cancel
```

The adapter does not use provider-local `acceptForSession`,
`acceptWithExecpolicyAmendment`, or network-policy amendments in version 1.
Conduit remains the policy and approval authority.

Permission-profile responses are constructed from the admitted Conduit
permission set. Vendor-suggested permission profiles are display data until
validated.

A Conduit approval is bound to:

- device
- Run
- adapter session
- active turn
- provider request ID
- normalized action
- action digest
- source and runtime revisions
- controller epoch
- expiry

A changed action requires another decision.

## Event normalization

Normal replay uses this vocabulary:

```text
session
status
assistant_message
assistant_message_delta
plan
tool_call
tool_result
approval_request
user_input_request
usage
warning
completed
error
adapter_error
```

Provider-private reasoning is not normalized into user-visible content.
User-message echoes are suppressed. Public assistant messages remain visible.

Unknown, malformed, and oversized records become bounded `adapter_error`
events. A bad record does not discard later valid LF records unless the process
or framing state is no longer safe.

The normal event stream contains references rather than unbounded command
output, file bodies, or provider payloads.

## Skills and instructions

The adapter may call stable `skills/list` to record the available skill catalog
and load errors.

Conduit records evidence separately:

- discovered
- loaded
- triggered
- followed
- outcome

A Skill is not marked used merely because its output resembles the Skill
instructions.

Instruction and Skill manifests contain hashes and precedence metadata.
Credential-bearing files and private reasoning are excluded.

Changing Skill enablement through `skills/config/write` is a separate
configuration operation. A normal Run cannot mutate its own evaluation
baseline silently.

## Bounds

Initial limits:

| Item | Limit |
| --- | --- |
| Provider LF record | 1 MiB |
| Normalized text field | 64 KiB |
| Pending provider requests | 128 |
| Normalized replay page | 1,000 events |
| Admission wait | configurable, default 20 seconds |
| Cancel convergence wait | configurable and separate from admission |
| Raw provider retention | device policy |

Limits are versioned configuration, not inferred from provider output.

## Porting boundary from OwnMesh

Reusable candidates:

- deterministic executable and shebang resolution
- bounded LF record parser
- source-backed protocol fixtures
- pure Codex event classification
- credential redaction helpers
- process-tree termination primitives

Rewritten for Conduit:

- adapter session supervisor integration
- retained active-turn state
- prompt admission receipt
- typed follow-up and steer operations
- Conduit approval bridge
- Run and Assignment state mapping
- normalized Trace storage
- opaque native-session custody
- conformance receipt storage

The following OwnMesh behaviors are not imported:

- reporting ready before the correlated `turn/start` response
- finding the active turn by scanning a log tail
- a protocol test that cannot become ready
- one generic parser for unrelated agent dialects
- broad version support inferred from a low minimum semver
- unconditional approval denial as the only policy bridge

## Contract files

- `spec/schemas/codex-adapter-v1.schema.json`
- `spec/examples/codex-adapter/`
- `docs/adr/0011-stateful-codex-app-server-adapter.md`
