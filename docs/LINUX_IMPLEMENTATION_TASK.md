# Linux implementation task

This branch is the integration branch for all non-visual Linux product work.

- Base branch: `feat/shared-domain-skeleton`
- Integration branch: `feat/linux-complete-implementation`
- Platform: Linux only
- Final dashboard UI: excluded from this task
- Do not merge the pull request. Push the completed implementation and mark it ready for review.

## Completion boundary

Implement the complete Linux product surface below. Do not stop after a demo path, a skeleton, a mock-only implementation, or a partial provider.

Included:

- Cloudflare Control Plane
- Linux `conduit-node`
- owner authentication, device enrollment, MCP OAuth and connector policy
- outbound-only Device transport, durable journal, replay and reconciliation
- Project, Source, Location, Session, Board, Project Agent, Assignment, Run, Task and Approval backends
- projectless Quick Command, Quick Agent Session and Quick VM
- Native, Restricted Native, Container and VM Runtime providers
- source isolation, Git worktrees, managed copies, Session Baselines and Change Sets
- Codex, Claude Code, OpenCode, Pi and Agy adapters when a real CLI/protocol exists
- Context compilation, Agent handoff and deterministic orchestration rules
- MCP endpoint and rate limiting
- Trace, logs, artifacts, Skill/AGENTS.md evidence and evaluation services
- Linux installation, systemd integration, storage, backup, migration, update and diagnostics
- CLI and APIs sufficient to operate every feature without the dashboard

Excluded:

- Windows and macOS runtime or CI support
- final dashboard layout, styling and visual components
- multi-tenant SaaS billing or organization management

Bare, unstyled HTML needed for passkey registration, OAuth consent or recovery is allowed. Do not make product UI decisions in this branch. Provide typed APIs, OpenAPI/schema contracts and realistic fixtures for the later dashboard.

## Required reading

Read before changing code:

- `AGENTS.md`
- all files under `docs/`
- all ADRs under `docs/adr/`
- all schemas and examples under `spec/`
- Issues `#14` through `#20`
- the complete diff and review history of PR `#15`

Use these repositories as references, not as code dumps:

### OwnMesh

Repository: `Aero123421/OwnMesh`

Inspect the current implementation for:

- structured Agent adapters and provider event normalization
- process supervision and PTY handling
- durable operation/session journals
- outbound transport and reconnect behavior
- credential redaction
- local IPC and path custody
- Linux service/install behavior

Port only code that fits Conduit's contracts. Do not import the OwnMesh workspace/session domain or its MCP-first product structure.

### CF Edge MCP Kit

Repository: `MOVEI144/CF-edge-mcp-kit`

Inspect at least:

- `packages/core/src/canonical.ts`
- `packages/core/src/operation.ts`
- `packages/core/src/policy.ts`
- `packages/core/src/replay.ts`
- `apps/worker/src/mcp.ts`
- `apps/worker/src/oauth-provider.ts`
- `docs/oauth-passkeys.md`
- `docs/operation-lifecycle.md`
- `docs/security-invariants.md`

Reuse or reimplement the useful boundaries:

- OAuth 2.1 resource/server behavior
- Passkey authentication and step-up approval
- operation commitments
- approval binding
- idempotency and replay classification
- outbound-only Device connectivity
- local-deny precedence
- fixed-origin external connectors

Do not inherit its deliberate prohibition on general command execution. Conduit supports commands and Full Access when policy explicitly permits them. Continue to prohibit model-controlled arbitrary URL connectors and credential return values.

## Parallel execution

Use parallel subagents and Git worktrees. Keep one coordinator responsible for schema changes, integration and final verification.

Suggested worktrees:

1. `linux/control-plane`
2. `linux/node-transport`
3. `linux/runtime-storage`
4. `linux/workspace-changeset`
5. `linux/agent-adapters`
6. `linux/collaboration-context`
7. `linux/mcp-observability`
8. `linux/cli-packaging-tests`

Rules:

- each workstream owns separate directories where possible
- schema or shared-domain changes go through the coordinator first
- commit by coherent workstream; do not squash unrelated areas into one commit
- continuously merge or rebase the integration branch into worktrees
- run relevant tests before merging a worktree
- never overwrite another subagent's changes to resolve a conflict cheaply
- do not create competing domain types for an existing schema concept
- do not open replacement PRs; integrate the completed work into this branch

## Cross-cutting invariants

These rules apply to every workstream.

1. Cloudflare stores shared metadata and routing state. Device files, CLI credentials, active process state, VM disks and raw logs remain Device-local unless an explicit artifact or retention policy uploads them.
2. The Device is the final authority for local execution. A Cloudflare allow decision cannot override a Device-local deny.
3. All Device connections are outbound. Do not require an inbound port on the user's PC.
4. Browser owner sessions, MCP OAuth grants, Device keys and Agent-provider credentials are separate identities.
5. Permission scope and approval mode are independent. Support `full_user`, `full_device` and `never` as real configurations.
6. Full Access must mean what it says within its declared boundary. Do not add hidden denials. Authentication, connector ceilings, local policy and audit still apply.
7. Every effectful operation binds actor, client, Device, Project/Session/Assignment where present, source revisions, Runtime request, access scope, approval mode, arguments, expiry and idempotency key into the operation commitment.
8. An effectful operation in `uncertain` is never automatically replayed.
9. Do not report a capability as effective without observed evidence.
10. Do not expose Docker, Podman or Incus management sockets to an Agent Runtime.
11. Do not mount an entire home directory into Container or VM runtimes as a credential shortcut.
12. Never put credentials, hidden reasoning, raw secrets or private canonical paths into Cloudflare metadata, fixtures, MCP output or normal logs.
13. Do not collect private chain-of-thought. Record visible messages, tool calls, commands, file effects, tests, public plans, state changes, usage and errors.
14. All externally supplied data is size-bounded before expensive parsing or allocation.
15. Production code must not contain `todo!`, `unimplemented!`, placeholder success, silent fallback, fake provider support or unconditional mock data.
16. Schema compatibility is explicit. Change v1 only when the existing contract is demonstrably wrong and update fixtures, migration notes and parity tests together; otherwise add a new version.
17. Run, Runtime, Agent native session, Collaboration Session and Task are different records.
18. Agent completion text does not advance a Session Baseline. Verification and explicit acceptance do.
19. One Run executes on one Device.
20. Final UI decisions are outside this branch.

## Workstream 1 — repository and shared contracts

Complete and harden the shared foundation.

Deliverables:

- preserve all PR `#15` parity, validation and bounded-error behavior
- create stable crate/package boundaries for Control Plane, Node, Runtime, Workspace, Agent adapters, Collaboration, Observability, MCP and CLI
- add one command entry point for full repository checks
- add generated-code drift checks and schema registry checks
- add database migration test infrastructure
- add feature/capability registry versions
- add structured public error mapping between Rust, TypeScript, HTTP, MCP and Node protocol
- add configuration parsing with explicit defaults and validation
- use XDG paths for Linux local data, configuration, cache, Runtime data and logs

CI requirements:

- Linux only
- no Windows/macOS matrix
- use dependency caches
- cancel superseded runs on the same branch
- use path-aware jobs where practical
- keep fast unit/contract checks separate from hardware-dependent live conformance
- do not weaken checks merely to shorten CI

## Workstream 2 — Cloudflare Control Plane

Create the production Control Plane under a clear app/package boundary.

Implement:

- Cloudflare Worker routing and versioned HTTP APIs
- D1 migrations and repositories
- Durable Objects for live Device routing and real-time Session/Board fan-out
- R2 bindings for configured artifact/trace uploads
- Queue-based asynchronous event/trace ingestion where useful
- local development with Wrangler/Miniflare and local D1 migrations
- deployment configuration templates without committed secrets

D1 must cover at least:

- owner principals
- passkeys
- owner sessions
- OAuth clients and grants
- connector policies and rate-limit profiles
- Device enrollments, Devices and Device keys
- Projects, Sources and Location metadata
- Collaboration Sessions
- Messages, revisions and structured mentions
- Project Agents
- Assignments and Assignment transitions
- Runs and Run transitions
- operation journal and idempotency records
- Approvals
- Tasks, dependencies and Session/Assignment links
- artifacts and custody metadata
- trace/run indexes and evidence summaries
- audit/security events
- schema and migration versions

Implement APIs for all records needed by the CLI and later dashboard. Use optimistic concurrency or compare-and-swap where revisions matter.

Do not keep durable truth only in Durable Object memory. Durable Objects must recover after eviction or restart.

## Workstream 3 — owner auth, Device identity and policy

Implement the complete single-owner security model.

Owner authentication:

- WebAuthn/passkey registration and authentication
- CSRF protection and secure browser sessions
- fresh-authentication/step-up checks for sensitive changes
- recovery records that cannot execute commands or read Project content
- passkey revocation and audit events

MCP authorization:

- OAuth 2.1 Authorization Code + PKCE
- resource metadata and audience/resource binding
- pre-registered and standards-compatible client registration paths where supported
- grant pause, revoke and reauthorization
- connector policy revision binding

Device identity:

- Ed25519 key generation on the Device
- private key never leaves the Device
- enrollment request, owner approval, challenge proof and completion
- key rotation, retiring keys and revocation
- connection epoch fencing

Policy:

- Device, Project, Runtime, operation, access-scope and approval ceilings
- exact per-connector permissions
- `full_user`, `full_device`, `never` and Custom scope
- local Device policy with deny precedence
- approval commitment bound to the exact operation
- immutable security-event records

## Workstream 4 — Device transport and `conduit-node`

Create the Linux Rust Node as a real service.

Node components:

- Device identity store
- local SQLite database with WAL, migrations and integrity checks
- durable inbound/outbound operation journal
- source/location registry
- Runtime registry
- process supervisor
- workspace manager
- credential broker
- storage manager
- Agent adapter registry
- trace/content store
- artifact collector
- local IPC server
- service lifecycle and update hooks

Transport:

- outbound WSS only
- `device.hello`, challenge, proof and accepted handshake
- protocol negotiation
- connection epochs
- ordered sequence numbers in both directions
- bounded frames and payload digest verification
- ACK and replay
- idempotency classification
- stale-connection fencing
- heartbeats and health receipts
- reconnect summary/plan/complete flow
- event-range replay and explicit event gaps
- terminal receipts

Durability rules:

- persist an admitted operation before acknowledging admission
- persist terminal state before sending a terminal receipt
- continue admitted work during a Cloudflare outage
- buffer normalized events locally
- reconcile after reconnect
- never re-run `uncertain` work without explicit action
- on Node restart, reconcile journal records with real process/container/VM/workspace state

Implement fault tests for duplicate delivery, stale epochs, out-of-order frames, disconnect before/after admission, disconnect before terminal receipt, Worker/DO restart, Node restart, corrupted journal, read-only journal and exhausted storage.

## Workstream 5 — Runtime providers, storage and credentials

Implement the shared `RuntimeProvider` contract and all Linux providers.

### Native

- direct process execution as the current user
- pipes and PTY modes
- process groups and descendant termination
- cwd, bounded environment projection and explicit executable identity
- cancellation, timeout, pause where supported and restart reconciliation
- `full_user` and `full_device` behavior
- optional, separately installed privileged helper for host elevation
- privileged helper must use typed requests, allowlists, operation commitments and no network listener

### Restricted Native

Use Linux controls where available:

- Landlock
- bubblewrap/user namespaces
- systemd scopes/cgroup v2
- seccomp or other bounded controls where justified

Detect actual host capability. Return `effective`, `degraded` or `unavailable` with evidence. Never claim isolation that was not applied.

### Container

Support Docker and Podman through provider adapters.

- image selection/build
- CPU, memory, PID and storage limits
- network modes
- source/workspace attachment
- ports and preview endpoints
- root inside the Container when configured
- stop, snapshot/export where supported, collect and destroy
- no host management socket inside the Agent Container

### VM

Implement Incus/KVM as the first Linux VM provider.

Support:

- provider detection and `conduit doctor`
- image and environment revisions
- Quick VM
- Project VM/Devbox
- Session/Run VM
- CPU, RAM, disk and network policy
- folder/workspace attachment through supported mechanisms
- guest agent bootstrap
- command, PTY and process control through the guest agent
- root inside the VM when configured
- snapshot, pause, resume, stop, archive, restore and destroy
- VM-internal Docker
- storage-pool selection
- recovery after host/Node restart
- custody receipts before destructive cleanup

Do not repartition disks, create destructive storage pools or alter global networking without an explicit operator command. Provide safe setup commands and detect prerequisites.

### Storage

Implement Device profiles for:

- hot storage
- archive storage
- backup storage
- cache storage

Track quotas and free space. Prevent cleanup of uncollected changes, credentials or the final custody copy. Implement retention, pinning, archive movement and restore.

### Credentials

Implement Device-local encrypted credential profiles and Agent-specific projections.

Support where valid:

- native host credentials
- read-only file projection
- ephemeral file projection
- bounded environment projection
- Agent socket/broker projection
- VM guest volume
- login-required state

Record metadata and evidence, never secret content. Implement per-Adapter import rules rather than copying the whole home directory.

## Workstream 6 — Sources, workspaces, Baselines and Change Sets

Implement the complete multi-folder Project model.

Source types:

- Git repository
- managed normal folder

Location behavior:

- a Source may have Locations on multiple Devices
- absolute canonical paths stay Device-local
- Cloudflare stores opaque Location IDs and safe display paths
- Git clones may be linked to one Source through repository identity
- normal folders are never auto-linked solely by name or similar content

Workspace modes:

- read-only
- direct
- isolated Git worktree
- managed copy

Git support must handle and report:

- dirty trees
- branch/worktree collisions
- repository identity
- SHA-1 and SHA-256 object formats
- shallow and partial clones
- sparse checkout
- submodules
- Git LFS
- missing objects
- detached HEAD
- upstream/remote changes
- external edits and divergence

Implement:

- unique Run branches and worktrees
- leases and cleanup
- managed-folder snapshots and file operation manifests
- multi-Source Session Baseline vectors
- immutable Change Sets
- draft state for uncommitted/uncaptured work
- exact-digest Review records
- verification requirements
- prepare/CAS/finalize acceptance flow
- separate acceptance, materialization, push and deploy operations
- custody receipts before cleanup
- explicit conflict and stale states

## Workstream 7 — Agent adapter framework

Create one common Adapter contract with:

- discover
- probe
- capability receipt
- authentication status
- model/effort discovery where available
- open
- send
- steer
- follow-up
- resume
- cancel
- state
- replay
- close

Implement and test:

- Codex
- Claude Code
- OpenCode
- Pi
- Agy

Inspect current official CLI behavior and the current OwnMesh adapters. Do not guess protocol fields or claim support based on an executable name alone.

Each Adapter must cover when supported:

- exact executable/version identity
- structured protocol before stdout scraping
- prompt accepted acknowledgement
- visible Agent messages
- tool calls and results
- commands
- file edits
- approvals
- usage
- subagents
- terminal state
- cancellation
- native session persistence and resume
- protocol/version incompatibility
- login-required state

If Agy cannot be identified from an actual installed CLI or OwnMesh implementation, report it as `unavailable` with evidence; do not fabricate a working adapter.

Create versioned protocol fixtures and an Adapter conformance suite. Live tests must be opt-in when they would consume paid model usage.

## Workstream 8 — Collaboration, assignment, tasks and context

Implement the non-visual collaboration backend.

Project Agents:

- persistent logical members independent of running processes
- profile/Adapter, role, model, effort, Device preference, Runtime preference, access and approval defaults
- readiness/login/capability status
- current and recent Runs

Board:

- normal Messages do not start Agents
- structured mention records, not regex-only parsing
- an `@agent` assignment creates a Message and Assignment atomically
- edits, quotes, code blocks and imported logs do not accidentally create Assignments
- origin identifies human, MCP client, Agent or system
- message revisions are retained

Assignment:

- one primary assignee
- objective, constraints and acceptance criteria
- selected Context Snapshot
- Source revisions
- model/effort/Runtime/Device/access/approval
- state machine and history
- queueing and concurrency limits
- additional instruction, read-only question and immediate steer are separate operations

Orchestration:

- roles for planner, implementer, reviewer, tester, researcher and integrator
- role changes actual Runtime/workspace permissions
- Agent-to-Agent `@` defaults to a proposed Assignment
- deterministic automation rules may auto-start a handoff
- cycle, depth, cost, Run-count and time limits
- no invisible swarm state

Tasks/Kanban backend:

- Task records, status, dependencies and links to Messages, Assignments, Runs and Change Sets
- Board/Assignment remain the execution records; Kanban is not the source of truth for Agent state

Context Compiler:

- Project overview/rules/decisions/resources
- Session summary and relevant recent Messages
- unread important Messages
- Assignment and role
- Source/Change Set/Artifact references
- AGENTS.md/CLAUDE.md and Skill catalog evidence
- bounded compilation and search fallback
- immutable Snapshot for every initial prompt, follow-up, answer, steer and resume
- priority and origin labels
- no full-history dump by default

## Workstream 9 — MCP Gateway and connector controls

Implement a remote MCP endpoint on Cloudflare using the same Control Plane services as the CLI and later dashboard.

Tool families must include typed, bounded operations for:

- Devices and health
- Projects, Sources and Locations
- Sessions and Board
- Project Agents
- Assignments and Runs
- Quick Command
- Quick Agent Session
- Runtime/VM lifecycle
- approvals
- Tasks
- artifacts
- log/trace search and summaries
- Skill and instruction reports
- comparisons and evaluations

Long operations return handles immediately. Never keep one MCP request open for the duration of an Agent Run or VM operation.

Implement Connector Policy enforcement for:

- Devices
- Projects
- operation families
- Runtime kinds
- maximum access scope
- most permissive approval mode
- raw-content permission
- artifact upload permission
- concurrency
- duration
- response bytes
- normalized/raw log transfer
- VM start rates
- weighted operation budgets

Rate limiting layers:

1. coarse Cloudflare edge limit
2. exact Control Plane connector/operation/concurrency/byte accounting
3. final Device resource and local-policy limits

Use Tools as the compatibility baseline. Resources or prompts may be added, but core operation must not depend on every MCP client supporting them.

External service connectors must use fixed origins and explicit schemas. Do not add an arbitrary URL fetch tool.

## Workstream 10 — Observatory, Skills and evaluations

Implement evidence capture from the first real Run.

Persist/index:

- immutable Run Manifest
- Context Snapshots
- normalized Event sequence and chain hashes
- content objects and raw segments
- visible Agent output
- tool calls/results
- commands/output
- file effects
- Git state and Change Sets
- tests and verification
- approvals
- subagents/handoffs
- usage/cost when reported
- errors and recovery states

Raw content remains Device-local by default. Implement redaction, sensitivity, retention and optional R2 upload policies.

AGENTS.md/CLAUDE.md evidence:

- discovery files and precedence
- hashes and byte counts
- eligibility
- loaded/skipped/truncated/overridden state
- instruction IDs where present
- observed compliance/violation/unknown results

Skill evidence:

- discovered
- eligible
- triggered
- loaded
- script/resource used
- followed
- outcome
- efficiency
- regression
- evidence strength: explicit, observed, inferred or unknown

Implement queries/reports for:

- Run search and Trace paging
- failure classification/clustering
- Agent/model/effort/Runtime/Device comparisons
- Skill and instruction version comparisons
- controlled matched evaluations
- candidate improvement proposals
- canary/default version state

Do not label correlation as causal improvement. Controlled comparisons must match task, base state, environment, Agent/model and other relevant variables.

Provide OpenTelemetry export as an adapter. Conduit's own schema remains authoritative.

## Workstream 11 — CLI, local operation and packaging

Implement a Linux CLI that exposes all non-visual functionality.

At minimum:

- `conduit auth ...`
- `conduit device enroll|list|show|revoke|doctor`
- `conduit project create|list|show|add-source|add-location`
- `conduit session create|list|show`
- `conduit board post|read|search`
- `conduit agent add|list|show|remove`
- `conduit assignment create|show|cancel|input|steer`
- `conduit run list|show|follow|pause|resume|cancel|recover`
- `conduit quick command|agent|vm`
- `conduit runtime list|show|start|stop|snapshot|archive|restore|destroy`
- `conduit task ...`
- `conduit logs search|show|export`
- `conduit eval start|show|compare`
- `conduit connector ...`
- `conduit storage ...`
- `conduit backup create|verify|restore`

Packaging:

- `conduit-node` systemd user service by default
- optional system service/privileged helper where required
- installation and uninstall scripts or packages
- XDG-compliant directories
- secure file permissions
- log rotation
- configuration migration
- database backup/restore
- Node upgrade with compatibility checks and rollback
- Cloudflare deployment instructions and scripts
- `conduit doctor` for all dependencies and capabilities

Do not require Container or VM prerequisites for basic Desktop Native use.

## Workstream 12 — testing and fault injection

Every production subsystem needs unit, contract and integration coverage.

Required suites:

- Rust and TypeScript unit tests
- shared fixture/parity tests
- JSON Schema validation and generated-code drift
- D1 migration forward/upgrade tests
- HTTP/API authorization tests
- OAuth/passkey ceremony tests
- Device enrollment and key-rotation tests
- Node protocol conformance
- operation idempotency/replay tests
- offline/reconnect/reconciliation tests
- Runtime provider conformance
- workspace/Git pathological-state tests
- Adapter fixture conformance
- MCP tool/schema/policy/rate-limit tests
- Trace/redaction/retention tests
- backup/restore and upgrade tests
- end-to-end Linux tests

Use local Cloudflare development tooling for automated integration. Hardware/service-dependent live suites must report a clear skip reason and have documented commands. Do not count skipped live tests as evidence that a provider works.

Fault injection must include:

- Worker and Durable Object restart
- Device disconnect
- stale connection epoch
- duplicated and out-of-order frames
- Node crash/restart
- Agent CLI crash
- Container/VM disappearance
- journal corruption/read-only state
- disk exhaustion
- worktree conflict and external edit
- missing Git/LFS/submodule objects
- expired approval and changed operation digest
- raw log retention gap

## End-to-end acceptance scenarios

Provide reproducible scripts and documentation for each scenario.

1. Start a local Control Plane and Linux Node.
2. Enroll `sahur-pc` with a Device key and owner approval.
3. Create a Project with multiple folders/Sources and one Primary Source.
4. Add a Codex Builder Project Agent.
5. Post a normal Board Message and prove no Agent starts.
6. Post a structured `@codex-builder` Assignment.
7. Run Codex in an isolated worktree, change code, run tests and produce a Change Set.
8. Show that Agent completion alone does not advance the Baseline.
9. Review and explicitly accept the Change Set, then materialize it.
10. Disconnect Cloudflare while the Run is active; continue locally and reconcile after reconnect without duplicate execution.
11. Run a projectless Quick Command.
12. Run a projectless Quick Agent Session.
13. Run a Container operation with enforced limits.
14. Create, stop, snapshot, restore and destroy a Quick VM with Incus when prerequisites are available.
15. Exercise `full_user + never` and `full_device + never` through explicit policy, with audit evidence.
16. Invoke the same operations through MCP and prove connector ceilings/rate limits.
17. Produce Run/Skill/Instruction reports from captured evidence.
18. Back up Control Plane metadata and Device-local metadata, verify and restore them.
19. Restart the Node and recover or accurately mark every active Runtime/Run.
20. Demonstrate all supported Agent adapters with fixture conformance and opt-in live checks.

## Required final verification

Add a repository command such as `just check-all` or `./scripts/check-all.sh` and make it run the applicable commands below.

At minimum:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r typecheck
pnpm -r test
pnpm -r build
python scripts/validate_spec.py
Control Plane local integration tests
Node protocol/reconciliation integration tests
Linux Runtime provider conformance tests
MCP conformance and rate-limit tests
Linux end-to-end suite
```

Also run:

- generated file drift checks
- secret scanning
- dependency/license checks already used by the repository
- release/package smoke tests
- systemd install/start/stop/uninstall smoke tests in an isolated environment

## Pull request completion checklist

Before marking ready for review:

- rebase/merge the latest `feat/shared-domain-skeleton`
- all workstreams are integrated into this branch
- no unresolved review thread from PR `#15` is regressed
- all Linux non-visual product features in this document are implemented
- no production TODO/stub/fake provider remains
- all migrations, generated files and fixtures are committed
- all automated checks pass
- live test results and skipped prerequisites are listed accurately
- PR body contains a feature matrix and test evidence
- known limitations are factual and limited to UI, unsupported external CLI behavior, unavailable host prerequisites or excluded non-Linux platforms
- documentation covers local development, Cloudflare deployment, Node setup, Runtime setup, storage, security, recovery, backup and MCP connection
- mark the PR ready for review
- do not merge it

When a real external credential, domain, paid model account or host capability is unavailable, complete the implementation, local/fake-provider conformance and setup path; record exactly what could not be live-verified. Never invent a successful deployment or live test.