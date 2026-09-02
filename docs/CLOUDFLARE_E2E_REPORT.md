# Cloudflare remote end-to-end report

This report records privacy-safe local and remote verification for pull request
19. It contains no Cloudflare account name or ID, account email, Workers
subdomain, local username or absolute path, credential, token, private key, raw
prompt, or generated Device identifier.

## Review 5086220413 verification

- Date: 2026-09-02
- Implementation commit: `1303f4d`
- Local result: PASS
- Merge state: not merged

The accelerated idle test connects the real Rust `NodeService` and `WssClient`
through the production Worker route to a SQLite-backed `DeviceRoom`. It runs
all 36,000 100 ms service polls in the first hour, then advances the same live
socket at each ten-minute checkpoint through 24 hours. The independent
Node-only regression executes all 864,000 polls for 24 hours.

| Connected idle evidence | Measured result |
| --- | ---: |
| Actual Node application sends after 1 hour | 6 |
| Actual Node application sends after 24 hours | 144 |
| DeviceRoom application receives | 144 |
| D1 statements / binding calls / maximum parameters | 144 / 144 / 5 |
| D1 rows read / written | 72 / 72 |
| Durable Object SQL statements / rows read / rows written | 1,152 / 8,784 / 72 |
| Retained inbound / cumulative ACK rows | 6 / 1 |
| Alarm schedules / invocations / remaining alarm | 0 / 0 / none |
| New Node outbox sequence during idle window | 0 |

Outer production-handler probes also passed: the six-message Queue consumer
used 24 D1 statements, `DeviceRoom.alarm()` used 8, and
`RetryScheduler.alarm()` used 16. Binding calls matched those statement counts
and maximum parameters were 6, 2, and 3 respectively. The 24-hour empty
backstop simulation wrote no D1 or scheduler rows and created no alarm. A
quiet BoardRoom retained at most 2,048 fanout rows and converged to zero with
250-row alarm pages. ConnectorLimiter retained one compact budget row while
100 read admissions produced 300 SQL statements and 100 measured row
mutations; retained cardinality is not reported as write usage.

The current production migration was retried before any Worker deployment.
The authenticated Cloudflare API confirmed that the configured D1 resource
still exists but rejected D1 service access with authorization code `7403`.
No migration, schema, data, or Worker version was changed. Therefore the
current implementation commit was not deployed and no current-commit remote
E2E is claimed. The previous isolated remote result below remains the latest
remote evidence, and production remains on its previously verified version.

## Previous isolated remote result

- Date: 2026-09-02
- Conduit commit: `5db228c`
- Result: PASS
- Remote scenario assertions: 7 of 7 passed
- Repository CI for the commit: 9 of 9 checks passed
- Merge state at the time of the report: not merged

The tested commit was deployed to a Cloudflare Worker with remote D1, R2,
Queue, dead-letter Queue, and SQLite-backed Durable Object bindings. The public
origin and all account-specific deployment identifiers are intentionally
omitted. Production smoke checks covered `/healthz`, OAuth authorization-server
metadata, OAuth protected-resource metadata, and the Passkey setup page.

## Isolation and data handling

Remote protocol testing used a separate Worker, D1 database, R2 bucket, Queue,
and dead-letter Queue. Test records used synthetic labels and randomly generated
cryptographic identities. The harness did not read a user home directory,
Device database, repository credential, provider login, browser profile, raw
log, or paid Agent account.

The bootstrap secret, token pepper, receipt-signing key, Passkey private key,
Device private key, OAuth authorization code, access token, refresh token, and
browser cookies were never printed or added to Git. The isolated remote
resources and their synthetic records were deleted after evidence collection.
The temporary local bootstrap material and remote harness were also deleted.

The production D1 database remained in clean bootstrap state with zero Owner
principals and zero Devices after the isolated test. No synthetic E2E identity
was written to production.

## Scenario evidence

| Step | Boundary exercised | Result | Evidence retained in this report |
| --- | --- | --- | --- |
| 1 | Worker routing and public metadata | PASS | Health returned `ok`; OAuth issuer/authorization endpoint matched the configured origin; the setup page exposed the Passkey ceremony entry point. |
| 2 | Clean Owner bootstrap and login | PASS | A P-256 WebAuthn credential with `none` attestation registered against an empty D1 database; logout and a signed authentication assertion produced a fresh Owner session. |
| 3 | Standard OAuth consent and PKCE | PASS | Dynamic registration required Owner approval. The authorization request contained only standard OAuth parameters and no `connector_policy_id`. The consent form selected an active Connector Policy, preserved `state`, and exchanged the code with PKCE S256 for a resource-bound bearer token. |
| 4 | Device enrollment and Passkey step-up | PASS | An ephemeral Ed25519 Device key signed the complete enrollment transcript. The Owner inspected the pending fingerprint, completed a fresh WebAuthn assertion, approved enrollment, and the polling receipt bound the resulting Device and key. |
| 5 | Actual Worker WebSocket route | PASS | A real `wss://` upgrade traversed the outer Worker route into the Device Durable Object. `device.hello` produced `device.challenge`; the Device signed the correlated authentication transcript; the server returned `transport.accepted` for the exact Device and connection. |
| 6 | Owner API identity separation | PASS | A separately issued short-lived Owner API bearer token authenticated at the Owner status endpoint; browser cookies and Device credentials were not accepted as substitutes. |
| 7 | Durable remote state | PASS | The isolated D1 database reported all 12 migrations, one Owner, one Passkey, one active OAuth grant, one active Device, and connection epoch 1 before teardown. |

The WebAuthn steps used a browser-compatible cryptographic harness and the
deployed browser routes. They did not use a physical authenticator or a
human-operated browser. The OAuth scenario used ChatGPT-compatible standard
parameters, but did not connect a real ChatGPT account.

## Fault discovered during remote execution

The initial WebSocket attempt reached the Worker but closed fail-closed with
code 1007 before returning `device.challenge`. Remote logs showed that Ajv was
trying to compile JSON Schema with dynamic function generation while handling
the first message. Local Miniflare tests did not expose this Cloudflare runtime
boundary.

Commit `5db228c` changed the wire package to generate standalone schema and
domain-format validators during repository generation. The deployed Worker no
longer compiles validators during startup or request handling. Generated-file
drift checking now covers both validator modules and rejects an unexpected
CommonJS runtime helper. After redeployment, the same remote WebSocket scenario
completed through correlated `transport.accepted`.

## Local and CI correlation

The remote result supplements, rather than replaces, deterministic repository
evidence:

- wire schema tests: 19 passed;
- Control Plane tests: 44 passed;
- schema validation: 5 schemas, 24 examples, and 6 invalid fixtures passed;
- generated wire drift check: passed;
- Worker deployment dry run: passed;
- GitHub Actions Rust, TypeScript, specification, packaging, and validation
  checks: 9 of 9 passed.

## Not covered by this remote run

The following items remain separate opt-in or host-dependent evidence and are
not implied by this report:

- physical Passkey or platform authenticator interaction;
- a real ChatGPT, Codex, Claude, OpenCode, Pi, or Agy paid account;
- a production Linux Node process using a retained Device identity;
- live Podman or Incus/KVM provider execution;
- the unimplemented Full Device privileged helper;
- Pi or ACP production interactive approval bridging.

Restricted Native, Docker, Incus, Agent lifecycle, restart recovery, durable
dispatch faults, Board-to-Baseline integration, and reviewer isolation remain
covered by the deterministic local and CI suites described in
[`LINUX_E2E.md`](LINUX_E2E.md). A missing live prerequisite is never counted as
evidence that a capability works.

## Reproduction requirements

An operator reproducing the remote scenario must use an isolated Cloudflare
deployment, an exact HTTPS origin, independent secrets installed through
Wrangler, and a clean D1 database with all migrations applied. The operator
must retain secrets outside Git, avoid logging bearer material, verify resource
names before teardown, and delete only the isolated test resources.

Provisioning and deployment behavior is documented in
[`LINUX_OPERATIONS.md`](LINUX_OPERATIONS.md). Local protocol equivalents are in
`apps/control-plane/test/browser-bootstrap.test.ts` and the Device transport
tests. Remote account identifiers and live secrets must not be added to a
public reproduction log.
