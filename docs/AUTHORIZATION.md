# Authentication and authorization

## Fixed identities

Conduit does not reuse one credential across browser login, MCP, devices, local IPC, and agent providers.

| Identity | Credential | Accepted by |
|---|---|---|
| Human owner | WebAuthn passkey | control-plane browser authentication and fresh step-up |
| Browser session | opaque secure cookie | dashboard HTTP API |
| OAuth client | registered client identity | authorization and token endpoints |
| OAuth grant | access and refresh token family | MCP protected resource |
| Device | Ed25519 device key | outbound device transport |
| Local IPC principal | operating-system peer credentials | local node socket |
| Agent provider account | provider-specific credential | Codex, Claude Code, OpenCode, Pi, Agy, or another adapter |

An OAuth token is not a device credential. A browser cookie is not accepted by the MCP endpoint. A device key cannot authorize dashboard actions. Agent-provider credentials remain on the device.

Every remote operation records both the human principal and the calling client. In the single-owner release these usually resolve to one owner, but they remain separate fields.

## Canonical origin

A deployment has one configured public origin, OAuth issuer, and WebAuthn relying-party ID.

```text
public_origin   https://conduit.example.com
oauth_issuer    https://conduit.example.com
webauthn_rp_id  conduit.example.com
```

Passkeys are scoped to the relying-party ID. Changing the public domain is a migration, not a cosmetic setting. The owner must register a passkey valid for the new relying-party ID before the old origin is retired.

## Owner bootstrap

The first deployment uses a one-time bootstrap secret.

1. The deploy command generates at least 256 bits of random material locally.
2. Only a verifier is installed in the Worker environment. The plaintext secret is shown once and is not placed in a URL.
3. `/setup` is available only while no owner exists and the bootstrap verifier is active.
4. The user enters the bootstrap secret and completes a WebAuthn registration with user verification required.
5. The control plane creates the owner principal and first passkey record.
6. The bootstrap verifier is burned. Replaying the bootstrap secret is rejected.
7. Recovery codes are generated and shown once.

The first passkey ceremony and bootstrap consumption are one transaction. A failed passkey registration does not consume the bootstrap secret.

The setup screen recommends registering a second passkey. One passkey is sufficient for the first release.

## Passkeys

Passkey records contain only public verification material and metadata:

- credential ID
- public key
- relying-party ID
- transports, when supplied
- authenticator attachment, when supplied
- sign counter observation
- created and last-used times
- user-chosen label
- active or revoked state

Authentication and registration challenges are one-time, origin-bound, and expire after five minutes. User verification is required.

A zero or non-increasing signature counter is not by itself treated as cloned-credential proof because synchronized passkeys may not provide a useful counter. It is retained as an observation.

Adding or removing a passkey requires a fresh passkey authentication. The final active passkey cannot be removed unless a replacement has already been registered or a recovery session is active.

## Browser sessions

The browser receives a random opaque session cookie. The database stores a verifier, not the cookie value.

Required cookie properties:

- `Secure`
- `HttpOnly`
- `SameSite=Lax` or stricter
- explicit expiry
- rotation after authentication and privilege changes

The default maximum session age is seven days with a 24-hour idle limit. Deployments may shorten both values.

State-changing browser requests require origin validation and a CSRF token. A valid cookie alone is not accepted from an untrusted origin.

A session records:

- owner principal
- session ID
- authentication time
- last activity
- whether user verification was present
- fresh-authentication time
- expiry
- revocation state

Sensitive settings require user verification within the last five minutes. Reopening the dashboard with an old session is not fresh authentication.

## Recovery

Bootstrap produces multiple one-time high-entropy recovery codes. Only keyed hashes are stored. Recovery codes are not OAuth bearer tokens and are not accepted by ordinary APIs.

A valid recovery code creates a restricted recovery session. That session may only:

- register a new passkey
- revoke existing browser sessions
- revoke or require reauthorization of OAuth grants
- generate replacement recovery codes
- view and revoke devices

It cannot run commands, start agents, read project data, or change device policy.

Completing recovery:

1. consumes the used code
2. requires registration of a new passkey
3. revokes existing browser sessions
4. revokes refresh-token families and marks MCP grants for reauthorization by default
5. generates replacement recovery codes

Device identities are not silently deleted during owner recovery. They are listed for explicit review.

If every passkey and recovery code is lost, recovery requires operator access to the Cloudflare deployment and deliberate replacement of the bootstrap/recovery verifier. There is no email fallback in the single-owner release.

## Fresh-authentication operations

The following changes require a fresh passkey ceremony:

- add or remove a passkey
- generate new recovery codes
- approve or revoke a device
- create an MCP grant
- broaden an MCP grant's device, project, operation, runtime, log, or artifact access
- set a connector ceiling to `full_user` or `full_device`
- permit `never` approval through an MCP connector
- permit raw log or raw content access
- enable or change remote elevation policy
- export credentials or encrypted secret material
- rotate control-plane signing keys

Narrowing or revoking a grant does not require fresh authentication, but still requires a valid owner session and CSRF protection.

## Device enrollment

A device creates its identity locally before contacting the control plane.

1. `conduit-node` generates an Ed25519 key pair.
2. The private key is stored in the operating-system credential store or a permission-restricted node state directory.
3. The node sends a bounded enrollment request containing the public key, proof of possession, protocol version, hostname label, OS, architecture, and node version.
4. The control plane returns a high-entropy device code, a short user code, a verification URI, and an expiry.
5. The node displays the user code and public-key fingerprint.
6. The owner opens the verification URI, performs fresh passkey authentication, reviews the device claims and fingerprint, and approves or denies the request.
7. The node polls using the device code. Approval returns the assigned device ID, key ID, control-plane signing public key, and an enrollment receipt.
8. The pending enrollment record becomes terminal and cannot be reused.

Enrollment expires after ten minutes by default. Polling and request creation are rate-limited. Claimed device labels are display data and do not establish authority.

The enrollment states are:

```text
pending_owner
  ├─ approved
  │    └─ completed
  ├─ denied
  ├─ expired
  └─ cancelled
```

Only `completed` devices may establish the device transport.

## Device connection authentication

The device transport uses outbound WSS. It does not use a long-lived bearer token.

A connection starts with a challenge-response exchange:

1. The node sends `device_id`, `key_id`, protocol version, capabilities, and a random client nonce.
2. The control plane returns a random server nonce, connection ID, server time, and challenge expiry.
3. The node signs the versioned transcript with its Ed25519 private key.
4. The control plane verifies the signature against the active device key.
5. The accepted connection receives a monotonically increasing connection epoch.
6. Older connections for the device are fenced and cannot publish events or receive work.

The signed transcript binds at least:

```text
conduit.device-auth.v1
public origin
connection ID
device ID
key ID
client nonce
server nonce
protocol version
server time
```

Challenge expiry is evaluated using control-plane time. Device clock skew is not used to decide whether the challenge is fresh.

Application messages bind the device ID, connection epoch, message ID, correlation ID, and monotonic sequence. Admission receipts, reconciliation summaries, and terminal receipts are signed or committed with the device key as defined by the node-transport protocol.

## Device-key rotation

Routine rotation is initiated on the device:

1. the node generates a new key
2. the rotation request is signed by both the old and new keys
3. the control plane verifies that the request came from the current device connection
4. the new key becomes active
5. the old key remains valid only for a bounded handover period
6. the rotation is recorded as a security event

A device that has lost its current private key must be re-enrolled. The owner may revoke a device and create a replacement enrollment.

## Device revocation

Device revocation requires fresh owner authentication.

Revocation immediately:

- marks all device keys revoked
- fences active device connections
- rejects new work and reconciliation messages
- prevents new approvals from targeting the device
- records a security event

If the device is online, the owner may additionally request that Conduit-managed runs stop before the connection closes. The UI distinguishes:

- revoke remote access and leave local work alone
- revoke remote access and request managed-run termination

An offline device cannot be forced to stop. Already admitted local work may continue under local policy. Its later results are not accepted until the device is explicitly restored or re-enrolled.

## Local IPC

Local CLI and desktop components connect to `conduit-node` through an operating-system local transport.

The node authenticates the peer using operating-system credentials. A same-user local process is not treated as proof that a human is present.

Local IPC may start work allowed by local policy. Installing elevation support, changing device-wide policy, exporting credentials, or enrolling the device requires an explicit local setup action or owner authorization.

## MCP protected resource

The remote MCP endpoint is a separate OAuth protected resource.

```text
resource  https://conduit.example.com/mcp
issuer    https://conduit.example.com
```

The MCP endpoint publishes OAuth Protected Resource Metadata. The authorization server publishes OAuth Authorization Server Metadata. Access tokens are audience-bound to the MCP resource.

The supported authorization flow is Authorization Code with PKCE S256. The implicit grant and resource-owner password grant are not supported.

The authorization request contains only standard OAuth and protected-resource parameters. It does not contain a `connector_policy_id` or another Conduit authority selector. After browser sign-in, Conduit lists the active Connector Policies already bound to the requesting client and owner. The owner selects one during consent, and the resulting grant stores its exact ID and revision.

The consent surface is usable in a normal WebAuthn-capable browser. A missing owner session redirects to browser passkey sign-in. A session older than the fresh-authentication window performs Passkey step-up in the same origin before enabling approval. Consent is submitted as an ordinary HTML form with a same-origin, session-bound CSRF value; it does not depend on a custom request header that a form cannot send.

Access tokens are short-lived. Refresh tokens rotate on use, and reuse of an old refresh token revokes the token family. The authorization server exposes token revocation. Lowering or revoking a grant takes effect independently of access-token expiry because each effectful call resolves the current server-side grant revision.

DPoP may be enabled for clients that support it. It is not required globally until ChatGPT, Claude, Perplexity, and other supported clients can all use it reliably.

## MCP client registration

Conduit supports the current MCP registration order:

1. Client ID Metadata Document
2. pre-registered client
3. Dynamic Client Registration compatibility mode

First-party Conduit clients are pre-registered. Client ID Metadata Documents are accepted after HTTPS validation and metadata checks.

Dynamic Client Registration is controlled by deployment policy:

- `disabled`
- `owner_confirmed`
- `known_clients`

The first release defaults to `owner_confirmed` to support clients that still depend on DCR. A DCR record is not an authorization grant. The owner still reviews the client name, client identifier, redirect URIs, requested scopes, and Conduit connector ceiling.

Redirect URIs are exact-match values. A client metadata change that alters redirect URIs, token endpoint authentication method, or client identity creates a new registration or requires owner confirmation. Public clients do not receive a reusable client secret merely because DCR was used.

## OAuth scopes

OAuth scopes are coarse protocol permissions. Device, project, runtime, access-scope, approval, rate-limit, and retention restrictions are stored in the Conduit connector policy.

Initial scopes:

| Scope | Allows |
|---|---|
| `conduit.read` | list and inspect allowed projects, sessions, devices, runs, and summaries |
| `conduit.board.write` | create board messages and structured assignment proposals |
| `conduit.run.start` | start agent and command runs within the connector ceiling |
| `conduit.run.control` | stop, pause, resume, and send follow-up input where supported |
| `conduit.runtime.manage` | create or control allowed containers and VMs |
| `conduit.logs.read` | read normalized and summarized logs |
| `conduit.logs.raw` | read raw command or provider logs when separately allowed |
| `conduit.approval.resolve` | resolve typed approval requests within the connector ceiling |
| `conduit.config.write` | change non-security configuration allowed by policy |
| `conduit.admin` | owner-level administrative API; not granted to ordinary MCP clients |

A token scope does not imply access to every device or project.

## OAuth grants and connector ceilings

An OAuth grant joins:

- owner principal
- OAuth client registration
- granted OAuth scopes
- connector policy ID and revision
- token family
- created, last-used, and expiry times
- active, paused, reauthorization-required, or revoked state

The connector policy limits:

- devices
- projects
- operation families
- runtime providers
- maximum access scope
- most permissive approval policy
- raw log and raw content access
- artifact upload and export
- rate-limit profile
- maximum run and command duration

Access scopes are ordered:

```text
read_only
selected_sources
project_full
full_user
full_device
```

Approval modes are ordered from most restrictive to most permissive:

```text
always
outside_scope
risk_classes
never
```

A run may choose a narrower access scope or a more restrictive approval mode than its connector ceiling. It cannot choose a broader or more permissive value.

`custom` access policies are admitted only after the server proves that each requested capability is a subset of the connector, project, and device policies. They are not ranked by name.

## Full access

`full_user`, `full_device`, and `never` are valid settings.

A remote MCP client can use them only when all of the following are true:

1. the owner granted the OAuth scope needed for the operation
2. the connector policy permits the target device and operation
3. the connector ceiling permits the requested access scope and approval mode
4. the project and project-agent policy permits it
5. the assignment requests it
6. the device policy permits it
7. the runtime provider supports it
8. the operating system or configured elevation helper can perform it

The MCP client cannot raise its own ceiling. Granting a connector `full_device` or `never` requires fresh passkey authentication in the dashboard.

Enabling host elevation on a device is a separate local setup step. A remote grant cannot install or enable the elevation helper by itself.

## Effective authorization

The effective authority for an operation is the intersection of:

1. owner principal state
2. browser or OAuth client state
3. OAuth scope
4. current connector-policy revision
5. project-agent and assignment settings
6. project policy
7. device policy
8. runtime-provider capabilities
9. operating-system permissions
10. typed approval receipt, when required

The authorization decision binds the exact target and revision. A later request cannot reuse an approval after the source location, runtime, arguments, operation digest, or controller epoch changes.

For MCP object operations, the control plane derives Project and Device authority from stored relationships before applying the Connector Policy. It does not accept a caller-supplied `projectId` as proof of ownership. The binding follows the stored graph, including Session to Project, Location to Source to Project, and Assignment, Run, Task, Artifact, trace, evidence, and operation references to their actual Project. Multiple denormalized references must resolve to the same Project and Device or the request fails closed.

MCP create operations resolve every referenced parent before policy admission. A supplied Project that disagrees with a Session, Assignment, Run, Source Location, or Project Agent is rejected before the record or operation is persisted. When an Agent Run names a Project Agent, its adapter and role are replaced with the stored Project Agent values. A stored `reviewer` role forces `read_only` access; a caller cannot promote or demote the role in request arguments.

Board text is never parsed as an approval receipt.

## Runtime approvals

When an approval policy requires human confirmation, the control plane creates a typed approval request containing:

- requester principal and OAuth client
- target device and run
- operation type
- normalized arguments
- source, location, runtime, and policy revisions
- payload digest
- expiry
- proposed reuse scope

The owner resolves the request through a fresh or sufficiently recent passkey-authenticated dashboard session. A valid receipt is one-time unless a bounded retry or session scope is explicitly approved.

When the admitted approval mode is `never`, Conduit does not create approval requests for actions already inside the effective authority. Unsupported platform capabilities and lower-layer denials remain errors; they are not hidden approval prompts.

## Rate limiting

Rate limiting has three layers.

### Edge

Cloudflare edge limits reject obvious abuse and oversized requests. They are not the source of truth for exact quotas.

### Control plane

A durable limiter keyed by OAuth grant enforces:

- request windows by operation family
- weighted operation budget
- concurrent commands
- concurrent agent runs
- runtime or VM starts per window
- maximum command duration
- maximum run duration
- response bytes
- normalized log bytes
- raw log bytes per day
- artifact upload bytes

Side-effecting retries with the same operation ID, idempotency key, and payload digest are charged once. A different digest under the same idempotency key is rejected before admission.

### Device

The device enforces final limits for processes, agents, containers, VMs, CPU, RAM, GPU, storage, local log retention, and runtime duration. The control plane cannot override these limits.

Rate-limit failures return a stable limit class and bounded retry time. They do not expose private quota state from other clients.

Pausing or revoking a connector takes effect immediately for new work. Already admitted work follows the run and device cancellation policy.

## Stored data

D1 may store:

- owner principal
- passkey public records
- hashed recovery records
- hashed browser-session verifiers
- OAuth client metadata and metadata digest
- OAuth grants and connector-policy revisions
- hashed or encrypted token-family records as required by the OAuth provider
- device public keys and status
- pending enrollment metadata
- security audit events

Worker secrets hold server-side peppers, signing keys, and bootstrap verifiers.

Devices store:

- device private keys
- agent-provider credentials
- local elevation configuration
- local IPC state
- runtime and raw-log data

Secret values are not written to board messages, normal traces, D1 metadata rows, or MCP tool results.

## Security events

The control plane records bounded events for:

- owner bootstrap
- passkey registration, authentication, and revocation
- recovery-code use
- browser-session creation and revocation
- OAuth client registration and metadata changes
- OAuth grant creation, policy changes, pause, reauthorization, and revocation
- refresh-token reuse detection
- device enrollment, key rotation, connection fencing, and revocation
- fresh-authentication protected changes
- rate-limit and authorization denials by stable reason code

Tokens, recovery codes, passkey assertions, device private material, raw prompts, and agent-provider credentials are not logged.

## Stable denial reasons

Initial authorization errors use stable codes:

```text
authentication_required
fresh_authentication_required
csrf_failed
client_not_registered
client_metadata_changed
grant_required
grant_paused
grant_revoked
grant_reauthorization_required
scope_insufficient
connector_ceiling_exceeded
project_not_allowed
device_not_allowed
device_offline
device_revoked
device_key_invalid
runtime_not_allowed
operation_not_allowed
approval_required
approval_expired
approval_digest_mismatch
rate_limited
resource_limit
platform_capability_unavailable
```

Provider or parser text is not copied into public authorization errors.

## First-release boundary

Required for the Linux native vertical slice:

- single-owner passkey bootstrap
- recovery codes
- owner browser sessions and fresh step-up
- device enrollment and Ed25519 challenge authentication
- device revoke and key rotation
- MCP Authorization Code with PKCE
- Protected Resource Metadata and Authorization Server Metadata
- pre-registration, Client ID Metadata Documents, and owner-confirmed DCR
- OAuth grants with server-side connector policies
- `full_user`, `full_device`, and `never` connector ceilings
- exact application rate limits
- security-event audit

Deferred:

- multiple human users and organizations
- external enterprise identity providers
- service accounts and client-credentials grants
- mandatory DPoP
- SCIM and organization policy
- cross-owner project sharing

## References

- MCP authorization: <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>
- OAuth Protected Resource Metadata: <https://www.rfc-editor.org/rfc/rfc9728>
- OAuth Authorization Server Metadata: <https://www.rfc-editor.org/rfc/rfc8414>
- OAuth security best current practice: <https://www.rfc-editor.org/rfc/rfc9700>
- OAuth device authorization grant: <https://www.rfc-editor.org/rfc/rfc8628>
- OAuth token revocation: <https://www.rfc-editor.org/rfc/rfc7009>
- DPoP: <https://www.rfc-editor.org/rfc/rfc9449>
- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>
- Cloudflare MCP authorization: <https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/>
