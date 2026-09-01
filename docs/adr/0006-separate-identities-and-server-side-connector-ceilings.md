# ADR 0006: Separate identities and server-side connector ceilings

- Status: Proposed
- Date: 2026-09-01

## Context

Conduit accepts requests from a browser dashboard, local CLI, remote MCP clients, and enrolled devices. It can start native commands, agents, containers, and VMs with access up to full device administration and no per-operation approval.

Using one API token for every path would make revocation, rate limiting, audit attribution, and least-privilege grants unreliable. Encoding the complete authorization policy into long-lived OAuth tokens would also make policy changes slow to take effect.

Devices need to reconnect without storing a reusable control-plane bearer token. MCP clients need current OAuth interoperability, including Protected Resource Metadata, PKCE, Client ID Metadata Documents, pre-registration, and compatibility with clients that still depend on Dynamic Client Registration.

## Decision

### Owner

The first release has one human owner authenticated with WebAuthn passkeys. Browser sessions use opaque secure cookies. Sensitive configuration changes require a fresh passkey ceremony.

Bootstrap uses a one-time high-entropy secret. Recovery uses one-time high-entropy recovery codes and a restricted recovery session.

### Devices

Each device creates an Ed25519 key pair locally. Enrollment binds the public key to an owner-approved device record. Outbound WSS connections use a signed challenge and a monotonically increasing connection epoch. Devices do not authenticate with OAuth access tokens.

### MCP clients

The MCP endpoint is an OAuth protected resource. Authorization Code with PKCE S256 is required. Client registration follows this order:

1. Client ID Metadata Document
2. pre-registration
3. owner-controlled Dynamic Client Registration compatibility mode

DCR registration does not create an authorization grant.

OAuth authorization requests remain client-portable and contain standard parameters only. A client does not name a Connector Policy. The owner selects one of the active policies already bound to that client on the browser consent page. Browser sign-in and stale-session step-up use WebAuthn on the authorization-server origin, and the final consent is a same-origin HTML form protected by a session-bound form CSRF token.

### Connector policy

OAuth scopes remain coarse. Each grant references a mutable, server-side connector policy containing:

- allowed devices and projects
- allowed operation families and runtime providers
- maximum access scope
- most permissive approval mode
- raw log and artifact permissions
- exact rate-limit profile

Every effectful request resolves the current grant and connector-policy revision. Lowering or revoking a policy does not wait for access-token expiry.

Object authorization resolves the target's stored Project and Device relationships before evaluating that policy. Caller-supplied Project identifiers are inputs to be checked, never evidence of ownership. Session, Source Location, Assignment, Run, Task, Artifact, trace, evidence, approval, and operation relationships must converge on one authority boundary or fail closed. MCP Agent starts that name a Project Agent bind the stored adapter and role; a stored Reviewer role forces read-only access.

### Full access

`full_user`, `full_device`, and `never` approval are valid settings. An MCP client may use them only when the owner explicitly grants a matching connector ceiling and the selected device and runtime support them.

The MCP client cannot broaden its own connector policy. Enabling host elevation remains a local device setup operation.

### Rate limiting

Cloudflare edge limits provide coarse abuse protection. A durable application limiter enforces exact grant budgets and concurrency. Each device applies final process, runtime, memory, storage, and duration limits.

### Credentials

WebAuthn credentials, browser cookies, OAuth tokens, device keys, local IPC identity, and agent-provider credentials remain separate. They are not converted into one another.

## Rejected alternatives

### One owner API token for dashboard, MCP, and devices

Rejected because theft gives unrelated authority, clients cannot be revoked independently, and attribution is weak.

### OAuth bearer tokens for device connections

Rejected because a copied token can impersonate a device. The device already has a durable asymmetric identity and can prove possession of its private key.

### Put all authorization details in a JWT

Rejected because device, project, and rate-limit policy changes must take effect immediately. Tokens carry a grant reference and coarse scopes; current policy stays server-side.

### Unrestricted Dynamic Client Registration

Rejected because registration metadata and redirect URIs are untrusted input. DCR remains an owner-confirmed compatibility path.

### Ban full device access through MCP

Rejected. Full access and no-approval operation are required product modes. They are controlled by explicit owner grants, connector ceilings, device setup, and audit rather than a hidden product-wide denial.

### Use Cloudflare Access as the only identity system

Rejected for the first release. Conduit needs passkey-based owner step-up, MCP OAuth grants, device enrollment, and connector-specific ceilings that are independent of an external identity provider. Access may be added as an outer deployment control.

## Consequences

- Authentication tables and protocol messages carry explicit actor, client, device, grant, and policy identifiers.
- Device enrollment and MCP authorization are separate user flows.
- The control plane performs a current-policy lookup for effectful MCP calls.
- OAuth clients remain interoperable without Conduit-specific authorization parameters; policy choice belongs to the owner consent surface.
- Object-level Connector decisions require a server-side relationship lookup, including cross-reference consistency checks for creates and updates.
- A stable public origin and WebAuthn relying-party ID must be selected before owner setup.
- Recovery must be tested as a restricted state, not an administrative bypass.
- DCR interoperability remains testable without treating arbitrary registered clients as trusted.
- Full-access connectors require a clear dashboard warning and fresh passkey authentication.
- Device revocation cannot force an offline computer to stop already admitted local work; the UI must state this limitation.

## Contract

- `docs/AUTHORIZATION.md`
- `spec/schemas/auth-v1.schema.json`
- `spec/examples/auth/`
