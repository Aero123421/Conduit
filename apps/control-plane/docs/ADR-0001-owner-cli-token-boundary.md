# ADR-0001: Separate owner CLI and connector bearer credentials

Status: accepted for the Linux control-plane slice

## Context

The browser owner session, OAuth connector grant, Device key, and local node IPC identity are separate authorities. The CLI needs a non-cookie credential for versioned owner APIs, but accepting an MCP OAuth token as owner authority would let a connector raise its own ceiling.

## Decision

A successful user-verifying passkey login may explicitly request an eight-hour owner CLI token. The plaintext is returned once with the `conduit_owner_` prefix; only a keyed verifier is stored in D1. Versioned owner APIs recognize that prefix before OAuth authentication and bind it to the owner principal. `/mcp` uses only OAuth grant tokens and therefore rejects owner CLI tokens. Policy broadening, passkey changes, Device enrollment approval, and equivalent fresh-authentication actions continue to require a browser session with a recent passkey ceremony.

Owner CLI tokens are independently revocable records. They are not browser cookies, OAuth grants, Device credentials, or Agent-provider credentials.

## Consequences

CLI automation can read and perform idempotent owner-authorized API mutations without CSRF because it does not use ambient cookies. It cannot perform fresh-passkey-only authority broadening. Connector scope and policy checks remain mandatory for OAuth tokens regardless of the requested API path.
