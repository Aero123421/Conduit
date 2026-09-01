# ADR 0004: Access scope and approval policy are independent

- Status: Accepted
- Date: 2026-09-01

## Decision

Every run has an Access Scope and an Approval Policy. They are evaluated separately.

Access presets include read only, selected sources, project full access, full user access, full device access, and custom. Approval presets include always, outside scope, selected risk classes, and never.

Full user or full device access with `never` approval is a supported explicit configuration. The effective authority remains bounded by actor/client authorization, connector ceiling, device policy, runtime capability, and operating-system permissions.

Every immutable operation envelope carries `requiredApprovalRiskClasses`. For an OAuth Connector, the Control Plane copies this bounded, unique list from the exact Connector Policy revision bound to the grant. An API or MCP caller cannot provide or override the field. The list is included in the operation commitment, durable operation journal, and Device delivery payload.

The owner first-party policy snapshots an empty list for approval modes other than `risk_classes`. If `risk_classes` is selected and the authoritative list is empty, the Control Plane snapshots all defined risk classes; an empty configuration must not silently turn that mode into `never`. A Connector's non-empty required list is retained for every approval mode, including `never`, because a requested mode cannot remove a grant-bound minimum approval requirement.

## Reasons

- a VM can safely grant root inside the guest without granting host access
- a user may want broad technical access but confirmation before external effects
- a trusted local or MCP workflow may require full access without repeated prompts
- combining access and approval into one “safe/full” switch hides what is actually permitted
- provider sandboxes and human approval answer different questions

## Consequences

- the UI always displays both settings
- a connector can impose a maximum scope even when a project agent has broader defaults
- the device remains the final local enforcement point
- there is no undocumented product-wide denial after full access and no approvals are explicitly configured
- unavailable elevation or provider capability is reported as unavailable, not silently simulated
- approval receipts bind one exact operation or explicit bounded reuse scope
- operation retries retain the exact policy revision and required-risk snapshot that was committed at admission
- changing a Connector Policy affects newly authorized operations and requires grant reauthorization; it does not rewrite existing operation envelopes

## Rejected alternatives

### Full access always means no approvals

Rejected because users may need full filesystem or command reach while still approving publication, secrets, deployment, or destructive effects.

### Never permit host full access

Rejected because direct operation of owned machines is a required use case and already exists in the predecessor workflow.

### A chat reply counts as approval

Rejected because message text does not bind an exact operation, target, arguments, expiry, or approver identity.

### Cloud policy can override local deny

Rejected because a compromised or stale control plane must not expand device authority.
