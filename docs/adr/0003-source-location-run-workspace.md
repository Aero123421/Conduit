# ADR 0003: Logical sources, device locations, and per-run workspaces

- Status: Accepted
- Date: 2026-09-01

## Decision

A Project contains logical Sources. Each Device can register a Location for a Source. Canonical paths remain device-local.

A Run executes on one Device and creates a Run Workspace from selected Locations. Supported workspace modes are direct, Git worktree, managed copy, and read only.

A Collaboration Session may retain an accepted baseline of source revisions. Runs produce proposed Change Sets. The baseline changes only through an explicit acceptance or configured direct-mode rule.

## Reasons

- one Git repository may exist on several computers at different paths
- projects can include multiple repositories and normal folders
- native direct editing and isolated cloud-agent-style work both need first-class support
- VMs do not prevent source conflicts when they mount the same host folder
- reviewers and implementers require different workspace permissions
- multi-source results need one recorded change set rather than an invented cross-repository commit

## Consequences

- one Run cannot transparently edit sources on several devices
- missing sources require explicit clone, transfer, or materialization
- non-Git folders are not automatically identified as the same source
- direct mode has weaker rollback and concurrency guarantees and must be shown as such
- worktree/managed-copy paths live in device-managed storage
- a VM or container receives the Run Workspace instead of an arbitrary host path by default

## Rejected alternatives

### Store absolute project paths in Cloudflare as source identity

Rejected because paths are device-specific, leak local details, and do not identify repository copies across devices.

### Project equals one folder

Rejected because the intended workflows include multiple repositories, reference folders, and projectless work.

### One mutable Session folder shared by every agent

Rejected because parallel and reviewer runs would race or overwrite each other. The session stores an accepted logical baseline, while each writer receives its own workspace.

### Always isolate changes

Rejected because direct use of an ordinary personal-computer folder and explicit full-access operation are required product paths.
