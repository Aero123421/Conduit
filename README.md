# Conduit

Status: Linux non-visual implementation. The final dashboard UI is intentionally
outside this branch.

Conduit manages work across registered computers. A run may use a local folder, an isolated worktree, a container, or a virtual machine. Projects are optional; one-off commands, agent sessions, and VMs are supported separately.

Implemented product boundaries:

- Cloudflare control plane, typed HTTP API and remote MCP gateway
- Linux reference node
- multiple registered devices
- projects with multiple folders and device-specific locations
- session board and `@` assignment
- native, container, and VM runtime providers
- explicit access scope and approval policy, including `full_user`; `full_device`
  is rejected as unavailable until a privileged helper is implemented
- run traces for agent, instruction, and skill analysis
- MCP as an optional OAuth client of the same control-plane services

The owner can operate the product without a dashboard through `conduit`. The
Linux Node uses outbound-only Device transport, keeps canonical paths,
credentials, active process state, VM disks, workspaces and raw logs local, and
applies Device-local deny policy after control-plane admission.

Build and run the complete repository gate:

```sh
corepack pnpm install --frozen-lockfile
./scripts/check-all.sh
```

Hardware, external service and paid-agent live checks are opt-in and report
unavailable prerequisites without claiming provider support:

```sh
./scripts/e2e-linux.sh
```

Start with [`docs/LINUX_OPERATIONS.md`](docs/LINUX_OPERATIONS.md) for local
development, deployment, installation, Runtime setup, security, backup and
recovery. The sanitized live deployment evidence is recorded in
[`docs/CLOUDFLARE_E2E_REPORT.md`](docs/CLOUDFLARE_E2E_REPORT.md). Domain and
protocol design documents are under [`docs/`](docs/).
