# Conduit

Status: design.

Conduit manages work across registered computers. A run may use a local folder, an isolated worktree, a container, or a virtual machine. Projects are optional; one-off commands, agent sessions, and VMs are supported separately.

Initial scope:

- Cloudflare control plane and browser dashboard
- Linux reference node
- multiple registered devices
- projects with multiple folders and device-specific locations
- session board and `@` assignment
- native, container, and VM runtime providers
- explicit access scope and approval policy, including full access
- run traces for agent, instruction, and skill analysis
- MCP as an optional client of the same control-plane API

Design documents are under [`docs/`](docs/).
