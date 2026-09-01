# conduit-runtime

Typed Linux Runtime Provider implementations.

Native launches exact argv without a shell reconstruction, supports pipes and
PTYs, creates a process group/session, spools output, applies timeouts, signals
the process tree, and reconciles PID plus `/proc` birth identity. Its durable
supervisor records distinguish running, lost, uncertain, and identity-conflict
outcomes after a Node restart.

Restricted Native performs live bubblewrap and systemd user-scope probes. It
applies the mechanisms to the actual launch when selected; missing required
controls fail admission. Kernel Landlock presence is reported as support, not
as effective enforcement, because this implementation does not yet apply a
Landlock ruleset.

Docker and Podman use fixed typed command construction, explicit resource and
network flags, explicit workspace mounts, and Conduit identity labels. No host
management socket can enter through the workspace attachment allowlist.

Incus uses KVM VM objects with Conduit metadata and supports prepare, guest
liveness start, inspect, stop/force-stop, pause/resume, snapshot, export/archive,
import/restore, collection gating, destroy, and restart reconciliation. It does
not create storage pools, repartition disks, or alter global networking.

Provider methods report unavailable when binaries, services, `/dev/kvm`, guest
exec, or required isolation are absent. They do not fall back to a weaker
Provider.
