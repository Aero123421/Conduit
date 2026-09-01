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

Docker and Podman reserve Runtime identity and the spec in a Device-owned record
before container creation. Start maps the bounded LaunchPlan executable, argv,
cwd, and environment directly to the container main process without a shell.
The deterministic container name, provider container ID, and LaunchPlan digest
form the inspected process identity. Provider logs are bounded and copied into a
Device-owned, mode-0600 collection before ordinary destruction. The adapters
support inspect, stop/kill, pause/resume, snapshot, image archive/import restore,
destroy, timeout enforcement, and non-replaying reconciliation. Resource and
network flags and workspace mounts are explicit; restricted or explicit-LAN
networking is rejected until an enforcement adapter exists. No host management
socket or entire home directory can enter through workspace attachments.

Incus uses KVM VM objects with Conduit metadata. Its inspected object lifecycle,
stop/force-stop, pause/resume, stopped-VM export/archive, import/restore,
collection gating, destroy, and restart reconciliation use typed CLI arguments.
Prepare and guest LaunchPlan start remain unavailable unless a versioned guest
execution identity contract is added; an `incus exec` client process alone is
not durable proof of the guest process identity. Snapshot digest custody and VM
agent-output collection likewise remain unavailable. Incus does not create
storage pools, repartition disks, or alter global networking.

Provider methods report unavailable when binaries, services, images, `/dev/kvm`,
guest execution identity, requested network enforcement, or required isolation
are absent. They do not pull images implicitly or fall back to a weaker Provider.
