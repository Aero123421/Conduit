# Linux packages

The ordinary Node package is user-owned and uses
`packaging/systemd/conduit-node.service`. Native host Full Device is a separate
root trust boundary:

- `conduit-privileged-helper@.socket` owns one `SOCK_SEQPACKET` endpoint per UID;
- `conduit-privileged-helper@.service` runs the networkless root helper;
- `conduit-privileged-helper` validates authority and owns the durable journal;
- `conduit-privileged-exec` is the fixed worker used by typed transient units.

The root package scripts must be invoked from root-owned staging. Installation
never creates authority. Only the installed helper admin interface generates
keys or changes root policy. Updates perform read-only compatibility checks
before and after atomic replacement and retain rollback evidence. Uninstall
refuses active custody and preserves keys/journal unless a separately confirmed
purge is requested.

`DESTDIR=/absolute/stage installers/install-privileged.sh` is for package
assembly and tests. It performs no live systemd action. See
`docs/LINUX_OPERATIONS.md` and `docs/LINUX_E2E.md` for operator and live-test
contracts.
