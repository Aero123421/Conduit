#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
conduit_temp="$(mktemp -d -t conduit-package-smoke-XXXXXXXX)"
conduit_node_pid=""
conduit_cleanup() {
  if [[ -n "$conduit_node_pid" ]] && kill -0 "$conduit_node_pid" 2>/dev/null; then
    kill -TERM "$conduit_node_pid" 2>/dev/null || true
    wait "$conduit_node_pid" 2>/dev/null || true
  fi
  rm -rf "$conduit_temp"
}
trap conduit_cleanup EXIT

cargo build --locked --release --bin conduit --bin conduit-node

conduit_home="$conduit_temp/home"
mkdir -p "$conduit_home"
HOME="$conduit_home" \
XDG_CONFIG_HOME="$conduit_home/.config" \
XDG_STATE_HOME="$conduit_home/.local/state" \
XDG_DATA_HOME="$conduit_home/.local/share" \
XDG_CACHE_HOME="$conduit_home/.cache" \
DESTDIR="$conduit_temp/root" \
  "$conduit_root/installers/install.sh" --prefix /usr/local

test -x "$conduit_temp/root/usr/local/bin/conduit"
test -x "$conduit_temp/root/usr/local/bin/conduit-node"
test -f "$conduit_temp/root$conduit_home/.config/systemd/user/conduit-node.service"
grep -q 'ExecStart=/usr/local/bin/conduit-node serve' \
  "$conduit_temp/root$conduit_home/.config/systemd/user/conduit-node.service"

# Exercise the installed artifacts through a real Node start, owner-only IPC
# health request, and stop. This is independent of a host user-systemd session
# while validating the exact ExecStart binary and XDG custody used by the unit.
conduit_runtime="$conduit_temp/runtime"
conduit_data="$conduit_temp/data"
conduit_log="$conduit_temp/conduit-node.log"
install -d -m 0700 "$conduit_runtime" "$conduit_data"
XDG_RUNTIME_DIR="$conduit_runtime" \
  "$conduit_temp/root/usr/local/bin/conduit-node" serve \
  --data-dir "$conduit_data" \
  --socket "$conduit_runtime/conduit/node.sock" >"$conduit_log" 2>&1 &
conduit_node_pid="$!"
for _ in $(seq 1 100); do
  [[ -S "$conduit_runtime/conduit/node.sock" ]] && break
  if ! kill -0 "$conduit_node_pid" 2>/dev/null; then
    echo "installed conduit-node exited before IPC became ready" >&2
    sed -n '1,120p' "$conduit_log" >&2
    exit 1
  fi
  sleep 0.02
done
test -S "$conduit_runtime/conduit/node.sock"
XDG_RUNTIME_DIR="$conduit_runtime" \
  "$conduit_temp/root/usr/local/bin/conduit" --output json device doctor >/dev/null
kill -TERM "$conduit_node_pid"
if wait "$conduit_node_pid"; then
  :
else
  conduit_status="$?"
  test "$conduit_status" -eq 143
fi
conduit_node_pid=""

HOME="$conduit_home" \
XDG_CONFIG_HOME="$conduit_home/.config" \
DESTDIR="$conduit_temp/root" \
  "$conduit_root/installers/uninstall.sh" --prefix /usr/local

test ! -e "$conduit_temp/root/usr/local/bin/conduit"
test -d "$conduit_temp/root$conduit_home/.local/state/conduit"
