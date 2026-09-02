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
  if [[ -n "${CONDUIT_TEST_SERVICE_PID:-}" && -f "${CONDUIT_TEST_SERVICE_PID:-}" ]]; then
    conduit_service_pid="$(<"$CONDUIT_TEST_SERVICE_PID")"
    kill -TERM "$conduit_service_pid" 2>/dev/null || true
  fi
  rm -rf -- "$conduit_temp"
}
trap conduit_cleanup EXIT

cargo build --locked --release --bin conduit --bin conduit-node

# Exercise the real installed artifacts without depending on host user systemd.
conduit_home="$conduit_temp/artifact-home"
conduit_stage="$conduit_temp/artifact-root"
mkdir -p "$conduit_home"
HOME="$conduit_home" \
XDG_CONFIG_HOME="$conduit_home/.config" \
XDG_STATE_HOME="$conduit_home/.local/state" \
XDG_DATA_HOME="$conduit_home/.local/share" \
XDG_CACHE_HOME="$conduit_home/.cache" \
XDG_RUNTIME_DIR="$conduit_home/runtime" \
DESTDIR="$conduit_stage" \
  "$conduit_root/installers/install.sh" --prefix /usr/local

conduit_installed_bindir="$conduit_stage/usr/local/bin"
conduit_installed_config="$conduit_stage$conduit_home/.config/conduit"
conduit_installed_unit="$conduit_stage$conduit_home/.config/systemd/user/conduit-node.service"
test -x "$conduit_installed_bindir/conduit"
test -x "$conduit_installed_bindir/conduit-node"
test -f "$conduit_installed_unit"
for conduit_owner_dir in \
  "$conduit_installed_config" \
  "$conduit_stage$conduit_home/.local/state/conduit" \
  "$conduit_stage$conduit_home/.local/share/conduit" \
  "$conduit_stage$conduit_home/.cache/conduit"; do
  test "$(stat -c '%a' "$conduit_owner_dir")" = 700
done
test "$(stat -c '%a' "$conduit_installed_config/node.env")" = 600
grep -Fq 'ExecStart=/usr/local/bin/conduit-node serve --data-dir ${CONDUIT_DATA_DIR} --socket ${CONDUIT_SOCKET} --launch-profiles ${CONDUIT_LAUNCH_PROFILES}' "$conduit_installed_unit"

conduit_runtime="$conduit_temp/artifact-runtime"
conduit_data="$conduit_temp/artifact-data"
conduit_log="$conduit_temp/artifact-node.log"
install -d -m 0700 "$conduit_runtime" "$conduit_data"
XDG_RUNTIME_DIR="$conduit_runtime" \
  "$conduit_installed_bindir/conduit-node" serve \
  --data-dir "$conduit_data" \
  --socket "$conduit_runtime/conduit/node.sock" > "$conduit_log" 2>&1 &
conduit_node_pid=$!
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
  "$conduit_installed_bindir/conduit" --output json device doctor >/dev/null
kill -TERM "$conduit_node_pid"
if wait "$conduit_node_pid"; then
  :
else
  conduit_status=$?
  test "$conduit_status" -eq 143
fi
conduit_node_pid=""

HOME="$conduit_home" \
XDG_CONFIG_HOME="$conduit_home/.config" \
XDG_STATE_HOME="$conduit_home/.local/state" \
XDG_DATA_HOME="$conduit_home/.local/share" \
XDG_CACHE_HOME="$conduit_home/.cache" \
XDG_RUNTIME_DIR="$conduit_home/runtime" \
DESTDIR="$conduit_stage" \
  "$conduit_root/installers/uninstall.sh" --prefix /usr/local
test ! -e "$conduit_installed_bindir/conduit"
test ! -e "$conduit_installed_bindir/conduit-node"
test -d "$conduit_stage$conduit_home/.config/conduit"
test -d "$conduit_stage$conduit_home/.local/state/conduit"
test -d "$conduit_stage$conduit_home/.local/share/conduit"
test -d "$conduit_stage$conduit_home/.cache/conduit"

# Wrap the real binaries in deterministic version/backup fixtures. IPC health
# still goes through the real installed CLI and Node.
conduit_make_release() {
  local conduit_destination="$1"
  local conduit_version="$2"
  local conduit_node_template="$3"
  install -d -m 0700 "$conduit_destination"
  sed \
    -e "s|@VERSION@|$conduit_version|g" \
    -e "s|@REAL_CONDUIT@|$conduit_root/target/release/conduit|g" \
    "$conduit_root/packaging/tests/fixture-conduit.in" > "$conduit_destination/conduit"
  sed \
    -e "s|@REAL_CONDUIT_NODE@|$conduit_root/target/release/conduit-node|g" \
    "$conduit_node_template" > "$conduit_destination/conduit-node"
  chmod 0755 "$conduit_destination/conduit" "$conduit_destination/conduit-node"
}

conduit_release_100="$conduit_temp/release-1.0.0"
conduit_release_110="$conduit_temp/release-1.1.0"
conduit_release_120_bad="$conduit_temp/release-1.2.0-fail"
conduit_release_090="$conduit_temp/release-0.9.0"
conduit_make_release "$conduit_release_100" 1.0.0 "$conduit_root/packaging/tests/fixture-conduit-node.in"
conduit_make_release "$conduit_release_110" 1.1.0 "$conduit_root/packaging/tests/fixture-conduit-node.in"
conduit_make_release "$conduit_release_120_bad" 1.2.0 "$conduit_root/packaging/tests/fixture-conduit-node-fail.in"
conduit_make_release "$conduit_release_090" 0.9.0 "$conduit_root/packaging/tests/fixture-conduit-node.in"

export HOME="$conduit_temp/update-home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_STATE_HOME="$HOME/.local/state"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_RUNTIME_DIR="$HOME/runtime"
export CONDUIT_TEST_BINDIR="$HOME/prefix/bin"
export CONDUIT_TEST_SERVICE_PID="$HOME/service.pid"
export CONDUIT_TEST_SERVICE_ENABLED="$HOME/service.enabled"
export CONDUIT_TEST_SERVICE_LOG="$HOME/service.log"
export CONDUIT_TEST_SYSTEMCTL_LOG="$HOME/systemctl.log"
export CONDUIT_TEST_BACKUP_LOG="$HOME/backup.log"
export CONDUIT_SYSTEMCTL="$conduit_root/packaging/tests/mock-systemctl"
export CONDUIT_HEALTH_ATTEMPTS=30
install -d -m 0700 "$HOME" "$XDG_RUNTIME_DIR"

CONDUIT_BUILD_DIR="$conduit_release_100" \
  "$conduit_root/installers/install.sh" --prefix "$HOME/prefix" --start
test "$("$CONDUIT_TEST_BINDIR/conduit" --version)" = "conduit 1.0.0"
"$CONDUIT_TEST_BINDIR/conduit" --output json device doctor >/dev/null
printf 'original state\n' > "$XDG_DATA_HOME/conduit/packaging-marker"
rm -f -- "$XDG_CONFIG_HOME/conduit/node.env"

if CONDUIT_TEST_INVALID_BACKUP=1 CONDUIT_BUILD_DIR="$conduit_release_110" \
  "$conduit_root/installers/update.sh" --prefix "$HOME/prefix"; then
  echo "unverified live backup unexpectedly allowed an update" >&2
  exit 1
fi
test "$("$CONDUIT_TEST_BINDIR/conduit" --version)" = "conduit 1.0.0"
"$CONDUIT_TEST_BINDIR/conduit" --output json device doctor >/dev/null
: > "$CONDUIT_TEST_BACKUP_LOG"

CONDUIT_BUILD_DIR="$conduit_release_110" \
  "$conduit_root/installers/update.sh" --prefix "$HOME/prefix"
test "$("$CONDUIT_TEST_BINDIR/conduit" --version)" = "conduit 1.1.0"
test "$(stat -c '%a' "$XDG_CONFIG_HOME/conduit/node.env")" = 600
test "$(sed -n '1p' "$CONDUIT_TEST_BACKUP_LOG")" = create
test "$(sed -n '2p' "$CONDUIT_TEST_BACKUP_LOG")" = verify
test -z "$(find "$CONDUIT_TEST_BINDIR" -maxdepth 1 -name '.conduit-install.*' -print -quit)"
"$CONDUIT_TEST_BINDIR/conduit" --output json device doctor >/dev/null

if CONDUIT_BUILD_DIR="$conduit_release_120_bad" \
  "$conduit_root/installers/update.sh" --prefix "$HOME/prefix"; then
  echo "injected update failure unexpectedly succeeded" >&2
  exit 1
fi
test "$("$CONDUIT_TEST_BINDIR/conduit" --version)" = "conduit 1.1.0"
test "$(<"$XDG_DATA_HOME/conduit/packaging-marker")" = "original state"
test ! -e "$XDG_DATA_HOME/conduit/injected-migration"
test -n "$(find "$XDG_STATE_HOME/conduit/upgrades" -type f -path '*/failed-data/injected-migration' -print -quit)"
test -z "$(find "$CONDUIT_TEST_BINDIR" -maxdepth 1 -name '.conduit-install.*' -print -quit)"
"$CONDUIT_TEST_BINDIR/conduit" --output json device doctor >/dev/null

if CONDUIT_BUILD_DIR="$conduit_release_090" \
  "$conduit_root/installers/update.sh" --prefix "$HOME/prefix"; then
  echo "downgrade unexpectedly succeeded" >&2
  exit 1
fi
test "$("$CONDUIT_TEST_BINDIR/conduit" --version)" = "conduit 1.1.0"
"$CONDUIT_TEST_BINDIR/conduit" --output json device doctor >/dev/null

"$conduit_root/installers/uninstall.sh" --prefix "$HOME/prefix"
test ! -e "$CONDUIT_TEST_BINDIR/conduit"
test ! -e "$CONDUIT_TEST_BINDIR/conduit-node"
test ! -e "$CONDUIT_TEST_SERVICE_PID"
test -d "$XDG_CONFIG_HOME/conduit"
test -d "$XDG_STATE_HOME/conduit"
test -d "$XDG_DATA_HOME/conduit"
test -d "$XDG_CACHE_HOME/conduit"
test "$(<"$XDG_DATA_HOME/conduit/packaging-marker")" = "original state"

echo "packaging smoke passed"
"$conduit_root/scripts/test-privileged-packaging.sh"
