#!/usr/bin/env bash
set -euo pipefail
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=installers/common.sh
source "$conduit_root/installers/common.sh"

conduit_prefix="${CONDUIT_PREFIX:-$HOME/.local}"
conduit_start=0
while (($#)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || { echo "--prefix requires a value" >&2; exit 2; }
      conduit_prefix="$2"
      shift 2
      ;;
    --start)
      conduit_start=1
      shift
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

conduit_require_absolute "install prefix" "$conduit_prefix"
conduit_destdir="${DESTDIR:-}"
if [[ -n "$conduit_destdir" ]]; then
  conduit_require_absolute DESTDIR "$conduit_destdir"
  ((conduit_start == 0)) || { echo "--start cannot be used with DESTDIR" >&2; exit 2; }
fi
conduit_set_paths

conduit_source_bin="${CONDUIT_BUILD_DIR:-$conduit_root/target/release}"
for conduit_binary in conduit conduit-node; do
  conduit_source="$conduit_source_bin/$conduit_binary"
  [[ -x "$conduit_source" && -f "$conduit_source" ]] || {
    echo "missing release binary: $conduit_source" >&2
    echo "run cargo build --locked --release --bin conduit --bin conduit-node first" >&2
    exit 4
  }
  if [[ -e "$conduit_destdir$conduit_bindir/$conduit_binary" || -L "$conduit_destdir$conduit_bindir/$conduit_binary" ]]; then
    echo "Conduit is already installed; use installers/update.sh" >&2
    exit 3
  fi
done
if [[ -e "$conduit_destdir$conduit_systemd_dir/conduit-node.service" || -L "$conduit_destdir$conduit_systemd_dir/conduit-node.service" ]]; then
  echo "Conduit service unit already exists; use installers/update.sh or remove the stale unit explicitly" >&2
  exit 3
fi

for conduit_dir in "$conduit_config_dir" "$conduit_state_dir" "$conduit_data_dir" "$conduit_cache_dir"; do
  conduit_assert_not_symlink "$conduit_destdir$conduit_dir"
  install -d -m 0700 "$conduit_destdir$conduit_dir"
  chmod 0700 "$conduit_destdir$conduit_dir"
  conduit_require_owner_only "$conduit_destdir$conduit_dir" directory
done
install -d -m 0755 "$conduit_destdir$conduit_bindir"
install -d -m 0700 "$conduit_destdir$conduit_systemd_dir"

conduit_unit_tmp="$(mktemp)"
conduit_env_tmp="$(mktemp)"
conduit_installed=0
conduit_cleanup() {
  local conduit_status=$?
  rm -f -- "$conduit_unit_tmp" "$conduit_env_tmp"
  if ((conduit_status != 0 && conduit_installed)); then
    if [[ -z "$conduit_destdir" && $conduit_start -eq 1 ]]; then
      conduit_systemctl disable --now conduit-node.service >/dev/null 2>&1 || true
    fi
    rm -f -- \
      "$conduit_destdir$conduit_bindir/conduit" \
      "$conduit_destdir$conduit_bindir/conduit-node" \
      "$conduit_destdir$conduit_systemd_dir/conduit-node.service"
  fi
  exit "$conduit_status"
}
trap conduit_cleanup EXIT

sed "s|@BINDIR@|$conduit_bindir|g" \
  "$conduit_root/packaging/systemd/conduit-node.service" > "$conduit_unit_tmp"
conduit_render_node_env > "$conduit_env_tmp"
conduit_atomic_install "$conduit_source_bin/conduit" "$conduit_destdir$conduit_bindir/conduit" 0755
conduit_installed=1
conduit_atomic_install "$conduit_source_bin/conduit-node" "$conduit_destdir$conduit_bindir/conduit-node" 0755
conduit_atomic_install "$conduit_unit_tmp" "$conduit_destdir$conduit_systemd_dir/conduit-node.service" 0600

conduit_env="$conduit_destdir$conduit_config_dir/node.env"
if [[ ! -e "$conduit_env" && ! -L "$conduit_env" ]]; then
  conduit_atomic_install "$conduit_env_tmp" "$conduit_env" 0600
fi
conduit_require_owner_only "$conduit_env" file

conduit_example="$conduit_destdir$conduit_config_dir/node.env.example"
conduit_assert_not_symlink "$conduit_example"
if [[ ! -e "$conduit_example" ]]; then
  conduit_atomic_install "$conduit_root/packaging/conduit-node.env.example" "$conduit_example" 0600
fi
conduit_require_owner_only "$conduit_example" file

if [[ -z "$conduit_destdir" ]]; then
  conduit_systemctl daemon-reload
  if ((conduit_start)); then
    [[ -n "$conduit_runtime_home" ]] || { echo "XDG_RUNTIME_DIR is required with --start" >&2; exit 2; }
    conduit_systemctl enable --now conduit-node.service
    conduit_wait_healthy "$conduit_bindir/conduit"
  fi
fi

conduit_installed=0
echo "installed conduit and conduit-node in $conduit_bindir"
