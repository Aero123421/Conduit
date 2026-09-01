#!/usr/bin/env bash
set -euo pipefail

conduit_prefix="${CONDUIT_PREFIX:-$HOME/.local}"
conduit_start=0

while (($#)); do
  case "$1" in
    --prefix)
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

if [[ "$conduit_prefix" != /* ]]; then
  echo "install prefix must be absolute" >&2
  exit 2
fi

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
conduit_destdir="${DESTDIR:-}"
conduit_bindir="$conduit_prefix/bin"
conduit_source_bin="${CONDUIT_BUILD_DIR:-$conduit_root/target/release}"
conduit_systemd_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

for conduit_binary in conduit conduit-node; do
  conduit_source="$conduit_source_bin/$conduit_binary"
  if [[ ! -x "$conduit_source" ]]; then
    echo "missing release binary: $conduit_source" >&2
    echo "run cargo build --release --bins first" >&2
    exit 4
  fi
done

install -d -m 0755 "$conduit_destdir$conduit_bindir"
install -m 0755 "$conduit_source_bin/conduit" "$conduit_destdir$conduit_bindir/conduit"
install -m 0755 "$conduit_source_bin/conduit-node" "$conduit_destdir$conduit_bindir/conduit-node"

install -d -m 0700 "$conduit_destdir$conduit_systemd_dir"
conduit_unit_tmp="$(mktemp)"
trap 'rm -f "$conduit_unit_tmp"' EXIT
sed "s|@BINDIR@|$conduit_bindir|g" \
  "$conduit_root/packaging/systemd/conduit-node.service" > "$conduit_unit_tmp"
install -m 0600 "$conduit_unit_tmp" "$conduit_destdir$conduit_systemd_dir/conduit-node.service"

for conduit_dir in \
  "${XDG_CONFIG_HOME:-$HOME/.config}/conduit" \
  "${XDG_STATE_HOME:-$HOME/.local/state}/conduit" \
  "${XDG_DATA_HOME:-$HOME/.local/share}/conduit" \
  "${XDG_CACHE_HOME:-$HOME/.cache}/conduit"; do
  install -d -m 0700 "$conduit_destdir$conduit_dir"
done

if [[ -z "$conduit_destdir" ]]; then
  systemctl --user daemon-reload
  if ((conduit_start)); then
    systemctl --user enable --now conduit-node.service
  fi
fi

echo "installed conduit and conduit-node in $conduit_bindir"
