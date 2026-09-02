#!/usr/bin/env bash
set -euo pipefail
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=installers/common.sh
source "$conduit_root/installers/common.sh"

conduit_prefix="${CONDUIT_PREFIX:-$HOME/.local}"
while (($#)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || { echo "--prefix requires a value" >&2; exit 2; }
      conduit_prefix="$2"
      shift 2
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
fi
conduit_set_paths

if [[ -z "$conduit_destdir" ]]; then
  conduit_active=0
  if conduit_systemctl is-active --quiet conduit-node.service; then
    conduit_active=1
  else
    conduit_status=$?
    [[ $conduit_status -eq 3 || $conduit_status -eq 4 ]] || exit "$conduit_status"
  fi
  if ((conduit_active)); then
    conduit_systemctl stop conduit-node.service
  fi
  if conduit_systemctl is-enabled --quiet conduit-node.service; then
    conduit_systemctl disable conduit-node.service
  else
    conduit_status=$?
    [[ $conduit_status -eq 1 || $conduit_status -eq 3 || $conduit_status -eq 4 ]] || exit "$conduit_status"
  fi
fi

for conduit_target in \
  "$conduit_destdir$conduit_bindir/conduit" \
  "$conduit_destdir$conduit_bindir/conduit-node" \
  "$conduit_destdir$conduit_systemd_dir/conduit-node.service"; do
  rm -f -- "$conduit_target"
done

if [[ -z "$conduit_destdir" ]]; then
  conduit_systemctl daemon-reload
fi

echo "removed Conduit binaries and service unit"
echo "retained configuration: $conduit_config_dir"
echo "retained state: $conduit_state_dir"
echo "retained data: $conduit_data_dir"
echo "retained cache: $conduit_cache_dir"
