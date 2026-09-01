#!/usr/bin/env bash
set -euo pipefail

conduit_prefix="${CONDUIT_PREFIX:-$HOME/.local}"
while (($#)); do
  case "$1" in
    --prefix)
      conduit_prefix="$2"
      shift 2
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

conduit_destdir="${DESTDIR:-}"
conduit_systemd_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

if [[ -z "$conduit_destdir" ]]; then
  systemctl --user disable --now conduit-node.service 2>/dev/null || true
fi

rm -f \
  "$conduit_destdir$conduit_prefix/bin/conduit" \
  "$conduit_destdir$conduit_prefix/bin/conduit-node" \
  "$conduit_destdir$conduit_systemd_dir/conduit-node.service"

if [[ -z "$conduit_destdir" ]]; then
  systemctl --user daemon-reload
fi

echo "removed Conduit binaries and service unit; configuration and data were retained"
