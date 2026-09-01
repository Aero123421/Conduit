#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
conduit_temp="$(mktemp -d -t conduit-package-smoke-XXXXXXXX)"
trap 'rm -rf "$conduit_temp"' EXIT

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

HOME="$conduit_home" \
XDG_CONFIG_HOME="$conduit_home/.config" \
DESTDIR="$conduit_temp/root" \
  "$conduit_root/installers/uninstall.sh" --prefix /usr/local

test ! -e "$conduit_temp/root/usr/local/bin/conduit"
test -d "$conduit_temp/root$conduit_home/.local/state/conduit"
