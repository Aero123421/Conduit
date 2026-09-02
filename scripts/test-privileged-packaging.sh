#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
conduit_temp_root="$(realpath -m "${TMPDIR:-/tmp}")"
conduit_temp="$(mktemp -d "$conduit_temp_root/conduit-privileged-package-XXXXXXXX")"
conduit_cleanup() {
  [[ "$conduit_temp" == "$conduit_temp_root"/conduit-privileged-package-* ]] || return 1
  find "$conduit_temp" -xdev -depth -delete
}
trap conduit_cleanup EXIT

# Verify that the package contract consumes the real release artifacts. The
# deterministic fixtures below exercise failure injection and rollback, but
# cannot prove that Cargo actually produces both installed executables.
conduit_real_release="$conduit_root/target/release"
for conduit_real_binary in conduit-privileged-helper conduit-privileged-exec; do
  test -x "$conduit_real_release/$conduit_real_binary"
  test ! -L "$conduit_real_release/$conduit_real_binary"
  "$conduit_real_release/$conduit_real_binary" --version |
    grep -Eq "^$conduit_real_binary [0-9]+\\.[0-9]+\\.[0-9]+$"
done
conduit_real_stage="$conduit_temp/real-root"
DESTDIR="$conduit_real_stage" CONDUIT_BUILD_DIR="$conduit_real_release" \
  "$conduit_root/installers/install-privileged.sh"
for conduit_real_binary in conduit-privileged-helper conduit-privileged-exec; do
  test -x "$conduit_real_stage/usr/libexec/conduit/$conduit_real_binary"
  test "$(stat -c '%a' "$conduit_real_stage/usr/libexec/conduit/$conduit_real_binary")" = 755
done
if command -v systemd-analyze >/dev/null 2>&1; then
  # `--root` deliberately does not read host units. Supply only the minimal
  # dependency names needed to validate the rendered package units without
  # coupling this deterministic test to the host's systemd installation.
  for conduit_fixture_unit in sysinit.target basic.target sockets.target; do
    printf '[Unit]\nDescription=packaging verification fixture\n' > \
      "$conduit_real_stage/usr/lib/systemd/system/$conduit_fixture_unit"
  done
  printf '[Unit]\nDescription=packaging verification fixture\n[Service]\nType=oneshot\nExecStart=/usr/libexec/conduit/conduit-privileged-helper --version\n' > \
    "$conduit_real_stage/usr/lib/systemd/system/dbus.service"
  systemd-analyze verify --root="$conduit_real_stage" \
    "$conduit_real_stage/usr/lib/systemd/system/conduit-privileged-helper@.socket" \
    "$conduit_real_stage/usr/lib/systemd/system/conduit-privileged-helper@.service"
fi

conduit_make_release() {
  local conduit_destination="$1"
  local conduit_version="$2"
  local conduit_protocol="$3"
  local conduit_fail_installed="$4"
  install -d -m 0700 "$conduit_destination"
  sed \
    -e "s|@VERSION@|$conduit_version|g" \
    -e "s|@PROTOCOL@|$conduit_protocol|g" \
    -e "s|@FAIL_INSTALLED@|$conduit_fail_installed|g" \
    "$conduit_root/packaging/tests/fixture-conduit-privileged-helper.in" \
    > "$conduit_destination/conduit-privileged-helper"
  sed -e "s|@VERSION@|$conduit_version|g" \
    "$conduit_root/packaging/tests/fixture-conduit-privileged-exec.in" \
    > "$conduit_destination/conduit-privileged-exec"
  chmod 0755 \
    "$conduit_destination/conduit-privileged-helper" \
    "$conduit_destination/conduit-privileged-exec"
}

conduit_release_100="$conduit_temp/release-1.0.0"
conduit_release_110="$conduit_temp/release-1.1.0"
conduit_release_120="$conduit_temp/release-1.2.0"
conduit_release_bad="$conduit_temp/release-1.3.0-bad"
conduit_release_old="$conduit_temp/release-0.9.0"
conduit_make_release "$conduit_release_100" 1.0.0 1 0
conduit_make_release "$conduit_release_110" 1.1.0 1 0
conduit_make_release "$conduit_release_120" 1.2.0 1 0
conduit_make_release "$conduit_release_bad" 1.3.0 1 1
conduit_make_release "$conduit_release_old" 0.9.0 0 0

conduit_stage="$conduit_temp/root"
export CONDUIT_TEST_PRIVILEGED_STATE="$conduit_stage/var/lib/conduit/privileged-helper"
export CONDUIT_TEST_PRIVILEGED_CONFIG="$conduit_stage/etc/conduit/privileged-helper.d"
export CONDUIT_PRIVILEGED_STATE_DIR=/var/lib/conduit/privileged-helper
export CONDUIT_PRIVILEGED_CONFIG_DIR=/etc/conduit/privileged-helper.d
export CONDUIT_PRIVILEGED_SYSTEMD_DIR=/usr/lib/systemd/system

DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_100" \
  "$conduit_root/installers/install-privileged.sh"

conduit_helper="$conduit_stage/usr/libexec/conduit/conduit-privileged-helper"
conduit_exec="$conduit_stage/usr/libexec/conduit/conduit-privileged-exec"
conduit_socket="$conduit_stage/usr/lib/systemd/system/conduit-privileged-helper@.socket"
conduit_service="$conduit_stage/usr/lib/systemd/system/conduit-privileged-helper@.service"
for conduit_binary in "$conduit_helper" "$conduit_exec"; do
  test -x "$conduit_binary"
  test ! -L "$conduit_binary"
  test "$(stat -c '%a' "$conduit_binary")" = 755
done
for conduit_unit in "$conduit_socket" "$conduit_service"; do
  test -f "$conduit_unit"
  test ! -L "$conduit_unit"
  test "$(stat -c '%a' "$conduit_unit")" = 644
done
test "$(stat -c '%a' "$CONDUIT_TEST_PRIVILEGED_STATE")" = 700
test "$(stat -c '%a' "$CONDUIT_TEST_PRIVILEGED_CONFIG")" = 700
test -z "$(find "$CONDUIT_TEST_PRIVILEGED_STATE" -mindepth 1 -print -quit)"
test -z "$(find "$CONDUIT_TEST_PRIVILEGED_CONFIG" -mindepth 1 -print -quit)"
grep -Fq 'ListenSequentialPacket=/run/conduit/privileged/%i.sock' "$conduit_socket"
grep -Fq 'SocketMode=0600' "$conduit_socket"
grep -Fq 'PassCredentials=yes' "$conduit_socket"
grep -Fq 'ExecStart=/usr/libexec/conduit/conduit-privileged-helper serve --expected-uid %i' "$conduit_service"
grep -Fq 'PrivateNetwork=yes' "$conduit_service"
grep -Fq 'RestrictAddressFamilies=AF_UNIX' "$conduit_service"
grep -Fq 'NoNewPrivileges=yes' "$conduit_service"
grep -Fq 'ConfigurationDirectoryMode=0700' "$conduit_service"

if DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_100" \
  "$conduit_root/installers/install-privileged.sh"; then
  echo "a second privileged install unexpectedly overwrote the package" >&2
  exit 1
fi

conduit_symlink_stage="$conduit_temp/symlink-root"
install -d -m 0755 "$conduit_symlink_stage/usr"
ln -s "$conduit_temp" "$conduit_symlink_stage/usr/libexec"
if DESTDIR="$conduit_symlink_stage" CONDUIT_BUILD_DIR="$conduit_release_100" \
  "$conduit_root/installers/install-privileged.sh"; then
  echo "a symlinked privileged package ancestor was unexpectedly accepted" >&2
  exit 1
fi

printf '1\n' > "$CONDUIT_TEST_PRIVILEGED_STATE/required-protocol"
printf '0\n' > "$CONDUIT_TEST_PRIVILEGED_STATE/active-count"
DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_110" \
  "$conduit_root/installers/update-privileged.sh"
test "$($conduit_helper --version)" = 'conduit-privileged-helper 1.1.0'

# Installing a compatible package while a Runtime is active must not alter the
# durable active count or invoke a service manager in DESTDIR mode.
printf '1\n' > "$CONDUIT_TEST_PRIVILEGED_STATE/active-count"
DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_120" \
  "$conduit_root/installers/update-privileged.sh"
test "$($conduit_helper --version)" = 'conduit-privileged-helper 1.2.0'
test "$(<"$CONDUIT_TEST_PRIVILEGED_STATE/active-count")" = 1

if DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_bad" \
  "$conduit_root/installers/update-privileged.sh"; then
  echo "a post-install compatibility failure unexpectedly committed" >&2
  exit 1
fi
test "$($conduit_helper --version)" = 'conduit-privileged-helper 1.2.0'
test "$(<"$CONDUIT_TEST_PRIVILEGED_STATE/active-count")" = 1

if DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_old" \
  "$conduit_root/installers/update-privileged.sh"; then
  echo "a privileged protocol downgrade unexpectedly committed" >&2
  exit 1
fi
test "$($conduit_helper --version)" = 'conduit-privileged-helper 1.2.0'

if DESTDIR="$conduit_stage" "$conduit_root/installers/uninstall-privileged.sh"; then
  echo "uninstall unexpectedly ignored active elevated Runtime custody" >&2
  exit 1
fi
DESTDIR="$conduit_stage" \
  "$conduit_root/installers/uninstall-privileged.sh" --terminate-active
test ! -e "$conduit_helper"
test ! -e "$conduit_exec"
test -d "$CONDUIT_TEST_PRIVILEGED_STATE"
test -d "$CONDUIT_TEST_PRIVILEGED_CONFIG"

if DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_old" \
  "$conduit_root/installers/install-privileged.sh"; then
  echo "reinstall unexpectedly downgraded preserved privileged state" >&2
  exit 1
fi
DESTDIR="$conduit_stage" CONDUIT_BUILD_DIR="$conduit_release_120" \
  "$conduit_root/installers/install-privileged.sh"
printf '0\n' > "$CONDUIT_TEST_PRIVILEGED_STATE/active-count"
printf '' > "$CONDUIT_TEST_PRIVILEGED_STATE/authority.lock"
chmod 0600 "$CONDUIT_TEST_PRIVILEGED_STATE/authority.lock"
if DESTDIR="$conduit_stage" \
  "$conduit_root/installers/uninstall-privileged.sh" --purge; then
  echo "purge unexpectedly omitted the explicit confirmation phrase" >&2
  exit 1
fi
DESTDIR="$conduit_stage" "$conduit_root/installers/uninstall-privileged.sh" \
  --purge --confirm-purge DELETE-CONDUIT-PRIVILEGED-STATE
test ! -e "$conduit_helper"
test ! -e "$CONDUIT_TEST_PRIVILEGED_STATE"
test ! -e "$CONDUIT_TEST_PRIVILEGED_CONFIG"

test -z "$(find "$conduit_stage" -name '.conduit-privileged-install.*' -print -quit)"
echo "privileged packaging smoke passed"
