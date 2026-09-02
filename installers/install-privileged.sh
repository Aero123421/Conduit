#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=installers/privileged-common.sh
source "$conduit_root/installers/privileged-common.sh"

conduit_privileged_prefix="${CONDUIT_PRIVILEGED_PREFIX:-/usr}"
while (($#)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || { echo "--prefix requires a value" >&2; exit 2; }
      conduit_privileged_prefix="$2"
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

conduit_privileged_destdir="${DESTDIR:-}"
conduit_privileged_set_paths
conduit_privileged_require_root_or_destdir
conduit_privileged_package_paths

conduit_source_bin="${CONDUIT_BUILD_DIR:-$conduit_root/target/release}"
for conduit_binary in conduit-privileged-helper conduit-privileged-exec; do
  conduit_source="$conduit_source_bin/$conduit_binary"
  [[ -x "$conduit_source" && -f "$conduit_source" && ! -L "$conduit_source" ]] || {
    echo "missing non-symlink release binary: $conduit_source" >&2
    echo "build the privileged helper and exec worker from the reviewed source first" >&2
    exit 4
  }
  conduit_privileged_assert_no_symlink_components "$conduit_source"
  conduit_privileged_assert_root_custody "$conduit_source"
done

for conduit_target in \
  "$conduit_privileged_helper" \
  "$conduit_privileged_exec" \
  "$conduit_privileged_socket_unit" \
  "$conduit_privileged_service_unit"; do
  if [[ -e "$conduit_target" || -L "$conduit_target" ]]; then
    echo "privileged package target already exists; use update-privileged.sh: $conduit_target" >&2
    exit 3
  fi
done

for conduit_path in \
  "$(conduit_privileged_target "$conduit_privileged_prefix")" \
  "$(conduit_privileged_target "$(dirname "$conduit_privileged_libexec_dir")")" \
  "$(conduit_privileged_target "$conduit_privileged_systemd_dir")" \
  "$(conduit_privileged_target "$(dirname "$conduit_privileged_config_dir")")" \
  "$(conduit_privileged_target "$(dirname "$conduit_privileged_state_dir")")"; do
  conduit_privileged_assert_no_symlink_components "$conduit_path"
  conduit_privileged_assert_root_custody "$conduit_path"
done

conduit_privileged_prepare_directory "$(conduit_privileged_target "$conduit_privileged_libexec_dir")" 0755
conduit_privileged_prepare_directory "$(conduit_privileged_target "$conduit_privileged_systemd_dir")" 0755
conduit_privileged_prepare_directory "$(conduit_privileged_target "$conduit_privileged_config_dir")" 0755
conduit_privileged_prepare_directory "$(conduit_privileged_target "$conduit_privileged_state_dir")" 0700

conduit_existing_state="$(conduit_privileged_target "$conduit_privileged_state_dir")"
if [[ -n "$(find "$conduit_existing_state" -mindepth 1 -print -quit)" ]]; then
  "$conduit_source_bin/conduit-privileged-helper" admin package-check \
    --installed-state "$conduit_existing_state" \
    --exec "$conduit_source_bin/conduit-privileged-exec" \
    --output json >/dev/null || {
      echo "candidate helper rejected preserved journal/protocol compatibility" >&2
      exit 4
    }
fi

conduit_install_temp="$(mktemp -d "$(conduit_privileged_target "$conduit_privileged_state_dir")/package-install.XXXXXXXX")"
chmod 0700 "$conduit_install_temp"
[[ -n "$conduit_privileged_destdir" ]] || chown root:root "$conduit_install_temp"
conduit_socket_tmp="$conduit_install_temp/helper.socket"
conduit_service_tmp="$conduit_install_temp/helper.service"
conduit_installed=0
conduit_cleanup() {
  local conduit_status=$?
  rm -f -- "$conduit_socket_tmp" "$conduit_service_tmp"
  rmdir -- "$conduit_install_temp" 2>/dev/null || true
  if ((conduit_status != 0 && conduit_installed)); then
    rm -f -- \
      "$conduit_privileged_helper" \
      "$conduit_privileged_exec" \
      "$conduit_privileged_socket_unit" \
      "$conduit_privileged_service_unit"
  fi
  exit "$conduit_status"
}
trap conduit_cleanup EXIT

for conduit_unit_source in \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.socket" \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.service"; do
  conduit_privileged_assert_no_symlink_components "$conduit_unit_source"
  conduit_privileged_assert_root_custody "$conduit_unit_source"
done

conduit_privileged_render_unit \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.socket" \
  "$conduit_socket_tmp"
conduit_privileged_render_unit \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.service" \
  "$conduit_service_tmp"

conduit_privileged_atomic_install \
  "$conduit_source_bin/conduit-privileged-helper" "$conduit_privileged_helper" 0755
conduit_installed=1
conduit_privileged_atomic_install \
  "$conduit_source_bin/conduit-privileged-exec" "$conduit_privileged_exec" 0755
conduit_privileged_atomic_install \
  "$conduit_socket_tmp" "$conduit_privileged_socket_unit" 0644
conduit_privileged_atomic_install \
  "$conduit_service_tmp" "$conduit_privileged_service_unit" 0644

conduit_privileged_daemon_reload
conduit_installed=0
echo "installed root-owned Conduit privileged helper package"
echo "no helper identity, policy, socket, or Full Device authority was enabled"
echo "run the installed helper's explicit admin prepare/enable commands locally as root"
