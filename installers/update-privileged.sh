#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=installers/privileged-common.sh
source "$conduit_root/installers/privileged-common.sh"

conduit_privileged_prefix="${CONDUIT_PRIVILEGED_PREFIX:-/usr}"
conduit_activate_uid=""
while (($#)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || { echo "--prefix requires a value" >&2; exit 2; }
      conduit_privileged_prefix="$2"
      shift 2
      ;;
    --activate-uid)
      (($# >= 2)) || { echo "--activate-uid requires a value" >&2; exit 2; }
      conduit_activate_uid="$2"
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
if [[ -n "$conduit_activate_uid" ]]; then
  conduit_privileged_validate_uid "$conduit_activate_uid"
  [[ -z "$conduit_privileged_destdir" ]] || {
    echo "--activate-uid cannot be used with DESTDIR" >&2
    exit 2
  }
fi

conduit_source_bin="${CONDUIT_BUILD_DIR:-$conduit_root/target/release}"
for conduit_binary in conduit-privileged-helper conduit-privileged-exec; do
  conduit_source="$conduit_source_bin/$conduit_binary"
  [[ -x "$conduit_source" && -f "$conduit_source" && ! -L "$conduit_source" ]] || {
    echo "missing non-symlink candidate binary: $conduit_source" >&2
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
  [[ -f "$conduit_target" && ! -L "$conduit_target" ]] || {
    echo "installed privileged package target is missing or unsafe: $conduit_target" >&2
    exit 4
  }
  conduit_privileged_assert_no_symlink_components "$conduit_target"
  conduit_privileged_assert_root_custody "$conduit_target"
done

conduit_privileged_package_status "$conduit_privileged_helper"
if [[ -n "$conduit_activate_uid" ]] && ((conduit_privileged_active_runtime_count != 0)); then
  echo "activation refused while elevated Runtime custody is active" >&2
  echo "repeat the update without --activate-uid to install without disturbing custody" >&2
  exit 3
fi
conduit_candidate_state="$(conduit_privileged_target "$conduit_privileged_state_dir")"
"$conduit_source_bin/conduit-privileged-helper" admin package-check \
  --installed-state "$conduit_candidate_state" \
  --exec "$conduit_source_bin/conduit-privileged-exec" \
  --output json >/dev/null || {
    echo "candidate helper rejected installed journal/protocol compatibility" >&2
    exit 4
  }

conduit_upgrade_root="$conduit_candidate_state/package-upgrades"
conduit_privileged_prepare_directory "$conduit_upgrade_root" 0700
conduit_lock="$conduit_upgrade_root/update.lock"
if ! mkdir -m 0700 -- "$conduit_lock" 2>/dev/null; then
  echo "another privileged helper update is in progress" >&2
  exit 3
fi
if [[ -z "$conduit_privileged_destdir" ]]; then
  chown root:root -- "$conduit_lock"
fi

conduit_transaction="$conduit_upgrade_root/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -m 0700 -- "$conduit_transaction"
if [[ -z "$conduit_privileged_destdir" ]]; then
  chown root:root -- "$conduit_transaction"
fi
conduit_socket_tmp="$conduit_transaction/candidate.socket"
conduit_service_tmp="$conduit_transaction/candidate.service"
for conduit_unit_source in \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.socket" \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.service"; do
  conduit_privileged_assert_no_symlink_components "$conduit_unit_source"
  conduit_privileged_assert_root_custody "$conduit_unit_source"
done
conduit_privileged_render_unit \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.socket" "$conduit_socket_tmp"
conduit_privileged_render_unit \
  "$conduit_root/packaging/systemd/conduit-privileged-helper@.service" "$conduit_service_tmp"

for conduit_pair in \
  "helper:$conduit_privileged_helper" \
  "exec:$conduit_privileged_exec" \
  "socket:$conduit_privileged_socket_unit" \
  "service:$conduit_privileged_service_unit"; do
  conduit_name="${conduit_pair%%:*}"
  conduit_path="${conduit_pair#*:}"
  conduit_privileged_atomic_install "$conduit_path" "$conduit_transaction/previous-$conduit_name" \
    "$([[ "$conduit_name" == helper || "$conduit_name" == exec ]] && echo 0755 || echo 0644)"
done
printf '%s\n' "$conduit_privileged_package_status_json" > "$conduit_transaction/pre-update-status.json"
chmod 0600 "$conduit_transaction/pre-update-status.json"
if [[ -z "$conduit_privileged_destdir" ]]; then
  chown root:root "$conduit_transaction/pre-update-status.json"
fi

conduit_replaced=0
conduit_activation_touched=0
conduit_rollback() {
  local conduit_status=$?
  trap - EXIT INT TERM
  set +e
  if ((conduit_status != 0 && conduit_replaced)); then
    conduit_rollback_failed=0
    conduit_privileged_atomic_install "$conduit_transaction/previous-helper" "$conduit_privileged_helper" 0755 || conduit_rollback_failed=1
    conduit_privileged_atomic_install "$conduit_transaction/previous-exec" "$conduit_privileged_exec" 0755 || conduit_rollback_failed=1
    conduit_privileged_atomic_install "$conduit_transaction/previous-socket" "$conduit_privileged_socket_unit" 0644 || conduit_rollback_failed=1
    conduit_privileged_atomic_install "$conduit_transaction/previous-service" "$conduit_privileged_service_unit" 0644 || conduit_rollback_failed=1
    conduit_privileged_daemon_reload >/dev/null 2>&1 || conduit_rollback_failed=1
    if ((conduit_activation_touched)); then
      systemctl restart "conduit-privileged-helper@$conduit_activate_uid.socket" >/dev/null 2>&1 || conduit_rollback_failed=1
    fi
    if ((conduit_rollback_failed)); then
      printf 'rollback_failed\n' > "$conduit_transaction/result"
      echo "privileged helper update failed and package rollback is incomplete" >&2
    else
      printf 'rolled_back\n' > "$conduit_transaction/result"
      echo "privileged helper update failed; package files were rolled back" >&2
    fi
    chmod 0600 "$conduit_transaction/result"
    [[ -n "$conduit_privileged_destdir" ]] || chown root:root "$conduit_transaction/result"
  fi
  rmdir -- "$conduit_lock" 2>/dev/null
  exit "$conduit_status"
}
trap conduit_rollback EXIT
trap 'exit 130' INT TERM

conduit_replaced=1
conduit_privileged_atomic_install \
  "$conduit_source_bin/conduit-privileged-helper" "$conduit_privileged_helper" 0755
conduit_privileged_atomic_install \
  "$conduit_source_bin/conduit-privileged-exec" "$conduit_privileged_exec" 0755
conduit_privileged_atomic_install "$conduit_socket_tmp" "$conduit_privileged_socket_unit" 0644
conduit_privileged_atomic_install "$conduit_service_tmp" "$conduit_privileged_service_unit" 0644
conduit_privileged_daemon_reload

# Re-open the real installed files and state. A candidate that only passed its
# source-tree probe cannot commit the package transaction.
"$conduit_privileged_helper" admin package-check \
  --installed-state "$conduit_candidate_state" \
  --exec "$conduit_privileged_exec" \
  --output json >/dev/null || {
    echo "installed candidate failed the post-install compatibility probe" >&2
    exit 4
  }

if [[ -n "$conduit_activate_uid" ]]; then
  conduit_activation_touched=1
  systemctl stop "conduit-privileged-helper@$conduit_activate_uid.service"
  systemctl restart "conduit-privileged-helper@$conduit_activate_uid.socket"
fi

printf 'complete\n' > "$conduit_transaction/result"
chmod 0600 "$conduit_transaction/result"
[[ -n "$conduit_privileged_destdir" ]] || chown root:root "$conduit_transaction/result"
trap - EXIT INT TERM
rmdir -- "$conduit_lock"
echo "updated privileged helper package"
if ((conduit_privileged_active_runtime_count != 0)); then
  echo "active elevated Runtime custody was left untouched; running helper processes retain their prior inode until they exit"
elif [[ -z "$conduit_activate_uid" ]]; then
  echo "use --activate-uid with the exact configured UID to restart its socket explicitly"
fi
echo "rollback evidence retained at $conduit_transaction"
