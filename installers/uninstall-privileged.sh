#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=installers/privileged-common.sh
source "$conduit_root/installers/privileged-common.sh"

conduit_privileged_prefix="${CONDUIT_PRIVILEGED_PREFIX:-/usr}"
conduit_terminate_active=0
conduit_purge=0
conduit_purge_confirmation=""
while (($#)); do
  case "$1" in
    --prefix)
      (($# >= 2)) || { echo "--prefix requires a value" >&2; exit 2; }
      conduit_privileged_prefix="$2"
      shift 2
      ;;
    --terminate-active)
      conduit_terminate_active=1
      shift
      ;;
    --purge)
      conduit_purge=1
      shift
      ;;
    --confirm-purge)
      (($# >= 2)) || { echo "--confirm-purge requires a value" >&2; exit 2; }
      conduit_purge_confirmation="$2"
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
[[ -f "$conduit_privileged_helper" && -x "$conduit_privileged_helper" && ! -L "$conduit_privileged_helper" ]] || {
  echo "installed privileged helper is missing or unsafe" >&2
  exit 4
}
conduit_privileged_assert_no_symlink_components "$conduit_privileged_helper"
conduit_privileged_assert_root_custody "$conduit_privileged_helper"

if ((conduit_purge)) && [[ "$conduit_purge_confirmation" != DELETE-CONDUIT-PRIVILEGED-STATE ]]; then
  echo "--purge requires --confirm-purge DELETE-CONDUIT-PRIVILEGED-STATE" >&2
  exit 2
fi
if ((!conduit_purge)) && [[ -n "$conduit_purge_confirmation" ]]; then
  echo "--confirm-purge is valid only with --purge" >&2
  exit 2
fi

conduit_policy_root="$(conduit_privileged_target "$conduit_privileged_config_dir")"
shopt -s nullglob
conduit_policy_files=("$conduit_policy_root"/*.json)
shopt -u nullglob
conduit_policy_uids=()
for conduit_policy in "${conduit_policy_files[@]}"; do
  conduit_policy_name="$(basename "$conduit_policy")"
  if [[ "$conduit_policy_name" =~ ^([0-9]+)\.json$ ]]; then
    conduit_uid="${BASH_REMATCH[1]}"
    conduit_privileged_validate_uid "$conduit_uid"
    conduit_policy_uids+=("$conduit_uid")
  fi
done

conduit_privileged_active_runtime_count=0
if ((${#conduit_policy_uids[@]} == 0)); then
  # DESTDIR fixtures and an unprepared package have no per-UID policy yet.
  conduit_privileged_package_status "$conduit_privileged_helper"
else
  conduit_total_active_runtime_count=0
  for conduit_uid in "${conduit_policy_uids[@]}"; do
    conduit_privileged_package_status "$conduit_privileged_helper" "$conduit_uid"
    conduit_total_active_runtime_count=$((
      conduit_total_active_runtime_count + conduit_privileged_active_runtime_count
    ))
  done
  conduit_privileged_active_runtime_count="$conduit_total_active_runtime_count"
fi
if ((conduit_privileged_active_runtime_count != 0 && !conduit_terminate_active)); then
  echo "uninstall refused: elevated Runtime custody is active" >&2
  echo "stop each Runtime normally, or repeat with the explicit --terminate-active root action" >&2
  exit 3
fi
if ((conduit_privileged_active_runtime_count != 0)); then
  if ((${#conduit_policy_uids[@]} == 0)); then
    "$conduit_privileged_helper" admin stop-active --output json >/dev/null || {
      echo "helper could not produce terminal custody for every active elevated Runtime" >&2
      exit 4
    }
    conduit_privileged_package_status "$conduit_privileged_helper"
    ((conduit_privileged_active_runtime_count == 0)) || {
      echo "uninstall refused: active elevated Runtime custody remains after stop-active" >&2
      exit 4
    }
  else
    for conduit_uid in "${conduit_policy_uids[@]}"; do
      "$conduit_privileged_helper" admin stop-active --uid "$conduit_uid" --output json >/dev/null || {
        echo "helper could not produce terminal custody for every active elevated Runtime" >&2
        exit 4
      }
      conduit_privileged_package_status "$conduit_privileged_helper" "$conduit_uid"
      ((conduit_privileged_active_runtime_count == 0)) || {
        echo "uninstall refused: active elevated Runtime custody remains after stop-active" >&2
        exit 4
      }
    done
  fi
fi

if [[ -z "$conduit_privileged_destdir" ]]; then
  for conduit_uid in "${conduit_policy_uids[@]}"; do
    conduit_socket_name="conduit-privileged-helper@$conduit_uid.socket"
    conduit_service_name="conduit-privileged-helper@$conduit_uid.service"
    if systemctl is-enabled --quiet "$conduit_socket_name"; then
      systemctl disable "$conduit_socket_name"
    else
      conduit_systemctl_status=$?
      [[ $conduit_systemctl_status -eq 1 || $conduit_systemctl_status -eq 3 || $conduit_systemctl_status -eq 4 ]] || exit "$conduit_systemctl_status"
    fi
    if systemctl is-active --quiet "$conduit_socket_name"; then
      systemctl stop "$conduit_socket_name"
    else
      conduit_systemctl_status=$?
      [[ $conduit_systemctl_status -eq 3 || $conduit_systemctl_status -eq 4 ]] || exit "$conduit_systemctl_status"
    fi
    if systemctl is-active --quiet "$conduit_service_name"; then
      systemctl stop "$conduit_service_name"
    else
      conduit_systemctl_status=$?
      [[ $conduit_systemctl_status -eq 3 || $conduit_systemctl_status -eq 4 ]] || exit "$conduit_systemctl_status"
    fi
  done
fi

if ((conduit_purge)); then
  if ((${#conduit_policy_uids[@]} == 0)); then
    "$conduit_privileged_helper" admin purge --output json >/dev/null || {
      echo "helper refused the explicit state purge" >&2
      exit 4
    }
  else
    for conduit_uid in "${conduit_policy_uids[@]}"; do
      "$conduit_privileged_helper" admin purge --uid "$conduit_uid" --output json >/dev/null || {
        echo "helper refused the explicit state purge" >&2
        exit 4
      }
    done
  fi

  # Package update transactions contain only a fixed set of rollback files,
  # but live outside per-UID helper state. Purge them without a recursive or
  # caller-selected deletion target after every Runtime has reached terminal
  # custody and every per-UID journal has been purged above.
  conduit_upgrade_root="$(conduit_privileged_target "$conduit_privileged_state_dir")/package-upgrades"
  if [[ -e "$conduit_upgrade_root" || -L "$conduit_upgrade_root" ]]; then
    [[ -d "$conduit_upgrade_root" && ! -L "$conduit_upgrade_root" ]] || {
      echo "unsafe privileged update evidence root" >&2
      exit 4
    }
    conduit_upgrade_owner=0
    [[ -z "$conduit_privileged_destdir" ]] || conduit_upgrade_owner="$(id -u)"
    test "$(stat -c '%u' "$conduit_upgrade_root")" = "$conduit_upgrade_owner" || {
      echo "privileged update evidence owner mismatch" >&2
      exit 4
    }
    (( (8#$(stat -c '%a' "$conduit_upgrade_root") & 8#077) == 0 )) || {
      echo "privileged update evidence permissions are too broad" >&2
      exit 4
    }
    shopt -s nullglob
    conduit_upgrade_transactions=("$conduit_upgrade_root"/*)
    shopt -u nullglob
    for conduit_transaction in "${conduit_upgrade_transactions[@]}"; do
      conduit_transaction_name="$(basename "$conduit_transaction")"
      [[ "$conduit_transaction_name" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ && \
          -d "$conduit_transaction" && ! -L "$conduit_transaction" && \
          "$(stat -c '%u' "$conduit_transaction")" = "$conduit_upgrade_owner" ]] || {
        echo "unsafe privileged update transaction during purge" >&2
        exit 4
      }
      shopt -s nullglob
      conduit_transaction_entries=("$conduit_transaction"/*)
      shopt -u nullglob
      for conduit_entry in "${conduit_transaction_entries[@]}"; do
        conduit_entry_name="$(basename "$conduit_entry")"
        case "$conduit_entry_name" in
          candidate.socket|candidate.service|previous-helper|previous-exec|previous-socket|previous-service|pre-update-status.json|result) ;;
          *) echo "unknown privileged update evidence during purge" >&2; exit 4 ;;
        esac
        [[ -f "$conduit_entry" && ! -L "$conduit_entry" && \
            "$(stat -c '%u' "$conduit_entry")" = "$conduit_upgrade_owner" ]] || {
          echo "unsafe privileged update evidence during purge" >&2
          exit 4
        }
        rm -f -- "$conduit_entry"
      done
      rmdir -- "$conduit_transaction"
    done
    rmdir -- "$conduit_upgrade_root"
  fi

  # Per-UID purge removes each custody directory. A base authority lock can
  # remain after package-level diagnostics; remove only that fixed file after
  # every Runtime is terminal and all helper state has been purged.
  conduit_base_authority_lock="$(conduit_privileged_target "$conduit_privileged_state_dir")/authority.lock"
  if [[ -e "$conduit_base_authority_lock" || -L "$conduit_base_authority_lock" ]]; then
    conduit_base_lock_owner=0
    [[ -z "$conduit_privileged_destdir" ]] || conduit_base_lock_owner="$(id -u)"
    [[ -f "$conduit_base_authority_lock" && ! -L "$conduit_base_authority_lock" && \
        "$(stat -c '%u' "$conduit_base_authority_lock")" = "$conduit_base_lock_owner" && \
        "$(stat -c '%a' "$conduit_base_authority_lock")" = 600 ]] || {
      echo "unsafe privileged package authority lock during purge" >&2
      exit 4
    }
    rm -f -- "$conduit_base_authority_lock"
  fi
fi

for conduit_target in \
  "$conduit_privileged_helper" \
  "$conduit_privileged_exec" \
  "$conduit_privileged_socket_unit" \
  "$conduit_privileged_service_unit"; do
  conduit_privileged_assert_no_symlink_components "$conduit_target"
  rm -f -- "$conduit_target"
done
conduit_privileged_daemon_reload
if [[ -z "$conduit_privileged_destdir" ]]; then
  rmdir -- /run/conduit/privileged /run/conduit 2>/dev/null || true
fi

if ((conduit_purge)); then
  # The installed helper performed the destructive deletion while it still had
  # its validated root-owned manifest. Only empty package directories are
  # removed here; broad recursive shell deletion is intentionally absent.
  rmdir -- \
    "$(conduit_privileged_target "$conduit_privileged_config_dir")" \
    "$(conduit_privileged_target "$conduit_privileged_state_dir")" \
    "$(conduit_privileged_target "$conduit_privileged_libexec_dir")" 2>/dev/null || true
  echo "removed privileged helper package and explicitly purged helper state"
else
  echo "removed privileged helper binaries and systemd units"
  echo "retained root policy: $(conduit_privileged_target "$conduit_privileged_config_dir")"
  echo "retained helper keys and durable journal: $(conduit_privileged_target "$conduit_privileged_state_dir")"
fi
