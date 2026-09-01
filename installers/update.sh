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
[[ -z "${DESTDIR:-}" ]] || { echo "updates cannot use DESTDIR" >&2; exit 2; }
conduit_set_paths
[[ -n "$conduit_runtime_home" ]] || { echo "XDG_RUNTIME_DIR is required for an update" >&2; exit 2; }

for conduit_dir in "$conduit_config_dir" "$conduit_state_dir" "$conduit_data_dir" "$conduit_cache_dir"; do
  conduit_assert_not_symlink "$conduit_dir"
  install -d -m 0700 "$conduit_dir"
  chmod 0700 "$conduit_dir"
  conduit_require_owner_only "$conduit_dir" directory
done
if [[ -e "$conduit_config_dir/node.env" || -L "$conduit_config_dir/node.env" ]]; then
  conduit_require_owner_only "$conduit_config_dir/node.env" file
fi

conduit_source_bin="${CONDUIT_BUILD_DIR:-$conduit_root/target/release}"
conduit_unit="$conduit_systemd_dir/conduit-node.service"
for conduit_binary in conduit conduit-node; do
  [[ -x "$conduit_source_bin/$conduit_binary" && -f "$conduit_source_bin/$conduit_binary" ]] || {
    echo "missing candidate release binary: $conduit_source_bin/$conduit_binary" >&2
    exit 4
  }
  [[ -x "$conduit_bindir/$conduit_binary" && -f "$conduit_bindir/$conduit_binary" && ! -L "$conduit_bindir/$conduit_binary" ]] || {
    echo "installed binary is missing or unsafe: $conduit_bindir/$conduit_binary" >&2
    exit 4
  }
done
[[ -f "$conduit_unit" && ! -L "$conduit_unit" ]] || {
  echo "installed service unit is missing or unsafe: $conduit_unit" >&2
  exit 4
}
conduit_require_owner_only "$conduit_unit" file

conduit_current_version="$(conduit_version "$conduit_bindir/conduit")" || {
  echo "cannot determine installed Conduit version" >&2
  exit 4
}
conduit_candidate_version="$(conduit_version "$conduit_source_bin/conduit")" || {
  echo "cannot determine candidate Conduit version" >&2
  exit 4
}
if conduit_version_is_downgrade "$conduit_current_version" "$conduit_candidate_version"; then
  echo "downgrade refused: installed $conduit_current_version, candidate $conduit_candidate_version" >&2
  echo "restore a schema-compatible backup explicitly instead of overwriting newer state" >&2
  exit 3
fi
"$conduit_source_bin/conduit-node" --help >/dev/null

conduit_upgrades_dir="$conduit_state_dir/upgrades"
conduit_assert_not_symlink "$conduit_upgrades_dir"
install -d -m 0700 "$conduit_upgrades_dir"
chmod 0700 "$conduit_upgrades_dir"
conduit_require_owner_only "$conduit_upgrades_dir" directory
conduit_lock="$conduit_state_dir/update.lock"
if ! mkdir -m 0700 "$conduit_lock" 2>/dev/null; then
  echo "another Conduit update is already in progress: $conduit_lock" >&2
  exit 3
fi
trap 'rmdir -- "$conduit_lock" 2>/dev/null' EXIT

conduit_transaction_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
conduit_transaction="$conduit_upgrades_dir/$conduit_transaction_id"
mkdir -m 0700 "$conduit_transaction"
conduit_backup_manifest=""

conduit_active=0
conduit_service_stopped=0
conduit_replacement_started=0
conduit_probe_pid=""
conduit_probe_runtime=""
conduit_env_created=0

conduit_restore_file() {
  local conduit_saved="$1"
  local conduit_target="$2"
  local conduit_mode="$3"
  if [[ -f "$conduit_saved" ]]; then
    conduit_atomic_install "$conduit_saved" "$conduit_target" "$conduit_mode"
  fi
}

conduit_rollback() {
  local conduit_status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$conduit_probe_pid" ]]; then
    kill "$conduit_probe_pid" 2>/dev/null
    wait "$conduit_probe_pid" 2>/dev/null
  fi
  if [[ -n "$conduit_probe_runtime" ]]; then
    rmdir -- "$conduit_probe_runtime/conduit" "$conduit_probe_runtime" 2>/dev/null
  fi
  if ((conduit_status != 0 && conduit_replacement_started)); then
    conduit_systemctl stop conduit-node.service >/dev/null 2>&1
    conduit_restore_file "$conduit_transaction/previous-conduit" "$conduit_bindir/conduit" 0755
    conduit_restore_file "$conduit_transaction/previous-conduit-node" "$conduit_bindir/conduit-node" 0755
    conduit_restore_file "$conduit_transaction/previous-conduit-node.service" "$conduit_unit" 0600
    if ((conduit_env_created)); then
      rm -f -- "$conduit_config_dir/node.env"
    fi
    if [[ -d "$conduit_data_dir" ]]; then
      mv -- "$conduit_data_dir" "$conduit_transaction/failed-data"
    fi
    if [[ -f "$conduit_transaction/data-was-absent" ]]; then
      :
    else
      install -d -m 0700 "$conduit_data_dir"
      cp -a -- "$conduit_transaction/rollback-data/." "$conduit_data_dir/"
      chmod 0700 "$conduit_data_dir"
    fi
    conduit_systemctl daemon-reload >/dev/null 2>&1
  fi
  if ((conduit_status != 0 && conduit_active && conduit_service_stopped)); then
    if conduit_systemctl start conduit-node.service >/dev/null 2>&1; then
      if ! conduit_wait_healthy "$conduit_bindir/conduit" >/dev/null 2>&1; then
        echo "rollback restored files and data, but the previous service is unhealthy" >&2
      fi
    else
      echo "rollback restored files and data, but the previous service did not start" >&2
    fi
  fi
  if ((conduit_status != 0)); then
    printf 'failed\n' > "$conduit_transaction/result"
    chmod 0600 "$conduit_transaction/result"
    echo "update failed; rollback evidence retained at $conduit_transaction" >&2
  fi
  rmdir -- "$conduit_lock" 2>/dev/null
  exit "$conduit_status"
}
trap conduit_rollback EXIT
trap 'exit 130' INT TERM

if conduit_systemctl is-active --quiet conduit-node.service; then
  conduit_active=1
else
  conduit_status=$?
  [[ $conduit_status -eq 3 || $conduit_status -eq 4 ]] || exit "$conduit_status"
fi

if ((conduit_active)); then
  conduit_backup_create="$($conduit_bindir/conduit --output json backup create --data '{}')"
  printf '%s\n' "$conduit_backup_create" > "$conduit_transaction/backup-create.json"
  chmod 0600 "$conduit_transaction/backup-create.json"
  conduit_backup_id="$(sed -nE 's/.*"backupId"[[:space:]]*:[[:space:]]*"([^"[:space:]]+)".*/\1/p' "$conduit_transaction/backup-create.json")"
  [[ "$conduit_backup_id" =~ ^backup_[A-Za-z0-9._:-]+$ ]] || {
    echo "live Node backup did not return a valid backupId" >&2
    exit 4
  }
  conduit_backup_manifest="$(sed -nE 's/.*"manifestPath"[[:space:]]*:[[:space:]]*"([^"[:cntrl:]]+)".*/\1/p' "$conduit_transaction/backup-create.json")"
  [[ "$conduit_backup_manifest" == /* && -f "$conduit_backup_manifest" && ! -L "$conduit_backup_manifest" ]] || {
    echo "live Node backup did not return an existing absolute regular manifestPath" >&2
    exit 4
  }
  conduit_require_owner_only "$conduit_backup_manifest" file
  conduit_backup_verify="$($conduit_bindir/conduit --output json backup verify --data "{\"backupId\":\"$conduit_backup_id\"}")"
  printf '%s\n' "$conduit_backup_verify" > "$conduit_transaction/backup-verify.json"
  chmod 0600 "$conduit_transaction/backup-verify.json"
  grep -Eq '"verified"[[:space:]]*:[[:space:]]*true' "$conduit_transaction/backup-verify.json" || {
    echo "live Node backup verification did not produce a verified receipt" >&2
    exit 4
  }
  conduit_verified_backup_id="$(sed -nE 's/.*"backupId"[[:space:]]*:[[:space:]]*"([^"[:space:]]+)".*/\1/p' "$conduit_transaction/backup-verify.json")"
  [[ "$conduit_verified_backup_id" == "$conduit_backup_id" ]] || {
    echo "backup verification receipt did not match the created backup" >&2
    exit 4
  }
  conduit_verified_manifest="$(sed -nE 's/.*"manifestPath"[[:space:]]*:[[:space:]]*"([^"[:cntrl:]]+)".*/\1/p' "$conduit_transaction/backup-verify.json")"
  [[ "$conduit_verified_manifest" == "$conduit_backup_manifest" ]] || {
    echo "backup verification manifest did not match the created backup" >&2
    exit 4
  }
fi

conduit_systemctl stop conduit-node.service
conduit_service_stopped=1

conduit_atomic_install "$conduit_bindir/conduit" "$conduit_transaction/previous-conduit" 0755
conduit_atomic_install "$conduit_bindir/conduit-node" "$conduit_transaction/previous-conduit-node" 0755
conduit_atomic_install "$conduit_unit" "$conduit_transaction/previous-conduit-node.service" 0600
install -d -m 0700 "$conduit_transaction/rollback-data"
if [[ -d "$conduit_data_dir" ]]; then
  cp -a -- "$conduit_data_dir/." "$conduit_transaction/rollback-data/"
else
  printf 'absent\n' > "$conduit_transaction/data-was-absent"
  chmod 0600 "$conduit_transaction/data-was-absent"
fi

# Open and migrate a disposable copy first. This is the schema compatibility
# check; the live state remains untouched until the candidate serves IPC here.
conduit_probe_data="$conduit_transaction/probe-data"
conduit_probe_runtime="$conduit_runtime_home/conduit-update-$$"
install -d -m 0700 "$conduit_probe_data" "$conduit_probe_runtime"
if [[ ! -f "$conduit_transaction/data-was-absent" ]]; then
  cp -a -- "$conduit_transaction/rollback-data/." "$conduit_probe_data/"
fi
"$conduit_source_bin/conduit-node" serve \
  --data-dir "$conduit_probe_data" \
  --socket "$conduit_probe_runtime/conduit/node.sock" \
  --launch-profiles "$conduit_config_dir/launch-profiles.json" &
conduit_probe_pid=$!
XDG_RUNTIME_DIR="$conduit_probe_runtime" conduit_wait_healthy "$conduit_source_bin/conduit"
kill "$conduit_probe_pid"
wait "$conduit_probe_pid" 2>/dev/null || true
conduit_probe_pid=""
rmdir -- "$conduit_probe_runtime/conduit" "$conduit_probe_runtime" 2>/dev/null || true
conduit_probe_runtime=""

conduit_unit_tmp="$conduit_transaction/candidate-conduit-node.service"
sed "s|@BINDIR@|$conduit_bindir|g" \
  "$conduit_root/packaging/systemd/conduit-node.service" > "$conduit_unit_tmp"
chmod 0600 "$conduit_unit_tmp"

if [[ ! -e "$conduit_config_dir/node.env" && ! -L "$conduit_config_dir/node.env" ]]; then
  conduit_env_tmp="$conduit_transaction/candidate-node.env"
  conduit_render_node_env > "$conduit_env_tmp"
  chmod 0600 "$conduit_env_tmp"
  conduit_atomic_install "$conduit_env_tmp" "$conduit_config_dir/node.env" 0600
  conduit_env_created=1
fi

conduit_replacement_started=1
conduit_atomic_install "$conduit_source_bin/conduit" "$conduit_bindir/conduit" 0755
conduit_atomic_install "$conduit_source_bin/conduit-node" "$conduit_bindir/conduit-node" 0755
conduit_atomic_install "$conduit_unit_tmp" "$conduit_unit" 0600
conduit_systemctl daemon-reload

if ((conduit_active || conduit_start)); then
  conduit_systemctl start conduit-node.service
  conduit_wait_healthy "$conduit_bindir/conduit"
fi

printf 'complete\n' > "$conduit_transaction/result"
chmod 0600 "$conduit_transaction/result"
trap - EXIT INT TERM
rmdir -- "$conduit_lock"
echo "updated Conduit from $conduit_current_version to $conduit_candidate_version"
if ((conduit_active)); then
  echo "verified pre-upgrade backup manifest retained at $conduit_backup_manifest"
fi
echo "rollback evidence retained at $conduit_transaction"
