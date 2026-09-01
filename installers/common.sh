#!/usr/bin/env bash

# Shared by the Linux installer scripts. Callers enable `set -euo pipefail`.

conduit_require_absolute() {
  local conduit_name="$1"
  local conduit_path="$2"
  if [[ -z "$conduit_path" || "$conduit_path" != /* || "$conduit_path" == *$'\n'* ]]; then
    echo "$conduit_name must be an absolute single-line path" >&2
    return 2
  fi
}

conduit_set_paths() {
  : "${HOME:?HOME is required}"
  conduit_require_absolute HOME "$HOME"
  conduit_config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
  conduit_state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
  conduit_data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
  conduit_cache_home="${XDG_CACHE_HOME:-$HOME/.cache}"
  conduit_runtime_home="${XDG_RUNTIME_DIR:-}"
  conduit_require_absolute XDG_CONFIG_HOME "$conduit_config_home"
  conduit_require_absolute XDG_STATE_HOME "$conduit_state_home"
  conduit_require_absolute XDG_DATA_HOME "$conduit_data_home"
  conduit_require_absolute XDG_CACHE_HOME "$conduit_cache_home"
  if [[ -n "$conduit_runtime_home" ]]; then
    conduit_require_absolute XDG_RUNTIME_DIR "$conduit_runtime_home"
  fi

  conduit_bindir="$conduit_prefix/bin"
  conduit_systemd_dir="$conduit_config_home/systemd/user"
  conduit_config_dir="$conduit_config_home/conduit"
  conduit_state_dir="$conduit_state_home/conduit"
  conduit_data_dir="$conduit_data_home/conduit"
  conduit_cache_dir="$conduit_cache_home/conduit"
}

conduit_assert_not_symlink() {
  local conduit_path="$1"
  if [[ -L "$conduit_path" ]]; then
    echo "refusing to replace symlink: $conduit_path" >&2
    return 4
  fi
}

conduit_require_owner_only() {
  local conduit_path="$1"
  local conduit_kind="$2"
  local conduit_uid conduit_mode
  conduit_assert_not_symlink "$conduit_path"
  if [[ "$conduit_kind" == directory ]]; then
    [[ -d "$conduit_path" ]] || { echo "required directory is unavailable: $conduit_path" >&2; return 4; }
  else
    [[ -f "$conduit_path" ]] || { echo "required regular file is unavailable: $conduit_path" >&2; return 4; }
  fi
  conduit_uid="$(stat -c '%u' "$conduit_path")"
  conduit_mode="$(stat -c '%a' "$conduit_path")"
  if [[ "$conduit_uid" != "$(id -u)" ]] || ((8#$conduit_mode & 8#077)); then
    echo "path must be owned by the current user and owner-only: $conduit_path" >&2
    return 4
  fi
}

conduit_atomic_install() {
  local conduit_source="$1"
  local conduit_target="$2"
  local conduit_mode="$3"
  local conduit_stage
  conduit_assert_not_symlink "$conduit_target"
  conduit_stage="$(mktemp "$(dirname "$conduit_target")/.conduit-install.XXXXXXXX")"
  if ! install -m "$conduit_mode" "$conduit_source" "$conduit_stage"; then
    rm -f -- "$conduit_stage"
    return 1
  fi
  mv -f -- "$conduit_stage" "$conduit_target"
}

conduit_environment_value() {
  local conduit_value="$1"
  conduit_value="${conduit_value//\\/\\\\}"
  conduit_value="${conduit_value//\"/\\\"}"
  printf '"%s"' "$conduit_value"
}

conduit_render_node_env() {
  printf 'CONDUIT_DATA_DIR=%s\n' "$(conduit_environment_value "$conduit_data_dir")"
  if [[ -n "$conduit_runtime_home" ]]; then
    printf 'CONDUIT_SOCKET=%s\n' "$(conduit_environment_value "$conduit_runtime_home/conduit/node.sock")"
  fi
  printf 'CONDUIT_LAUNCH_PROFILES=%s\n' \
    "$(conduit_environment_value "$conduit_config_dir/launch-profiles.json")"
}

conduit_systemctl() {
  "${CONDUIT_SYSTEMCTL:-systemctl}" --user "$@"
}

conduit_wait_healthy() {
  local conduit_cli="$1"
  local conduit_attempts="${CONDUIT_HEALTH_ATTEMPTS:-50}"
  local conduit_count=0
  while ((conduit_count < conduit_attempts)); do
    if "$conduit_cli" --output json --timeout-seconds 2 device doctor >/dev/null 2>&1; then
      return 0
    fi
    conduit_count=$((conduit_count + 1))
    sleep 0.1
  done
  echo "conduit-node did not return a healthy local IPC receipt" >&2
  return 1
}

conduit_version() {
  local conduit_binary="$1"
  local conduit_output
  conduit_output="$($conduit_binary --version 2>/dev/null)" || return 1
  if [[ "$conduit_output" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  else
    return 1
  fi
}

conduit_version_is_downgrade() {
  local conduit_current="$1"
  local conduit_candidate="$2"
  local conduit_current_parts conduit_candidate_parts conduit_index
  IFS=. read -r -a conduit_current_parts <<< "$conduit_current"
  IFS=. read -r -a conduit_candidate_parts <<< "$conduit_candidate"
  for conduit_index in 0 1 2; do
    if ((10#${conduit_candidate_parts[$conduit_index]} < 10#${conduit_current_parts[$conduit_index]})); then
      return 0
    fi
    if ((10#${conduit_candidate_parts[$conduit_index]} > 10#${conduit_current_parts[$conduit_index]})); then
      return 1
    fi
  done
  return 1
}
