#!/usr/bin/env bash

# Shared by the root-helper package scripts. Callers enable strict mode and set
# a restrictive PATH and umask before sourcing this file.

conduit_privileged_fail() {
  echo "$*" >&2
  return 1
}

conduit_privileged_require_absolute() {
  local conduit_name="$1"
  local conduit_path="$2"
  if [[ -z "$conduit_path" || "$conduit_path" != /* || "$conduit_path" =~ [[:cntrl:]] ]]; then
    conduit_privileged_fail "$conduit_name must be an absolute single-line path"
    return 2
  fi
  if [[ "$(realpath -m -- "$conduit_path")" != "$conduit_path" ]]; then
    conduit_privileged_fail "$conduit_name must be normalized without symlink-independent dot components"
    return 2
  fi
}

conduit_privileged_validate_uid() {
  local conduit_uid="$1"
  [[ "$conduit_uid" =~ ^[1-9][0-9]*$ ]] || {
    conduit_privileged_fail "target UID must be a positive decimal UID"
    return 2
  }
  ((10#$conduit_uid <= 4294967294)) || {
    conduit_privileged_fail "target UID is outside the supported range"
    return 2
  }
  getent passwd "$conduit_uid" >/dev/null || {
    conduit_privileged_fail "target UID does not identify a local account"
    return 2
  }
}

conduit_privileged_set_paths() {
  conduit_privileged_require_absolute "install prefix" "$conduit_privileged_prefix"
  if [[ -n "$conduit_privileged_destdir" ]]; then
    conduit_privileged_require_absolute DESTDIR "$conduit_privileged_destdir"
  fi
  conduit_privileged_libexec_dir="$conduit_privileged_prefix/libexec/conduit"
  if [[ -n "$conduit_privileged_destdir" ]]; then
    conduit_privileged_systemd_dir="${CONDUIT_PRIVILEGED_SYSTEMD_DIR:-/usr/lib/systemd/system}"
    conduit_privileged_config_dir="${CONDUIT_PRIVILEGED_CONFIG_DIR:-/etc/conduit/privileged-helper.d}"
    conduit_privileged_state_dir="${CONDUIT_PRIVILEGED_STATE_DIR:-/var/lib/conduit/privileged-helper}"
  else
    # A preserved sudo environment must not redirect root authority or durable
    # custody into an attacker-controlled directory.
    conduit_privileged_systemd_dir=/usr/lib/systemd/system
    conduit_privileged_config_dir=/etc/conduit/privileged-helper.d
    conduit_privileged_state_dir=/var/lib/conduit/privileged-helper
  fi
  conduit_privileged_require_absolute "systemd unit directory" "$conduit_privileged_systemd_dir"
  conduit_privileged_require_absolute "helper policy directory" "$conduit_privileged_config_dir"
  conduit_privileged_require_absolute "helper state directory" "$conduit_privileged_state_dir"
}

conduit_privileged_target() {
  printf '%s%s\n' "$conduit_privileged_destdir" "$1"
}

conduit_privileged_assert_no_symlink_components() {
  local conduit_path="$1"
  local conduit_component
  local conduit_current=""
  local -a conduit_components
  conduit_privileged_require_absolute path "$conduit_path"
  IFS=/ read -r -a conduit_components <<< "${conduit_path#/}"
  for conduit_component in "${conduit_components[@]}"; do
    [[ -n "$conduit_component" ]] || continue
    conduit_current="$conduit_current/$conduit_component"
    if [[ -L "$conduit_current" ]]; then
      conduit_privileged_fail "refusing symlink path component: $conduit_current"
      return 4
    fi
  done
}

conduit_privileged_assert_root_custody() {
  local conduit_path="$1"
  local conduit_component conduit_uid conduit_mode
  local conduit_current=""
  local -a conduit_components
  [[ -z "$conduit_privileged_destdir" ]] || return 0
  IFS=/ read -r -a conduit_components <<< "${conduit_path#/}"
  for conduit_component in "${conduit_components[@]}"; do
    [[ -n "$conduit_component" ]] || continue
    conduit_current="$conduit_current/$conduit_component"
    [[ -e "$conduit_current" ]] || break
    conduit_privileged_assert_no_symlink_components "$conduit_current"
    conduit_uid="$(stat -c '%u' -- "$conduit_current")"
    conduit_mode="$(stat -c '%a' -- "$conduit_current")"
    if [[ "$conduit_uid" != 0 || $((8#$conduit_mode & 8#022)) -ne 0 ]]; then
      conduit_privileged_fail "root package path is not root-owned and non-writable by group/other: $conduit_current"
      return 4
    fi
  done
}

conduit_privileged_require_root_or_destdir() {
  if [[ -z "$conduit_privileged_destdir" && "$(id -u)" != 0 ]]; then
    conduit_privileged_fail "the privileged package operation requires an explicit local root action"
    return 3
  fi
}

conduit_privileged_prepare_directory() {
  local conduit_path="$1"
  local conduit_mode="$2"
  conduit_privileged_assert_no_symlink_components "$conduit_path"
  install -d -m "$conduit_mode" -- "$conduit_path"
  chmod "$conduit_mode" -- "$conduit_path"
  if [[ -z "$conduit_privileged_destdir" ]]; then
    chown root:root -- "$conduit_path"
    conduit_privileged_assert_root_custody "$conduit_path"
  fi
}

conduit_privileged_atomic_install() {
  local conduit_source="$1"
  local conduit_target="$2"
  local conduit_mode="$3"
  local conduit_stage
  [[ -f "$conduit_source" && ! -L "$conduit_source" ]] || {
    conduit_privileged_fail "package source must be a regular non-symlink: $conduit_source"
    return 4
  }
  conduit_privileged_assert_no_symlink_components "$conduit_target"
  conduit_stage="$(mktemp "$(dirname "$conduit_target")/.conduit-privileged-install.XXXXXXXX")"
  if [[ -z "$conduit_privileged_destdir" ]]; then
    if ! install -o root -g root -m "$conduit_mode" -- "$conduit_source" "$conduit_stage"; then
      rm -f -- "$conduit_stage"
      return 1
    fi
  else
    if ! install -m "$conduit_mode" -- "$conduit_source" "$conduit_stage"; then
      rm -f -- "$conduit_stage"
      return 1
    fi
  fi
  if ! sync -f "$conduit_stage" || ! mv -T -- "$conduit_stage" "$conduit_target"; then
    rm -f -- "$conduit_stage"
    return 1
  fi
  sync -f "$(dirname "$conduit_target")"
}

conduit_privileged_render_unit() {
  local conduit_source="$1"
  local conduit_target="$2"
  sed "s|@LIBEXECDIR@|$conduit_privileged_libexec_dir|g" "$conduit_source" > "$conduit_target"
  chmod 0644 "$conduit_target"
}

conduit_privileged_package_status() {
  local conduit_helper="$1"
  local conduit_uid="${2:-}"
  local conduit_output
  local -a conduit_status_args=(admin package-status --output json)
  if [[ -n "$conduit_uid" ]]; then
    conduit_status_args+=(--uid "$conduit_uid")
  fi
  conduit_output="$($conduit_helper "${conduit_status_args[@]}")" || {
    conduit_privileged_fail "installed helper could not report durable package custody"
    return 4
  }
  ((${#conduit_output} <= 65536)) || {
    conduit_privileged_fail "installed helper package status exceeded the bounded response"
    return 4
  }
  [[ "$conduit_output" =~ \"activeRuntimeCount\"[[:space:]]*:[[:space:]]*(0|[1-9][0-9]*) ]] || {
    conduit_privileged_fail "installed helper package status omitted activeRuntimeCount"
    return 4
  }
  conduit_privileged_active_runtime_count="${BASH_REMATCH[1]}"
  conduit_privileged_package_status_json="$conduit_output"
}

conduit_privileged_daemon_reload() {
  [[ -n "$conduit_privileged_destdir" ]] || systemctl daemon-reload
}

conduit_privileged_package_paths() {
  conduit_privileged_helper="$(conduit_privileged_target "$conduit_privileged_libexec_dir/conduit-privileged-helper")"
  conduit_privileged_exec="$(conduit_privileged_target "$conduit_privileged_libexec_dir/conduit-privileged-exec")"
  conduit_privileged_socket_unit="$(conduit_privileged_target "$conduit_privileged_systemd_dir/conduit-privileged-helper@.socket")"
  conduit_privileged_service_unit="$(conduit_privileged_target "$conduit_privileged_systemd_dir/conduit-privileged-helper@.service")"
}
