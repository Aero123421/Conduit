#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$conduit_root"

conduit_confirm=0
conduit_control_url="${CONDUIT_FULL_DEVICE_E2E_CONTROL_URL:-}"
while (($#)); do
  case "$1" in
    --i-understand-this-runs-reviewed-code-as-root)
      conduit_confirm=1
      shift
      ;;
    --control-url)
      (($# >= 2)) || { echo "--control-url requires a value" >&2; exit 2; }
      conduit_control_url="$2"
      shift 2
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

((conduit_confirm)) || {
  echo "live Full Device E2E requires --i-understand-this-runs-reviewed-code-as-root" >&2
  exit 2
}
[[ "$conduit_control_url" =~ ^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$ ]] || {
  echo "CONDUIT_FULL_DEVICE_E2E_CONTROL_URL must be the exact HTTPS test origin" >&2
  exit 2
}
conduit_device_id="${CONDUIT_FULL_DEVICE_E2E_DEVICE_ID:-}"
[[ "$conduit_device_id" =~ ^dev_[A-Za-z0-9_-]{8,120}$ ]] || {
  echo "CONDUIT_FULL_DEVICE_E2E_DEVICE_ID must identify the isolated test Device" >&2
  exit 2
}
if [[ -n "${CONDUIT_FULL_DEVICE_E2E_CONTROL_CREDENTIAL_FILE:-}" ]]; then
  conduit_credential_file="$CONDUIT_FULL_DEVICE_E2E_CONTROL_CREDENTIAL_FILE"
  [[ "$conduit_credential_file" == /* && -f "$conduit_credential_file" && ! -L "$conduit_credential_file" ]] || {
    echo "control credential file must be an absolute regular non-symlink" >&2
    exit 2
  }
  test "$(stat -c '%u:%a' "$conduit_credential_file")" = "$(id -u):600" || {
    echo "control credential file must be owned by the Device user with mode 0600" >&2
    exit 2
  }
fi
[[ "$(hostname)" == "${CONDUIT_FULL_DEVICE_E2E_HOSTNAME:-sahur-pc}" ]] || {
  echo "live Full Device E2E is restricted to the explicitly selected host" >&2
  exit 3
}
[[ "$(id -u)" != 0 ]] || { echo "run the orchestrator as the Device user, not root" >&2; exit 3; }
[[ "$(cat /proc/1/comm)" == systemd ]] || { echo "system systemd is not PID 1" >&2; exit 4; }
sudo -n true || { echo "non-interactive local root authorization is unavailable" >&2; exit 4; }
systemctl is-system-running --quiet || { echo "system systemd is not running" >&2; exit 4; }
busctl --system introspect org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager --no-pager | grep -F StartTransientUnit >/dev/null || {
    echo "system systemd does not expose the typed transient-unit API" >&2
    exit 4
  }
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || {
  echo "unified cgroup v2 is unavailable" >&2
  exit 4
}

if [[ -n "$(git status --porcelain=v1)" ]]; then
  echo "live evidence requires a clean exact PR head" >&2
  exit 3
fi
conduit_commit="$(git rev-parse HEAD)"
if [[ -n "${CONDUIT_FULL_DEVICE_E2E_EXPECTED_COMMIT:-}" && \
      "$conduit_commit" != "$CONDUIT_FULL_DEVICE_E2E_EXPECTED_COMMIT" ]]; then
  echo "checked-out commit does not match CONDUIT_FULL_DEVICE_E2E_EXPECTED_COMMIT" >&2
  exit 3
fi
conduit_public_evidence_dir="${CONDUIT_FULL_DEVICE_E2E_PUBLIC_REPORT_DIR:-$conduit_root/.conduit/evidence/full-device-$conduit_commit}"
[[ "$conduit_public_evidence_dir" == /* && ! -e "$conduit_public_evidence_dir" && ! -L "$conduit_public_evidence_dir" ]] || {
  echo "public report directory must be a new absolute path" >&2
  exit 2
}

for conduit_existing in \
  /usr/libexec/conduit \
  /usr/lib/systemd/system/conduit-privileged-helper@.socket \
  /usr/lib/systemd/system/conduit-privileged-helper@.service \
  /etc/conduit/privileged-helper.d \
  /var/lib/conduit/privileged-helper \
  /run/conduit/privileged; do
  if sudo -n test -e "$conduit_existing" || sudo -n test -L "$conduit_existing"; then
    echo "refusing to touch a pre-existing privileged helper installation" >&2
    exit 3
  fi
done

# Compile both the live driver and every installed binary before creating root
# state. There is no fallback to a fake helper when these targets are absent.
cargo build --locked --release \
  --bin conduit \
  --bin conduit-node \
  --bin conduit-privileged-helper \
  --bin conduit-privileged-exec
cargo test --locked -p conduit-node --test full_device_live --no-run

conduit_user_evidence="$(mktemp -d -t conduit-full-device-evidence-XXXXXXXX)"
conduit_root_parent=/var/lib/conduit-full-device-e2e
sudo -n install -d -o root -g root -m 0700 "$conduit_root_parent"
conduit_root_stage="$(sudo -n mktemp -d "$conduit_root_parent/run.XXXXXXXX")"
[[ "$conduit_root_stage" == "$conduit_root_parent"/run.* ]] || {
  echo "root staging path escaped the dedicated E2E parent" >&2
  exit 4
}
conduit_package_root="$conduit_root_stage/package"
conduit_cleanup_started=0

conduit_cleanup() {
  local conduit_status=$?
  trap - EXIT INT TERM
  set +e
  conduit_cleanup_package_ok=1
  if ((conduit_cleanup_started)); then
    if sudo -n test -x /usr/libexec/conduit/conduit-privileged-helper; then
      sudo -n "$conduit_package_root/installers/uninstall-privileged.sh" \
        --terminate-active --purge \
        --confirm-purge DELETE-CONDUIT-PRIVILEGED-STATE >/dev/null 2>&1 || \
        conduit_cleanup_package_ok=0
    fi
  fi
  if ((conduit_cleanup_package_ok)) && sudo -n test -d "$conduit_root_stage"; then
    sudo -n find "$conduit_root_stage" -xdev -depth -delete
  fi
  if ((conduit_cleanup_package_ok)); then
    sudo -n systemctl reset-failed 'conduit-elevated-live-*' >/dev/null 2>&1 || true
    sudo -n rmdir "$conduit_root_parent" >/dev/null 2>&1 || true
  else
    echo "automatic cleanup could not prove terminal custody; root staging was retained for explicit recovery" >&2
  fi
  if [[ -d "$conduit_user_evidence" ]]; then
    find "$conduit_user_evidence" -xdev -depth -delete
  fi
  exit "$conduit_status"
}
trap conduit_cleanup EXIT
trap 'exit 130' INT TERM

sudo -n install -d -o root -g root -m 0700 \
  "$conduit_package_root" \
  "$conduit_package_root/bin" \
  "$conduit_package_root/installers" \
  "$conduit_package_root/packaging" \
  "$conduit_package_root/packaging/systemd"
for conduit_script in privileged-common.sh install-privileged.sh update-privileged.sh uninstall-privileged.sh; do
  sudo -n install -o root -g root -m 0755 \
    "$conduit_root/installers/$conduit_script" \
    "$conduit_package_root/installers/$conduit_script"
done
for conduit_unit in conduit-privileged-helper@.socket conduit-privileged-helper@.service; do
  sudo -n install -o root -g root -m 0644 \
    "$conduit_root/packaging/systemd/$conduit_unit" \
    "$conduit_package_root/packaging/systemd/$conduit_unit"
done
for conduit_binary in conduit-privileged-helper conduit-privileged-exec; do
  sudo -n install -o root -g root -m 0755 \
    "$conduit_root/target/release/$conduit_binary" \
    "$conduit_package_root/bin/$conduit_binary"
done
sudo -n find "$conduit_package_root" -xdev \
  \( -type d -o -type f \) ! -user root -print -quit | grep -q . && {
    echo "root staging ownership verification failed" >&2
    exit 4
  }

conduit_cleanup_started=1
sudo -n env CONDUIT_BUILD_DIR="$conduit_package_root/bin" \
  "$conduit_package_root/installers/install-privileged.sh"

conduit_helper=/usr/libexec/conduit/conduit-privileged-helper
export CONDUIT_FULL_DEVICE_E2E=1
export CONDUIT_FULL_DEVICE_E2E_COMMIT="$conduit_commit"
export CONDUIT_FULL_DEVICE_E2E_CONTROL_URL="$conduit_control_url"
export CONDUIT_FULL_DEVICE_E2E_DEVICE_ID="$conduit_device_id"
export CONDUIT_FULL_DEVICE_E2E_UID="$(id -u)"
export CONDUIT_FULL_DEVICE_E2E_HELPER="$conduit_helper"
export CONDUIT_FULL_DEVICE_E2E_EXEC=/usr/libexec/conduit/conduit-privileged-exec
export CONDUIT_FULL_DEVICE_E2E_SOCKET="/run/conduit/privileged/$(id -u).sock"
export CONDUIT_FULL_DEVICE_E2E_PACKAGE_ROOT="$conduit_package_root"
export CONDUIT_FULL_DEVICE_E2E_INSTALLER="$conduit_package_root/installers/install-privileged.sh"
export CONDUIT_FULL_DEVICE_E2E_UPDATER="$conduit_package_root/installers/update-privileged.sh"
export CONDUIT_FULL_DEVICE_E2E_UNINSTALLER="$conduit_package_root/installers/uninstall-privileged.sh"
export CONDUIT_FULL_DEVICE_E2E_EVIDENCE_DIR="$conduit_user_evidence"
export CONDUIT_FULL_DEVICE_E2E_ROOT_STAGE="$conduit_root_stage"

# Create the Device identity as the unprivileged Device user. Only the public
# key is handed to the root helper; the private key remains mode 0600 locally.
export CONDUIT_FULL_DEVICE_E2E_PHASE=bootstrap
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture
conduit_node_public_key="$conduit_user_evidence/node-public.key"
test "$(stat -c '%u:%a:%s' "$conduit_node_public_key")" = \
  "$(id -u):600:32"

conduit_registration_bundle="$conduit_user_evidence/registration-bundle.json"
conduit_prepare_result="$conduit_user_evidence/prepare-result.json"
sudo -n "$conduit_helper" admin prepare \
  --uid "$(id -u)" \
  --device-id "$conduit_device_id" \
  --public-origin "$conduit_control_url" \
  --node-public-key-file "$conduit_node_public_key" \
  --output json > "$conduit_prepare_result"
sudo -n "$conduit_helper" admin registration-bundle \
  --uid "$(id -u)" \
  --output json > "$conduit_registration_bundle"
chmod 0600 "$conduit_registration_bundle"
[[ -s "$conduit_registration_bundle" ]] || {
  echo "root helper did not produce a bounded public registration bundle" >&2
  exit 4
}
(("$(stat -c '%s' "$conduit_registration_bundle")" <= 65536)) || {
  echo "root helper registration bundle exceeded 65536 bytes" >&2
  exit 4
}

export CONDUIT_FULL_DEVICE_E2E_REGISTRATION_BUNDLE="$conduit_registration_bundle"

# The first phase creates and Owner-activates the isolated Control Plane ticket
# issuer, approves the exact helper registration through fresh Passkey, and
# exports only its public key/activation evidence. It cannot change root policy.
export CONDUIT_FULL_DEVICE_E2E_PHASE=registration
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture

conduit_issuer_key="$conduit_user_evidence/issuer-public-key.json"
conduit_issuer_jwk="$conduit_user_evidence/issuer-public-jwk.json"
conduit_registration_approval="$conduit_user_evidence/registration-approval.json"
for conduit_registration_evidence in \
  "$conduit_issuer_key" \
  "$conduit_issuer_jwk" \
  "$conduit_registration_approval"; do
  [[ -f "$conduit_registration_evidence" && ! -L "$conduit_registration_evidence" ]] || {
    echo "registration phase omitted required public activation evidence" >&2
    exit 4
  }
  (("$(stat -c '%s' "$conduit_registration_evidence")" <= 65536)) || {
    echo "registration phase evidence exceeded 65536 bytes" >&2
    exit 4
  }
done
conduit_issuer_fingerprint="$(sed -nE 's/.*"fingerprint"[[:space:]]*:[[:space:]]*"([A-Za-z0-9._:-]{16,256})".*/\1/p' "$conduit_issuer_key")"
[[ "$conduit_issuer_fingerprint" =~ ^[A-Za-z0-9._:-]{16,256}$ ]] || {
  echo "issuer public-key evidence omitted its bounded fingerprint" >&2
  exit 4
}
if grep -Eiq '(private.?key|secret)' "$conduit_issuer_key"; then
  echo "issuer key export contains forbidden private material" >&2
  exit 4
fi
grep -Eq '"status"[[:space:]]*:[[:space:]]*"active"' "$conduit_issuer_key" || {
  echo "privilege-ticket issuer key is not active" >&2
  exit 4
}
grep -Eq '"ownerActivated"[[:space:]]*:[[:space:]]*true' "$conduit_issuer_key" || {
  echo "privilege-ticket issuer lacks Owner activation evidence" >&2
  exit 4
}
conduit_registration_digest="$(sed -nE 's/.*"registrationBundleDigest"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})".*/\1/p' "$conduit_registration_approval")"
[[ "$conduit_registration_digest" =~ ^[0-9a-f]{64}$ ]] || {
  echo "registration approval omitted the canonical bundle digest" >&2
  exit 4
}
grep -Eq "\"deviceId\"[[:space:]]*:[[:space:]]*\"$conduit_device_id\"" \
  "$conduit_registration_approval" || {
    echo "Control Plane approval does not bind the isolated test Device" >&2
    exit 4
  }
grep -Eq '"freshPasskey"[[:space:]]*:[[:space:]]*true' "$conduit_registration_approval" || {
  echo "helper registration was not approved with fresh Passkey evidence" >&2
  exit 4
}
grep -Eq '"status"[[:space:]]*:[[:space:]]*"active"' "$conduit_registration_approval" || {
  echo "helper registration is not active at the isolated Control Plane" >&2
  exit 4
}

# Pinning the issuer and enabling the root policy are separate explicit local
# root actions. Neither action is exposed through the remote Control Plane.
sudo -n "$conduit_helper" admin pin-ticket-key \
  --uid "$(id -u)" \
  --issuer-key-file "$conduit_issuer_jwk" \
  --expected-fingerprint "$conduit_issuer_fingerprint" \
  --output json > "$conduit_user_evidence/root-key-pin.json"
sudo -n "$conduit_helper" admin policy \
  --uid "$(id -u)" \
  --allow-unrestricted-launch true \
  --allowed-adapters codex \
  --allowed-launch-profiles full-device-live \
  --output json > "$conduit_user_evidence/root-policy-opt-in.json"
sudo -n "$conduit_helper" admin enable \
  --uid "$(id -u)" \
  --output json > "$conduit_user_evidence/root-policy-enable.json"
for conduit_root_evidence in \
  "$conduit_user_evidence/root-key-pin.json" \
  "$conduit_user_evidence/root-policy-opt-in.json" \
  "$conduit_user_evidence/root-policy-enable.json"; do
  [[ -s "$conduit_root_evidence" ]] || {
    echo "root setup action omitted its bounded evidence" >&2
    exit 4
  }
  (("$(stat -c '%s' "$conduit_root_evidence")" <= 65536)) || {
    echo "root setup evidence exceeded 65536 bytes" >&2
    exit 4
  }
done
grep -Eq '"pinned"[[:space:]]*:[[:space:]]*true' \
  "$conduit_user_evidence/root-key-pin.json" || {
    echo "root policy did not confirm the exact issuer key pin" >&2
    exit 4
  }
grep -Fq "$conduit_issuer_fingerprint" "$conduit_user_evidence/root-key-pin.json" || {
  echo "root key-pin evidence does not bind the expected fingerprint" >&2
  exit 4
}
grep -Eq '"enabled"[[:space:]]*:[[:space:]]*true' \
  "$conduit_user_evidence/root-policy-enable.json" || {
    echo "root policy did not confirm local enablement" >&2
    exit 4
  }
grep -Eq '"policyRevision"[[:space:]]*:[[:space:]]*[1-9][0-9]*' \
  "$conduit_user_evidence/root-policy-enable.json" || {
  echo "root enable evidence omitted the effective policy revision" >&2
  exit 4
}
grep -Eq '"policyDigest"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' \
  "$conduit_user_evidence/root-policy-enable.json" || {
  echo "root enable evidence omitted the effective policy digest" >&2
  exit 4
}

# Local issuer pinning and opt-in advance the root policy revision. Refresh the
# signed public bundle and repeat the Owner activation boundary so Node never
# activates authority against the earlier disabled policy evidence.
sudo -n "$conduit_helper" admin registration-bundle \
  --uid "$(id -u)" \
  --output json > "$conduit_registration_bundle"
chmod 0600 "$conduit_registration_bundle"
export CONDUIT_FULL_DEVICE_E2E_PHASE=registration
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture
conduit_enabled_policy_digest="$(sed -nE 's/.*"policyDigest"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})".*/\1/p' "$conduit_registration_bundle")"
[[ "$conduit_enabled_policy_digest" =~ ^[0-9a-f]{64}$ ]] || {
  echo "enabled registration bundle omitted policy digest" >&2
  exit 4
}
grep -Eq "\"helperPolicyDigest\"[[:space:]]*:[[:space:]]*\"$conduit_enabled_policy_digest\"" \
  "$conduit_registration_approval" || {
  echo "Owner activation did not bind the enabled root policy attestation" >&2
  exit 4
}

# Full User must remain an ordinary Device-user path. Run it while the system
# helper socket is externally proven inactive so a hidden helper dependency or
# contact cannot produce a false pass.
if systemctl is-active --quiet "conduit-privileged-helper@$(id -u).socket"; then
  echo "privileged helper socket was unexpectedly active before Full User probe" >&2
  exit 4
else
  conduit_socket_status=$?
  [[ $conduit_socket_status -eq 3 || $conduit_socket_status -eq 4 ]] || exit "$conduit_socket_status"
fi
export CONDUIT_FULL_DEVICE_E2E_PHASE=full_user
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture

sudo -n systemctl enable --now "conduit-privileged-helper@$(id -u).socket"
for _ in $(seq 1 100); do
  sudo -n test -S "/run/conduit/privileged/$(id -u).sock" && break
  sleep 0.02
done
sudo -n test -S "/run/conduit/privileged/$(id -u).sock"
test "$(sudo -n stat -c '%u:%a' "/run/conduit/privileged/$(id -u).sock")" = "$(id -u):600"

export CONDUIT_FULL_DEVICE_E2E_PHASE=exercise
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture

# The exercise deliberately leaves one exact elevated Runtime alive. Update
# package files without service activation, prove uninstall fails closed, then
# restart the helper while systemd retains target-process custody. A new Node
# process performs durable attach below.
sudo -n "$conduit_helper" admin package-status --uid "$(id -u)" --output json \
  > "$conduit_user_evidence/active-before-update.json"
grep -Eq '"activeRuntimeCount"[[:space:]]*:[[:space:]]*1' \
  "$conduit_user_evidence/active-before-update.json" || {
  echo "live driver did not retain exactly one active elevated Runtime" >&2
  exit 4
}
sudo -n env CONDUIT_BUILD_DIR="$conduit_package_root/bin" \
  "$conduit_package_root/installers/update-privileged.sh" \
  > "$conduit_user_evidence/active-update.txt"
sudo -n "$conduit_helper" admin package-status --uid "$(id -u)" --output json \
  > "$conduit_user_evidence/active-after-update.json"
grep -Eq '"activeRuntimeCount"[[:space:]]*:[[:space:]]*1' \
  "$conduit_user_evidence/active-after-update.json" || {
  echo "package update lost active elevated Runtime custody" >&2
  exit 4
}

# Force a post-replacement compatibility failure from a root-owned candidate.
# The candidate succeeds only from its staging path, so the installed probe
# fails after replacement and must restore every previous package inode.
conduit_rollback_candidate="$conduit_root_stage/rollback-candidate"
sudo -n install -d -o root -g root -m 0700 "$conduit_rollback_candidate"
conduit_rollback_helper="$conduit_user_evidence/rollback-helper"
printf '%s\n' \
  '#!/bin/sh' \
  'case "$0" in' \
  '  /var/lib/conduit-full-device-e2e/run.*/rollback-candidate/conduit-privileged-helper)' \
  '    [ "$1" = admin ] && [ "$2" = package-check ] && exit 0' \
  '    ;;' \
  'esac' \
  'exit 42' > "$conduit_rollback_helper"
chmod 0700 "$conduit_rollback_helper"
sudo -n install -o root -g root -m 0755 \
  "$conduit_rollback_helper" \
  "$conduit_rollback_candidate/conduit-privileged-helper"
sudo -n install -o root -g root -m 0755 \
  "$conduit_package_root/bin/conduit-privileged-exec" \
  "$conduit_rollback_candidate/conduit-privileged-exec"
conduit_helper_hash_before="$(sudo -n sha256sum /usr/libexec/conduit/conduit-privileged-helper | cut -d' ' -f1)"
set +e
sudo -n env CONDUIT_BUILD_DIR="$conduit_rollback_candidate" \
  "$conduit_package_root/installers/update-privileged.sh" \
  > "$conduit_user_evidence/rollback-update.txt" 2>&1
conduit_rollback_status=$?
set -e
[[ $conduit_rollback_status -eq 4 ]] || {
  echo "live injected update did not fail at the installed compatibility probe" >&2
  exit 4
}
conduit_helper_hash_after="$(sudo -n sha256sum /usr/libexec/conduit/conduit-privileged-helper | cut -d' ' -f1)"
[[ "$conduit_helper_hash_before" = "$conduit_helper_hash_after" ]] || {
  echo "live package rollback did not restore the helper binary" >&2
  exit 4
}
sudo -n find /var/lib/conduit/privileged-helper/package-upgrades \
  -mindepth 2 -maxdepth 2 -type f -name result -exec grep -Fxq rolled_back {} \; -print \
  | grep -F /result >/dev/null || {
  echo "live package rollback omitted durable rolled_back evidence" >&2
  exit 4
}
sudo -n "$conduit_helper" admin package-status --uid "$(id -u)" --output json \
  > "$conduit_user_evidence/active-after-rollback.json"
grep -Eq '"activeRuntimeCount"[[:space:]]*:[[:space:]]*1' \
  "$conduit_user_evidence/active-after-rollback.json" || {
  echo "live package rollback lost active elevated Runtime custody" >&2
  exit 4
}
set +e
sudo -n "$conduit_package_root/installers/uninstall-privileged.sh" \
  > "$conduit_user_evidence/active-uninstall.txt" 2>&1
conduit_active_uninstall_status=$?
set -e
[[ $conduit_active_uninstall_status -eq 3 ]] || {
  echo "uninstall did not fail closed with active elevated Runtime custody" >&2
  exit 4
}
sudo -n systemctl restart "conduit-privileged-helper@$(id -u).service"
sudo -n "$conduit_helper" admin package-status --uid "$(id -u)" --output json \
  > "$conduit_user_evidence/active-after-helper-restart.json"
grep -Eq '"activeRuntimeCount"[[:space:]]*:[[:space:]]*1' \
  "$conduit_user_evidence/active-after-helper-restart.json" || {
  echo "helper restart did not preserve active elevated Runtime custody" >&2
  exit 4
}
conduit_helper_pid="$(systemctl show --property MainPID --value "conduit-privileged-helper@$(id -u).service")"
[[ "$conduit_helper_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo "helper service omitted its live process identity" >&2
  exit 4
}
sudo -n ss -H -a -n -t -u -p > "$conduit_user_evidence/ip-sockets.local"
if grep -F "pid=$conduit_helper_pid," "$conduit_user_evidence/ip-sockets.local" >/dev/null; then
  echo "privileged helper unexpectedly owns an IP socket" >&2
  exit 4
fi
rm -f "$conduit_user_evidence/ip-sockets.local"
printf '%s\n' '{"schemaVersion":1,"activeUpdate":{"passed":true,"custodyBefore":1,"custodyAfter":1,"activationRestarted":false},"rollback":{"passed":true,"postReplacementFailureInjected":true,"previousBinaryRestored":true,"activeCustodyPreserved":true},"activeUninstall":{"passed":true,"refused":true,"exitStatus":3},"helperServiceRestart":{"passed":true,"custodyBefore":1,"custodyAfter":1},"networkIsolation":{"passed":true,"helperIpSockets":0}}' \
  > "$conduit_user_evidence/packaging-live-summary.json"
chmod 0600 "$conduit_user_evidence/packaging-live-summary.json"

export CONDUIT_FULL_DEVICE_E2E_PHASE=recover
cargo test --locked -p conduit-node --test full_device_live \
  -- --ignored --exact full_device_live_systemd_root_e2e --nocapture
sudo -n test ! -e "$conduit_root_stage/root-marker"

conduit_driver_summary="$conduit_user_evidence/driver-summary.json"
[[ -f "$conduit_driver_summary" && ! -L "$conduit_driver_summary" ]] || {
  echo "live driver did not produce driver-summary.json" >&2
  exit 4
}
(("$(stat -c '%s' "$conduit_driver_summary")" <= 262144)) || {
  echo "live driver summary exceeded the public evidence bound" >&2
  exit 4
}
if grep -Eiq '(/home/|machine.?id|boot.?id|hardware.?serial|ip.?address|private.?key|secret|credential|raw.?prompt|canonical.?path)' \
  "$conduit_driver_summary"; then
  echo "live driver summary contains a field forbidden from public OSS evidence" >&2
  exit 4
fi

sudo -n "$conduit_helper" admin package-status --uid "$(id -u)" --output json \
  > "$conduit_user_evidence/final-package-status.json"
grep -Eq '"activeRuntimeCount"[[:space:]]*:[[:space:]]*0' \
  "$conduit_user_evidence/final-package-status.json"
sudo -n systemd-analyze security --no-pager \
  "conduit-privileged-helper@$(id -u).service" \
  > "$conduit_user_evidence/systemd-security.txt"
(("$(stat -c '%s' "$conduit_user_evidence/systemd-security.txt")" <= 262144)) || {
  echo "systemd security evidence exceeded the local bound" >&2
  exit 4
}

# Finish by exercising default state preservation followed by an explicit
# destructive test purge. Transaction rollback is covered by the deterministic
# package test; this live run uses only exact release artifacts from this head.
sudo -n "$conduit_package_root/installers/uninstall-privileged.sh"
sudo -n test -d /var/lib/conduit/privileged-helper
sudo -n test -d /etc/conduit/privileged-helper.d
sudo -n env CONDUIT_BUILD_DIR="$conduit_package_root/bin" \
  "$conduit_package_root/installers/install-privileged.sh"
sudo -n "$conduit_package_root/installers/uninstall-privileged.sh" \
  --purge --confirm-purge DELETE-CONDUIT-PRIVILEGED-STATE
conduit_cleanup_started=0

for conduit_removed in \
  /usr/libexec/conduit \
  /usr/lib/systemd/system/conduit-privileged-helper@.socket \
  /usr/lib/systemd/system/conduit-privileged-helper@.service \
  /etc/conduit/privileged-helper.d \
  /var/lib/conduit/privileged-helper \
  /run/conduit/privileged; do
  if sudo -n test -e "$conduit_removed" || sudo -n test -L "$conduit_removed"; then
    echo "live Full Device E2E cleanup left a managed path" >&2
    exit 4
  fi
done
sudo -n systemctl reset-failed 'conduit-elevated-live-*'
[[ -z "$(systemctl list-units --all 'conduit-elevated-live-*' --no-legend --plain)" ]] || {
  echo "live Full Device E2E cleanup left a transient target unit" >&2
  exit 4
}

conduit_kernel="$(uname -r)"
conduit_systemd="$(systemctl --version | sed -nE '1s/^systemd ([0-9]+).*$/\1/p')"
conduit_os_id="$(sed -nE 's/^ID=([A-Za-z0-9._-]+)$/\1/p' /etc/os-release | head -1)"
conduit_os_version="$(sed -nE 's/^VERSION_ID="?([A-Za-z0-9._-]+)"?$/\1/p' /etc/os-release | head -1)"
for conduit_fact in "$conduit_kernel" "$conduit_systemd" "$conduit_os_id" "$conduit_os_version"; do
  [[ "$conduit_fact" =~ ^[A-Za-z0-9._~+-]+$ ]] || {
    echo "host evidence contained an unexpected representation" >&2
    exit 4
  }
done
printf '{"schemaVersion":1,"hostLabel":"dedicated-linux-e2e","commit":"%s","osId":"%s","osVersion":"%s","kernel":"%s","systemd":"%s","cleanupComplete":true}\n' \
  "$conduit_commit" "$conduit_os_id" "$conduit_os_version" "$conduit_kernel" "$conduit_systemd" \
  > "$conduit_user_evidence/host-summary.json"
install -d -m 0700 "$conduit_public_evidence_dir"
install -m 0600 "$conduit_driver_summary" "$conduit_public_evidence_dir/driver-summary.json"
install -m 0600 "$conduit_user_evidence/host-summary.json" "$conduit_public_evidence_dir/host-summary.json"

echo "Full Device live E2E passed for commit $conduit_commit"
echo "bounded sanitized evidence was retained below the configured public report directory"
