#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$conduit_root"

cargo test --locked --workspace --test e2e_linux 2>/dev/null || {
  echo "Rust Linux E2E target is not available or failed" >&2
  exit 1
}

if corepack pnpm --filter @conduit/control-plane run | grep -q 'test:e2e'; then
  corepack pnpm --filter @conduit/control-plane test:e2e
else
  echo "Control Plane E2E script is unavailable" >&2
  exit 1
fi

for conduit_live in docker podman incus; do
  if ! command -v "$conduit_live" >/dev/null 2>&1; then
    echo "LIVE SKIP $conduit_live: executable not installed"
  fi
done

for conduit_agent in codex claude opencode pi agy; do
  if ! command -v "$conduit_agent" >/dev/null 2>&1; then
    echo "LIVE SKIP $conduit_agent: executable not installed"
  fi
done

echo "Paid Agent inference is opt-in and was not started by this script."
