#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$conduit_root"

cargo test --locked --workspace --test e2e_linux

if corepack pnpm --filter @conduit/control-plane run | grep -q 'test:e2e'; then
  corepack pnpm --filter @conduit/control-plane test:e2e
else
  echo "Control Plane E2E script is unavailable" >&2
  exit 1
fi

for conduit_live in docker podman incus; do
  if command -v "$conduit_live" >/dev/null 2>&1; then
    echo "LIVE NOT RUN $conduit_live: executable is present; daemon-backed lifecycle checks are an explicit opt-in"
  else
    echo "LIVE NOT RUN $conduit_live: prerequisite executable is not installed"
  fi
done

for conduit_agent in codex claude opencode pi agy; do
  if command -v "$conduit_agent" >/dev/null 2>&1; then
    echo "LIVE NOT RUN $conduit_agent: executable is present; login and paid inference were not authorized"
  else
    echo "LIVE NOT RUN $conduit_agent: prerequisite executable is not installed"
  fi
done

echo "No daemon-backed provider lifecycle or paid Agent inference was started by this deterministic suite."
