#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$conduit_root"

pnpm --filter @conduit/schema build
timeout 5m cargo test -p conduit-node node_service_wss_worker_route_device_room_accelerated_idle_e2e -- --ignored --nocapture
