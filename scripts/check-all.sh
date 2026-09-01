#!/usr/bin/env bash
set -euo pipefail

conduit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$conduit_root"

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked

corepack pnpm install --frozen-lockfile
corepack pnpm --filter @conduit/schema check:wire
corepack pnpm -r typecheck
corepack pnpm -r test
corepack pnpm -r build
python scripts/validate_spec.py

git diff --exit-code -- packages/conduit-schema/src/generated

if git grep -n -E '(BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|AKIA[0-9A-Z]{16})' -- . ':!scripts/check-all.sh'; then
  echo "secret-like material found in tracked files" >&2
  exit 1
fi

cargo metadata --locked --format-version 1 >/dev/null
"$conduit_root/scripts/test-packaging.sh"
