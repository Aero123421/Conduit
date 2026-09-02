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
"$conduit_root/scripts/e2e-node-worker-idle.sh"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import jsonschema, referencing' >/dev/null 2>&1; then
  conduit_python="$(command -v python3)"
elif command -v python >/dev/null 2>&1 && python -c 'import jsonschema, referencing' >/dev/null 2>&1; then
  conduit_python="$(command -v python)"
elif command -v uv >/dev/null 2>&1; then
  uv run --with-requirements requirements-spec.txt python scripts/validate_spec.py
  conduit_python=""
else
  echo "Specification validation requires Python 3 with requirements-spec.txt, or uv" >&2
  exit 4
fi
if [[ -n "$conduit_python" ]]; then
  "$conduit_python" scripts/validate_spec.py
fi

git diff --exit-code -- packages/conduit-schema/src/generated

if git grep -n -E '(BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|AKIA[0-9A-Z]{16})' -- . ':!scripts/check-all.sh'; then
  echo "secret-like material found in tracked files" >&2
  exit 1
fi

cargo metadata --locked --format-version 1 >/dev/null
"$conduit_root/scripts/test-packaging.sh"
cargo build --locked --release -p conduit-privileged-helper --bins
"$conduit_root/scripts/test-privileged-packaging.sh"
"$conduit_root/scripts/e2e-linux.sh"
