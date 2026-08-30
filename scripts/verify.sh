#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/static_validate.py
python3 scripts/source_sanity.py
python3 -m unittest discover -s scripts/tests -p "test_*.py"
python3 scripts/reference_lab.py --fuzz-iterations 100000
if command -v cargo >/dev/null 2>&1; then
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-targets --locked
  cargo test --workspace --doc --locked
  cargo run --locked -p latencydesk-stress
else
  echo "cargo is unavailable; Rust gates were not executed" >&2
  exit 4
fi
