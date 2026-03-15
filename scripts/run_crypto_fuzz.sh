#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo install cargo-fuzz
for target in fuzz/fuzz_targets/*.rs; do
    name=$(basename "$target" .rs)
    cargo fuzz run "$name" -- -runs=1000000
done