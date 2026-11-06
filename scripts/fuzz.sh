#!/usr/bin/env bash
# Run every fuzz target for a fixed time. Usage: scripts/fuzz.sh [duration]
set -euo pipefail
dur="${1:-60s}"
cd "$(dirname "$0")/.."
for pkg in ./src/hep ./src/decoder; do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz'); do
    echo "==> $pkg $target ($dur)"
    go test -run '^$' -fuzz "^${target}\$" -fuzztime "$dur" "$pkg"
  done
done
