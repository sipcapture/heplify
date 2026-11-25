#!/usr/bin/env bash
# Run every fuzz target for a fixed time. Usage: scripts/fuzz.sh [duration]
set -euo pipefail
dur="${1:-60s}"
cd "$(dirname "$0")/.."
log="$(mktemp)"
trap 'rm -f "${log}"' EXIT

# Files the fuzz engine has already kept for this target.
corpus_sig() {
    local dir="$1"
    if [ -d "${dir}" ]; then
        find "${dir}" -type f -printf '%P %s\n' | sort
    fi
}

# Go 1.26 reports a finished -fuzztime run as "context deadline exceeded"
# when the coordinator sees the parent context's deadline before the child
# fuzz context is canceled (golang/go#75804). That message is not a crash:
# no input is written. A real crash still adds a file under testdata/fuzz
# or prints "Failing input written to", and those runs keep failing.
fuzztime_deadline_only() {
    local corpus="$1"
    local before="$2"
    local after
    after="$(corpus_sig "${corpus}")"
    [ "${before}" = "${after}" ] || return 1
    grep -q 'context deadline exceeded' "${log}" || return 1
    grep -q 'Failing input written to' "${log}" && return 1
    grep -q 'panic:' "${log}" && return 1
    return 0
}

for pkg in ./src/hep ./src/decoder; do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz'); do
    echo "==> $pkg $target ($dur)"
    corpus="${pkg}/testdata/fuzz/${target}"
    before="$(corpus_sig "${corpus}")"
    set +e
    go test -run '^$' -fuzz "^${target}\$" -fuzztime "$dur" "$pkg" 2>&1 | tee "${log}"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "${rc}" -eq 0 ]; then
      continue
    fi
    if fuzztime_deadline_only "${corpus}" "${before}"; then
      echo "warning: ${target} hit the fuzztime deadline with no crashing input (golang/go#75804)"
      continue
    fi
    exit "${rc}"
  done
done
