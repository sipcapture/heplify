#!/usr/bin/env bash
# Build the statically linked heplify binary (bundled libpcap, static glibc).
#
# amd64 is compiled for the x86-64 baseline. See scripts/amd64_baseline_env.sh
# and heplify issue 411. The release workflow runs this on ubuntu-24.04,
# whose libc is baseline; the march flags cover a compiler whose default
# is x86-64-v3.
#
# Usage: scripts/build_static.sh <output> [goarch]
#
# Environment:
#   VERSION, GIT_COMMIT, BUILD_DATE  embedded in the binary
#   LIBPCAP_DIR                      default: <repo>/build/libpcap
#                                    (build it with scripts/build_libpcap.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT="${1:?usage: build_static.sh <output> [goarch]}"
GOARCH="${2:-${GOARCH:-$(go env GOARCH)}}"
LIBPCAP_DIR="${LIBPCAP_DIR:-${ROOT_DIR}/build/libpcap}"

if [ ! -f "${LIBPCAP_DIR}/lib/libpcap.a" ]; then
    echo "ERROR: ${LIBPCAP_DIR}/lib/libpcap.a not found. Run scripts/build_libpcap.sh first." >&2
    exit 1
fi

# shellcheck source=amd64_baseline_env.sh
source "${SCRIPT_DIR}/amd64_baseline_env.sh"
amd64_baseline_apply

VERSION="${VERSION:-dev}"
GIT_COMMIT="${GIT_COMMIT:-unknown}"
BUILD_DATE="${BUILD_DATE:-unknown}"

cd "${ROOT_DIR}"
echo "==> Static heplify (${GOARCH}) -> ${OUTPUT}"
echo "    GOAMD64=${GOAMD64:-<unset>} CGO_CFLAGS=${CGO_CFLAGS:-<unset>}"

CGO_ENABLED=1 GOOS=linux GOARCH="${GOARCH}" \
CGO_CFLAGS="${CGO_CFLAGS:+${CGO_CFLAGS} }-I${LIBPCAP_DIR}/include" \
CGO_LDFLAGS="-L${LIBPCAP_DIR}/lib" \
go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.GitCommit=${GIT_COMMIT} -linkmode external -extldflags '-static'" \
    -trimpath \
    -o "${OUTPUT}" \
    ./src/cmd/heplify

bash "${SCRIPT_DIR}/check_amd64_baseline.sh" "${OUTPUT}"
