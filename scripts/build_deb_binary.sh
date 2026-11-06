#!/usr/bin/env bash
#
# build_deb_binary.sh — build the dynamically linked heplify binary shipped in the .deb.
#
# Built in the "builder" stage of docker/Dockerfile on an old Debian release
# (bookworm by default, glibc 2.36), so that it runs on that release and newer
# ones (and on Ubuntu 22.04+). It links the system libpcap and libc dynamically.
# The result is checked: it may only need libc and libpcap, and the libc floor
# declared in nfpm.yaml (Depends: libc6 (>= X)) must cover the glibc symbols used.
#
# Usage:
#   ./scripts/build_deb_binary.sh [OUTPUT]      # default: ./heplify-deb
#
# Environment: VERSION, GIT_COMMIT, BUILD_DATE (embedded in the binary),
#              DEBIAN_RELEASE (default: bookworm), DOCKER (container CLI, default: docker).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT="${1:-${ROOT_DIR}/heplify-deb}"
DEBIAN_RELEASE="${DEBIAN_RELEASE:-bookworm}"
IMAGE="heplify-deb-builder:${DEBIAN_RELEASE}"
DOCKER="${DOCKER:-docker}"

command -v "${DOCKER}" >/dev/null 2>&1 || { echo "ERROR: ${DOCKER} is required" >&2; exit 1; }

echo "==> Building heplify on Debian ${DEBIAN_RELEASE} (dynamic)"
"${DOCKER}" build -f "${ROOT_DIR}/docker/Dockerfile" --target builder \
    --build-arg "DEBIAN_RELEASE=${DEBIAN_RELEASE}" \
    --build-arg "VERSION=${VERSION:-dev}" \
    --build-arg "GIT_COMMIT=${GIT_COMMIT:-unknown}" \
    --build-arg "BUILD_DATE=${BUILD_DATE:-unknown}" \
    -t "${IMAGE}" "${ROOT_DIR}"

cid="$("${DOCKER}" create "${IMAGE}")"
trap '"${DOCKER}" rm -f "${cid}" >/dev/null' EXIT
"${DOCKER}" cp "${cid}:/build/heplify" "${OUTPUT}"
echo "==> ${OUTPUT}"

echo "==> Checking dynamic dependencies"
inspect() { "${DOCKER}" run --rm "${IMAGE}" sh -c "$1"; }

needed="$(inspect "readelf -d /build/heplify | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | sort | tr '\n' ' '")"
if [ "${needed}" != "libc.so.6 libpcap.so.0.8 " ]; then
    echo "ERROR: unexpected shared libraries: ${needed}" >&2
    echo "       the deb declares dependencies on libc6 and libpcap0.8 only (nfpm.yaml)" >&2
    exit 1
fi

used="$(inspect "objdump -T /build/heplify | grep -o 'GLIBC_[0-9][0-9.]*' | sort -uV | tail -n 1" | sed 's/GLIBC_//')"
declared="$(sed -n 's/.*libc6 (>= \([0-9.]*\)).*/\1/p' "${ROOT_DIR}/nfpm.yaml" | head -n 1)"
if [ -z "${declared}" ]; then
    echo "ERROR: no 'libc6 (>= X)' dependency found in nfpm.yaml" >&2
    exit 1
fi
if [ "$(printf '%s\n%s\n' "${declared}" "${used}" | sort -V | tail -n 1)" != "${declared}" ]; then
    echo "ERROR: the binary needs glibc ${used} but nfpm.yaml declares libc6 (>= ${declared})" >&2
    exit 1
fi
echo "    needs: ${needed}"
echo "    glibc symbols up to ${used}, declared: libc6 (>= ${declared})"
