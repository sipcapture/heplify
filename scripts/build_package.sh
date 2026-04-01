#!/bin/bash
#
# build_package.sh - Build heplify deb/rpm packages using nfpm via Docker
#
# Usage:
#   ./scripts/build_package.sh [VERSION]
#
# Examples:
#   ./scripts/build_package.sh          # auto-detects version from git tag
#   ./scripts/build_package.sh 1.2.3    # use explicit version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PACKAGE="heplify"
ARCH="amd64"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

cd "${ROOT_DIR}"

# --- Version resolution ---
if [ -n "${1:-}" ]; then
    VERSION="$1"
elif [ -n "${VERSION:-}" ]; then
    : # already set in environment
else
    VERSION="$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0")"
fi

# Strip leading 'v' for nfpm
VERSION="${VERSION#v}"

log_info "Building packages for ${PACKAGE} v${VERSION} (${ARCH})"

# --- Check binary ---
if [ ! -f "${ROOT_DIR}/${PACKAGE}" ]; then
    log_warn "Binary '${PACKAGE}' not found — building static binary now..."
    LIBPCAP_DIR="${ROOT_DIR}/build/libpcap"
    if [ ! -f "${LIBPCAP_DIR}/lib/libpcap.a" ]; then
        log_info "Building local libpcap (no DBus/RDMA)..."
        chmod +x "${SCRIPT_DIR}/build_libpcap.sh"
        "${SCRIPT_DIR}/build_libpcap.sh"
    fi
    BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    CGO_ENABLED=1 \
    CGO_CFLAGS="-I${LIBPCAP_DIR}/include" \
    CGO_LDFLAGS="-L${LIBPCAP_DIR}/lib" \
    go build \
        -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -linkmode external -extldflags '-static'" \
        -trimpath \
        -o "${PACKAGE}" \
        ./src/cmd/heplify
    log_info "Static build complete: ${PACKAGE}"
fi

# --- Check Docker ---
if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed. Please install Docker and try again."
    exit 1
fi

# --- Build DEB ---
log_info "Building .deb package..."
docker run --rm \
    -v "${ROOT_DIR}:/tmp/pkg" \
    -e VERSION="${VERSION}" \
    -w /tmp/pkg \
    goreleaser/nfpm pkg \
        --config /tmp/pkg/nfpm.yaml \
        --target "/tmp/pkg/${PACKAGE}-${VERSION}-${ARCH}.deb"
log_info "Created: ${PACKAGE}-${VERSION}-${ARCH}.deb"

# --- Build RPM ---
log_info "Building .rpm package..."
docker run --rm \
    -v "${ROOT_DIR}:/tmp/pkg" \
    -e VERSION="${VERSION}" \
    -w /tmp/pkg \
    goreleaser/nfpm pkg \
        --config /tmp/pkg/nfpm.yaml \
        --target "/tmp/pkg/${PACKAGE}-${VERSION}-${ARCH}.rpm"
log_info "Created: ${PACKAGE}-${VERSION}-${ARCH}.rpm"

echo ""
log_info "Done! Packages:"
ls -lh "${ROOT_DIR}/${PACKAGE}-${VERSION}-${ARCH}".{deb,rpm} 2>/dev/null || true
