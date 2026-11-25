#!/usr/bin/env bash
# Downloads and builds a minimal static libpcap (no DBus, no RDMA)
# Result: build/libpcap/lib/libpcap.a  +  build/libpcap/include/

set -euo pipefail

LIBPCAP_VERSION="${LIBPCAP_VERSION:-1.10.4}"
LIBPCAP_URL="https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz"
BUILD_DIR="$(cd "$(dirname "$0")/.." && pwd)/build"
LIBPCAP_SRC="${BUILD_DIR}/libpcap-src"
LIBPCAP_OUT="${BUILD_DIR}/libpcap"

echo "==> Building libpcap ${LIBPCAP_VERSION} (static, no DBus, no RDMA)"
echo "    Source : ${LIBPCAP_SRC}"
echo "    Output : ${LIBPCAP_OUT}"

# ── dependencies ───────────────────────────────────────────────────────────
command -v gcc  >/dev/null || { echo "ERROR: gcc not found"; exit 1; }
command -v make >/dev/null || { echo "ERROR: make not found"; exit 1; }

# amd64 objects stay on the x86-64 baseline. A libpcap.a built with the
# default gcc of GitHub's ubuntu-26.04 image (x86-64-v3) makes the static
# heplify binary raise SIGILL on older CPUs (issue 411).
# shellcheck source=amd64_baseline_env.sh
source "$(cd "$(dirname "$0")" && pwd)/amd64_baseline_env.sh"
amd64_baseline_apply
if [ -n "${CFLAGS:-}" ]; then
    echo "    CFLAGS : ${CFLAGS}"
fi

mkdir -p "${LIBPCAP_SRC}" "${LIBPCAP_OUT}"

# ── download ────────────────────────────────────────────────────────────────
TARBALL="${BUILD_DIR}/libpcap-${LIBPCAP_VERSION}.tar.gz"
if [ ! -f "${TARBALL}" ]; then
    echo "==> Downloading ${LIBPCAP_URL}"
    curl -fsSL "${LIBPCAP_URL}" -o "${TARBALL}"
else
    echo "==> Tarball already present, skipping download"
fi

# ── extract ─────────────────────────────────────────────────────────────────
if [ ! -f "${LIBPCAP_SRC}/configure" ]; then
    echo "==> Extracting..."
    tar -xzf "${TARBALL}" -C "${LIBPCAP_SRC}" --strip-components=1
else
    echo "==> Source already extracted, skipping"
fi

# ── configure ───────────────────────────────────────────────────────────────
cd "${LIBPCAP_SRC}"
if [ ! -f Makefile ]; then
    echo "==> Configuring (static, no dbus, no rdma)..."
    ./configure \
        --prefix="${LIBPCAP_OUT}" \
        --disable-dbus \
        --disable-rdma \
        --disable-dpdk \
        --disable-usb \
        --disable-bluetooth
else
    echo "==> Already configured, skipping"
fi

# ── build & install ─────────────────────────────────────────────────────────
echo "==> Building..."
make -j"$(nproc)"

echo "==> Installing to ${LIBPCAP_OUT}..."
make install

echo ""
echo "Done. Static library: ${LIBPCAP_OUT}/lib/libpcap.a"
