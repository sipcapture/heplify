#!/usr/bin/env bash
#
# update_formula.sh — point Formula/heplify.rb at a published release.
#
# Downloads the heplify_darwin_arm64 asset of the given release, computes its
# sha256 and rewrites the download URL and `sha256` in Formula/heplify.rb.
#
# Usage:
#   ./scripts/update_formula.sh [VERSION]
#
# If VERSION is omitted, the nearest git tag is used. A leading 'v' is ignored.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FORMULA="${ROOT_DIR}/Formula/heplify.rb"

VERSION="${1:-$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 2>/dev/null || true)}"
VERSION="${VERSION#v}"
if [ -z "${VERSION}" ]; then
    echo "Usage: $0 VERSION" >&2
    exit 1
fi

URL="https://github.com/sipcapture/heplify/releases/download/${VERSION}/heplify_darwin_arm64"
TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

echo "==> Downloading ${URL}"
curl -fsSL "${URL}" -o "${TMP}"

if command -v sha256sum >/dev/null 2>&1; then
    SHA256="$(sha256sum "${TMP}" | cut -d' ' -f1)"
else
    SHA256="$(shasum -a 256 "${TMP}" | cut -d' ' -f1)"
fi

# Portable in-place edit (GNU and BSD sed)
sed -e "s|/releases/download/[^/]*/heplify_darwin_arm64|/releases/download/${VERSION}/heplify_darwin_arm64|" \
    -e "s|^  sha256 \".*\"|  sha256 \"${SHA256}\"|" \
    "${FORMULA}" > "${FORMULA}.new"
mv "${FORMULA}.new" "${FORMULA}"

echo "==> ${FORMULA}: version ${VERSION}, sha256 ${SHA256}"
