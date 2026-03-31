#!/usr/bin/env bash
#
# update_version.sh — update Version in src/cmd/heplify/version.go.
#
# Usage:
#   ./scripts/update_version.sh [VERSION]
#
# If VERSION is omitted, the version is derived from the nearest git tag via
# `git describe --tags --abbrev=0`.
#
# Examples:
#   ./scripts/update_version.sh 1.3.0
#   ./scripts/update_version.sh          # reads from git tag
#   VERSION=1.4.0 ./scripts/update_version.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/src/cmd/heplify/version.go"

# --- Resolve version ---
if [ -n "${1:-}" ]; then
    VERSION="$1"
elif [ -n "${VERSION:-}" ]; then
    : # already exported
else
    VERSION="$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")"
fi

# Strip leading 'v' for consistency
VERSION="${VERSION#v}"

echo "Updating ${VERSION_FILE} → v${VERSION}"

sed -i "s/var Version = \".*\"/var Version = \"${VERSION}\"/" "${VERSION_FILE}"

echo "Done."
