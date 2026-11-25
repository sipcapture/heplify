#!/usr/bin/env bash
#
# check_package.sh — static checks on the heplify deb and rpm packages.
#
# Checks: installed files/modes/owners against scripts/package/expected-contents.txt,
# lintian (deb), rpmlint (rpm), systemd-analyze verify on the packaged unit, and
# the maintainer scripts through the shellcheck linter. Known lintian/rpmlint
# findings are listed in scripts/package/{lintian-suppressed-tags.txt,rpmlintrc}.
#
# Usage:
#   ./scripts/check_package.sh PACKAGE.deb PACKAGE.rpm
#
# Requires: dpkg-deb, rpm, lintian, rpmlint, systemd-analyze, shellcheck.
# Build the packages first, e.g. `make package VERSION=0.0.0`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="${SCRIPT_DIR}/package"

if [ $# -ne 2 ]; then
    echo "Usage: $0 PACKAGE.deb PACKAGE.rpm" >&2
    exit 2
fi
DEB="$1"
RPM="$2"

for tool in dpkg-deb rpm lintian rpmlint systemd-analyze shellcheck; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: ${tool} not found" >&2; exit 2; }
done
for f in "${DEB}" "${RPM}"; do
    [ -f "${f}" ] || { echo "ERROR: ${f} not found" >&2; exit 2; }
done

failures=0
step() { echo; echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

step "Package contents (files, modes, owners)"
expected="$(grep -v '^#' "${PKG_DIR}/expected-contents.txt" | sort)"
compare_contents() { # NAME ACTUAL
    if diff -u <(echo "${expected}") <(echo "$2"); then
        echo "$1: contents match"
    else
        fail "$1 contents differ from scripts/package/expected-contents.txt (diff above)"
    fi
}
compare_contents deb "$(dpkg-deb -c "${DEB}" | awk '$1 ~ /^-/ { print $1, $2, substr($6, 2) }' | sort)"
compare_contents rpm "$(rpm -qp --qf '[%{FILEMODES:perms} %{FILEUSERNAME}/%{FILEGROUPNAME} %{FILENAMES}\n]' "${RPM}" \
    | awk '$1 ~ /^-/' | sort)"

step "lintian (${DEB})"
lintian --suppress-tags-from-file "${PKG_DIR}/lintian-suppressed-tags.txt" --fail-on error "${DEB}" \
    || fail "lintian reported errors"

step "rpmlint (${RPM})"
rpmlint --rpmlintrc "${PKG_DIR}/rpmlintrc" "${RPM}" || fail "rpmlint reported errors"

# Lines systemd-analyze emitted for the unit under test. verify also walks
# other unit files already installed on the host and prints their diagnostics
# (ubuntu-latest warns that CPUAccounting= was removed from xfs and
# WALinuxAgent units). Those do not name heplify.service, so they are not
# failures. A line that names no unit file is kept: it may be a general
# error about the unit we asked to verify.
classify_verify_output() {
    local line
    while IFS= read -r line || [ -n "${line}" ]; do
        [ -z "${line}" ] && continue
        if printf '%s\n' "${line}" | grep -q -F 'heplify.service'; then
            printf '%s\n' "${line}"
            continue
        fi
        if printf '%s\n' "${line}" | grep -q -E '^/.+\.(service|slice|socket|target|mount|timer|path|swap|scope):'; then
            continue
        fi
        printf '%s\n' "${line}"
    done
}

step "systemd-analyze verify (packaged unit)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
dpkg-deb --fsys-tarfile "${DEB}" | tar -xO ./usr/lib/systemd/system/heplify.service > "${tmp}/heplify.service"
grep -q '^ExecStart=/usr/bin/heplify ' "${tmp}/heplify.service" \
    || fail "ExecStart does not point at /usr/bin/heplify"
# The binary is not installed on the host: verify a copy with a stand-in command.
sed -i 's|^ExecStart=/usr/bin/heplify|ExecStart=/bin/true|' "${tmp}/heplify.service"
# systemd-analyze exits 0 even when it ignores invalid settings, so the
# diagnostics that belong to this unit are the failure signal.
out="$(systemd-analyze verify "${tmp}/heplify.service" 2>&1 || true)"
relevant="$(printf '%s\n' "${out}" | classify_verify_output || true)"
if [ -n "${relevant}" ]; then
    printf '%s\n' "${relevant}" >&2
    fail "systemd-analyze verify reported problems"
else
    echo "unit OK"
fi

step "shellcheck (maintainer scripts)"
shellcheck "${PKG_DIR}"/*.sh "${BASH_SOURCE[0]}" || fail "shellcheck reported problems"

echo
if [ "${failures}" -ne 0 ]; then
    echo "${failures} check(s) failed" >&2
    exit 1
fi
echo "All package checks passed"
