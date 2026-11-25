#!/usr/bin/env bash
# Fail when an amd64 ELF declares that it needs a microarchitecture above
# the x86-64 baseline. The amd64v3 glibc on GitHub's ubuntu-26.04 runners
# records "x86-64-v3" in this note; heplify 2.1.1 shipped with that note
# and died with SIGILL on CPUs without BMI2 (issue 411).
#
# Non-amd64 binaries are ignored, so the same call works for arm64.

set -euo pipefail

bin="${1:?usage: check_amd64_baseline.sh <elf>}"

if ! command -v readelf >/dev/null 2>&1; then
    echo "ERROR: readelf is required to check ${bin}" >&2
    exit 1
fi

machine="$(readelf -h "${bin}" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
case "${machine}" in
    *X86-64*) ;;
    *)
        exit 0
        ;;
esac

isa="$(readelf -nW "${bin}" | sed -n 's/.*x86 ISA needed: //p' | head -n 1)"
if [ -z "${isa}" ]; then
    echo "ERROR: ${bin} has no 'x86 ISA needed' note, so the baseline cannot be confirmed" >&2
    exit 1
fi

echo "${bin}: x86 ISA needed: ${isa}"
case "${isa}" in
    *x86-64-v2*|*x86-64-v3*|*x86-64-v4*)
        echo "ERROR: ${bin} requires ${isa}." >&2
        echo "Static amd64 builds must stay on the x86-64 baseline (heplify issue 411)." >&2
        exit 1
        ;;
esac
case "${isa}" in
    *x86-64-baseline*) ;;
    *)
        echo "ERROR: ${bin} ISA note does not include x86-64-baseline (${isa})" >&2
        exit 1
        ;;
esac
