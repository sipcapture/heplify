#!/usr/bin/env bash
# Source this file, then call amd64_baseline_apply.
#
# GitHub's ubuntu-26.04 runners install Ubuntu's amd64v3 variant. gcc there
# defaults to -march=x86-64-v3, and the static libc needs BMI2. A heplify
# binary built that way raises SIGILL (bzhi) on older CPUs and on virtual
# machines that do not expose x86-64-v3. See heplify issue 411.
#
# The flags are appended so the baseline -march wins over an earlier one.

amd64_baseline_apply() {
    local arch="${GOARCH:-}"
    if [ -z "${arch}" ]; then
        case "$(uname -m)" in
            x86_64|amd64) arch=amd64 ;;
            *) return 0 ;;
        esac
    fi
    if [ "${arch}" != "amd64" ]; then
        return 0
    fi

    local march="-march=x86-64 -mtune=generic"
    export GOAMD64=v1
    export CFLAGS="${CFLAGS:+${CFLAGS} }${march}"
    export CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }${march}"
    export CGO_CFLAGS="${CGO_CFLAGS:+${CGO_CFLAGS} }${march}"
    export CGO_CXXFLAGS="${CGO_CXXFLAGS:+${CGO_CXXFLAGS} }${march}"
}
