#!/usr/bin/env bash
#
# test_package.sh — install/upgrade/remove tests for the heplify deb and rpm.
#
#   lifecycle IMAGE PACKAGE [OLD_PACKAGE]
#       In a clean container (docker run IMAGE): optionally install OLD_PACKAGE
#       (e.g. the latest published release), install or upgrade to PACKAGE,
#       reinstall it, then remove and (deb) purge it. Checks the homer
#       user/group, file owners and modes, that files moved by older packages
#       (/usr/local/bin/heplify, /etc/systemd/system/heplify.service) are gone,
#       and what is kept or removed on removal.
#       Containers have no systemd: the systemctl branches of the maintainer
#       scripts are not exercised here.
#
#   e2e PACKAGE.deb
#       On a host with systemd and sudo (CI runner VM): install the deb, run the
#       service with a config that captures SIP on lo and sends HEP to a local
#       UDP listener, and check that the unit is active, runs as homer with only
#       CAP_NET_RAW/CAP_NET_ADMIN/CAP_NET_BIND_SERVICE, that a SIP packet sent
#       over lo arrives as HEP3, and that the journal has no errors.
#       It changes the host (installs and removes the package): CI only.
#
# Environment: DOCKER (container CLI, default: docker), DOCKER_RUN_OPTS (extra
# "docker run" options), DNF_OPTS (extra dnf options in the rpm container).

set -euo pipefail

DOCKER="${DOCKER:-docker}"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
    sed -n '3,24p' "${SCRIPT_PATH}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }

# assert_stat PATH MODE OWNER:GROUP
assert_stat() {
    local got
    [ -e "$1" ] || fail "$1 is missing"
    got="$(stat -c '%a %U:%G' "$1")"
    [ "${got}" = "$2 $3" ] || fail "$1 is ${got}, want $2 $3"
    ok "$1 $2 $3"
}

assert_absent() {
    [ ! -e "$1" ] || fail "$1 should not exist"
    ok "$1 absent"
}

assert_installed() {
    getent group homer >/dev/null || fail "group homer missing"
    getent passwd homer >/dev/null || fail "user homer missing"
    [ "$(id -gn homer)" = homer ] || fail "homer's primary group is $(id -gn homer)"
    ok "user and group homer"
    assert_stat /usr/bin/heplify 755 root:root
    assert_stat /etc/heplify/heplify.json 640 root:homer
    assert_stat /var/lib/heplify 750 homer:homer
    assert_stat /usr/lib/systemd/system/heplify.service 644 root:root
    assert_stat /etc/init.d/heplify 755 root:root
    # Moved by #364/#366: an upgrade from an older package must drop them.
    assert_absent /usr/local/bin/heplify
    assert_absent /etc/systemd/system/heplify.service
    /usr/bin/heplify -version >/dev/null || fail "heplify -version failed"
    ok "heplify -version"
}

# Runs inside the container. $1 = new package, $2 = old package or "".
lifecycle_inside() {
    local new="$1" old="${2:-}" kind
    case "${new}" in
        *.deb) kind=deb ;;
        *.rpm) kind=rpm ;;
        *) fail "unknown package type: ${new}" ;;
    esac

    if [ "${kind}" = deb ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        install_pkg() { apt-get install -y -qq "$1" >/dev/null; }
        reinstall_pkg() { apt-get install -y -qq --reinstall "$1" >/dev/null; }
    else
        # DNF_OPTS: extra dnf options, e.g. --disablerepo='*' when offline.
        # shellcheck disable=SC2086
        install_pkg() { dnf install -y -q ${DNF_OPTS:-} "$1" >/dev/null; }
        # shellcheck disable=SC2086
        reinstall_pkg() { dnf reinstall -y -q ${DNF_OPTS:-} "$1" >/dev/null; }
    fi

    if [ -n "${old}" ]; then
        echo "==> install old package $(basename "${old}")"
        install_pkg "${old}"
        echo '{"local": "edit"}' > /etc/heplify/heplify.json
    fi

    echo "==> install $(basename "${new}")"
    install_pkg "${new}"
    assert_installed
    if [ -n "${old}" ]; then
        # The config is a conffile/%config(noreplace): a local edit survives.
        grep -q '"local"' /etc/heplify/heplify.json || fail "upgrade replaced the edited config"
        ok "edited config kept on upgrade"
    fi

    echo "==> reinstall"
    reinstall_pkg "${new}"
    assert_installed

    echo "==> remove"
    if [ "${kind}" = deb ]; then
        apt-get remove -y -qq heplify >/dev/null
        assert_absent /usr/bin/heplify
        [ -e /etc/heplify/heplify.json ] || fail "remove deleted the config (only purge should)"
        ok "config kept on remove"
        getent passwd homer >/dev/null || fail "remove deleted the homer user"

        echo "==> purge"
        dpkg --purge heplify >/dev/null
        assert_absent /etc/heplify/heplify.json
        assert_absent /var/lib/heplify
        getent passwd homer >/dev/null || fail "purge deleted the homer user (it is kept on purpose)"
        ok "homer user kept on purge"
    else
        # shellcheck disable=SC2086
        dnf remove -y -q ${DNF_OPTS:-} heplify >/dev/null
        assert_absent /usr/bin/heplify
        assert_absent /usr/lib/systemd/system/heplify.service
        [ -d /var/lib/heplify ] || fail "rpm erase removed /var/lib/heplify (it is kept)"
        ok "/var/lib/heplify kept on erase"
        getent passwd homer >/dev/null || fail "erase deleted the homer user"
        ok "homer user kept on erase"
    fi
    echo "PASS: lifecycle $(basename "${new}")"
}

lifecycle() {
    [ $# -ge 2 ] || usage
    local image="$1" new old="" args
    new="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
    [ -f "${new}" ] || fail "${new} not found"
    args=(-v "${new}:/pkg/new/$(basename "${new}"):ro" -v "${SCRIPT_PATH}:/test_package.sh:ro")
    if [ $# -ge 3 ] && [ -n "$3" ]; then
        old="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
        [ -f "${old}" ] || fail "${old} not found"
        args+=(-v "${old}:/pkg/old/$(basename "${old}"):ro")
        old="/pkg/old/$(basename "${old}")"
    fi
    echo "==> ${image}: $(basename "${new}")${old:+ (upgrade from $(basename "${old}"))}"
    # shellcheck disable=SC2086
    "${DOCKER}" run --rm -e DNF_OPTS ${DOCKER_RUN_OPTS:-} "${args[@]}" "${image}" \
        bash /test_package.sh _lifecycle_inside "/pkg/new/$(basename "${new}")" "${old}"
}

e2e() {
    [ $# -eq 1 ] || usage
    local deb listener_pid cfg pid capeff out journal
    deb="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
    [ -d /run/systemd/system ] || fail "e2e needs systemd"
    out="$(mktemp -d)"
    # The marker identifies our SIP packet in the HEP payload.
    local marker
    marker="heplify-e2e-$$-$(date +%s)"

    echo "==> install $(basename "${deb}")"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${deb}" >/dev/null

    echo "==> configure: capture SIP on lo, HEP over UDP to 127.0.0.1:9060"
    cfg="$(mktemp)"
    # The packaged config is root:homer 0640: read it through sudo.
    # shellcheck disable=SC2024 # the redirect is meant to run as the caller
    sudo cat /etc/heplify/heplify.json > "${cfg}"
    python3 - "${cfg}" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
s = c["socket"][0]
s.update(device="lo", promisc=False, capture_mode=["SIP"], fanout_workers=0)
t = c["transport"][0]
t.update(host="127.0.0.1", port=9060, transport="udp", active=True)
for other in c["transport"][1:]:
    other["active"] = False
c["log_settings"].update(level="info", stdout=True)
json.dump(c, open(sys.argv[1], "w"), indent=2)
EOF
    sudo install -m 0640 -o root -g homer "${cfg}" /etc/heplify/heplify.json
    rm -f "${cfg}"

    # Wait for one HEP3 packet that carries the marker.
    python3 - "${marker}" "${out}/hep" <<'EOF' &
import socket, sys
marker, path = sys.argv[1].encode(), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 9060))
s.settimeout(60)
while True:
    data, _ = s.recvfrom(65535)
    if data[:4] == b"HEP3" and marker in data:
        open(path, "wb").write(data)
        break
# Keep the port open while the sender stops, so heplify does not log
# "connection refused" for the resent copies.
s.settimeout(3)
try:
    while True:
        s.recvfrom(65535)
except socket.timeout:
    pass
EOF
    listener_pid=$!

    echo "==> start the service"
    sudo systemctl start heplify.service
    sleep 3
    systemctl is-active --quiet heplify.service || {
        sudo journalctl -u heplify.service --no-pager | tail -50
        fail "heplify.service is not active"
    }
    ok "heplify.service active"

    pid="$(systemctl show -p MainPID --value heplify.service)"
    [ "$(ps -o user= -p "${pid}" | tr -d ' ')" = homer ] || fail "service runs as $(ps -o user= -p "${pid}")"
    [ "$(ps -o group= -p "${pid}" | tr -d ' ')" = homer ] || fail "service group is $(ps -o group= -p "${pid}")"
    ok "runs as homer:homer"
    # CAP_NET_BIND_SERVICE (10), CAP_NET_ADMIN (12), CAP_NET_RAW (13).
    capeff="$(awk '/^CapEff:/ {print $2}' "/proc/${pid}/status")"
    [ "${capeff}" = 0000000000003400 ] || fail "CapEff is ${capeff}, want 0000000000003400"
    ok "CapEff ${capeff}"

    echo "==> send a SIP OPTIONS over lo"
    python3 - "${marker}" "${out}/hep" <<'EOF'
import os, socket, sys, time
m, done = sys.argv[1], sys.argv[2]
msg = ("OPTIONS sip:e2e@127.0.0.1 SIP/2.0\r\n"
       "Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK-" + m + "\r\n"
       "From: <sip:test@127.0.0.1>;tag=1\r\n"
       "To: <sip:e2e@127.0.0.1>\r\n"
       "Call-ID: " + m + "\r\n"
       "CSeq: 1 OPTIONS\r\n"
       "Max-Forwards: 70\r\n"
       "Content-Length: 0\r\n\r\n").encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5070))
# Resend a few times in case capture was not ready yet.
for _ in range(10):
    s.sendto(msg, ("127.0.0.1", 5060))
    time.sleep(1)
    if os.path.exists(done):
        break
EOF
    if ! wait "${listener_pid}"; then
        sudo journalctl -u heplify.service --no-pager | tail -50
        fail "no HEP3 packet with the SIP message reached 127.0.0.1:9060"
    fi
    ok "SIP packet arrived as HEP3 ($(stat -c %s "${out}/hep") bytes)"

    # The text log is colored even under systemd: strip ANSI codes first.
    journal="$(sudo journalctl -u heplify.service --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g')"
    if grep -E '(^|[[:space:]])(ERR|FTL|PNC)([[:space:]]|$)|panic:' <<<"${journal}"; then
        fail "errors in the journal"
    fi
    ok "no errors in the journal"

    echo "==> remove"
    sudo systemctl stop heplify.service
    sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq heplify >/dev/null
    rm -rf "${out}"
    echo "PASS: e2e $(basename "${deb}")"
}

[ $# -ge 1 ] || usage
cmd="$1"
shift
case "${cmd}" in
    lifecycle) lifecycle "$@" ;;
    e2e) e2e "$@" ;;
    _lifecycle_inside) lifecycle_inside "$@" ;;
    *) usage ;;
esac
