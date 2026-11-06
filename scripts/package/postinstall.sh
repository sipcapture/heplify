#!/bin/sh
# Post-install for the heplify deb/rpm (nfpm). Runs on fresh install and upgrade.
set -e

# heplify runs as homer:homer, the user shared with the other HOMER
# components. An existing homer user (e.g. from a HOMER install) is reused.
if ! getent group homer >/dev/null 2>&1; then
    groupadd --system homer
fi
if ! getent passwd homer >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --gid homer --home-dir /var/lib/heplify --no-create-home \
        --shell "$nologin" --comment "HOMER services" homer
fi

# Home/state directory. Also created by the unit (StateDirectory=), but doing it
# here keeps the account's home valid right after install. Not shipped in the
# package: dpkg would chown it before this script has created the user.
install -d -o homer -g homer -m 0750 /var/lib/heplify

# The config may hold HEP/Prometheus passwords: readable by the service only.
if [ -f /etc/heplify/heplify.json ]; then
    chgrp homer /etc/heplify/heplify.json
    chmod 0640 /etc/heplify/heplify.json
fi

# No-op without systemd (containers, chroots).
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Restarts only if already running: a fresh install is not started with
    # the default config, edit /etc/heplify/heplify.json first.
    systemctl try-restart heplify.service || true
fi
