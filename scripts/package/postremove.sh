#!/bin/sh
# Post-remove for the heplify deb/rpm (nfpm).
# $1: deb = remove|purge|upgrade|...; rpm = 0 (erase) | 1 (upgrade).
# The homer user/group is kept on purge on purpose (Debian policy: system
# users are not removed, to avoid orphaned file ownership).
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

if [ "$1" = purge ]; then
    rm -rf /var/lib/heplify
fi
