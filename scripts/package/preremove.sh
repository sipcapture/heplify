#!/bin/sh
# Pre-remove for the heplify deb/rpm (nfpm).
# $1: deb = remove|upgrade|deconfigure; rpm = 0 (erase) | 1 (upgrade).
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now heplify.service || true
        fi
        ;;
esac
