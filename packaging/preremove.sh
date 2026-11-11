#!/bin/sh
# deb passes "remove"/"upgrade"; rpm passes 0 (erase) or 1 (upgrade).
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now go-ddns >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
