#!/bin/sh
# Data (/var/lib/go-ddns), config and the go-ddns user are kept on removal.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
