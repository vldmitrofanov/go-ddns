#!/bin/sh
set -e
# Config holds the AWS secret: root may edit, the service may only read.
chgrp go-ddns /etc/go-ddns /etc/go-ddns/config.toml /etc/go-ddns/blacklist.d /etc/go-ddns/blacklist.d/manual.txt 2>/dev/null || true
chmod 0750 /etc/go-ddns
chmod 0640 /etc/go-ddns/config.toml
chmod 0770 /etc/go-ddns/blacklist.d   # service appends auto-bans here
chown -R go-ddns:go-ddns /var/lib/go-ddns

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # On upgrade, restart if it was running. Fresh installs are NOT started:
    # the config needs AWS keys first.
    if systemctl is-active --quiet go-ddns; then
        systemctl restart go-ddns || true
    else
        echo "go-ddns installed. Edit /etc/go-ddns/config.toml, then: systemctl enable --now go-ddns"
    fi
fi
exit 0
