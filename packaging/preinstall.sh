#!/bin/sh
# Create the service account (works for both deb and rpm).
set -e
getent group go-ddns >/dev/null || groupadd --system go-ddns
getent passwd go-ddns >/dev/null || useradd --system --gid go-ddns \
    --no-create-home --home-dir /var/lib/go-ddns --shell /usr/sbin/nologin \
    --comment "go-ddns service" go-ddns
exit 0
