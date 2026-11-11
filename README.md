# go-ddns

Small dynamic-DNS server for AWS Route 53. A client calls

    curl -H "Authorization: Bearer ddns_xxx" "https://ddns.example.com/update?domain=home.example.com"

and the A record (or AAAA if the caller is on IPv6) is set to the caller's source IP.

* `domain=home.example.com`: update one domain
* `domain=a.example.com,b.example.com`: update several
* `domain=all`, or no parameter: update **every** domain the client owns

The server only calls Route 53 when the IP actually changed (cached per domain in SQLite).
Domains in the same hosted zone are sent as one change batch.

## Install from a release

Packages are built for **amd64** and **arm64**. The binary is fully static, so it runs on any
systemd-based distro whatever its glibc version.
Every file is on the [Releases page](https://github.com/vldmitrofanov/go-ddns/releases).

```bash
# Pick the latest version automatically (or set e.g. VER=0.0.1)
VER=$(curl -s https://api.github.com/repos/vldmitrofanov/go-ddns/releases/latest | grep -Po '"tag_name": *"v\K[^"]+')
URL=https://github.com/vldmitrofanov/go-ddns/releases/download/v$VER
```

**Debian / Ubuntu**

```bash
ARCH=$(dpkg --print-architecture)            # amd64 or arm64
curl -LO $URL/go-ddns_${VER}_${ARCH}.deb
sudo apt install ./go-ddns_${VER}_${ARCH}.deb
```

**RHEL / Rocky / Alma / Fedora / Amazon Linux**

```bash
sudo dnf install $URL/go-ddns-${VER}-1.$(uname -m).rpm     # x86_64 or aarch64
```

**Any other Linux (tarball)**

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -L $URL/go-ddns_${VER}_linux_${ARCH}.tar.gz | tar xz
sudo make install        # or copy go-ddns + deploy/ files by hand
```

To verify a download, check it against `SHA256SUMS` from the same release (`sha256sum -c --ignore-missing SHA256SUMS`).

### What the package does

* installs `/usr/bin/go-ddns` and the systemd unit `go-ddns.service`
* creates the system user `go-ddns`
* installs `/etc/go-ddns/config.toml` (mode 0640, `root:go-ddns`). Upgrades never overwrite it.
* creates `/etc/go-ddns/blacklist.d/` and `/var/lib/go-ddns/`
* does **not** start the service on a fresh install, because it needs AWS keys first. On upgrade it restarts the service if it was running.

### After install

```bash
sudo vi /etc/go-ddns/config.toml               # AWS keys, port
sudo systemctl enable --now go-ddns
journalctl -u go-ddns -f
```

IAM: attach [`deploy/iam-policy.json`](deploy/iam-policy.json) to the user whose keys go in the config.
The package also installs it as `/usr/share/doc/go-ddns/iam-policy.json`.

Upgrading means installing the newer package the same way. Uninstalling (`apt remove` / `dnf remove`) stops the service
but keeps the config, the database and the `go-ddns` user.

## Admin

The admin commands use the same binary. **Run them as the `go-ddns` user**, so the database files stay writable by the service:

    alias ddns='sudo -u go-ddns go-ddns'

    ddns client add home-router                                # prints UUID
    ddns token add home-router -name mikrotik -expires 8760h   # prints token ONCE
    ddns domain add home-router home.example.com               # hosted zone auto-detected
    ddns domain add home-router vpn.example.org -zone Z0123456789ABC -ttl 300
    ddns client list | token list | domain list
    ddns token disable 3
    ddns ban 203.0.113.0/24 "scanner"
    ddns unban 203.0.113.0/24
    ddns bans
    ddns version

If you ran them as root by accident, run `sudo chown go-ddns:go-ddns /var/lib/go-ddns/*` to fix it.

## Tables

| table   | key | notes |
|---------|-----|-------|
| clients | `id` UUID | name, enabled |
| tokens  | int | `client_id`, **sha256** of the token (the plaintext is never stored), expires_at, last_used_at/ip |
| domains | int | `client_id`, fqdn (unique), zone_id, ttl, last_ipv4, last_ipv6 |

Deleting a client cascades to its tokens and domains.

## Blacklist

* Every `*.txt`, `*.list` and `*.conf` file in `/etc/go-ddns/blacklist.d/` is loaded. Each line holds one IP or CIDR.
* The server reloads the files when they change, or on `systemctl reload go-ddns`.
* An IP is banned automatically after `max_failures` bad requests within `window`. Bad requests are an invalid or missing token, an unknown path (`/wp-login.php`, `/.env`, ...) or a wrong method. The ban is appended to `auto.txt` with a timestamp and reason.
* Banned peers are dropped at `accept()` with a TCP RST. They never see an HTTP response.
* IPs in `whitelist` are never banned. Add your own networks there so you can't lock yourself out.

## Notes

* Put it behind TLS (the `[tls]` section or a reverse proxy). If you use a reverse proxy, list it in `trusted_proxies`, or every client will appear as the proxy's IP.
* The "unchanged" check trusts the DB. If you edit a record by hand in the AWS console, force the next update with
  `sudo -u go-ddns sqlite3 /var/lib/go-ddns/ddns.db "UPDATE domains SET last_ipv4=NULL WHERE fqdn='x'"`.

## Building from source

Needs Go and gcc (the SQLite driver uses cgo).

    git clone https://github.com/vldmitrofanov/go-ddns && cd go-ddns
    make build              # static binary ./go-ddns
    sudo make install       # same layout as the packages
    make package            # local .deb/.rpm into dist/ (needs nfpm)

## Releasing

Push a `v*` tag. GitHub Actions then builds static amd64/arm64 binaries, packages them as `.deb`, `.rpm` and `.tar.gz`
with `SHA256SUMS`, and publishes a GitHub Release:

    git tag -a v0.0.2 -m "v0.0.2"
    git push origin v0.0.2

## License

MIT, see [LICENSE](LICENSE).
