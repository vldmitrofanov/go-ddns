# go-ddns

Small dynamic-DNS server for AWS Route 53. A client calls

    curl -H "Authorization: Bearer ddns_xxx" "https://ddns.example.com/update?domain=home.example.com"

and the A record (or AAAA if the caller is on IPv6) is set to the caller's source IP.

* `domain=home.example.com`: update one domain
* `domain=a.example.com,b.example.com`: update several
* `domain=all`, or no parameter: update **every** domain the client owns

The server only calls Route 53 when the IP actually changed (cached per domain in SQLite).
Domains in the same hosted zone are sent as one change batch.

## Build & install

    go mod tidy        # re-verifies module checksums on your machine
    make build         # needs gcc (mattn/go-sqlite3 uses cgo)
    sudo make install
    sudo vi /etc/go-ddns/config.toml   # AWS keys, port
    sudo systemctl enable --now go-ddns

IAM: attach `deploy/iam-policy.json` to the user whose keys go in the config.

## Admin

The admin commands use the same binary. Run them as root (or as a user who can read the config and DB):

    go-ddns client add home-router                          # prints UUID
    go-ddns token add home-router -name mikrotik -expires 8760h   # prints token ONCE
    go-ddns domain add home-router home.example.com         # hosted zone auto-detected
    go-ddns domain add home-router vpn.example.org -zone Z0123456789ABC -ttl 300
    go-ddns client list | token list | domain list
    go-ddns token disable 3
    go-ddns ban 203.0.113.0/24 "scanner"
    go-ddns unban 203.0.113.0/24
    go-ddns bans

**Running the DB commands as root?** Then `chown go-ddns /var/lib/go-ddns/*` afterwards, or run them with
`sudo -u go-ddns`, so the service can still write the DB.

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
* The "unchanged" check trusts the DB. If you edit a record by hand in the AWS console, run
  `sqlite3 /var/lib/go-ddns/ddns.db "UPDATE domains SET last_ipv4=NULL WHERE fqdn='x'"` to force the next update.
