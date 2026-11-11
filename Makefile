BIN     := go-ddns
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)

# Fully static binary (glibc static + pure-Go DNS/user lookup, no dlopen):
# runs on any Linux regardless of the distro's glibc version.
GOFLAGS_STATIC := -trimpath -tags 'osusergo netgo sqlite_omit_load_extension'
LDFLAGS        := -s -w -X main.version=$(VERSION) -linkmode external -extldflags '-static'

build:
	CGO_ENABLED=1 go build $(GOFLAGS_STATIC) -ldflags "$(LDFLAGS)" -o $(BIN) .

install: build
	install -m 0755 $(BIN) /usr/bin/$(BIN)
	id go-ddns >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/go-ddns --shell /usr/sbin/nologin go-ddns
	install -d -m 0750 -o root -g go-ddns /etc/go-ddns
	install -d -m 0770 -o root -g go-ddns /etc/go-ddns/blacklist.d
	install -d -m 0750 -o go-ddns -g go-ddns /var/lib/go-ddns
	[ -f /etc/go-ddns/config.toml ] || install -m 0640 -o root -g go-ddns deploy/config.toml /etc/go-ddns/config.toml
	[ -f /etc/go-ddns/blacklist.d/manual.txt ] || install -m 0660 -o root -g go-ddns deploy/manual.txt /etc/go-ddns/blacklist.d/manual.txt
	install -m 0644 deploy/go-ddns.service /etc/systemd/system/go-ddns.service
	systemctl daemon-reload
	@echo "Edit /etc/go-ddns/config.toml, then: systemctl enable --now go-ddns"

# Local package build (needs nfpm: https://nfpm.goreleaser.com/install/)
package: build
	mkdir -p dist
	VERSION=$(VERSION) ARCH=$$(go env GOARCH) nfpm pkg -f nfpm.yaml -p deb -t dist/
	VERSION=$(VERSION) ARCH=$$(go env GOARCH) nfpm pkg -f nfpm.yaml -p rpm -t dist/

.PHONY: build install package
