BIN := go-ddns

build:
	CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o $(BIN) .

# Cross-compile for a Raspberry Pi / ARM box (needs: apt install gcc-aarch64-linux-gnu)
build-arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
	  go build -trimpath -ldflags="-s -w" -o $(BIN)-arm64 .

install: build
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)
	id go-ddns >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin go-ddns
	install -d -m 0750 -o root -g go-ddns /etc/go-ddns
	install -d -m 0770 -o root -g go-ddns /etc/go-ddns/blacklist.d
	install -d -m 0750 -o go-ddns -g go-ddns /var/lib/go-ddns
	[ -f /etc/go-ddns/config.toml ] || install -m 0640 -o root -g go-ddns deploy/config.toml /etc/go-ddns/config.toml
	[ -f /etc/go-ddns/blacklist.d/manual.txt ] || install -m 0660 -o root -g go-ddns deploy/manual.txt /etc/go-ddns/blacklist.d/manual.txt
	install -m 0644 deploy/go-ddns.service /etc/systemd/system/go-ddns.service
	systemctl daemon-reload
	@echo "Edit /etc/go-ddns/config.toml, then: systemctl enable --now go-ddns"

.PHONY: build build-arm64 install
