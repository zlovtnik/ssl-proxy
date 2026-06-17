.PHONY: build test dependency-boundaries bench docker lint clean deploy-ready up-ready diagnose memo-show memo-log pipeline-health audit-threats atheros-search-build atheros-search-test atheros-search-proto

ZIG_GLOBAL_CACHE_DIR := $(CURDIR)/.zig-cache/global
ZIG_LOCAL_CACHE_DIR := $(CURDIR)/.zig-cache/local
GO_BIN_DIR := $(shell go env GOPATH)/bin

# Build project binaries: root proxy, Atheros sensor, and Java coordinator.
build:
	cargo build --release -p sync-plane
	cargo build --release -p ssl-proxy
	cargo build --release -p atheros-sensor
	cargo build --release -p db-migrator
	cd services/zig-coordinator && gradle build

# Run tests
test:
	cargo test -p sync-plane
	cargo test -p ssl-proxy
	cargo test -p atheros-sensor
	cargo test -p db-migrator
	$(MAKE) dependency-boundaries
	cd services/zig-coordinator && gradle test

dependency-boundaries:
	@command -v rg >/dev/null
	@! rg -n 'use ssl_proxy|ssl_proxy::|ssl-proxy = \{ path = "\.\./\.\."' services/atheros-sensor services/atheros-sensor/Cargo.toml
	@cargo tree -p atheros-sensor --depth 1 --prefix none | awk '$$1 == "ssl-proxy" { found=1; print; } END { exit found ? 1 : 0 }'
	@cargo tree -p ssl-proxy --depth 1 --prefix none | awk '$$1 == "atheros-sensor" { found=1; print; } END { exit found ? 1 : 0 }'

# Run local benchmark baselines.
bench:
	cargo bench --bench wg_packet_obfuscation

# Build Docker images used by the compose stack.
docker:
	docker compose build ssl-proxy java-coordinator redpanda postgres

atheros-search-proto:
	cd services/atheros-search && PATH="$(GO_BIN_DIR):$$PATH" protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/atheros/search/v1/search.proto

atheros-search-build:
	cd services/atheros-search && go build -o "$${TMPDIR:-/tmp}/atheros-search" ./cmd/server

atheros-search-test:
	cd services/atheros-search && go test ./...

# Run clippy lints
lint:
	cargo clippy -- -D warnings

# Clean build artifacts
clean:
	cargo clean


# Bring up compose stack, verify services, and print peer QR codes.
# Example: make up-ready PROFILE_MODE=iphone SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
up-ready:
	./scripts/up-ready.sh

# Non-mutating diagnosis and signature classification.
# Example: make diagnose PROFILE_MODE=linux-shim SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
diagnose:
	./scripts/diagnose.sh

# Show operational memory ledger.
memo-show:
	./scripts/memo-show.sh

# Append one operational incident line.
# Example: make memo-log EVENT="iphone browse ok" CONTEXT="server 192.168.1.221 amd64; client 192.168.1.68 iPhone" RESULT=pass PROFILE_MODE=iphone
memo-log:
	./scripts/memo-log.sh

pipeline-health:
	./scripts/sync-status.sh

audit-threats:
	docker compose exec -T postgres psql "$${DATABASE_URL:-postgres://sync:sync@127.0.0.1:5432/sync}" \
	  -c "SELECT * FROM v_wireless_threats LIMIT 50;" 2>/dev/null || \
	  echo "[audit-threats] Run 'make pipeline-health' first to verify DB is up"

# Backward-compatible alias with deprecation warning.
deploy-ready: up-ready
	@echo "[deploy-ready][WARN] Deprecated target. Use 'make up-ready PROFILE_MODE=...'."
