.PHONY: build test docker lint clean deploy-ready up-ready diagnose memo-show memo-log pipeline-health audit-threats

ZIG_GLOBAL_CACHE_DIR := $(CURDIR)/.zig-cache/global
ZIG_LOCAL_CACHE_DIR := $(CURDIR)/.zig-cache/local

# Build project binaries: root, services/oracle-worker, and services/zig-coordinator
build:
	cargo build --release
	cd services/atheros-sensor && cargo build --release
	cd services/oracle-worker && cargo build --release
	cd services/zig-coordinator && ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" zig build -Doptimize=ReleaseSafe

# Run tests
test:
	cargo test
	cd services/atheros-sensor && cargo test
	cd services/oracle-worker && cargo test
	cd services/zig-coordinator && ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" zig build test

# Build Docker images for all services
docker:
	docker compose build ssl-proxy zig-coordinator oracle-worker nats postgres

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
