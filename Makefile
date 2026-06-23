.PHONY: build test dependency-boundaries bench docker lint clean deploy deploy-ready up-ready diagnose memo-show memo-log pipeline-health audit-threats atheros-search-build atheros-search-test atheros-search-proto registry-buildx registry-build-all registry-build-ssl-proxy registry-build-java-coordinator registry-build-integration-console registry-build-atheros-sensor registry-build-atheros-search registry-build-wg-key-rotator registry-build-postgres registry-build-atheros-search-ui registry-build-vec-worker require-registry require-deploy-vars

ZIG_GLOBAL_CACHE_DIR := $(CURDIR)/.zig-cache/global
ZIG_LOCAL_CACHE_DIR := $(CURDIR)/.zig-cache/local
GO_BIN_DIR = $(shell go env GOPATH)/bin
REGISTRY ?=
TAG ?= $(shell git rev-parse --short HEAD)
IMAGE_TAG ?= latest
PLATFORM ?= linux/amd64
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
ATHEROS_SEARCH_UI_API_BASE ?= http://localhost:8080
ATHEROS_SEARCH_UI_TITLE ?= atheros search
REGISTRY_BUILD_TARGETS := registry-build-ssl-proxy registry-build-java-coordinator registry-build-integration-console registry-build-atheros-sensor registry-build-atheros-search registry-build-wg-key-rotator registry-build-postgres registry-build-atheros-search-ui

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
	REGISTRY=local IMAGE_TAG=dev docker compose -f docker-compose.yaml -f docker-compose.build.yaml build ssl-proxy java-coordinator postgres

require-registry:
	@test -n "$(REGISTRY)" || (echo "REGISTRY is required, for example REGISTRY=192.168.1.221:5000" >&2; exit 2)

require-deploy-vars:
	@test -n "$(DEPLOY_HOST)" || (echo "DEPLOY_HOST is required, for example DEPLOY_HOST=user@192.168.1.221" >&2; exit 2)
	@test -n "$(DEPLOY_PATH)" || (echo "DEPLOY_PATH is required, for example DEPLOY_PATH=/path/to/ssl-proxy" >&2; exit 2)

registry-buildx:
	@if docker buildx inspect cross >/dev/null 2>&1; then \
		docker buildx use cross; \
	else \
		docker buildx create --use --name cross; \
	fi

registry-build-all: $(REGISTRY_BUILD_TARGETS)
	@if [ -f services/vec-worker/Dockerfile ]; then \
		"$${MAKE:-make}" registry-build-vec-worker REGISTRY="$(REGISTRY)" TAG="$(TAG)" PLATFORM="$(PLATFORM)"; \
	else \
		echo "[registry-build-all] skipping vec-worker: services/vec-worker/Dockerfile not found"; \
	fi

registry-build-ssl-proxy: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file Dockerfile \
		--target ssl-proxy \
		--build-arg VCS_REF=$(TAG) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(REGISTRY)/ssl-proxy:$(TAG) \
		--tag $(REGISTRY)/ssl-proxy:latest \
		--push .

registry-build-java-coordinator: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file services/zig-coordinator/Dockerfile \
		--tag $(REGISTRY)/java-coordinator:$(TAG) \
		--tag $(REGISTRY)/java-coordinator:latest \
		--push .

registry-build-integration-console: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file apps/integration-console/Dockerfile \
		--tag $(REGISTRY)/integration-console:$(TAG) \
		--tag $(REGISTRY)/integration-console:latest \
		--push .

registry-build-atheros-sensor: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file Dockerfile \
		--target atheros-sensor \
		--build-arg VCS_REF=$(TAG) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(REGISTRY)/atheros-sensor:$(TAG) \
		--tag $(REGISTRY)/atheros-sensor:latest \
		--push .

registry-build-atheros-search: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file services/atheros-search/Dockerfile \
		--tag $(REGISTRY)/atheros-search:$(TAG) \
		--tag $(REGISTRY)/atheros-search:latest \
		--push .

registry-build-wg-key-rotator: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file apps/wg-key-rotator/Dockerfile \
		--tag $(REGISTRY)/wg-key-rotator:$(TAG) \
		--tag $(REGISTRY)/wg-key-rotator:latest \
		--push ./apps/wg-key-rotator

registry-build-postgres: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file docker/postgres/Dockerfile \
		--tag $(REGISTRY)/ssl-proxy-postgres:$(TAG) \
		--tag $(REGISTRY)/ssl-proxy-postgres:latest \
		--push .

registry-build-atheros-search-ui: registry-buildx require-registry
	docker buildx build --platform $(PLATFORM) \
		--file Dockerfile \
		--build-arg VITE_API_BASE="$(ATHEROS_SEARCH_UI_API_BASE)" \
		--build-arg VITE_APP_TITLE="$(ATHEROS_SEARCH_UI_TITLE)" \
		--tag $(REGISTRY)/atheros-search-ui:$(TAG) \
		--tag $(REGISTRY)/atheros-search-ui:latest \
		--push ./apps/integration-console/atheros-search-ui

registry-build-vec-worker: registry-buildx require-registry
	@if [ ! -f services/vec-worker/Dockerfile ]; then \
		echo "vec-worker image cannot be built: services/vec-worker/Dockerfile not found" >&2; \
		exit 1; \
	fi
	docker buildx build --platform $(PLATFORM) \
		--file services/vec-worker/Dockerfile \
		--tag $(REGISTRY)/vec-worker:$(TAG) \
		--tag $(REGISTRY)/vec-worker:latest \
		--push .

deploy: require-deploy-vars
	ssh "$(DEPLOY_HOST)" "cd '$(DEPLOY_PATH)' && docker compose pull && docker compose up -d"

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
