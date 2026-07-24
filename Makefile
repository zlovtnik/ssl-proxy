.PHONY: build test dependency-boundaries runtime-datastore-policy tidb-schema-contract cutover-evidence-test bench docker lint clean deploy deploy-ready up-ready diagnose memo-show memo-log db-check-connections pipeline-health k8s-status audit-threats ops-test smoke bench-wg-path prep-ath setup-ubuntu configure-containerd-registry schema-migrator-smoke shellcheck-tier-b atheros-search-build atheros-search-test atheros-search-proto schema-migrator-test schema-migrator-ui-test registry-buildx registry-build-all registry-build-stack registry-mirror-all registry-build-vec-worker require-registry require-deploy-vars

ZIG_GLOBAL_CACHE_DIR := $(CURDIR)/.zig-cache/global
ZIG_LOCAL_CACHE_DIR := $(CURDIR)/.zig-cache/local
GO_BIN_DIR = $(shell go env GOPATH)/bin
OPS_BOOTSTRAP :=
OPS_VENV ?= ops/.venv
UV := $(shell command -v uv 2>/dev/null)

ifeq ($(origin OPS), undefined)
ifneq ($(origin OPS_PYTHON), undefined)
OPS = PYTHONPATH=ops/src $(OPS_PYTHON) -m sslproxy_ops
OPS_TEST = PYTHONPATH=ops/src $(OPS_PYTHON) -m unittest discover -s ops/tests -v
else
ifneq ($(UV),)
OPS = uv run --project ops python -m sslproxy_ops
OPS_TEST = uv run --project ops python -m unittest discover -s ops/tests -v
else
OPS_PYTHON = $(OPS_VENV)/bin/python
OPS_BOOTSTRAP = $(OPS_VENV)/.installed
OPS = $(OPS_PYTHON) -m sslproxy_ops
OPS_TEST = $(OPS_PYTHON) -m unittest discover -s ops/tests -v
endif
endif
endif
OPS_TEST ?= PYTHONPATH=ops/src python3 -m unittest discover -s ops/tests -v
REGISTRY ?=
REGISTRY_BUILDER ?= cross
REGISTRY_PLAIN_HTTP ?= auto
TAG ?= $(shell git rev-parse --short HEAD)
IMAGE_TAG ?= latest
PLATFORM ?= linux/amd64
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
ATHEROS_SEARCH_UI_API_BASE ?= http://localhost:8080
ATHEROS_SEARCH_UI_TITLE ?= atheros search
KUBE_NAMESPACE ?= default
KUBE_CONTEXT ?=
KUBE_RELEASE ?= ssl-proxy
KUBECTL ?= kubectl
REGISTRY_BUILD_NAMES := ssl-proxy java-coordinator atheros-sensor atheros-search wg-key-rotator atheros-search-ui schema-migrator-backend schema-migrator-ui tidb-runtime-schema
REGISTRY_BUILD_TARGETS := $(addprefix registry-build-,$(REGISTRY_BUILD_NAMES))
REGISTRY_MIRROR_IMAGES := redpandadata/redpanda:latest minio/minio:RELEASE.2025-09-07T16-13-09Z minio/mc:RELEASE.2025-08-13T08-35-41Z prom/prometheus:v2.54.1 grafana/loki:3.1.1 grafana/promtail:3.1.1 jaegertracing/all-in-one:1.62.0 otel/opentelemetry-collector-contrib:0.107.0 grafana/grafana:11.1.4 prom/node-exporter:v1.8.2 gcr.io/cadvisor/cadvisor:v0.49.1 prom/pushgateway:v1.8.0 quay.io/keycloak/keycloak:26.2.5 traefik:v3.6.2 busybox:1.37.0 pingcap/tidb:v8.5.0

ifeq ($(ENABLE_LEGACY_TARGETS),1)
include Makefile.legacy
endif

# Build project binaries: root proxy, Atheros sensor, and Java coordinator.
build:
	cargo build --release -p sync-plane
	cargo build --release -p ssl-proxy
	cargo build --release -p atheros-sensor
	cd apps/schema-migrator && sbt compile
	cd services/octopus && sbt assembly

# Run tests
test:
	$(MAKE) runtime-datastore-policy
	$(MAKE) tidb-schema-contract
	$(MAKE) cutover-evidence-test
	cargo test -p sync-plane
	cargo test -p ssl-proxy
	cargo test -p atheros-sensor
	$(MAKE) schema-migrator-test
	$(MAKE) dependency-boundaries
	cd services/octopus && sbt test

runtime-datastore-policy:
	scripts/check-runtime-datastores.py

tidb-schema-contract:
	scripts/check-tidb-schema-contract.py

cutover-evidence-test:
	python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v

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
	REGISTRY=local IMAGE_TAG=dev docker compose -f docker-compose.yaml -f docker-compose.build.yaml build ssl-proxy java-coordinator

require-registry:
	@test -n "$(REGISTRY)" || (echo "REGISTRY is required, for example REGISTRY=192.168.1.221:5000" >&2; exit 2)

require-deploy-vars:
	@test -n "$(DEPLOY_HOST)" || (echo "DEPLOY_HOST is required, for example DEPLOY_HOST=user@192.168.1.221" >&2; exit 2)
	@test -n "$(DEPLOY_PATH)" || (echo "DEPLOY_PATH is required, for example DEPLOY_PATH=/path/to/ssl-proxy" >&2; exit 2)

registry-buildx:
	@registry_host="$(REGISTRY)"; \
	registry_host="$${registry_host%%/*}"; \
	plain_http="$(REGISTRY_PLAIN_HTTP)"; \
	case "$$plain_http" in \
		auto) \
			case "$$registry_host" in \
				localhost:*|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) plain_http=1 ;; \
				*) plain_http=0 ;; \
			esac ;; \
		1|true|yes) plain_http=1 ;; \
		0|false|no) plain_http=0 ;; \
		*) echo "REGISTRY_PLAIN_HTTP must be auto, 1, or 0" >&2; exit 2 ;; \
	esac; \
	if [ "$$plain_http" = 1 ]; then \
		if [ -z "$$registry_host" ]; then \
			echo "REGISTRY is required when REGISTRY_PLAIN_HTTP=1" >&2; \
			exit 2; \
		fi; \
		builder_host="$$(printf '%s' "$$registry_host" | sed 's/[^[:alnum:]-]/-/g')"; \
		builder="$(REGISTRY_BUILDER)-http-$$builder_host"; \
		config="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$$builder.toml"; \
		printf '[registry."%s"]\n  http = true\n' "$$registry_host" > "$$config"; \
		if docker buildx inspect "$$builder" >/dev/null 2>&1; then \
			docker buildx use "$$builder"; \
		else \
			docker buildx create --use --name "$$builder" --driver docker-container --buildkitd-config "$$config"; \
		fi; \
	elif docker buildx inspect "$(REGISTRY_BUILDER)" >/dev/null 2>&1; then \
		docker buildx use "$(REGISTRY_BUILDER)"; \
	else \
		docker buildx create --use --name "$(REGISTRY_BUILDER)"; \
	fi

registry-build-all: $(REGISTRY_BUILD_TARGETS)

registry-mirror-all: require-registry
	@set -e; \
	for image in $(REGISTRY_MIRROR_IMAGES); do \
		destination="$(REGISTRY)/$$image"; \
		echo "[registry-mirror] $$image -> $$destination"; \
		docker pull --platform "$(PLATFORM)" "$$image"; \
		docker tag "$$image" "$$destination"; \
		docker push "$$destination"; \
	done

registry-build-stack: registry-build-all registry-mirror-all

define registry_build_target
.PHONY: registry-build-$(1)
registry-build-$(1): registry-buildx require-registry
	@set -e; \
	for _r in 1 2 3; do \
		if docker buildx build --platform $(PLATFORM) \
			--file $(2) $(3) \
			--tag $(REGISTRY)/$(4):$(TAG) \
			--tag $(REGISTRY)/$(4):latest \
			--push $(5); then \
			exit 0; \
		fi; \
		echo "[registry-build-$(1)] attempt $$$${_r} failed, retrying in 3s..." >&2; \
		sleep 3; \
	done; \
	echo "[registry-build-$(1)] failed after 3 attempts" >&2; \
	exit 1
endef

$(eval $(call registry_build_target,ssl-proxy,Dockerfile,--target ssl-proxy --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),ssl-proxy,.))
$(eval $(call registry_build_target,java-coordinator,services/octopus/Dockerfile,,java-coordinator,.))
$(eval $(call registry_build_target,atheros-sensor,Dockerfile,--target atheros-sensor --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),atheros-sensor,.))
$(eval $(call registry_build_target,atheros-search,services/atheros-search/Dockerfile,,atheros-search,.))
$(eval $(call registry_build_target,wg-key-rotator,apps/wg-key-rotator/Dockerfile,,wg-key-rotator,./apps/wg-key-rotator))
$(eval $(call registry_build_target,atheros-search-ui,apps/integration-console/atheros-search-ui/Dockerfile,--build-arg VITE_API_BASE="$(ATHEROS_SEARCH_UI_API_BASE)" --build-arg VITE_APP_TITLE="$(ATHEROS_SEARCH_UI_TITLE)",atheros-search-ui,./apps/integration-console/atheros-search-ui))
$(eval $(call registry_build_target,schema-migrator-backend,apps/schema-migrator/Dockerfile.backend,,schema-migrator-backend,./apps/schema-migrator))
$(eval $(call registry_build_target,schema-migrator-ui,apps/schema-migrator/frontend/Dockerfile,,schema-migrator-ui,./apps/schema-migrator))
$(eval $(call registry_build_target,tidb-runtime-schema,k8s/tidb-schema-executor/Dockerfile,,tidb-runtime-schema,.))

registry-build-vec-worker:
	@echo "[registry-build-vec-worker] vec-worker is consolidated into atheros-search"
	@"$${MAKE:-make}" registry-build-atheros-search REGISTRY="$(REGISTRY)" TAG="$(TAG)" PLATFORM="$(PLATFORM)"

deploy: require-deploy-vars
	ssh "$(DEPLOY_HOST)" "cd '$(DEPLOY_PATH)' && docker compose pull && docker compose up -d"

atheros-search-proto:
	cd services/atheros-search && PATH="$(GO_BIN_DIR):$$PATH" protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/atheros/search/v1/search.proto

atheros-search-build:
	cd services/atheros-search && go build -o "$${TMPDIR:-/tmp}/atheros-search" ./cmd/server

atheros-search-test:
	cd services/atheros-search && go test ./...

schema-migrator-test:
	cd apps/schema-migrator && sbt test
	$(MAKE) schema-migrator-ui-test

schema-migrator-ui-test:
	cd apps/schema-migrator/schema-migrator-ui && bun run test
	cd apps/schema-migrator/schema-migrator-ui && bun run build
$(OPS_VENV)/.installed: ops/pyproject.toml ops/uv.lock scripts/lib/ops-python.sh
	@bash -lc 'source scripts/lib/ops-python.sh; sslproxy_ensure_ops_venv "$$PWD"'

# Run clippy lints
lint:
	cargo clippy -- -D warnings

# Clean build artifacts
clean:
	cargo clean


# Build/mirror registry images, upgrade the Kubernetes Helm release, verify it,
# and print peer QR codes. Set UP_READY_DEPLOYMENT_TARGET=compose for Compose.
# Example: make up-ready PROFILE_MODE=iphone SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
up-ready: $(OPS_BOOTSTRAP)
	$(OPS) up-ready

# Non-mutating diagnosis and signature classification.
# Example: make diagnose PROFILE_MODE=linux-shim SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
diagnose: $(OPS_BOOTSTRAP)
	$(OPS) diagnose

# Show operational memory ledger.
memo-show: $(OPS_BOOTSTRAP)
	$(OPS) memo show

# Append one operational incident line.
# Example: make memo-log EVENT="iphone browse ok" CONTEXT="server 192.168.1.221 amd64; client 192.168.1.68 iPhone" RESULT=pass PROFILE_MODE=iphone
memo-log: $(OPS_BOOTSTRAP)
	$(OPS) memo log

db-check-connections: $(OPS_BOOTSTRAP)
	$(OPS) db check-connections

pipeline-health: $(OPS_BOOTSTRAP)
	$(OPS) pipeline status

# Print a read-only Kubernetes diagnostic snapshot for the ssl-proxy namespace.
# Override the defaults with KUBE_NAMESPACE, KUBE_CONTEXT, KUBE_RELEASE, or KUBECTL.
k8s-status:
	KUBECTL="$(KUBECTL)" KUBE_CONTEXT="$(KUBE_CONTEXT)" KUBE_RELEASE="$(KUBE_RELEASE)" scripts/k8s-namespace-status.sh "$(KUBE_NAMESPACE)"

smoke: $(OPS_BOOTSTRAP)
	$(OPS) smoke

bench-wg-path: $(OPS_BOOTSTRAP)
	$(OPS) bench wg-path

schema-migrator-smoke: $(OPS_BOOTSTRAP)
	$(OPS) schema-migrator smoke

prep-ath: $(OPS_BOOTSTRAP)
	$(OPS) host prep-ath

setup-ubuntu: $(OPS_BOOTSTRAP)
	$(OPS) host setup-ubuntu

# Run once as root on each Kubernetes node that pulls from REGISTRY.
configure-containerd-registry: require-registry $(OPS_BOOTSTRAP)
	@registry_host="$(REGISTRY)"; \
	registry_host="$${registry_host%%/*}"; \
	plain_http="$(REGISTRY_PLAIN_HTTP)"; \
	case "$$plain_http" in \
		auto) \
			case "$$registry_host" in \
				localhost:*|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) plain_http=1 ;; \
				*) plain_http=0 ;; \
			esac ;; \
		1|true|yes) plain_http=1 ;; \
		0|false|no) plain_http=0 ;; \
		*) echo "REGISTRY_PLAIN_HTTP must be auto, 1, or 0" >&2; exit 2 ;; \
	esac; \
	if [ "$$plain_http" = 1 ]; then \
		transport_arg=--plain-http; \
	else \
		transport_arg=--tls; \
	fi; \
	if [ -n "$(UV)" ]; then \
		sudo env REGISTRY="$(REGISTRY)" "$(UV)" run --project "$(CURDIR)/ops" python -m sslproxy_ops host configure-containerd-registry --registry "$(REGISTRY)" "$$transport_arg"; \
	else \
		sudo env REGISTRY="$(REGISTRY)" "$(OPS_PYTHON)" -m sslproxy_ops host configure-containerd-registry --registry "$(REGISTRY)" "$$transport_arg"; \
	fi

shellcheck-tier-b: $(OPS_BOOTSTRAP)
	$(OPS) host shellcheck-tier-b

ops-test: $(OPS_BOOTSTRAP)
	$(OPS_TEST)

audit-threats:
	$(OPS) pipeline status

# Backward-compatible alias with deprecation warning.
deploy-ready: up-ready
	@echo "[deploy-ready][WARN] Deprecated target. Use 'make up-ready PROFILE_MODE=...'."
