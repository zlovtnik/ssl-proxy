.DEFAULT_GOAL := build-all

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

REGISTRY ?= 192.168.1.221:5000
REGISTRY_PLAIN_HTTP ?= 0
ENV ?= prod
KUBE_CONTEXT ?=
BUILDER ?= ssl-proxy-publisher
BUILDX_READY ?= 0
PLATFORM ?= linux/amd64
TAG ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LOCAL_IMAGE_PREFIX ?= ssl-proxy-local
KUSTOMIZE ?= kustomize
PUBLISH_REPOSITORY ?=
PUBLISH_METADATA_FILE ?=

ATHEROS_SEARCH_UI_API_BASE ?=
ATHEROS_SEARCH_UI_TITLE ?= atheros search

SERVICES := ssl-proxy java-coordinator atheros-sensor atheros-search wg-key-rotator atheros-search-ui schema-migrator-backend schema-migrator-ui tidb-runtime-schema
DEPLOYABLE_SERVICES := $(filter-out wg-key-rotator,$(SERVICES))
BUILD_TARGETS := $(addprefix build-,$(SERVICES))
PUBLISH_TARGETS := $(addprefix publish-,$(SERVICES))
BUMP_DIGEST_TARGETS := $(addprefix bump-digest-,$(DEPLOYABLE_SERVICES))

.PHONY: build build-all publish publish-all recover-stack ci-publish-services buildx-ready require-registry docs-check gitops-check test lint dependency-boundaries atheros-search-test $(BUILD_TARGETS) $(PUBLISH_TARGETS) $(BUMP_DIGEST_TARGETS)

build: build-all

publish:
	python3 scripts/publish_images.py \
		--environment "$(ENV)" \
		--tag "$(TAG)" \
		--build-date "$(BUILD_DATE)" \
		--builder "$(BUILDER)" \
		--platform "$(PLATFORM)" \
		--registry-plain-http "$(REGISTRY_PLAIN_HTTP)" \
		--atheros-search-ui-api-base "$(ATHEROS_SEARCH_UI_API_BASE)" \
		--atheros-search-ui-title "$(ATHEROS_SEARCH_UI_TITLE)" \
		--make-command "$(MAKE)"

build-all: $(BUILD_TARGETS)

publish-all: $(PUBLISH_TARGETS)

recover-stack:
	python3 scripts/recover_stack.py \
		--environment "$(ENV)" \
		--kube-context "$(KUBE_CONTEXT)" \
		--kustomize "$(KUSTOMIZE)" \
		--registry-plain-http "$(REGISTRY_PLAIN_HTTP)"

# Read-only image inventory for CI fan-out. Keep build-all for local loaded-image workflows.
ci-publish-services:
	@printf '%s\n' $(SERVICES)

docs-check:
	python3 scripts/check-docs.py

gitops-check:
	python3 scripts/image_contract.py contract --environment dev >/dev/null
	python3 scripts/image_contract.py contract --environment prod >/dev/null
	python3 scripts/check-gitops.py --kustomize "$(KUSTOMIZE)"

test:
	cargo test -p sync-plane
	cargo test -p ssl-proxy
	cargo test -p atheros-sensor
	cd apps/schema-migrator && sbt test
	cd services/octopus && sbt test
	$(MAKE) atheros-search-test
	$(MAKE) dependency-boundaries

lint:
	cargo clippy -- -D warnings

dependency-boundaries:
	@command -v rg >/dev/null
	@! rg -n 'use ssl_proxy|ssl_proxy::|ssl-proxy = \{ path = "\.\./\.\."' services/atheros-sensor services/atheros-sensor/Cargo.toml
	@cargo tree -p atheros-sensor --depth 1 --prefix none | awk '$$1 == "ssl-proxy" { found=1; print; } END { exit found ? 1 : 0 }'
	@cargo tree -p ssl-proxy --depth 1 --prefix none | awk '$$1 == "atheros-sensor" { found=1; print; } END { exit found ? 1 : 0 }'

atheros-search-test:
	cd services/atheros-search && go test ./...

require-registry:
	@test -n "$(REGISTRY)" || { echo "REGISTRY is required" >&2; exit 2; }

buildx-ready: require-registry
	@docker info >/dev/null
	@registry_host="$(REGISTRY)"; \
	registry_host="$${registry_host%%/*}"; \
	config="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$(BUILDER).toml"; \
	stamp="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$(BUILDER).mode"; \
	if docker buildx inspect "$(BUILDER)" >/dev/null 2>&1; then \
		if [ -f "$$stamp" ]; then \
			configured_registry="$$(sed -n '1p' "$$stamp")"; \
			configured_mode="$$(sed -n '2p' "$$stamp")"; \
			if [ "$$configured_mode" != "$(REGISTRY_PLAIN_HTTP)" ] || { [ "$(REGISTRY_PLAIN_HTTP)" = "1" ] && [ "$$configured_registry" != "$$registry_host" ]; }; then \
				echo "Buildx builder $(BUILDER) uses REGISTRY_PLAIN_HTTP=$$configured_mode for $$configured_registry, but REGISTRY_PLAIN_HTTP=$(REGISTRY_PLAIN_HTTP) was requested for $$registry_host." >&2; \
				echo "Use an unused dedicated builder (for example BUILDER=$(BUILDER)-http) or remove and recreate $(BUILDER) after confirming it is safe." >&2; \
				exit 2; \
			fi; \
		elif [ "$(REGISTRY_PLAIN_HTTP)" = "1" ]; then \
			echo "Buildx builder $(BUILDER) already exists, so its HTTP registry configuration for $$registry_host cannot be verified." >&2; \
			echo "Use an unused dedicated HTTP-configured builder (for example BUILDER=$(BUILDER)-http) instead of proceeding with HTTPS." >&2; \
			exit 2; \
		fi; \
	else \
		if [ "$(REGISTRY_PLAIN_HTTP)" = "1" ]; then \
			printf '[registry."%s"]\n  http = true\n' "$$registry_host" > "$$config"; \
			docker buildx create --name "$(BUILDER)" --driver docker-container --buildkitd-config "$$config" >/dev/null; \
		else \
			docker buildx create --name "$(BUILDER)" --driver docker-container >/dev/null; \
		fi; \
		printf '%s\n%s\n' "$$registry_host" "$(REGISTRY_PLAIN_HTTP)" > "$$stamp"; \
	fi
	@docker buildx inspect "$(BUILDER)" --bootstrap >/dev/null

define service_rules
build-$(1):
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(LOCAL_IMAGE_PREFIX)/$(4):$(TAG)" --load "$(5)"

publish-$(1):
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(if $(strip $(PUBLISH_REPOSITORY)),$(PUBLISH_REPOSITORY),$(REGISTRY)/$(4)):$(TAG)" --tag "$(if $(strip $(PUBLISH_REPOSITORY)),$(PUBLISH_REPOSITORY),$(REGISTRY)/$(4)):latest" --push $(if $(strip $(PUBLISH_METADATA_FILE)),--metadata-file "$(PUBLISH_METADATA_FILE)",) "$(5)"
endef

$(eval $(call service_rules,ssl-proxy,Dockerfile,--target ssl-proxy --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),ssl-proxy,.))
$(eval $(call service_rules,java-coordinator,services/octopus/Dockerfile,,java-coordinator,.))
$(eval $(call service_rules,atheros-sensor,Dockerfile,--target atheros-sensor --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),atheros-sensor,.))
$(eval $(call service_rules,atheros-search,services/atheros-search/Dockerfile,,atheros-search,.))
$(eval $(call service_rules,wg-key-rotator,apps/wg-key-rotator/Dockerfile,,wg-key-rotator,apps/wg-key-rotator))
$(eval $(call service_rules,atheros-search-ui,apps/integration-console/atheros-search-ui/Dockerfile,--build-arg 'VITE_API_BASE=$(ATHEROS_SEARCH_UI_API_BASE)' --build-arg 'VITE_APP_TITLE=$(ATHEROS_SEARCH_UI_TITLE)',atheros-search-ui,apps/integration-console/atheros-search-ui))
$(eval $(call service_rules,schema-migrator-backend,apps/schema-migrator/Dockerfile.backend,,schema-migrator-backend,apps/schema-migrator))
$(eval $(call service_rules,schema-migrator-ui,apps/schema-migrator/frontend/Dockerfile,,schema-migrator-ui,apps/schema-migrator))
$(eval $(call service_rules,tidb-runtime-schema,k8s/tidb-schema-executor/Dockerfile,,tidb-runtime-schema,.))

ifneq ($(BUILDX_READY),1)
$(BUILD_TARGETS) $(PUBLISH_TARGETS): buildx-ready
endif

define bump_digest_rule
bump-digest-$(1):
	@test -n "$(ENV)" || { echo "ENV is required (dev or prod)" >&2; exit 2; }
	@test -n "$(DIGEST)" || { echo "DIGEST is required (sha256:...)" >&2; exit 2; }
	./scripts/bump-image-digest.sh "$(1)" "$(ENV)" "$(DIGEST)"
endef

$(foreach service,$(DEPLOYABLE_SERVICES),$(eval $(call bump_digest_rule,$(service))))
