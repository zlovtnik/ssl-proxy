.DEFAULT_GOAL := build-all

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

REGISTRY ?= 192.168.1.242:5000
REGISTRY_PLAIN_HTTP ?= 0
REGISTRY_KEEP_RECENT ?= 12
REGISTRY_CLEAN_CONFIRM ?=
REGISTRY_GC_CONFIRM ?=
ENV ?= prod
KUBE_CONTEXT ?=
KUBECTL ?= kubectl
ARGOCD_NAMESPACE ?= argocd
ARGOCD_TIMEOUT ?= 30m
PRODUCTION_GATE_REVISION ?= $(shell git rev-parse HEAD)
PRODUCTION_GATE_TIMEOUT ?= 30m
PRODUCTION_GATE_POLL_INTERVAL ?= 10s
BUILDER ?= ssl-proxy-publisher
BUILDER_NETWORK ?=
BUILDX_READY ?= 0
PLATFORM ?= linux/amd64
TAG ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LOCAL_IMAGE_PREFIX ?= ssl-proxy-local
KUSTOMIZE ?= kubectl
KUSTOMIZE_EDITOR ?= kustomize
PUBLISH_REPOSITORY ?=
PUBLISH_METADATA_FILE ?=
override PARENT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
override OCTOPUS_COMMIT := $(shell git -C services/octopus rev-parse HEAD 2>/dev/null)

ATHEROS_SEARCH_UI_API_BASE ?=
ATHEROS_SEARCH_UI_TITLE ?= atheros search
ATHEROS_SEARCH_UI_KEYCLOAK_URL ?= https://gateway.rclabs.uk
ATHEROS_SEARCH_UI_KEYCLOAK_REALM ?= middleware
ATHEROS_SEARCH_UI_KEYCLOAK_CLIENT_ID ?= atheros-search-ui

SERVICES := ssl-proxy java-coordinator atheros-sensor atheros-search wg-key-rotator atheros-search-ui schema-migrator-backend schema-migrator-ui postgres-runtime-schema
# wg-key-rotator is an operational tool, not a long-lived Kubernetes workload.
DEPLOYABLE_SERVICES := $(filter-out wg-key-rotator,$(SERVICES))
BUILD_TARGETS := $(addprefix build-,$(SERVICES))
PUBLISH_TARGETS := $(addprefix publish-,$(SERVICES))
BUMP_DIGEST_TARGETS := $(addprefix bump-digest-,$(DEPLOYABLE_SERVICES))
ARGOCD_APPLICATIONS := ssl-proxy-prod-bootstrap ssl-proxy-prod-data-plane ssl-proxy-prod-app-stack
KUBECTL_CONTEXT_ARG = $(if $(strip $(KUBE_CONTEXT)),--context "$(KUBE_CONTEXT)",)

.PHONY: build build-all publish publish-all prep-ath kube-context-check recover-stack production-gate stack-health pvc-audit argocd-server-health argocd-status argocd-wait ci-publish-services buildx-ready require-registry registry-clean-plan registry-clean registry-gc octopus-source-integrity check-java-coordinator-image jenkins-plugin-lock jenkins-plugin-audit docs-check gitops-check test lint dependency-boundaries atheros-search-test $(BUILD_TARGETS) $(PUBLISH_TARGETS) $(BUMP_DIGEST_TARGETS)

build: build-all

publish: octopus-source-integrity
	python3 scripts/publish_images.py \
		--environment "$(ENV)" \
		--tag "$(TAG)" \
		--build-date "$(BUILD_DATE)" \
		--builder "$(BUILDER)" \
		--platform "$(PLATFORM)" \
		--registry-plain-http "$(REGISTRY_PLAIN_HTTP)" \
		--atheros-search-ui-api-base "$(ATHEROS_SEARCH_UI_API_BASE)" \
		--atheros-search-ui-title "$(ATHEROS_SEARCH_UI_TITLE)" \
		--atheros-search-ui-keycloak-url "$(ATHEROS_SEARCH_UI_KEYCLOAK_URL)" \
		--atheros-search-ui-keycloak-realm "$(ATHEROS_SEARCH_UI_KEYCLOAK_REALM)" \
		--atheros-search-ui-keycloak-client-id "$(ATHEROS_SEARCH_UI_KEYCLOAK_CLIENT_ID)" \
		--make-command "$(MAKE)"

build-all: $(BUILD_TARGETS)

publish-all: octopus-source-integrity $(PUBLISH_TARGETS)

prep-ath:
	sudo ./scripts/prep_ath.sh \
		--reg-domain "$${ATH_SENSOR_REG_DOMAIN:-US}" \
		--channel "$${ATH_SENSOR_CHANNEL:-6}" \
		"$${ATH_SENSOR_DEVICE:-wlan0}"

kube-context-check:
	@context="$(strip $(KUBE_CONTEXT))"; \
	source="KUBE_CONTEXT"; \
	if [ -z "$$context" ]; then \
		context="$$( $(KUBECTL) config current-context 2>/dev/null || true )"; \
		source="kubectl current-context"; \
	fi; \
	if [ -z "$$context" ]; then \
		echo "No Kubernetes context is active. Set KUBE_CONTEXT to one of:" >&2; \
		$(KUBECTL) config get-contexts -o name >&2 || true; \
		exit 2; \
	fi; \
	if ! $(KUBECTL) config get-contexts "$$context" -o name >/dev/null 2>&1; then \
		echo "Kubernetes context '$$context' is not present in the effective kubeconfig." >&2; \
		echo "Available contexts:" >&2; \
		$(KUBECTL) config get-contexts -o name >&2 || true; \
		echo "Check KUBECONFIG, or omit KUBE_CONTEXT to use the active context." >&2; \
		exit 2; \
	fi; \
	server="$$( $(KUBECTL) --context "$$context" config view --minify \
		-o jsonpath='{.clusters[0].cluster.server}' )"; \
	$(KUBECTL) --context "$$context" version --request-timeout=5s -o json >/dev/null; \
	printf 'Kubernetes context: %s (%s)\nKubernetes API:     %s\n' "$$context" "$$source" "$$server"

recover-stack: kube-context-check
	python3 scripts/recover_stack.py \
		--environment "$(ENV)" \
		--kubectl "$(KUBECTL)" \
		--kube-context "$(KUBE_CONTEXT)" \
		--kustomize "$(KUSTOMIZE)" \
		--registry-plain-http "$(REGISTRY_PLAIN_HTTP)"

pvc-audit: kube-context-check
	python3 scripts/pvc_audit.py --kubectl "$(KUBECTL)" $(if $(strip $(KUBE_CONTEXT)),--context "$(KUBE_CONTEXT)",)

production-gate:
	@test -n "$(PRODUCTION_GATE_REVISION)" || { echo "PRODUCTION_GATE_REVISION is required" >&2; exit 2; }
	python3 scripts/production_gate.py \
		--revision "$(PRODUCTION_GATE_REVISION)" \
		--kubectl "$(KUBECTL)" \
		--kube-context "$(KUBE_CONTEXT)" \
		--namespace "$(ARGOCD_NAMESPACE)" \
		--timeout "$(PRODUCTION_GATE_TIMEOUT)" \
		--poll-interval "$(PRODUCTION_GATE_POLL_INTERVAL)"

argocd-server-health: kube-context-check
	$(KUBECTL) $(KUBECTL_CONTEXT_ARG) --namespace "$(ARGOCD_NAMESPACE)" wait \
		--for=condition=Available deployment --all --timeout="$(ARGOCD_TIMEOUT)"
	$(KUBECTL) $(KUBECTL_CONTEXT_ARG) --namespace "$(ARGOCD_NAMESPACE)" rollout status \
		statefulset/argocd-application-controller --timeout="$(ARGOCD_TIMEOUT)"

argocd-status: argocd-server-health
	$(KUBECTL) $(KUBECTL_CONTEXT_ARG) --namespace "$(ARGOCD_NAMESPACE)" get \
		applications.argoproj.io \
		--selector app.kubernetes.io/part-of=ssl-proxy \
		-o custom-columns='NAME:.metadata.name,SYNC:.status.sync.status,HEALTH:.status.health.status,REVISION:.status.sync.revision,PATH:.spec.source.path'

argocd-wait: argocd-server-health
	@for application in $(ARGOCD_APPLICATIONS); do \
		$(KUBECTL) $(KUBECTL_CONTEXT_ARG) --namespace "$(ARGOCD_NAMESPACE)" wait \
			--for=jsonpath='{.status.sync.status}'=Synced \
			application/$$application --timeout="$(ARGOCD_TIMEOUT)"; \
	done
	@for application in $(ARGOCD_APPLICATIONS); do \
		$(KUBECTL) $(KUBECTL_CONTEXT_ARG) --namespace "$(ARGOCD_NAMESPACE)" wait \
			--for=jsonpath='{.status.health.status}'=Healthy \
			application/$$application --timeout="$(ARGOCD_TIMEOUT)"; \
	done

stack-health: gitops-check argocd-status recover-stack argocd-wait

# Read-only image inventory for CI fan-out. Keep build-all for local loaded-image workflows.
ci-publish-services:
	@printf '%s\n' $(SERVICES)

octopus-source-integrity:
	python3 scripts/octopus_image_contract.py source

check-java-coordinator-image:
	@test -n "$(IMAGE)" || { echo "IMAGE is required" >&2; exit 2; }
	python3 scripts/octopus_image_contract.py image "$(IMAGE)"

jenkins-plugin-lock:
	python3 scripts/jenkins_plugins.py lock

jenkins-plugin-audit:
	python3 scripts/jenkins_plugins.py audit

docs-check:
	python3 scripts/check-docs.py

gitops-check:
	python3 scripts/image_contract.py contract --environment prod >/dev/null
	python3 scripts/check-gitops.py --kustomize "$(KUSTOMIZE_EDITOR)"

test:
	cargo test -p sync-plane
	cargo test -p ssl-proxy
	cargo test -p atheros-sensor
	cd apps/schema-migrator && sbt 'Test / testFull'
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

platform-sync-lint:
	cd services/platform-sync && go vet ./...
	cd services/platform-sync && go test ./...

require-registry:
	@test -n "$(REGISTRY)" || { echo "REGISTRY is required" >&2; exit 2; }

registry-clean-plan: require-registry kube-context-check
	python3 scripts/registry_cleanup.py \
		--registry "$(REGISTRY)" \
		$(if $(filter 1,$(REGISTRY_PLAIN_HTTP)),--plain-http,) \
		$(if $(strip $(KUBE_CONTEXT)),--context "$(KUBE_CONTEXT)",) \
		--keep-recent "$(REGISTRY_KEEP_RECENT)"

registry-clean: require-registry kube-context-check
	python3 scripts/registry_cleanup.py \
		--registry "$(REGISTRY)" \
		$(if $(filter 1,$(REGISTRY_PLAIN_HTTP)),--plain-http,) \
		$(if $(strip $(KUBE_CONTEXT)),--context "$(KUBE_CONTEXT)",) \
		--keep-recent "$(REGISTRY_KEEP_RECENT)" \
		--apply \
		--confirm "$(REGISTRY_CLEAN_CONFIRM)"

registry-gc:
	@test "$(REGISTRY_GC_CONFIRM)" = "GC-REGISTRY-BLOBS" || { \
		echo "Set REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS after manifest cleanup review." >&2; \
		exit 2; \
	}
	@docker compose -f docker-compose.ci.yaml stop registry; \
	status=0; \
	docker compose -f docker-compose.ci.yaml run --rm registry \
		garbage-collect /etc/docker/registry/config.yml || status=$$?; \
	docker compose -f docker-compose.ci.yaml up -d registry; \
	exit $$status

buildx-ready: require-registry
	@docker info >/dev/null
	@registry_host="$(REGISTRY)"; \
	registry_host="$${registry_host%%/*}"; \
	config="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$(BUILDER).toml"; \
	stamp="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$(BUILDER).mode"; \
	recreate=0; \
	if docker buildx inspect "$(BUILDER)" >/dev/null 2>&1; then \
		if [ -f "$$stamp" ]; then \
			configured_registry="$$(sed -n '1p' "$$stamp")"; \
			configured_mode="$$(sed -n '2p' "$$stamp")"; \
			configured_network="$$(sed -n '3p' "$$stamp")"; \
			if [ "$$configured_mode" != "$(REGISTRY_PLAIN_HTTP)" ] || { [ "$(REGISTRY_PLAIN_HTTP)" = "1" ] && [ "$$configured_registry" != "$$registry_host" ]; } || [ "$$configured_network" != "$(BUILDER_NETWORK)" ]; then \
				echo "Buildx builder $(BUILDER) uses REGISTRY_PLAIN_HTTP=$$configured_mode for $$configured_registry with BUILDER_NETWORK=$${configured_network:-default}, but REGISTRY_PLAIN_HTTP=$(REGISTRY_PLAIN_HTTP) and BUILDER_NETWORK=$(if $(strip $(BUILDER_NETWORK)),$(BUILDER_NETWORK),default) were requested for $$registry_host." >&2; \
				echo "Use an unused dedicated builder (for example BUILDER=$(BUILDER)-http) or remove and recreate $(BUILDER) after confirming it is safe." >&2; \
				exit 2; \
			fi; \
		elif [ "$(REGISTRY_PLAIN_HTTP)" = "1" ] || [ -n "$(BUILDER_NETWORK)" ]; then \
			echo "Buildx builder $(BUILDER) already exists with unverified configuration; removing and recreating." >&2; \
			docker buildx rm "$(BUILDER)" >/dev/null 2>&1 || { echo "Failed to remove unverified builder $(BUILDER). Remove it manually and retry." >&2; exit 2; }; \
			recreate=1; \
		fi; \
	else \
		recreate=1; \
	fi; \
	if [ "$$recreate" = "1" ]; then \
		set -- docker buildx create --name "$(BUILDER)" --driver docker-container; \
		if [ -n "$(BUILDER_NETWORK)" ]; then \
			set -- "$$@" --driver-opt "network=$(BUILDER_NETWORK)"; \
		fi; \
		if [ "$(REGISTRY_PLAIN_HTTP)" = "1" ]; then \
			printf '[registry."%s"]\n  http = true\n' "$$registry_host" > "$$config"; \
			set -- "$$@" --buildkitd-config "$$config"; \
		fi; \
		"$$@" >/dev/null; \
		printf '%s\n%s\n%s\n' "$$registry_host" "$(REGISTRY_PLAIN_HTTP)" "$(BUILDER_NETWORK)" > "$$stamp"; \
	fi
	@docker buildx inspect "$(BUILDER)" --bootstrap >/dev/null

define service_rules
build-$(1):
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(LOCAL_IMAGE_PREFIX)/$(4):$(TAG)" --load "$(5)"

publish-$(1):
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(if $(strip $(PUBLISH_REPOSITORY)),$(PUBLISH_REPOSITORY),$(REGISTRY)/$(4)):$(TAG)" --tag "$(if $(strip $(PUBLISH_REPOSITORY)),$(PUBLISH_REPOSITORY),$(REGISTRY)/$(4)):latest" --push $(if $(strip $(PUBLISH_METADATA_FILE)),--metadata-file "$(PUBLISH_METADATA_FILE)",) "$(5)"
endef

$(eval $(call service_rules,ssl-proxy,Dockerfile,--target ssl-proxy --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),ssl-proxy,.))
$(eval $(call service_rules,java-coordinator,services/octopus/Dockerfile,--build-arg PARENT_COMMIT=$(PARENT_COMMIT) --build-arg OCTOPUS_COMMIT=$(OCTOPUS_COMMIT),java-coordinator,.))
$(eval $(call service_rules,atheros-sensor,Dockerfile,--target atheros-sensor --build-arg VCS_REF=$(TAG) --build-arg BUILD_DATE=$(BUILD_DATE),atheros-sensor,.))
$(eval $(call service_rules,atheros-search,services/atheros-search/Dockerfile,,atheros-search,.))
$(eval $(call service_rules,wg-key-rotator,apps/wg-key-rotator/Dockerfile,,wg-key-rotator,apps/wg-key-rotator))
$(eval $(call service_rules,atheros-search-ui,apps/integration-console/atheros-search-ui/Dockerfile,--build-arg 'VITE_API_BASE=$(ATHEROS_SEARCH_UI_API_BASE)' --build-arg 'VITE_APP_TITLE=$(ATHEROS_SEARCH_UI_TITLE)' --build-arg 'VITE_KEYCLOAK_URL=$(ATHEROS_SEARCH_UI_KEYCLOAK_URL)' --build-arg 'VITE_KEYCLOAK_REALM=$(ATHEROS_SEARCH_UI_KEYCLOAK_REALM)' --build-arg 'VITE_KEYCLOAK_CLIENT_ID=$(ATHEROS_SEARCH_UI_KEYCLOAK_CLIENT_ID)',atheros-search-ui,apps/integration-console/atheros-search-ui))
$(eval $(call service_rules,schema-migrator-backend,apps/schema-migrator/Dockerfile.backend,,schema-migrator-backend,apps/schema-migrator))
$(eval $(call service_rules,schema-migrator-ui,apps/schema-migrator/frontend/Dockerfile,,schema-migrator-ui,apps/schema-migrator))
$(eval $(call service_rules,postgres-runtime-schema,k8s/postgres-schema-executor/Dockerfile,,postgres-runtime-schema,.))

ifneq ($(BUILDX_READY),1)
$(BUILD_TARGETS) $(PUBLISH_TARGETS): buildx-ready
endif

publish-java-coordinator: octopus-source-integrity

define bump_digest_rule
bump-digest-$(1):
	@test "$(ENV)" = "prod" || { echo "ENV=prod is required" >&2; exit 2; }
	@test -n "$(DIGEST)" || { echo "DIGEST is required (sha256:...)" >&2; exit 2; }
	KUSTOMIZE="$(KUSTOMIZE_EDITOR)" ./scripts/bump-image-digest.sh "$(1)" "$(ENV)" "$(DIGEST)"
endef

$(foreach service,$(DEPLOYABLE_SERVICES),$(eval $(call bump_digest_rule,$(service))))

bump-digest-java-coordinator: octopus-source-integrity
