.DEFAULT_GOAL := build-all

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

REGISTRY ?= 192.168.1.221:5000
REGISTRY_PLAIN_HTTP ?= 1
BUILDER ?= ssl-proxy-publisher
PLATFORM ?= linux/amd64
TAG ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LOCAL_IMAGE_PREFIX ?= ssl-proxy-local

KUBECTL ?= kubectl
KUBE_CONTEXT ?= wiretrap-k3s
ARGOCD_NAMESPACE ?= argocd
ARGOCD_TIMEOUT ?= 20m
ARGOCD_DATA_PLANE_APP ?= ssl-proxy-data-plane
ARGOCD_APP_STACK_APP ?= ssl-proxy-app-stack

ATHEROS_SEARCH_UI_API_BASE ?=
ATHEROS_SEARCH_UI_TITLE ?= atheros search

SERVICES := ssl-proxy java-coordinator atheros-sensor atheros-search wg-key-rotator atheros-search-ui schema-migrator-backend schema-migrator-ui tidb-runtime-schema
BUILD_TARGETS := $(addprefix build-,$(SERVICES))
PUBLISH_TARGETS := $(addprefix publish-,$(SERVICES))

.PHONY: build build-all publish publish-all release-all buildx-ready require-registry argocd-update argocd-update-all $(BUILD_TARGETS) $(PUBLISH_TARGETS)

build: build-all
publish: publish-all
argocd-update: argocd-update-all

build-all: $(BUILD_TARGETS)

publish-all: $(PUBLISH_TARGETS)

release-all:
	$(MAKE) publish-all REGISTRY="$(REGISTRY)" TAG="$(TAG)" PLATFORM="$(PLATFORM)"
	$(MAKE) argocd-update-all REGISTRY="$(REGISTRY)" TAG="$(TAG)" KUBE_CONTEXT="$(KUBE_CONTEXT)"

require-registry:
	@test -n "$(REGISTRY)" || { echo "REGISTRY is required" >&2; exit 2; }

buildx-ready: require-registry
	@docker info >/dev/null
	@if ! docker buildx inspect "$(BUILDER)" >/dev/null 2>&1; then \
		registry_host="$(REGISTRY)"; \
		registry_host="$${registry_host%%/*}"; \
		config="$${TMPDIR:-/tmp}/ssl-proxy-buildkitd-$(BUILDER).toml"; \
		if [ "$(REGISTRY_PLAIN_HTTP)" = "1" ]; then \
			printf '[registry."%s"]\n  http = true\n' "$$registry_host" > "$$config"; \
			docker buildx create --name "$(BUILDER)" --driver docker-container --buildkitd-config "$$config" >/dev/null; \
		else \
			docker buildx create --name "$(BUILDER)" --driver docker-container >/dev/null; \
		fi; \
	fi
	@docker buildx inspect "$(BUILDER)" --bootstrap >/dev/null

define service_rules
build-$(1): buildx-ready
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(LOCAL_IMAGE_PREFIX)/$(4):$(TAG)" --load "$(5)"

publish-$(1): buildx-ready
	docker buildx build --builder "$(BUILDER)" --platform "$(PLATFORM)" --file "$(2)" $(3) --tag "$(REGISTRY)/$(4):$(TAG)" --tag "$(REGISTRY)/$(4):latest" --push "$(5)"
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

argocd-update-all: require-registry
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" patch application "$(ARGOCD_DATA_PLANE_APP)" --type merge -p '{"spec":{"source":{"kustomize":{"images":["tidb-runtime-schema=$(REGISTRY)/tidb-runtime-schema:$(TAG)"]}}}}' >/dev/null
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" patch application "$(ARGOCD_APP_STACK_APP)" --type merge -p '{"spec":{"source":{"kustomize":{"images":["ssl-proxy=$(REGISTRY)/ssl-proxy:$(TAG)","java-coordinator=$(REGISTRY)/java-coordinator:$(TAG)","atheros-sensor=$(REGISTRY)/atheros-sensor:$(TAG)","atheros-search=$(REGISTRY)/atheros-search:$(TAG)","atheros-search-ui=$(REGISTRY)/atheros-search-ui:$(TAG)","schema-migrator-backend=$(REGISTRY)/schema-migrator-backend:$(TAG)","schema-migrator-ui=$(REGISTRY)/schema-migrator-ui:$(TAG)"]}}}}' >/dev/null
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" annotate application "$(ARGOCD_DATA_PLANE_APP)" argocd.argoproj.io/refresh=hard --overwrite >/dev/null
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" patch application "$(ARGOCD_DATA_PLANE_APP)" --type merge -p '{"operation":{"sync":{"prune":true,"syncOptions":["CreateNamespace=true","PrunePropagationPolicy=foreground","ApplyOutOfSyncOnly=true","ServerSideApply=true"]}}}' >/dev/null
	$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" wait application/"$(ARGOCD_DATA_PLANE_APP)" --for=jsonpath='{.status.operationState.phase}'=Succeeded --timeout="$(ARGOCD_TIMEOUT)"
	$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" wait application/"$(ARGOCD_DATA_PLANE_APP)" --for=jsonpath='{.status.health.status}'=Healthy --timeout="$(ARGOCD_TIMEOUT)"
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" annotate application "$(ARGOCD_APP_STACK_APP)" argocd.argoproj.io/refresh=hard --overwrite >/dev/null
	@$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" patch application "$(ARGOCD_APP_STACK_APP)" --type merge -p '{"operation":{"sync":{"prune":true,"syncOptions":["CreateNamespace=true","PrunePropagationPolicy=foreground","ApplyOutOfSyncOnly=true","ServerSideApply=true"]}}}' >/dev/null
	$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" wait application/"$(ARGOCD_APP_STACK_APP)" --for=jsonpath='{.status.operationState.phase}'=Succeeded --timeout="$(ARGOCD_TIMEOUT)"
	$(KUBECTL) --context "$(KUBE_CONTEXT)" -n "$(ARGOCD_NAMESPACE)" wait application/"$(ARGOCD_APP_STACK_APP)" --for=jsonpath='{.status.health.status}'=Healthy --timeout="$(ARGOCD_TIMEOUT)"
