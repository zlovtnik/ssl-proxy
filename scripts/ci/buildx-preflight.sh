#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_check_inotify
ci_refresh_context
docker_cmd version
curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
  --retry 2 --retry-all-errors --retry-delay 2 "http://${REGISTRY}/v2/" >/dev/null
env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make buildx-ready \
  BUILDER="$BUILDER" BUILDER_NETWORK="$BUILDER_NETWORK" \
  REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP"
