#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
mkdir -p artifacts
source_revision="$(git rev-parse HEAD)"
build_tag="$(git rev-parse --short=12 HEAD)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" python3 scripts/publish_images.py \
  --environment prod --only "$CHANGED_SERVICES" --reuse-submodules "$SUBMODULE_CI_READY" \
  --tag "$build_tag" --build-date "$build_date" \
  --source-revision "$source_revision" --builder "$BUILDER" \
  --platform linux/amd64 --registry-plain-http "$REGISTRY_PLAIN_HTTP" \
  --max-workers 3 --manifest-out "$RELEASE_MANIFEST" \
  --commands-out "$BUMP_COMMANDS_REPORT" --make-command make
echo
echo '=== Manual production digest update report ==='
cat "$BUMP_COMMANDS_REPORT"
if [ "$SHOULD_PUBLISH_REDPANDA_MAINT" = true ]; then
  env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make --no-print-directory publish-redpanda-maint \
    TAG="$build_tag" BUILD_DATE="$build_date" BUILDER="$BUILDER" PLATFORM=linux/amd64 \
    REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
    PUBLISH_REPOSITORY="$REGISTRY/redpanda-maint" \
    PUBLISH_METADATA_FILE=artifacts/redpanda-maint-buildx.json
  redpanda_maint_digest="$(python3 scripts/image_contract.py buildx-digest artifacts/redpanda-maint-buildx.json)"
  echo "redpanda-maint pushed digest: $redpanda_maint_digest"
  echo 'Pin that digest and add ../../../base/redpanda-maintenance to the reviewed prod data-plane slice only after the platform Secret exists.'
else
  echo 'skipped: no redpanda-maintenance changes'
fi
if [ "$SHOULD_PUBLISH_STATS_READER" = true ]; then
  env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make --no-print-directory publish-stats-reader \
    TAG="$build_tag" BUILD_DATE="$build_date" BUILDER="$BUILDER" PLATFORM=linux/amd64 \
    REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
    PUBLISH_REPOSITORY="$REGISTRY/stats-reader" \
    PUBLISH_METADATA_FILE=artifacts/stats-reader-buildx.json
  stats_reader_digest="$(python3 scripts/image_contract.py buildx-digest artifacts/stats-reader-buildx.json)"
  echo "stats-reader pushed digest: $stats_reader_digest"
  echo 'Pin that digest in the reviewed app-stack overlays before adding the stats-reader resource and public route.'
else
  echo 'skipped: no stats-reader changes'
fi
