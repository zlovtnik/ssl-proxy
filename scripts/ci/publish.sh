#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
mkdir -p artifacts
source_revision="$(git rev-parse HEAD)"
build_tag="$(git rev-parse --short=12 HEAD)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
selected_services="${CHANGED_SERVICES:-}"
if [ "$SHOULD_PUBLISH_OCTOPUS_METRICS" = true ]; then
  selected_services="${selected_services:+$selected_services,}octopus-metrics"
fi
# DQ has reviewed pins for onboarding, but still requires explicit activation.
# Publish it once through the candidate path, including on a full-image build.
IFS=, read -r -a requested_services <<< "$selected_services"
selected_services=""
for service in "${requested_services[@]}"; do
  case "$service" in
    delip-queve-manager|delip-queve-worker) SHOULD_PUBLISH_DQ=true ;;
    '') ;;
    *) selected_services="${selected_services:+$selected_services,}$service" ;;
  esac
done
env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" python3 scripts/publish_images.py \
  --environment prod --only "$selected_services" --reuse-submodules "$SUBMODULE_CI_READY" \
  --tag "$build_tag" --build-date "$build_date" \
  --source-revision "$source_revision" --builder "$BUILDER" \
  --platform linux/amd64 --registry-plain-http "$REGISTRY_PLAIN_HTTP" \
  --max-workers 3 --manifest-out "$RELEASE_MANIFEST" \
  --commands-out "$BUMP_COMMANDS_REPORT" --make-command make
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
if [ "${SHOULD_PUBLISH_DQ:-false}" = true ]; then
  for service in delip-queve-manager delip-queve-worker; do
    env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
      DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make --no-print-directory "publish-$service" \
      TAG="$build_tag" BUILD_DATE="$build_date" BUILDER="$BUILDER" PLATFORM=linux/amd64 \
      REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
      PUBLISH_REPOSITORY="$REGISTRY/$service" \
      PUBLISH_METADATA_FILE="artifacts/$service-buildx.json"
  done
else
  echo 'skipped: no DQ image changes'
fi
# Record candidate digests separately; a pin alone does not activate DQ.
python3 - "$RELEASE_MANIFEST" "$BUMP_COMMANDS_REPORT" "$REGISTRY" \
  "$SHOULD_PUBLISH_REDPANDA_MAINT" "${SHOULD_PUBLISH_DQ:-false}" <<'PY'
import json
import sys
from pathlib import Path
from scripts.image_contract import load_buildx_digest

manifest_path, report_path = map(Path, sys.argv[1:3])
registry, redpanda, dq = sys.argv[3:]
manifest = json.loads(manifest_path.read_text())
candidates = []
for service, slice_name, selected in (
    ("redpanda-maint", "data-plane", redpanda),
    ("delip-queve-manager", "app-stack", dq),
    ("delip-queve-worker", "app-stack", dq),
):
    if selected == "true":
        candidates.append({
            "service": service,
            "slice": slice_name,
            "repository": f"{registry}/{service}",
            "digest": load_buildx_digest(Path(f"artifacts/{service}-buildx.json")),
            "sourceRevision": manifest["sourceRevision"],
            "activationRequired": True,
        })
manifest["candidateImages"] = candidates
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
report = report_path.read_text().rstrip()
if candidates:
    if report == "No digest updates are required.":
        report = "No digest updates for currently deployed services; candidates below require activation."
    report += "\n\nPublished candidates requiring activation:\n"
    report += "\n".join(
        f"{entry['service']}: {entry['repository']}@{entry['digest']} ({entry['slice']})"
        for entry in candidates
    )
    report += "\nVerify platform inputs and activation prerequisites, then promote the digest and matching processor manifest in reviewed Git."
report_path.write_text(report + "\n")
PY
printf '\nManual production digest update report\n'
cat "$BUMP_COMMANDS_REPORT"
