#!/usr/bin/env bash
# Update one deployable image digest in its owning canonical slice.
set -euo pipefail

usage() {
  echo "usage: $0 <service> prod <sha256:64-lowercase-hex-digest>" >&2
  exit 2
}

if [ "$#" -ne 3 ]; then
  usage
fi

service="$1"
environment="$2"
digest="$3"

case "$environment" in
  prod) ;;
  *)
    echo "environment must be prod" >&2
    usage
    ;;
esac

case "$digest" in
  sha256:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *)
    echo "digest must be sha256 followed by exactly 64 lowercase hexadecimal characters" >&2
    exit 2
    ;;
esac

case "$service" in
  postgres-runtime-schema)
    slice="data-plane"
    ;;
  ssl-proxy|java-coordinator|atheros-sensor|atheros-search|atheros-search-ui|schema-migrator-backend|schema-migrator-ui)
    slice="app-stack"
    ;;
  wg-key-rotator)
    echo "wg-key-rotator is Compose-only and has no Kubernetes digest slice" >&2
    exit 2
    ;;
  *)
    echo "unsupported deployable service: $service" >&2
    exit 2
    ;;
esac

repository_root="${SSL_PROXY_REPOSITORY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
kustomize="${KUSTOMIZE:-kustomize}"

if [ "$service" = "java-coordinator" ]; then
  python3 "$repository_root/scripts/octopus_image_contract.py" source \
    --repository-root "$repository_root"
fi

if ! command -v "$kustomize" >/dev/null 2>&1; then
  echo "Kustomize executable is unavailable: $kustomize" >&2
  exit 1
fi
if [ "${kustomize##*/}" = "kubectl" ]; then
  echo "Digest updates require the standalone kustomize CLI; kubectl supports rendering only" >&2
  exit 2
fi

validate_overlay() {
  local overlay="$1"
  local kustomization="$overlay/kustomization.yaml"
  if [ ! -f "$kustomization" ]; then
    echo "canonical Kustomization is missing: $kustomization" >&2
    exit 1
  fi

  # Kustomize may reorder mapping keys. Resolve the existing repository
  # structurally instead of depending on name/newName line order.
  python3 "$repository_root/scripts/image_contract.py" repository \
    --kustomization "$kustomization" --service "$service"
}

update_overlay() {
  local overlay="$1"
  local new_name="$2"

  (
    cd "$overlay"
    "$kustomize" edit set image "$service=$new_name@$digest"
  )
  "$kustomize" build --load-restrictor LoadRestrictionsNone "$overlay" >/dev/null
}

slice_overlay="$repository_root/cyber-stack/matrix/$environment/$slice"
slice_new_name="$(validate_overlay "$slice_overlay")"

update_overlay "$slice_overlay" "$slice_new_name"

echo "Updated $environment/$slice $service to $digest"
