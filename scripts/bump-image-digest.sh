#!/usr/bin/env bash
# Update one deployable image digest in its sole canonical environment slice.
set -euo pipefail

usage() {
  echo "usage: $0 <service> <dev|prod> <sha256:64-lowercase-hex-digest>" >&2
  exit 2
}

if [ "$#" -ne 3 ]; then
  usage
fi

service="$1"
environment="$2"
digest="$3"

case "$environment" in
  dev|prod) ;;
  *)
    echo "environment must be dev or prod" >&2
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
  tidb-runtime-schema)
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

if ! command -v "$kustomize" >/dev/null 2>&1; then
  echo "Kustomize executable is unavailable: $kustomize" >&2
  exit 1
fi

update_overlay() {
  local overlay="$1"
  local kustomization="$overlay/kustomization.yaml"
  local new_name
  if [ ! -f "$kustomization" ]; then
    echo "canonical Kustomization is missing: $kustomization" >&2
    exit 1
  fi

  # Kustomize edits only an existing image entry. Verify the service belongs
  # to this overlay before changing it.
  new_name="$(awk -v service="$service" '
    $1 == "-" && $2 == "name:" {
      active = ($3 == service)
      if (active) count++
      next
    }
    active && $1 == "newName:" { new_name = $2 }
    END {
      if (count != 1 || new_name == "") exit 1
      print new_name
    }
  ' "$kustomization")" || {
    echo "$kustomization must contain exactly one image mapping for $service" >&2
    exit 1
  }

  (
    cd "$overlay"
    "$kustomize" edit set image "$service=$new_name@$digest"
  )
  "$kustomize" build --load-restrictor LoadRestrictionsNone "$overlay" >/dev/null
}

slice_overlay="$repository_root/cyber-stack/matrix/$environment/$slice"
aggregate_overlay="$repository_root/cyber-stack/matrix/$environment"
update_overlay "$slice_overlay"
update_overlay "$aggregate_overlay"

echo "Updated $environment/$slice and $environment aggregate $service to $digest"
