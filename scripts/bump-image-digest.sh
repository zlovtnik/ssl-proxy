#!/usr/bin/env bash
# Atomically update one deployable image digest in its canonical slice and aggregate.
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
octopus_contract="$repository_root/scripts/octopus_image_contract.py"

if [ "$service" = "java-coordinator" ]; then
  python3 "$octopus_contract" source \
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
aggregate_overlay="$repository_root/cyber-stack/matrix/$environment"
slice_new_name="$(validate_overlay "$slice_overlay")"
aggregate_new_name="$(validate_overlay "$aggregate_overlay")"
if [ "$slice_new_name" != "$aggregate_new_name" ]; then
  echo "image repository differs between $environment/$slice and aggregate" >&2
  exit 2
fi

promotion_record="$slice_overlay/java-coordinator-promotion.json"
if [ "$service" = "java-coordinator" ]; then
  candidate_image="${JAVA_COORDINATOR_IMAGE:-}"
  expected_candidate="$slice_new_name@$digest"
  if [ -z "$candidate_image" ]; then
    echo "JAVA_COORDINATOR_IMAGE is required for java-coordinator promotion" >&2
    exit 2
  fi
  if [ "$candidate_image" != "$expected_candidate" ]; then
    echo "java-coordinator candidate must be the exact canonical digest reference: expected $expected_candidate" >&2
    exit 2
  fi

  if [ "$environment" = "prod" ]; then
    dev_slice="$repository_root/cyber-stack/matrix/dev/app-stack/kustomization.yaml"
    dev_aggregate="$repository_root/cyber-stack/matrix/dev/kustomization.yaml"
    dev_slice_pin="$(python3 "$repository_root/scripts/image_contract.py" pin \
      --kustomization "$dev_slice" --service java-coordinator)"
    dev_aggregate_pin="$(python3 "$repository_root/scripts/image_contract.py" pin \
      --kustomization "$dev_aggregate" --service java-coordinator)"
    if [ "$dev_slice_pin" != "$dev_aggregate_pin" ]; then
      echo "dev java-coordinator pin differs between app-stack and aggregate" >&2
      exit 2
    fi
    IFS=$'\t' read -r dev_repository dev_digest <<<"$dev_slice_pin"
    if [ "$dev_digest" != "$digest" ]; then
      echo "production java-coordinator digest must exactly match the tested dev pin: dev=$dev_digest requested=$digest" >&2
      exit 2
    fi
    if [ "$dev_repository" != "$slice_new_name" ]; then
      echo "dev and production java-coordinator repositories must match for exact digest promotion" >&2
      exit 2
    fi
    dev_promotion_record="$repository_root/cyber-stack/matrix/dev/app-stack/java-coordinator-promotion.json"
    python3 "$octopus_contract" image "$candidate_image" \
      --expected-digest "$digest" \
      --promotion-record "$dev_promotion_record" \
      --repository-root "$repository_root"
  else
    python3 "$octopus_contract" image "$candidate_image" \
      --expected-digest "$digest" \
      --repository-root "$repository_root"
  fi
fi

backup_dir="$(mktemp -d "${TMPDIR:-/tmp}/ssl-proxy-image-bump.XXXXXX")"
slice_kustomization="$slice_overlay/kustomization.yaml"
aggregate_kustomization="$aggregate_overlay/kustomization.yaml"
slice_backup="$backup_dir/slice-kustomization.yaml"
aggregate_backup="$backup_dir/aggregate-kustomization.yaml"
cp "$slice_kustomization" "$slice_backup"
cp "$aggregate_kustomization" "$aggregate_backup"
promotion_record_existed=0
promotion_record_backup="$backup_dir/java-coordinator-promotion.json"
if [ "$service" = "java-coordinator" ] && [ -f "$promotion_record" ]; then
  cp "$promotion_record" "$promotion_record_backup"
  promotion_record_existed=1
fi
committed=0

cleanup() {
  local status="$?"
  trap - EXIT
  if [ "$committed" -ne 1 ]; then
    cp "$slice_backup" "$slice_kustomization"
    cp "$aggregate_backup" "$aggregate_kustomization"
    if [ "$service" = "java-coordinator" ]; then
      if [ "$promotion_record_existed" -eq 1 ]; then
        cp "$promotion_record_backup" "$promotion_record"
      else
        rm -f "$promotion_record"
      fi
    fi
  fi
  rm -f "$slice_backup" "$aggregate_backup" "$promotion_record_backup"
  rmdir "$backup_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$service" = "java-coordinator" ]; then
  if [ "$environment" = "dev" ]; then
    python3 "$octopus_contract" record "$promotion_record" \
      --repository "$slice_new_name" \
      --digest "$digest" \
      --repository-root "$repository_root"
  else
    cp "$dev_promotion_record" "$promotion_record"
  fi
fi

update_overlay "$slice_overlay" "$slice_new_name"
update_overlay "$aggregate_overlay" "$aggregate_new_name"
committed=1

echo "Updated $environment/$slice and $environment aggregate $service to $digest"
