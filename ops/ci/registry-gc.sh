#!/usr/bin/env bash
set -Eeuo pipefail

# Weekly registry garbage collection for the ssl-proxy CI registry.
#
# Manifest deletion (the retention planner) stays a reviewed, manual step:
# scripts/registry_cleanup.py protects Git-pinned and live digests and needs a
# reachable cluster, so this script never deletes manifests. It only reclaims
# blobs whose manifests are already gone.
#
# Usage:
#   ops/ci/registry-gc.sh            # plan: report sizes and the cleanup plan
#   ops/ci/registry-gc.sh --apply    # stop, garbage-collect, restart

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="$repo_root/docker-compose.ci.yaml"
volume_name="${REGISTRY_VOLUME:-ssl-proxy-ci_registry-data}"
keep_recent="${REGISTRY_KEEP_RECENT:-12}"
apply=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) printf 'registry-gc: unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
  shift
done

registry="${REGISTRY:-}"
if [ -z "$registry" ] && [ -f "$repo_root/.env" ]; then
  registry="$(sed -n 's/^REGISTRY=//p' "$repo_root/.env" | head -n 1)"
fi
if [ -z "$registry" ]; then
  printf 'registry-gc: REGISTRY is not set and .env has no REGISTRY entry\n' >&2
  exit 1
fi

volume_path="/var/lib/docker/volumes/$volume_name/_data"
size() {
  if [ -d "$volume_path" ]; then
    du -sh "$volume_path" 2>/dev/null | awk '{print $1}'
  else
    printf 'unknown'
  fi
}

printf 'registry=%s volume=%s before=%s\n' "$registry" "$volume_name" "$(size)"

if [ "$apply" -eq 0 ]; then
  printf 'plan: manifest retention plan (read-only)\n'
  if ! make -C "$repo_root" registry-clean-plan \
      REGISTRY="$registry" REGISTRY_PLAIN_HTTP="${REGISTRY_PLAIN_HTTP:-1}" \
      REGISTRY_KEEP_RECENT="$keep_recent"; then
    printf 'plan: retention plan failed; check the Kubernetes context and registry reachability\n'
  fi
  printf 'plan: nothing was changed; re-run with --apply to garbage-collect blobs\n'
  exit 0
fi

if [ "${REGISTRY_GC_CONFIRM:-}" != "GC-REGISTRY-BLOBS" ]; then
  printf 'registry-gc: set REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS to apply\n' >&2
  exit 1
fi

make -C "$repo_root" registry-gc \
  REGISTRY="$registry" \
  REGISTRY_GC_CONFIRM="$REGISTRY_GC_CONFIRM" \
  REGISTRY_PLAIN_HTTP="${REGISTRY_PLAIN_HTTP:-1}"

printf 'registry=%s volume=%s after=%s\n' "$registry" "$volume_name" "$(size)"
