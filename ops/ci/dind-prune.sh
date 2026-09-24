#!/usr/bin/env bash
set -Eeuo pipefail

# Reclaim build cache inside the privileged Jenkins Docker-in-Docker engine.
# Only cache and unused images are touched: containers, volumes and the
# Jenkins home directory are never removed. The next build after a prune is
# slower, nothing else changes.
#
# Usage:
#   ops/ci/dind-prune.sh            # plan: report cache usage
#   ops/ci/dind-prune.sh --apply    # prune cache older than DIND_KEEP_HOURS
#
# Environment:
#   DIND_SERVICE_LABEL  compose label of the DinD container
#   DIND_BUILDER        buildx builder created by the Jenkinsfile
#   DIND_KEEP_HOURS     age filter for prune (default 168 = 7 days)
#   DIND_KEEP_STORAGE   build cache ceiling passed to prune (default 20GB)

service_label="${DIND_SERVICE_LABEL:-com.docker.compose.service=jenkins-docker}"
builder="${DIND_BUILDER:-ssl-proxy-jenkins-http-host}"
keep_hours="${DIND_KEEP_HOURS:-168}"
keep_storage="${DIND_KEEP_STORAGE:-20GB}"
apply=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) printf 'dind-prune: unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
  shift
done

if ! command -v docker >/dev/null 2>&1; then
  printf 'dind-prune: docker is not installed\n' >&2
  exit 1
fi

container_id="$(docker ps --filter "label=$service_label" --format '{{.ID}}' | head -n 1)"
if [ -z "$container_id" ]; then
  printf 'dind-prune: no container with label %s is running\n' "$service_label" >&2
  exit 1
fi

dind() {
  docker exec "$container_id" docker "$@"
}

report() {
  printf '===== docker-in-docker usage (%s) =====\n' "$container_id"
  dind system df || true
  printf '\n===== buildx cache (%s) =====\n' "$builder"
  dind buildx du --builder "$builder" || true
}

report

if [ "$apply" -eq 0 ]; then
  printf '\nplan: nothing was pruned; re-run with --apply\n'
  exit 0
fi

printf '\npruning build cache older than %sh with a %s ceiling\n' "$keep_hours" "$keep_storage"
dind buildx prune --builder "$builder" --filter "until=${keep_hours}h" \
  --keep-storage "$keep_storage" -f || printf 'dind-prune: buildx prune failed\n'
dind builder prune --keep-storage "$keep_storage" -f ||
  printf 'dind-prune: dockerd buildkit prune failed\n'
dind image prune -a --filter "until=${keep_hours}h" -f ||
  printf 'dind-prune: image prune failed\n'

printf '\n'
report
printf 'dind-prune: complete; %s remains under %s\n' "$builder" "$keep_storage"
