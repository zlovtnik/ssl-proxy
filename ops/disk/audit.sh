#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only storage audit for the wiretrap host and the platform it runs.
# Every section degrades to a "skipped" line when its tool or permission is
# missing, so the script is safe to run unprivileged.
#
# Usage: ops/disk/audit.sh [label]
# Writes: ops/disk/snapshots/YYYY-MM-DD-<label>.txt  (override with AUDIT_OUTPUT_DIR)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
label="${1:-audit}"
output_dir="${AUDIT_OUTPUT_DIR:-$repo_root/ops/disk/snapshots}"
output_file="$output_dir/$(date -u +%Y-%m-%d)-${label//[^A-Za-z0-9._-]/_}.txt"

redpanda_brokers="${RPK_BROKERS:-ssl-proxy-redpanda:9092}"
redpanda_namespace="${REDPANDA_NAMESPACE:-ssl-proxy}"
redpanda_pod="${REDPANDA_POD:-ssl-proxy-redpanda-0}"
postgres_container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
dind_service_label="${DIND_SERVICE_LABEL:-com.docker.compose.service=jenkins-docker}"

host_paths=(
  /var/lib/rancher/k3s/agent/containerd
  /var/lib/kubelet/pods
  /var/log/pods
  /var/log/containers
  /var/lib/docker/containers
  /var/lib/rancher/k3s/storage
  /var/log
)

mkdir -p "$output_dir"

section() {
  printf '\n===== %s =====\n' "$1"
}

run_optional() {
  # run_optional <command...> - print output, or explain the skip
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'skipped: %s not installed\n' "$1"
    return 0
  fi
  if ! "$@"; then
    printf 'skipped: command failed: %s\n' "$*"
  fi
  return 0
}

as_root() {
  # Use sudo without prompting when the audit is not run as root.
  if [ "$(id -u)" -eq 0 ]; then
    if ! "$@"; then
      printf 'skipped: command failed: %s\n' "$*"
    fi
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    if ! sudo -n "$@"; then
      printf 'skipped: command failed: %s\n' "$*"
    fi
  else
    printf 'skipped: needs root (passwordless sudo unavailable): %s\n' "$*"
  fi
  return 0
}

du_flags="-s -h"
if du -x -s -h /dev/null >/dev/null 2>&1; then
  du_flags="-x -s -h"
fi

dind_container() {
  command -v docker >/dev/null 2>&1 || return 1
  docker ps --filter "label=$dind_service_label" --format '{{.ID}}' | head -n 1
}

{
  section "run"
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  hostname
  printf 'label=%s\n' "$label"

  section "filesystems"
  df -h
  printf '\n'
  df -i

  section "host paths (du)"
  for path in "${host_paths[@]}"; do
    if [ -d "$path" ]; then
      as_root du $du_flags "$path" 2>/dev/null || printf 'unreadable: %s\n' "$path"
    else
      printf 'absent: %s\n' "$path"
    fi
  done

  section "container runtime images and containers"
  as_root k3s crictl images
  printf '\n'
  as_root k3s crictl ps -a

  section "host docker"
  run_optional docker system df -v

  section "docker-in-docker (jenkins)"
  if container_id="$(dind_container)" && [ -n "$container_id" ]; then
    run_optional docker exec "$container_id" docker system df -v
  else
    printf 'skipped: no %s container is running\n' "$dind_service_label"
  fi

  section "redpanda topic sizes"
  if command -v rpk >/dev/null 2>&1; then
    run_optional rpk cluster logdirs describe --aggregate-into topic --brokers "$redpanda_brokers"
    printf '\n'
    run_optional rpk topic describe wireless.audit -p --brokers "$redpanda_brokers"
    printf '\n'
    run_optional rpk topic describe sync.oracle.load -p --brokers "$redpanda_brokers"
    printf '\n'
    run_optional rpk topic describe sync.scan.request -p --brokers "$redpanda_brokers"
  elif command -v kubectl >/dev/null 2>&1; then
    run_optional kubectl -n "$redpanda_namespace" exec "$redpanda_pod" -- \
      rpk cluster logdirs describe --aggregate-into topic
    printf '\n'
    run_optional kubectl -n "$redpanda_namespace" exec "$redpanda_pod" -- \
      rpk topic describe wireless.audit -p
  else
    printf 'skipped: neither rpk nor kubectl is available\n'
  fi

  section "consumer groups on capped topics"
  if command -v rpk >/dev/null 2>&1; then
    run_optional rpk group list --brokers "$redpanda_brokers"
    while read -r group; do
      [ -n "$group" ] || continue
      printf '\n--- group %s ---\n' "$group"
      rpk group describe "$group" --brokers "$redpanda_brokers" 2>/dev/null |
        awk 'NR <= 2 || $1 == "wireless.audit" || $1 == "sync.oracle.load" || $1 == "sync.scan.request" || $1 == "sync.oracle.result" || $1 == "proxy.events"' ||
        printf 'skipped: group describe failed for %s\n' "$group"
    done < <(rpk group list --brokers "$redpanda_brokers" 2>/dev/null |
      awk '$1 == "BROKER" && $2 == "GROUP" { header = 1; next } header && NF { print $2 }')
  else
    printf 'skipped: rpk is not installed\n'
  fi

  section "postgres relation sizes"
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$postgres_container"; then
    if [ -f "$repo_root/ops/sql/pg-size-report.sql" ]; then
      docker exec -i "$postgres_container" \
        psql -U platform_admin -d sync -v ON_ERROR_STOP=1 -f - \
        <"$repo_root/ops/sql/pg-size-report.sql" || printf 'skipped: postgres report failed\n'
    else
      printf 'skipped: ops/sql/pg-size-report.sql is missing\n'
    fi
  else
    printf 'skipped: %s is not running\n' "$postgres_container"
  fi

  section "logs"
  if command -v journalctl >/dev/null 2>&1; then
    as_root journalctl --disk-usage 2>/dev/null || printf 'skipped: journalctl needs root\n'
  else
    printf 'skipped: journalctl is not installed\n'
  fi
  for path in /var/log/pods /var/lib/docker/containers; do
    if [ -d "$path" ]; then
      as_root du $du_flags "$path" 2>/dev/null || printf 'unreadable: %s\n' "$path"
    fi
  done
} >"$output_file" 2>&1

chmod 0644 "$output_file"
printf 'audit written to %s\n' "$output_file"
