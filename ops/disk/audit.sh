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
redpanda_namespace="${REDPANDA_NAMESPACE:-prod-ssl-proxy}"
redpanda_pod="${REDPANDA_POD:-ssl-proxy-redpanda-0}"
postgres_container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
dind_service_label="${DIND_SERVICE_LABEL:-com.docker.compose.service=jenkins-docker}"
# Prefer the caller's kubeconfig, then the k3s admin config readable by root
# (systemd timer), then whatever the ambient kubectl already uses.
kubeconfig="${KUBECONFIG:-}"
if [ -z "$kubeconfig" ] && [ -r /etc/rancher/k3s/k3s.yaml ]; then
  kubeconfig="/etc/rancher/k3s/k3s.yaml"
fi

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

kubectl_audit() {
  # kubectl_audit <kubectl args...> - same as kubectl, with the resolved
  # kubeconfig when one was found.
  if [ -n "$kubeconfig" ]; then
    kubectl --kubeconfig "$kubeconfig" "$@"
  else
    kubectl "$@"
  fi
}

run_rpk() {
  # run_rpk <rpk args...> - local rpk when installed, otherwise the rpk inside
  # the Redpanda pod. Returns non-zero when neither path is available.
  if command -v rpk >/dev/null 2>&1; then
    rpk "$@" --brokers "$redpanda_brokers"
  elif command -v kubectl >/dev/null 2>&1; then
    kubectl_audit -n "$redpanda_namespace" exec "$redpanda_pod" -- rpk "$@"
  else
    return 1
  fi
}

run_rpk_optional() {
  # run_rpk_optional <rpk args...> - print output, or explain the skip.
  if command -v rpk >/dev/null 2>&1; then
    if ! rpk "$@" --brokers "$redpanda_brokers"; then
      printf 'skipped: command failed: rpk %s\n' "$*"
    fi
  elif command -v kubectl >/dev/null 2>&1; then
    if ! kubectl_audit -n "$redpanda_namespace" exec "$redpanda_pod" -- rpk "$@"; then
      printf 'skipped: command failed: kubectl exec %s -- rpk %s\n' "$redpanda_pod" "$*"
    fi
  else
    printf 'skipped: neither rpk nor kubectl is available\n'
  fi
  return 0
}

filter_filesystems() {
  # Drop overlay/tmpfs/shm rows that repeat the root filesystem or hold no
  # persistent data, and report how many were dropped.
  awk '
    NR == 1 { print; next }
    $1 == "overlay" || $1 == "tmpfs" || $1 == "shm" { omitted++; next }
    { print }
    END { printf "# %d overlay/tmpfs/shm mounts omitted\n", omitted + 0 }
  '
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
  df -h | filter_filesystems
  printf '\n'
  df -i | filter_filesystems

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
  run_rpk_optional cluster logdirs describe --aggregate-into topic
  printf '\n'
  run_rpk_optional topic describe wireless.audit -p
  printf '\n'
  run_rpk_optional topic describe sync.oracle.load -p
  printf '\n'
  run_rpk_optional topic describe sync.scan.request -p

  section "consumer groups on capped topics"
  if command -v rpk >/dev/null 2>&1 || command -v kubectl >/dev/null 2>&1; then
    if group_listing="$(run_rpk group list 2>/dev/null)"; then
      printf '%s\n' "$group_listing"
      while read -r group; do
        [ -n "$group" ] || continue
        printf '\n--- group %s ---\n' "$group"
        run_rpk group describe "$group" 2>/dev/null |
          awk 'NR <= 2 || $1 == "wireless.audit" || $1 == "sync.oracle.load" || $1 == "sync.scan.request" || $1 == "sync.oracle.result" || $1 == "proxy.events"' ||
          printf 'skipped: group describe failed for %s\n' "$group"
      done < <(printf '%s\n' "$group_listing" |
        awk '
          $1 == "GROUPS" { single = 1; header = 1; next }
          $1 == "BROKER" { header = 1; next }
          header && NF { if (single) print $1; else print $2 }
        ')
    else
      printf 'skipped: could not list consumer groups\n'
    fi
  else
    printf 'skipped: neither rpk nor kubectl is available\n'
  fi

  section "postgres relation sizes"
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$postgres_container"; then
    if [ -f "$repo_root/ops/sql/pg-size-report.sql" ]; then
      # The local socket requires SCRAM, and psql has no tty here, so the
      # password is exported inside the container from its own secret file;
      # stdin stays reserved for the report.
      if ! docker exec -i "$postgres_container" sh -eu -c \
        'PGPASSWORD=$(tr -d "\r\n" </run/platform-secrets/platform_admin.password); export PGPASSWORD; exec psql -U platform_admin -d sync -v ON_ERROR_STOP=1 -f -' \
        <"$repo_root/ops/sql/pg-size-report.sql"; then
        printf 'skipped: postgres report failed\n'
      fi
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
