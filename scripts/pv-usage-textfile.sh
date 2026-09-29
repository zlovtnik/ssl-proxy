#!/usr/bin/env bash
set -euo pipefail

# Publish host storage usage for node_exporter from the k3s host. Runs as root
# from scripts/systemd/ssl-proxy-pv-usage-textfile.service.
#
# k3s local-path volumes are bind mounts on the host filesystem rather than
# separate filesystems, so kubelet's kubelet_volume_stats_* series report the
# host rootfs numbers for every PVC. These measurements are the authority for
# local-path volumes and feed pvc:utilization:ratio.
#
# Every section aborts on failure before the atomic rename, so the previous good
# snapshot stays in place and StorageTextfileStale fires. Publishing a partial
# file would hide the failure that the alert exists to catch.

output_dir="${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
pvc_root="${K3S_PVC_ROOT:-/var/lib/rancher/k3s/storage}"
docker_root="${DOCKER_VOLUME_ROOT:-/var/lib/docker/volumes}"
kubeconfig="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
kubernetes_namespace="${KUBERNETES_NAMESPACE:-prod-ssl-proxy}"
redpanda_pod="${REDPANDA_POD:-ssl-proxy-redpanda-0}"
postgres_container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
postgres_user="${POSTGRES_USER:-platform_admin}"
postgres_database="${POSTGRES_DATABASE:-sync}"
node_name="${NODE_NAME:-$(hostname)}"
output_file="$output_dir/ssl_proxy_storage.prom"

# Host paths that no Kubernetes object or Docker volume accounts for. A growth
# spike in one of these shows up as a filesystem shrink alert with a named
# cause, instead of an unattributed drop in node_filesystem_avail_bytes.
host_paths="${HOST_PATHS:-/var/lib/docker /var/lib/rancher/k3s/agent/containerd /var/lib/rancher/k3s/storage /var/log}"

mkdir -p "$output_dir"
temporary_file="$(mktemp "$output_dir/.ssl_proxy_storage.XXXXXX")"
trap 'rm -f "$temporary_file"' EXIT

bytes_used() {
  du -sxB1 "$1" | awk '{print $1}'
}

# Kubernetes capacities are quantity strings such as 20Gi or 1073741824. An
# unparseable quantity exits non-zero: a silent zero would report a volume as
# 0% full. Callers validate every capacity before any output is written, so the
# failure aborts the publish and StorageTextfileStale fires.
quantity_to_bytes() {
  local quantity="$1" value fraction unit binary scale
  if [[ -z "$quantity" || "$quantity" =~ ^([0-9]+)$ ]]; then
    printf '%s\n' "${quantity:-0}"
    return 0
  fi
  if [[ "$quantity" =~ ^([0-9]+)(\.([0-9]+))?([KMGTPE])(i?)$ ]]; then
    value="${BASH_REMATCH[1]}"
    fraction="${BASH_REMATCH[3]}"
    unit="${BASH_REMATCH[4]}"
    binary="${BASH_REMATCH[5]}"
  else
    printf 'unparseable capacity quantity: %s\n' "$quantity" >&2
    return 1
  fi
  if [[ "$binary" == "i" ]]; then
    case "$unit" in
      K) scale=1024 ;;
      M) scale=1048576 ;;
      G) scale=1073741824 ;;
      T) scale=1099511627776 ;;
      P) scale=1125899906842624 ;;
    esac
  else
    case "$unit" in
      K) scale=1000 ;;
      M) scale=1000000 ;;
      G) scale=1000000000 ;;
      T) scale=1000000000000 ;;
      P) scale=1000000000000000 ;;
    esac
  fi
  if [[ -n "$fraction" ]]; then
    fraction="$((10#${fraction} * scale / 10 ** ${#fraction}))"
  else
    fraction=0
  fi
  printf '%s\n' "$((value * scale + fraction))"
}

pg_psql() {
  # pg_psql <sql> - read-only query against the sync database. The local
  # socket requires SCRAM and psql has no tty under docker exec, so the
  # password is exported inside the container from its own secret file.
  docker exec "$postgres_container" sh -eu -c \
    'PGPASSWORD=$(tr -d "\r\n" </run/platform-secrets/platform_admin.password); export PGPASSWORD; exec psql -X -At -U "$1" -d "$2" -c "$3"' \
    psql-wrap "$postgres_user" "$postgres_database" "$1"
}

# PV name, claim namespace, claim name and requested capacity, tab separated.
# An unbound PV yields two fields and is skipped. The lookup is assigned before
# the loop because a command substitution inside a here-string does not trip
# `set -e`, which would publish zero volume series on a failed lookup. The
# capacity conversion runs here too, so an unparseable quantity aborts the
# publish instead of emitting a wrong denominator.
pv_inventory="$(
  kubectl --kubeconfig "$kubeconfig" get pv -o go-template='{{range .items}}{{.metadata.name}}{{"\t"}}{{with .spec.claimRef}}{{.namespace}}{{"\t"}}{{.name}}{{"\t"}}{{end}}{{.spec.capacity.storage}}{{"\n"}}{{end}}'
)"
pvc_rows=""
while IFS=$'\t' read -r pv_name claim_namespace claim_name capacity; do
  [ -n "$pv_name" ] && [ -n "$claim_name" ] || continue
  pvc_rows+="$pv_name"$'\t'"$claim_namespace"$'\t'"$claim_name"$'\t'"$(quantity_to_bytes "$capacity")"$'\n'
done <<<"$pv_inventory"

{
  printf '%s\n' '# HELP ssl_proxy_storage_textfile_timestamp_seconds Last successful storage textfile publication.'
  printf '%s\n' '# TYPE ssl_proxy_storage_textfile_timestamp_seconds gauge'
  printf 'ssl_proxy_storage_textfile_timestamp_seconds %s\n' "$(date +%s)"

  printf '%s\n' '# HELP ssl_proxy_host_path_used_bytes Disk bytes used by a monitored host path.'
  printf '%s\n' '# TYPE ssl_proxy_host_path_used_bytes gauge'
  for path in $host_paths; do
    [ -d "$path" ] || continue
    printf 'ssl_proxy_host_path_used_bytes{class="host_path",node="%s",path="%s"} %s\n' \
      "$node_name" "$path" "$(bytes_used "$path")"
  done
  printf '%s\n' '# HELP ssl_proxy_host_path_capacity_bytes Declared capacity in bytes for a monitored k3s local-path volume.'
  printf '%s\n' '# TYPE ssl_proxy_host_path_capacity_bytes gauge'
  while IFS=$'\t' read -r pv_name claim_namespace claim_name capacity_bytes; do
    [ -n "$pv_name" ] || continue
    path="$pvc_root/$pv_name"
    [ -d "$path" ] || continue
    printf 'ssl_proxy_host_path_capacity_bytes{class="k3s_pvc",node="%s",namespace="%s",persistentvolumeclaim="%s"} %s\n' \
      "$node_name" "$claim_namespace" "$claim_name" "$capacity_bytes"
    printf 'ssl_proxy_host_path_used_bytes{class="k3s_pvc",node="%s",namespace="%s",persistentvolumeclaim="%s"} %s\n' \
      "$node_name" "$claim_namespace" "$claim_name" "$(bytes_used "$path")"
  done <<<"$pvc_rows"

  printf '%s\n' '# HELP docker_volume_used_bytes Disk bytes used by a Docker volume.'
  printf '%s\n' '# TYPE docker_volume_used_bytes gauge'
  for path in "$docker_root"/*/_data; do
    [ -d "$path" ] || continue
    volume="$(basename "$(dirname "$path")")"
    printf 'docker_volume_used_bytes{volume="%s"} %s\n' "$volume" "$(bytes_used "$path")"
  done

  if command -v kubectl >/dev/null 2>&1 && [ -r "$kubeconfig" ]; then
    printf '%s\n' '# HELP redpanda_topic_log_bytes Bytes retained for each Redpanda topic.'
    printf '%s\n' '# TYPE redpanda_topic_log_bytes gauge'
    # Redpanda and PostgreSQL are supplementary: each has its own availability
    # alert, and their failure must not suppress the host path and volume
    # measurements that feed pvc:utilization:ratio. A pipeline that fails under
    # pipefail would otherwise abort the whole snapshot.
    if ! topic_lines="$(kubectl --kubeconfig "$kubeconfig" -n "$kubernetes_namespace" exec "$redpanda_pod" -- rpk cluster logdirs describe --aggregate-into topic 2>/dev/null)"; then
      topic_lines=''
      printf 'skipped: could not read Redpanda topic sizes\n' >&2
    fi
    printf '%s\n' "$topic_lines" | awk 'NR > 1 && $4 ~ /^[0-9]+$/ { printf "redpanda_topic_log_bytes{topic=\"%s\"} %s\n", $3, $4 }'
  fi

  if command -v docker >/dev/null 2>&1 &&
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$postgres_container"; then
    printf '%s\n' '# HELP ssl_proxy_postgres_database_bytes Disk bytes used by each PostgreSQL database.'
    printf '%s\n' '# TYPE ssl_proxy_postgres_database_bytes gauge'
    pg_psql "SELECT datname || ' ' || pg_database_size(datname) FROM pg_database WHERE datistemplate = false" |
      while IFS=' ' read -r datname bytes; do
        case "$bytes" in ''|*[!0-9]*) continue ;; esac
        printf 'ssl_proxy_postgres_database_bytes{datname="%s"} %s\n' "$datname" "$bytes"
      done || true

    printf '%s\n' '# HELP ssl_proxy_postgres_relation_bytes Disk bytes used by the largest relations.'
    printf '%s\n' '# TYPE ssl_proxy_postgres_relation_bytes gauge'
    pg_psql "SELECT n.nspname || ' ' || c.relname || ' ' || pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('octopus_core', 'atheros_search', 'schema_migrator', 'keycloak') AND c.relkind IN ('r', 'p') ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 15" |
      while IFS=' ' read -r schema relation bytes; do
        case "$bytes" in ''|*[!0-9]*) continue ;; esac
        printf 'ssl_proxy_postgres_relation_bytes{schema="%s",relation="%s"} %s\n' "$schema" "$relation" "$bytes"
      done || true
  fi
} > "$temporary_file"

chmod 0644 "$temporary_file"
mv "$temporary_file" "$output_file"
