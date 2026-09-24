#!/usr/bin/env bash
set -euo pipefail

output_dir="${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
pvc_root="${K3S_PVC_ROOT:-/k3s}"
docker_root="${DOCKER_VOLUME_ROOT:-/var/lib/docker/volumes}"
kubeconfig="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
kubernetes_namespace="${KUBERNETES_NAMESPACE:-prod-ssl-proxy}"
redpanda_pod="${REDPANDA_POD:-ssl-proxy-redpanda-0}"
postgres_container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
postgres_user="${POSTGRES_USER:-platform_admin}"
postgres_database="${POSTGRES_DATABASE:-sync}"
output_file="$output_dir/ssl_proxy_storage.prom"

mkdir -p "$output_dir"
temporary_file="$(mktemp "$output_dir/.ssl_proxy_storage.XXXXXX")"
trap 'rm -f "$temporary_file"' EXIT

bytes_used() {
  du -sxB1 "$1" | awk '{print $1}'
}

pg_psql() {
  # pg_psql <sql> - read-only query against the sync database. The local
  # socket requires SCRAM and psql has no tty under docker exec, so the
  # password is exported inside the container from its own secret file.
  docker exec "$postgres_container" sh -eu -c \
    'PGPASSWORD=$(tr -d "\r\n" </run/platform-secrets/platform_admin.password); export PGPASSWORD; exec psql -X -At -U "$1" -d "$2" -c "$3"' \
    psql-wrap "$postgres_user" "$postgres_database" "$1"
}

{
  printf '%s\n' '# HELP ssl_proxy_storage_textfile_timestamp_seconds Last successful storage textfile publication.'
  printf '%s\n' '# TYPE ssl_proxy_storage_textfile_timestamp_seconds gauge'
  printf 'ssl_proxy_storage_textfile_timestamp_seconds %s\n' "$(date +%s)"

  printf '%s\n' '# HELP ssl_proxy_host_path_used_bytes Disk bytes used by a monitored host path.'
  printf '%s\n' '# TYPE ssl_proxy_host_path_used_bytes gauge'
  for path in "$pvc_root"/pvc-*; do
    [ -d "$path" ] || continue
    printf 'ssl_proxy_host_path_used_bytes{class="k3s_pvc",path="%s"} %s\n' "${path##*/}" "$(bytes_used "$path")"
  done

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
    kubectl --kubeconfig "$kubeconfig" -n "$kubernetes_namespace" exec "$redpanda_pod" -- \
      rpk cluster logdirs describe --aggregate-into topic 2>/dev/null | \
      awk 'NR > 1 && $4 ~ /^[0-9]+$/ { printf "redpanda_topic_log_bytes{topic=\"%s\"} %s\n", $3, $4 }'
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
