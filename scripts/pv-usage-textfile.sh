#!/usr/bin/env bash
set -euo pipefail

output_dir="${NODE_EXPORTER_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
pvc_root="${K3S_PVC_ROOT:-/k3s}"
docker_root="${DOCKER_VOLUME_ROOT:-/var/lib/docker/volumes}"
kubeconfig="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
kubernetes_namespace="${KUBERNETES_NAMESPACE:-prod-ssl-proxy}"
redpanda_pod="${REDPANDA_POD:-ssl-proxy-redpanda-0}"
output_file="$output_dir/ssl_proxy_storage.prom"

mkdir -p "$output_dir"
temporary_file="$(mktemp "$output_dir/.ssl_proxy_storage.XXXXXX")"
trap 'rm -f "$temporary_file"' EXIT

bytes_used() {
  du -sxB1 "$1" | awk '{print $1}'
}

{
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
      awk 'NR > 1 && $4 ~ /^[0-9]+$/ { printf "redpanda_topic_log_bytes{topic=\\\"%s\\\"} %s\\n", $3, $4 }'
  fi
} > "$temporary_file"

chmod 0644 "$temporary_file"
mv "$temporary_file" "$output_file"
