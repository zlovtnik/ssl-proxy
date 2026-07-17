#!/usr/bin/env bash

set -uo pipefail

namespace="${1:-ssl-proxy}"
kubectl_bin="${KUBECTL:-kubectl}"
kube_context="${KUBE_CONTEXT:-}"
helm_release="${KUBE_RELEASE:-ssl-proxy}"

if ! command -v "$kubectl_bin" >/dev/null 2>&1; then
  echo "[k8s-status] kubectl executable not found: $kubectl_bin" >&2
  exit 127
fi

kubectl_cmd=("$kubectl_bin")
helm_cmd=(helm)
if [[ -n "$kube_context" ]]; then
  kubectl_cmd+=(--context "$kube_context")
  helm_cmd+=(--kube-context "$kube_context")
fi

section() {
  printf '\n=== %s ===\n' "$1"
}

show() {
  local label="$1"
  shift
  section "$label"
  if ! "$@"; then
    echo "[k8s-status] unavailable (continuing)" >&2
  fi
}

current_context="$("${kubectl_cmd[@]}" config current-context 2>/dev/null || true)"
cluster_server="$("${kubectl_cmd[@]}" config view --minify -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null || true)"

section "Cluster"
printf 'Context:   %s\n' "${current_context:-unknown}"
printf 'API server: %s\n' "${cluster_server:-unknown}"
printf 'Namespace: %s\n' "$namespace"

if ! "${kubectl_cmd[@]}" get namespace "$namespace" -o wide; then
  echo "[k8s-status] cannot read namespace '$namespace'" >&2
  exit 1
fi

show "Helm releases" "${helm_cmd[@]}" list --namespace "$namespace"
show "Helm release status ($helm_release)" \
  "${helm_cmd[@]}" status "$helm_release" --namespace "$namespace"

show "Workload status" \
  "${kubectl_cmd[@]}" get deployments,statefulsets,daemonsets,jobs,cronjobs \
  --namespace "$namespace" -o wide

show "Pods" \
  "${kubectl_cmd[@]}" get pods --namespace "$namespace" -o wide \
  --sort-by='.metadata.name'

show "Pod health details" \
  "${kubectl_cmd[@]}" get pods --namespace "$namespace" \
  -o 'custom-columns=NAME:.metadata.name,PHASE:.status.phase,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[*].restartCount,WAITING:.status.containerStatuses[*].state.waiting.reason,LAST_EXIT:.status.containerStatuses[*].lastState.terminated.reason,QOS:.status.qosClass' \
  --sort-by='.metadata.name'

show "Pod images" \
  "${kubectl_cmd[@]}" get pods --namespace "$namespace" \
  -o 'custom-columns=POD:.metadata.name,CONTAINERS:.spec.containers[*].name,IMAGES:.spec.containers[*].image' \
  --sort-by='.metadata.name'

show "Declared container and host ports" \
  "${kubectl_cmd[@]}" get pods --namespace "$namespace" \
  -o 'custom-columns=POD:.metadata.name,HOST_NETWORK:.spec.hostNetwork,CONTAINERS:.spec.containers[*].name,CONTAINER_PORTS:.spec.containers[*].ports[*].containerPort,HOST_PORTS:.spec.containers[*].ports[*].hostPort,PROTOCOLS:.spec.containers[*].ports[*].protocol' \
  --sort-by='.metadata.name'

show "Services and exposed ports" \
  "${kubectl_cmd[@]}" get services --namespace "$namespace" -o wide \
  --sort-by='.metadata.name'

show "Endpoint slices" \
  "${kubectl_cmd[@]}" get endpointslices.discovery.k8s.io \
  --namespace "$namespace" -o wide --sort-by='.metadata.name'

show "Ingress" \
  "${kubectl_cmd[@]}" get ingress --namespace "$namespace" -o wide \
  --sort-by='.metadata.name'

show "Storage" \
  "${kubectl_cmd[@]}" get persistentvolumeclaims --namespace "$namespace" -o wide \
  --sort-by='.metadata.name'

show "Availability, scaling, quotas, and network policy" \
  "${kubectl_cmd[@]}" get poddisruptionbudgets,horizontalpodautoscalers,resourcequotas,limitranges,networkpolicies \
  --namespace "$namespace" -o wide

show "Pod resource usage (metrics-server optional)" \
  "${kubectl_cmd[@]}" top pods --namespace "$namespace" --containers

show "Warning events" \
  "${kubectl_cmd[@]}" get events --namespace "$namespace" \
  --field-selector='type=Warning' --sort-by='.lastTimestamp'

section "Snapshot complete"
printf 'Captured read-only status for namespace %s at %s\n' \
  "$namespace" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
