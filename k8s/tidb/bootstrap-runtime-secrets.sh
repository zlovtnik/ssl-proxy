#!/bin/bash
set -euo pipefail

# Fresh-cluster bootstrap only. Do not run this script to rotate TiDB TLS:
# k8s/tidb/generate-tls-secrets.sh preserves all existing runtime credentials.
NAMESPACE="default"

generate_password() {
  openssl rand -base64 32 | tr -d '=' | head -c 32
}

octopus_password="$(generate_password)"
atheros_search_password="$(generate_password)"
schema_migrator_password="$(generate_password)"
keycloak_password="$(generate_password)"
redis_password="$(generate_password)"

kubectl create secret generic tidb-octopus \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${octopus_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

atheros_search_dsn="atheros_search_runtime:${atheros_search_password}@tcp(ssl-proxy-tidb.default.svc.cluster.local:4000)/atheros_search"
kubectl create secret generic tidb-atheros-search \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${atheros_search_password}" \
  --from-literal=dsn="${atheros_search_dsn}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-schema-migrator \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${schema_migrator_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-keycloak \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${keycloak_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-schema-owner \
  --namespace="${NAMESPACE}" \
  --from-literal=dsn="mysql://root@ssl-proxy-tidb:4000/" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic redis-runtime \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${redis_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Fresh-cluster runtime secrets created. Apply k8s/tidb/init-job.yaml next."
