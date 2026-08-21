#!/bin/bash
set -euo pipefail

# Fresh-cluster bootstrap only. TiDB transport is plaintext in the supported
# dev and production deployment surfaces; credentials remain mandatory.
NAMESPACE="default"

generate_password() {
  openssl rand -base64 32 | tr -d '=' | head -c 32
}

octopus_password="$(generate_password)"
atheros_search_password="$(generate_password)"
schema_migrator_password="$(generate_password)"
keycloak_password="$(generate_password)"
root_password="$(generate_password)"
schema_owner_password="$(generate_password)"
redis_password="$(generate_password)"

kubectl create secret generic tidb-root \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${root_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-octopus \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${octopus_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-atheros-search \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${atheros_search_password}" \
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
  --from-literal=password="${schema_owner_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic redis-runtime \
  --namespace="${NAMESPACE}" \
  --from-literal=password="${redis_password}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Fresh-cluster runtime secrets created. Apply k8s/tidb/init-job.yaml next."
