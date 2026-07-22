#!/bin/bash
set -euo pipefail

NAMESPACE="ssl-proxy"
SECRET_NAME="tidb-client-ca"
CERT_DIR=$(mktemp -d)

echo "Generating self-signed CA..."
openssl genrsa -out ${CERT_DIR}/ca.key 2048
openssl req -new -x509 -days 3650 -key ${CERT_DIR}/ca.key -out ${CERT_DIR}/ca.crt \
  -subj "/CN=TiDB Client CA"

echo "Creating Kubernetes secret..."
kubectl create secret generic ${SECRET_NAME} \
  --namespace=${NAMESPACE} \
  --from-file=ca.crt=${CERT_DIR}/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Generating account passwords..."
generate_password() {
  openssl rand -base64 32 | tr -d '=' | head -c 32
}

OCTOPUS_PW=$(generate_password)
ATHEROS_SEARCH_PW=$(generate_password)
INTEGRATION_CONSOLE_PW=$(generate_password)
SCHEMA_MIGRATOR_PW=$(generate_password)

echo "Creating account secrets..."
kubectl create secret generic tidb-octopus \
  --namespace=${NAMESPACE} \
  --from-literal=password="${OCTOPUS_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-atheros-search \
  --namespace=${NAMESPACE} \
  --from-literal=password="${ATHEROS_SEARCH_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-integration-console \
  --namespace=${NAMESPACE} \
  --from-literal=password="${INTEGRATION_CONSOLE_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-schema-migrator \
  --namespace=${NAMESPACE} \
  --from-literal=password="${SCHEMA_MIGRATOR_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Creating schema owner DSN secret..."
DSN="mysql://root@ssl-proxy-tidb:4000/"
kubectl create secret generic tidb-schema-owner \
  --namespace=${NAMESPACE} \
  --from-literal=dsn="${DSN}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "TLS secrets created successfully."
rm -rf ${CERT_DIR}
