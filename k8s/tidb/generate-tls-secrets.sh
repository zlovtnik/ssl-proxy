#!/bin/bash
set -euo pipefail

NAMESPACE="ssl-proxy"
SECRET_NAME="tidb-client-ca"
CERT_DIR=$(mktemp -d)

echo "Generating self-signed CA..."
openssl genrsa -out ${CERT_DIR}/ca.key 2048
openssl req -new -x509 -days 3650 -key ${CERT_DIR}/ca.key -out ${CERT_DIR}/ca.crt \
  -subj "/CN=TiDB Client CA"

echo "Creating client CA secret..."
kubectl create secret generic ${SECRET_NAME} \
  --namespace=${NAMESPACE} \
  --from-file=ca.crt=${CERT_DIR}/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Generating TiDB server certificate signed by client CA..."
cat > ${CERT_DIR}/tidb-server.cnf << 'TLS_EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = ssl-proxy-tidb

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ssl-proxy-tidb.ssl-proxy.svc.cluster.local
DNS.2 = ssl-proxy-tidb
TLS_EOF

openssl req -newkey rsa:2048 -nodes \
  -keyout ${CERT_DIR}/tidb-server.key \
  -out ${CERT_DIR}/tidb-server.csr \
  -config ${CERT_DIR}/tidb-server.cnf

openssl x509 -req -days 3650 \
  -in ${CERT_DIR}/tidb-server.csr \
  -CA ${CERT_DIR}/ca.crt -CAkey ${CERT_DIR}/ca.key \
  -CAcreateserial \
  -out ${CERT_DIR}/tidb-server.crt \
  -extfile ${CERT_DIR}/tidb-server.cnf \
  -extensions req_ext

echo "Creating TiDB server TLS secret..."
kubectl create secret tls tidb-server-tls \
  --namespace=${NAMESPACE} \
  --cert=${CERT_DIR}/tidb-server.crt \
  --key=${CERT_DIR}/tidb-server.key \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Generating account passwords..."
generate_password() {
  openssl rand -base64 32 | tr -d '=' | head -c 32
}

OCTOPUS_PW=$(generate_password)
ATHEROS_SEARCH_PW=$(generate_password)
INTEGRATION_CONSOLE_PW=$(generate_password)
SCHEMA_MIGRATOR_PW=$(generate_password)
KEYCLOAK_PW=$(generate_password)

echo "Creating account secrets..."
kubectl create secret generic tidb-octopus \
  --namespace=${NAMESPACE} \
  --from-literal=password="${OCTOPUS_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

ATHEROS_SEARCH_DSN="atheros_search_runtime:${ATHEROS_SEARCH_PW}@tcp(ssl-proxy-tidb.ssl-proxy.svc.cluster.local:4000)/atheros_search"
kubectl create secret generic tidb-atheros-search \
  --namespace=${NAMESPACE} \
  --from-literal=password="${ATHEROS_SEARCH_PW}" \
  --from-literal=dsn="${ATHEROS_SEARCH_DSN}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-schema-migrator \
  --namespace=${NAMESPACE} \
  --from-literal=password="${SCHEMA_MIGRATOR_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic tidb-keycloak \
  --namespace=${NAMESPACE} \
  --from-literal=password="${KEYCLOAK_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Creating schema owner DSN secret..."
DSN="mysql://root@ssl-proxy-tidb:4000/"
kubectl create secret generic tidb-schema-owner \
  --namespace=${NAMESPACE} \
  --from-literal=dsn="${DSN}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Creating redis-runtime secret..."
REDIS_PW=$(generate_password)
kubectl create secret generic redis-runtime \
  --namespace=${NAMESPACE} \
  --from-literal=password="${REDIS_PW}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "TLS secrets created successfully."
rm -rf ${CERT_DIR}
