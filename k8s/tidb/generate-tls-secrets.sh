#!/bin/bash
set -euo pipefail

NAMESPACE="ssl-proxy"
CA_SECRET_NAME="tidb-client-ca"
SERVER_SECRET_NAME="tidb-server-tls"
CERT_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${CERT_DIR}"
}
trap cleanup EXIT

echo "Generating self-signed CA..."
openssl genrsa -out "${CERT_DIR}/ca.key" 2048
cat > "${CERT_DIR}/ca.cnf" << 'TLS_EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = TiDB Client CA

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
TLS_EOF
openssl req -new -x509 -days 3650 \
  -key "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" \
  -config "${CERT_DIR}/ca.cnf" \
  -extensions v3_ca

echo "Creating client CA secret..."
kubectl create secret generic "${CA_SECRET_NAME}" \
  --namespace="${NAMESPACE}" \
  --from-file="ca.crt=${CERT_DIR}/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Generating TiDB server certificate signed by the client CA..."
cat > "${CERT_DIR}/tidb-server.cnf" << 'TLS_EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = ssl-proxy-tidb

[req_ext]
subjectAltName = @alt_names

[v3_server]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = ssl-proxy-tidb.ssl-proxy.svc.cluster.local
DNS.2 = ssl-proxy-tidb
TLS_EOF

openssl req -newkey rsa:2048 -nodes \
  -keyout "${CERT_DIR}/tidb-server.key" \
  -out "${CERT_DIR}/tidb-server.csr" \
  -config "${CERT_DIR}/tidb-server.cnf"

openssl x509 -req -days 3650 \
  -in "${CERT_DIR}/tidb-server.csr" \
  -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/tidb-server.crt" \
  -extfile "${CERT_DIR}/tidb-server.cnf" \
  -extensions v3_server

openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/tidb-server.crt"

echo "Creating TiDB server TLS secret..."
kubectl create secret tls "${SERVER_SECRET_NAME}" \
  --namespace="${NAMESPACE}" \
  --cert="${CERT_DIR}/tidb-server.crt" \
  --key="${CERT_DIR}/tidb-server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "TiDB TLS secrets rotated successfully. Runtime credentials were not changed."
