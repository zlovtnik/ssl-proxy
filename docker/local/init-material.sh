#!/bin/sh
set -eu

umask 077
secrets=/local-secrets
tls=/postgres-tls
octopus=/octopus-secrets
mkdir -p "${secrets}" "${tls}" "${octopus}"
chown 0:999 "${secrets}"
chmod 0750 "${secrets}"
chmod 0755 "${tls}" "${octopus}"

for account in platform_admin schema_owner octopus_runtime octopus_metrics \
  atheros_search_runtime schema_migrator_runtime keycloak_runtime; do
  password="${secrets}/${account}.password"
  if [ ! -e "${password}" ]; then
    openssl rand -hex 32 >"${password}.tmp"
    mv "${password}.tmp" "${password}"
  fi
  [ -s "${password}" ] || { echo "empty local password file: ${password}" >&2; exit 1; }
  chown 0:999 "${password}"
  chmod 0440 "${password}"
done

# Retain existing material: restarting the stack must not rotate its CA or keys.
if [ ! -e "${tls}/ca.key" ] && [ ! -e "${tls}/ca.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj '/CN=ssl-proxy local development CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "${tls}/ca.key" -out "${tls}/ca.crt"
fi
[ -s "${tls}/ca.key" ] && [ -s "${tls}/ca.crt" ] || {
  echo "incomplete local CA material; restore the TLS volume" >&2
  exit 1
}

# A retained server certificate must still match the current CA and hostname.
if { [ ! -e "${tls}/server.key" ] && [ ! -e "${tls}/server.crt" ]; } ||
  { [ -e "${tls}/server.crt" ] &&
    ! openssl verify -CAfile "${tls}/ca.crt" -verify_hostname postgres \
      "${tls}/server.crt" >/dev/null 2>&1; }; then
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj '/CN=postgres' \
    -keyout "${tls}/server.key" -out "${tls}/server.csr"
  cat >"${tls}/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1
EOF
  openssl x509 -req -sha256 -days 3650 -in "${tls}/server.csr" \
    -CA "${tls}/ca.crt" -CAkey "${tls}/ca.key" -CAcreateserial \
    -extfile "${tls}/server.ext" -out "${tls}/server.crt"
  rm -f "${tls}/server.csr" "${tls}/server.ext"
fi
[ -s "${tls}/server.key" ] && [ -s "${tls}/server.crt" ] || {
  echo "incomplete local PostgreSQL TLS material; restore the TLS volume" >&2
  exit 1
}
openssl verify -CAfile "${tls}/ca.crt" -verify_hostname postgres "${tls}/server.crt"
chmod 0600 "${tls}/ca.key" "${tls}/server.key"
chmod 0444 "${tls}/ca.crt" "${tls}/server.crt"
chown 999:999 "${tls}/server.key"
cp "${tls}/ca.crt" "${secrets}/ca.crt"
cp "${tls}/ca.crt" "${octopus}/ca.crt"
cp "${secrets}/octopus_runtime.password" "${octopus}/octopus_runtime.password"
chmod 0444 "${secrets}/ca.crt" "${octopus}/ca.crt" "${octopus}/octopus_runtime.password"
echo 'Local passwords and PostgreSQL TLS material are ready'
