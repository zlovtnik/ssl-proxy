#!/bin/sh
set -eu

schema_root="/workspace/sql/tidb"
dsn="${TIDB_SCHEMA_OWNER_DSN:?TIDB_SCHEMA_OWNER_DSN is required}"
ca_file="${TIDB_TLS_CA_FILE:?TIDB_TLS_CA_FILE is required}"

case "${dsn}" in
  mysql://*@*/*) ;;
  *) echo "TIDB_SCHEMA_OWNER_DSN must be a mysql:// URL" >&2; exit 2 ;;
esac

authority="${dsn#mysql://}"
authority="${authority%%/*}"
credentials="${authority%@*}"
endpoint="${authority#*@}"
db_user="${credentials%%:*}"
db_password=""
if [ "${credentials}" != "${db_user}" ]; then
  db_password="${credentials#*:}"
fi
db_host="${endpoint%:*}"
db_port="${endpoint##*:}"

if [ -z "${db_user}" ] || [ -z "${db_host}" ] || [ "${db_host}" = "${endpoint}" ]; then
  echo "TIDB_SCHEMA_OWNER_DSN must include user, host, and port" >&2
  exit 2
fi

mysql_run() {
  MYSQL_PWD="${db_password}" mysql \
    --protocol=TCP \
    --host="${db_host}" \
    --port="${db_port}" \
    --user="${db_user}" \
    --ssl-mode=VERIFY_IDENTITY \
    --ssl-ca="${ca_file}" \
    "$@"
}

apply_domain() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  checksums="${schema_root}/${domain}/checksums.sha256"

  awk '
    /^apply_order:$/ { active = 1; next }
    active && /^  - / { print substr($0, 5); next }
    active && /^[^ ]/ { exit }
  ' "${manifest}" | while IFS= read -r relative; do
    [ -n "${relative}" ] || continue
    sql_file="${schema_root}/${domain}/${relative}"
    expected="$(awk -v path="${relative}" '$2 == path { print $1 }' "${checksums}")"
    actual="$(sha256sum "${sql_file}" | awk '{ print $1 }')"
    if [ "${expected}" != "${actual}" ]; then
      echo "checksum mismatch: ${domain}/${relative}" >&2
      exit 1
    fi
    echo "applying ${domain}/${relative}"
    mysql_run < "${sql_file}"
  done
}

for domain in octopus_core atheros_search integration_console schema_migrator; do
  apply_domain "${domain}"
done

atheros_manifest_sha="$(awk '/^manifest_sha256:/{ print $2; exit }' "${schema_root}/atheros_search/manifest.yaml")"
mysql_run -e "UPDATE atheros_search.schema_manifest SET manifest_sha256='${atheros_manifest_sha}', schema_ready=1, vector_ready=1, applied_at=UTC_TIMESTAMP(6), details=JSON_OBJECT('state', 'ready', 'executor', 'tidb-runtime-schema') WHERE component='atheros-search';"

echo "canonical TiDB schemas applied and Atheros Search readiness recorded"
