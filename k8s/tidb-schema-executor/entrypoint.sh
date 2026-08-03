#!/bin/sh
set -eu

schema_root="/workspace/sql/tidb"
dsn="${TIDB_SCHEMA_OWNER_DSN:?TIDB_SCHEMA_OWNER_DSN is required}"
ca_file="${TIDB_TLS_CA_FILE:?TIDB_TLS_CA_FILE is required}"
octopus_account="${TIDB_OCTOPUS_ACCOUNT:?TIDB_OCTOPUS_ACCOUNT is required}"
atheros_search_account="${TIDB_ATHEROS_SEARCH_ACCOUNT:?TIDB_ATHEROS_SEARCH_ACCOUNT is required}"
schema_migrator_account="${TIDB_SCHEMA_MIGRATOR_ACCOUNT:?TIDB_SCHEMA_MIGRATOR_ACCOUNT is required}"

for account in "${octopus_account}" "${atheros_search_account}" "${schema_migrator_account}"; do
  case "${account}" in
    *[!A-Za-z0-9_]*|'')
      echo "runtime account names may contain only letters, digits, and underscores" >&2
      exit 2
      ;;
  esac
done

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

apply_grant_fixture() {
  fixture="$1"
  sed \
    -e "s/{{OCTOPUS_ACCOUNT}}/${octopus_account}/g" \
    -e "s/{{ATHEROS_SEARCH_ACCOUNT}}/${atheros_search_account}/g" \
    -e "s/{{SCHEMA_MIGRATOR_STATE_ACCOUNT}}/${schema_migrator_account}/g" \
    "${fixture}" | mysql_run
}

for domain in octopus_core atheros_search integration_console schema_migrator; do
  apply_domain "${domain}"
done

# The TiDB bootstrap job grants database-wide privileges so it can create
# accounts before tables exist. Once canonical DDL is present, replace those
# bootstrap grants with the checked-in table ownership matrix.
mysql_run -e "REVOKE SELECT, INSERT, UPDATE, DELETE ON atheros_search.* FROM '${octopus_account}', '${atheros_search_account}';"
mysql_run -e "REVOKE SELECT ON octopus_core.* FROM '${atheros_search_account}';"
apply_grant_fixture "${schema_root}/octopus_core/grants/least_privilege.sql.tmpl"
apply_grant_fixture "${schema_root}/atheros_search/grants/least_privilege.sql.tmpl"
apply_grant_fixture "${schema_root}/schema_migrator/grants/least_privilege.sql.tmpl"

atheros_manifest_sha="$(awk '/^manifest_sha256:/{ print $2; exit }' "${schema_root}/atheros_search/manifest.yaml")"
mysql_run -e "UPDATE atheros_search.schema_manifest SET manifest_sha256='${atheros_manifest_sha}', schema_ready=1, vector_ready=1, applied_at=UTC_TIMESTAMP(6), details=JSON_OBJECT('state', 'ready', 'executor', 'tidb-runtime-schema') WHERE component='atheros-search';"

echo "canonical TiDB schemas applied and Atheros Search readiness recorded"
