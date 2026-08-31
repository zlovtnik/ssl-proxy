#!/bin/sh
set -eu

schema_root="/workspace/sql/postgres"
db_host="${POSTGRES_HOST:?POSTGRES_HOST is required}"
db_port="${POSTGRES_PORT:-5432}"
db_name="${POSTGRES_DATABASE:-sync}"
db_user="${POSTGRES_SCHEMA_OWNER_USER:?POSTGRES_SCHEMA_OWNER_USER is required}"
db_password="${POSTGRES_SCHEMA_OWNER_PASSWORD:?POSTGRES_SCHEMA_OWNER_PASSWORD is required}"
db_ssl_mode="${PGSSLMODE:?PGSSLMODE is required}"
db_ssl_server_name="${POSTGRES_SSL_SERVER_NAME:?POSTGRES_SSL_SERVER_NAME is required}"
db_ssl_root_cert="${PGSSLROOTCERT:?PGSSLROOTCERT is required}"
octopus_account="${POSTGRES_OCTOPUS_ACCOUNT:?POSTGRES_OCTOPUS_ACCOUNT is required}"
search_account="${POSTGRES_ATHEROS_SEARCH_ACCOUNT:?POSTGRES_ATHEROS_SEARCH_ACCOUNT is required}"
migrator_account="${POSTGRES_SCHEMA_MIGRATOR_ACCOUNT:?POSTGRES_SCHEMA_MIGRATOR_ACCOUNT is required}"
keycloak_account="${POSTGRES_KEYCLOAK_ACCOUNT:?POSTGRES_KEYCLOAK_ACCOUNT is required}"

[ "${db_name}" = "sync" ] || { echo "POSTGRES_DATABASE must be sync" >&2; exit 2; }
[ "${db_ssl_mode}" = "verify-full" ] || { echo "PGSSLMODE must be verify-full" >&2; exit 2; }
[ "${db_ssl_server_name}" = "${db_host}" ] || { echo "POSTGRES_SSL_SERVER_NAME must equal POSTGRES_HOST" >&2; exit 2; }
[ -f "${db_ssl_root_cert}" ] || { echo "PGSSLROOTCERT must be a regular file" >&2; exit 2; }
for account in "${octopus_account}" "${search_account}" "${migrator_account}" "${keycloak_account}"; do
  case "${account}" in *[!A-Za-z0-9_]*|'') echo "runtime role names contain invalid characters" >&2; exit 2;; esac
done

export PGPASSWORD="${db_password}"
psql_run() {
  psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --host="${db_host}" --port="${db_port}" --username="${db_user}" --dbname="${db_name}" "$@"
}

manifest_digest() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  (
    awk '/^apply_order:$/ { active=1; next } active && /^  - / { print substr($0,5); next } active && /^[^ ]/ { exit }' "${manifest}" |
    while IFS= read -r relative; do
      printf '%s\0' "${relative}"
      cat "${schema_root}/${domain}/${relative}"
      printf '\0'
    done
  ) | sha256sum | awk '{print $1}'
}

apply_domain() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  checksums="${schema_root}/${domain}/checksums.sha256"
  expected_manifest="$(awk '/^manifest_sha256:/{print $2; exit}' "${manifest}")"
  [ "${expected_manifest}" = "$(manifest_digest "${domain}")" ] ||
    { echo "manifest checksum mismatch: ${domain}" >&2; exit 1; }
  awk '/^apply_order:$/ { active=1; next } active && /^  - / { print substr($0,5); next } active && /^[^ ]/ { exit }' "${manifest}" |
  while IFS= read -r relative; do
    sql_file="${schema_root}/${domain}/${relative}"
    expected="$(awk -v path="${relative}" '$2 == path {print $1}' "${checksums}")"
    [ "${expected}" = "$(sha256sum "${sql_file}" | awk '{print $1}')" ] ||
      { echo "checksum mismatch: ${domain}/${relative}" >&2; exit 1; }
    psql_run --file="${sql_file}"
  done
}

psql_run --file="${schema_root}/00_extensions/001_runtime_extensions.sql"
for domain in octopus_core atheros_search schema_migrator keycloak; do apply_domain "${domain}"; done

for domain in octopus_core atheros_search schema_migrator; do
  grep -hioE 'CREATE TABLE IF NOT EXISTS [a-z_]+\.[a-z0-9_]+' "${schema_root}/${domain}"/01_tables/*.sql |
  awk '{print $6}' | while IFS= read -r object; do
    psql_run --tuples-only --no-align --command="SELECT to_regclass('${object}') IS NOT NULL" |
      grep -qx t || { echo "missing required object: ${object}" >&2; exit 1; }
  done
done

psql_run --tuples-only --no-align --command="
  SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('octopus_core','atheros_search','schema_migrator')
    AND p.prokind IN ('f','p')" | grep -qx 0
psql_run --tuples-only --no-align --command="
  SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('octopus_core','atheros_search','schema_migrator')
    AND NOT t.tgisinternal" | grep -qx 0

sed -e "s/{{OCTOPUS_ACCOUNT}}/${octopus_account}/g" \
    -e "s/{{ATHEROS_SEARCH_ACCOUNT}}/${search_account}/g" \
    "${schema_root}/octopus_core/grants/least_privilege.sql.tmpl" | psql_run
sed -e "s/{{OCTOPUS_ACCOUNT}}/${octopus_account}/g" \
    -e "s/{{ATHEROS_SEARCH_ACCOUNT}}/${search_account}/g" \
    "${schema_root}/atheros_search/grants/least_privilege.sql.tmpl" | psql_run
sed -e "s/{{SCHEMA_MIGRATOR_STATE_ACCOUNT}}/${migrator_account}/g" \
    "${schema_root}/schema_migrator/grants/least_privilege.sql.tmpl" | psql_run
sed -e "s/{{KEYCLOAK_ACCOUNT}}/${keycloak_account}/g" \
    "${schema_root}/keycloak/grants/least_privilege.sql.tmpl" | psql_run

# Transaction-pool clients must not depend on a one-time client connection
# initializer. Role defaults are applied whenever PgBouncer opens an upstream
# PostgreSQL session and remain correct when a transaction borrows a new one.
psql_run --set=ON_ERROR_STOP=1 <<SQL
BEGIN;
ALTER ROLE "${octopus_account}" IN DATABASE "${db_name}" SET search_path TO octopus_core, atheros_search;
ALTER ROLE "${search_account}" IN DATABASE "${db_name}" SET search_path TO atheros_search;
ALTER ROLE "${migrator_account}" IN DATABASE "${db_name}" SET search_path TO schema_migrator;
ALTER ROLE "${keycloak_account}" IN DATABASE "${db_name}" SET search_path TO keycloak;
COMMIT;
SQL

ath_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/atheros_search/manifest.yaml")"
oct_version="$(awk '/^schema_version:/{print $2; exit}' "${schema_root}/octopus_core/manifest.yaml")"
oct_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/octopus_core/manifest.yaml")"
mig_version="$(awk '/^schema_version:/{print $2; exit}' "${schema_root}/schema_migrator/manifest.yaml")"
mig_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/schema_migrator/manifest.yaml")"

psql_run --command="UPDATE atheros_search.schema_manifest SET manifest_sha256='${ath_sha}', schema_ready=true, vector_ready=true, applied_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE component='atheros-search'"
psql_run --command="UPDATE octopus_core.schema_readiness SET required_version='${oct_version}', applied_version='${oct_version}', required_checksum='${oct_sha}', applied_checksum='${oct_sha}', ready=true, checked_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE domain='octopus_core'"
psql_run --command="INSERT INTO schema_migrator.state_schema_migrations(version,checksum,applied_at,applied_by) VALUES ('${mig_version}','${mig_sha}',CURRENT_TIMESTAMP,'postgres-runtime-schema') ON CONFLICT (version) DO UPDATE SET checksum=EXCLUDED.checksum, applied_at=EXCLUDED.applied_at, applied_by=EXCLUDED.applied_by"
psql_run --command="UPDATE schema_migrator.schema_readiness SET required_version='${mig_version}', applied_version='${mig_version}', required_checksum='${mig_sha}', applied_checksum='${mig_sha}', ready=true, checked_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE domain='schema_migrator'"

echo "canonical PostgreSQL schemas applied and readiness recorded"
