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
for account in "${db_user}" "${octopus_account}" "${search_account}" "${migrator_account}" "${keycloak_account}"; do
  case "${account}" in *[!A-Za-z0-9_]*|'') echo "runtime role names contain invalid characters" >&2; exit 2;; esac
done

export PGPASSWORD="${db_password}"
psql_run() {
  psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --host="${db_host}" --port="${db_port}" --username="${db_user}" --dbname="${db_name}" "$@"
}

manifest_paths() {
  manifest="$1"
  awk '/^apply_order:$/ { active=1; next } active && /^  - / { print substr($0,5); next } active && /^[^ ]/ { exit }' "${manifest}"
}

migration_key() {
  domain="$1"
  relative="$2"
  key="runtime/${domain}/${relative}"
  [ "${#key}" -le 128 ] || { echo "migration key exceeds 128 characters: ${key}" >&2; exit 1; }
  printf '%s\n' "${key}"
}

assert_domain_ownership() {
  domain="$1"
  include_relations="$2"
  drift="$(psql_run --tuples-only --no-align --command="
    SELECT format('schema %I is owned by %I, expected %I', namespace.nspname, owner.rolname, current_user)
    FROM pg_namespace namespace
    JOIN pg_roles owner ON owner.oid = namespace.nspowner
    WHERE namespace.nspname = '${domain}'
      AND owner.rolname <> current_user
    UNION ALL
    SELECT format('%s %I.%I is owned by %I, expected %I',
                  CASE relation.relkind
                    WHEN 'S' THEN 'sequence'
                    WHEN 'v' THEN 'view'
                    WHEN 'm' THEN 'materialized view'
                    WHEN 'p' THEN 'partitioned table'
                    WHEN 'f' THEN 'foreign table'
                    ELSE 'table'
                  END,
                  namespace.nspname, relation.relname, owner.rolname, current_user)
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_roles owner ON owner.oid = relation.relowner
    WHERE '${include_relations}' = 'true'
      AND namespace.nspname = '${domain}'
      AND relation.relkind IN ('r','p','v','m','S','f')
      AND owner.rolname <> current_user
    ORDER BY 1")"
  [ -z "${drift}" ] || {
    echo "schema ownership drift detected before migration:" >&2
    printf '%s\n' "${drift}" >&2
    echo "refusing to apply or attest ${domain}; reconcile ownership with an authorized administrator" >&2
    exit 1
  }
}

record_migration() {
  domain="$1"
  relative="$2"
  checksum="$3"
  applied_by="$4"
  key="$(migration_key "${domain}" "${relative}")"
  case "${applied_by}" in *[!A-Za-z0-9_-]*|'') echo "invalid migration actor: ${applied_by}" >&2; exit 1;; esac
  psql_run --quiet --command="
      INSERT INTO schema_migrator.state_schema_migrations(version, checksum, applied_at, applied_by)
      VALUES ('${key}', '${checksum}', CURRENT_TIMESTAMP, '${applied_by}')
      ON CONFLICT (version) DO NOTHING"
  observed="$(psql_run --tuples-only --no-align \
    --command="SELECT checksum FROM schema_migrator.state_schema_migrations WHERE version = '${key}'")"
  [ "${observed}" = "${checksum}" ] || {
    echo "migration checksum drift: ${domain}/${relative} recorded=${observed:-missing} expected=${checksum}" >&2
    exit 1
  }
}

bootstrap_migration_ledger() {
  schema_file="${schema_root}/schema_migrator/00_schemas/001_schema_migrator_database.sql"
  control_file="${schema_root}/schema_migrator/01_tables/001_schema_control.sql"
  assert_domain_ownership schema_migrator true
  if [ "$(psql_run --tuples-only --no-align --command="SELECT to_regclass('schema_migrator.state_schema_migrations') IS NOT NULL")" != "t" ]; then
    echo "bootstrapping schema migration ledger"
    psql_run --file="${schema_file}"
    psql_run --file="${control_file}"
    assert_domain_ownership schema_migrator true
    record_migration schema_migrator 00_schemas/001_schema_migrator_database.sql \
      "$(sha256sum "${schema_file}" | awk '{print $1}')" postgres-runtime-schema-bootstrap
    record_migration schema_migrator 01_tables/001_schema_control.sql \
      "$(sha256sum "${control_file}" | awk '{print $1}')" postgres-runtime-schema-bootstrap
  fi
}

apply_tracked_file() {
  domain="$1"
  relative="$2"
  checksum="$3"
  sql_file="$4"
  key="$(migration_key "${domain}" "${relative}")"
  wrapper="$(mktemp /tmp/postgres-schema-migration.XXXXXX)"
  trap 'rm -f "${wrapper}"' EXIT HUP INT TERM
  {
    printf '%s\n' '\set ON_ERROR_STOP on'
    printf '%s\n' 'BEGIN;'
    printf '%s\n' "SELECT pg_advisory_xact_lock(hashtextextended('ssl-proxy-postgres-schema-executor', 0));"
    printf '%s\n' "SELECT EXISTS (SELECT 1 FROM schema_migrator.state_schema_migrations WHERE version = :'migration_key' AND checksum <> :'migration_checksum') AS migration_checksum_mismatch \\gset"
    printf '%s\n' '\if :migration_checksum_mismatch'
    printf '%s\n' "DO \$\$ BEGIN RAISE EXCEPTION 'migration checksum drift for ${key}'; END \$\$;"
    printf '%s\n' '\endif'
    printf '%s\n' "SELECT EXISTS (SELECT 1 FROM schema_migrator.state_schema_migrations WHERE version = :'migration_key' AND checksum = :'migration_checksum') AS migration_already_applied \\gset"
    printf '%s\n' '\if :migration_already_applied'
    printf '%s\n' '\echo migration already applied: :migration_key'
    printf '%s\n' '\else'
    printf '\\ir %s\n' "${sql_file}"
    printf '%s\n' "INSERT INTO schema_migrator.state_schema_migrations(version, checksum, applied_at, applied_by) VALUES (:'migration_key', :'migration_checksum', CURRENT_TIMESTAMP, 'postgres-runtime-schema');"
    printf '%s\n' '\echo migration applied: :migration_key'
    printf '%s\n' '\endif'
    printf '%s\n' 'COMMIT;'
  } >"${wrapper}"
  psql_run --set=migration_key="${key}" --set=migration_checksum="${checksum}" --file="${wrapper}"
  rm -f "${wrapper}"
  trap - EXIT HUP INT TERM
}

role_search_path_is_current() {
  account="$1"
  expected_search_path="$2"
  expected_setting="search_path=${expected_search_path}"
  [ "$(psql_run --tuples-only --no-align --command="
    SELECT EXISTS (
      SELECT 1
      FROM pg_db_role_setting setting
      JOIN pg_roles role ON role.oid = setting.setrole
      JOIN pg_database database ON database.oid = setting.setdatabase
      WHERE role.rolname = '${account}'
        AND database.datname = '${db_name}'
        AND '${expected_setting}' = ANY(setting.setconfig)
    )")" = "t" ]
}

ensure_role_search_path() {
  account="$1"
  expected_search_path="$2"
  if role_search_path_is_current "${account}" "${expected_search_path}"; then
    echo "role search_path already configured: ${account}"
    return
  fi
  psql_run --command="ALTER ROLE \"${account}\" IN DATABASE \"${db_name}\" SET search_path TO ${expected_search_path}"
}

manifest_digest() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  (
    manifest_paths "${manifest}" |
    while IFS= read -r relative; do
      printf '%s\0' "${relative}"
      cat "${schema_root}/${domain}/${relative}"
      printf '\0'
    done
  ) | sha256sum | awk '{print $1}'
}

domain_required_objects_exist() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  objects="$(
    manifest_paths "${manifest}" |
    while IFS= read -r relative; do
      grep -hioE 'CREATE TABLE IF NOT EXISTS [a-z_]+\.[a-z0-9_]+' "${schema_root}/${domain}/${relative}" || true
    done |
    awk '{print $6}'
  )"

  [ -n "${objects}" ] || return 1
  for object in ${objects}; do
    psql_run --tuples-only --no-align --command="SELECT to_regclass('${object}') IS NOT NULL" |
      grep -qx t || {
        echo "missing required object: ${object}" >&2
        return 1
      }
  done
}

domain_attested_checksum() {
  domain="$1"
  case "${domain}" in
    octopus_core|atheros_search|schema_migrator) ;;
    *) return 1 ;;
  esac
  [ "$(psql_run --tuples-only --no-align --command="SELECT to_regclass('${domain}.schema_readiness') IS NOT NULL")" = "t" ] ||
    return 1
  psql_run --tuples-only --no-align --command="
    SELECT applied_checksum
    FROM ${domain}.schema_readiness
    WHERE domain = '${domain}'
      AND ready
      AND applied_version = required_version
      AND applied_checksum = required_checksum"
}

adopt_baseline_file() {
  domain="$1"
  baseline="$2"
  while read -r checksum relative extra; do
    [ -n "${checksum:-}" ] || continue
    [ -z "${extra:-}" ] || { echo "invalid baseline row: ${baseline}" >&2; exit 1; }
    case "${checksum}" in *[!0-9a-f]*|'') echo "invalid baseline checksum: ${baseline}" >&2; exit 1;; esac
    [ "${#checksum}" -eq 64 ] || { echo "invalid baseline checksum: ${baseline}" >&2; exit 1; }
    case "${relative}" in
      ''|/*|*..*|*[!A-Za-z0-9_./-]*) echo "invalid baseline path: ${baseline}" >&2; exit 1;;
    esac
    current="${schema_root}/${domain}/${relative}"
    if [ -f "${current}" ]; then
      observed="$(sha256sum "${current}" | awk '{print $1}')"
      [ "${observed}" = "${checksum}" ] || {
        echo "cannot adopt changed historical migration: ${domain}/${relative}" >&2
        echo "recorded baseline=${checksum} current=${observed}; add a new migration file instead" >&2
        exit 1
      }
    fi
    record_migration "${domain}" "${relative}" "${checksum}" legacy-manifest-attestation
  done <"${baseline}"
}

baseline_domain_ledger() {
  domain="$1"
  expected_manifest="$2"
  checksums="$3"
  recorded_count="$(psql_run --tuples-only --no-align --command="
    SELECT count(*) FROM schema_migrator.state_schema_migrations WHERE version LIKE 'runtime/${domain}/%'")"
  [ "${recorded_count}" = "0" ] || return

  attested_checksum="$(domain_attested_checksum "${domain}" || true)"
  [ -n "${attested_checksum}" ] || {
    echo "no trusted pre-ledger attestation for ${domain}; manifest files will be applied"
    return
  }
  if [ "${attested_checksum}" = "${expected_manifest}" ]; then
    domain_required_objects_exist "${domain}" || {
      echo "refusing to adopt incomplete attested domain: ${domain}" >&2
      exit 1
    }
    baseline="${checksums}"
  else
    baseline="${schema_root}/${domain}/baselines/${attested_checksum}.sha256"
    [ -f "${baseline}" ] || {
      echo "no trusted migration baseline for ${domain} attestation ${attested_checksum}" >&2
      echo "refusing to replay historical schema files without an explicit baseline" >&2
      exit 1
    }
  fi
  echo "adopting trusted pre-ledger migrations: ${domain} (${attested_checksum})"
  adopt_baseline_file "${domain}" "${baseline}"
}

apply_domain() {
  domain="$1"
  manifest="${schema_root}/${domain}/manifest.yaml"
  checksums="${schema_root}/${domain}/checksums.sha256"
  expected_manifest="$(awk '/^manifest_sha256:/{print $2; exit}' "${manifest}")"
  [ "${expected_manifest}" = "$(manifest_digest "${domain}")" ] ||
    { echo "manifest checksum mismatch: ${domain}" >&2; exit 1; }
  case "${domain}" in
    keycloak) assert_domain_ownership "${domain}" false ;;
    *) assert_domain_ownership "${domain}" true ;;
  esac
  baseline_domain_ledger "${domain}" "${expected_manifest}" "${checksums}"
  echo "reconciling schema domain from migration ledger: ${domain}"
  manifest_paths "${manifest}" |
  while IFS= read -r relative; do
    case "${relative}" in
      ''|/*|*..*|*[!A-Za-z0-9_./-]*) echo "invalid manifest path: ${domain}/${relative}" >&2; exit 1;;
    esac
    sql_file="${schema_root}/${domain}/${relative}"
    expected="$(awk -v path="${relative}" '$2 == path {print $1}' "${checksums}")"
    [ -n "${expected}" ] || { echo "missing checksum: ${domain}/${relative}" >&2; exit 1; }
    [ "${expected}" = "$(sha256sum "${sql_file}" | awk '{print $1}')" ] ||
      { echo "checksum mismatch: ${domain}/${relative}" >&2; exit 1; }
    apply_tracked_file "${domain}" "${relative}" "${expected}" "${sql_file}"
  done
  domain_required_objects_exist "${domain}" || exit 1
  case "${domain}" in
    keycloak) assert_domain_ownership "${domain}" false ;;
    *) assert_domain_ownership "${domain}" true ;;
  esac
}

bootstrap_migration_ledger
extension_relative="00_extensions/001_runtime_extensions.sql"
extension_file="${schema_root}/${extension_relative}"
extension_checksum="$(awk -v path="001_runtime_extensions.sql" '$2 == path {print $1}' "${schema_root}/00_extensions/checksums.sha256")"
[ -n "${extension_checksum}" ] || { echo "missing checksum: ${extension_relative}" >&2; exit 1; }
[ "${extension_checksum}" = "$(sha256sum "${extension_file}" | awk '{print $1}')" ] ||
  { echo "checksum mismatch: ${extension_relative}" >&2; exit 1; }
apply_tracked_file global "${extension_relative}" "${extension_checksum}" "${extension_file}"
psql_run --tuples-only --no-align --command="
  SELECT EXISTS (
    SELECT 1 FROM pg_extension extension
    JOIN pg_namespace namespace ON namespace.oid = extension.extnamespace
    WHERE extension.extname = 'vector' AND namespace.nspname = 'public'
  )" | grep -qx t || { echo "pgvector extension must be installed in public" >&2; exit 1; }
for domain in octopus_core atheros_search schema_migrator keycloak; do apply_domain "${domain}"; done

psql_run --tuples-only --no-align --command="
  SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('octopus_core','atheros_search','schema_migrator')
    AND p.prokind IN ('f','p')" | grep -qx 0
psql_run --tuples-only --no-align --command="
  SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('octopus_core','atheros_search','schema_migrator')
    AND NOT t.tgisinternal" | grep -qx 0

for domain in octopus_core atheros_search schema_migrator keycloak; do
  case "${domain}" in
    octopus_core)
      sed -e "s/{{OCTOPUS_ACCOUNT}}/${octopus_account}/g" \
          -e "s/{{ATHEROS_SEARCH_ACCOUNT}}/${search_account}/g" \
          "${schema_root}/octopus_core/grants/least_privilege.sql.tmpl" | psql_run
      ;;
    atheros_search)
      sed -e "s/{{OCTOPUS_ACCOUNT}}/${octopus_account}/g" \
          -e "s/{{ATHEROS_SEARCH_ACCOUNT}}/${search_account}/g" \
          "${schema_root}/atheros_search/grants/least_privilege.sql.tmpl" | psql_run
      ;;
    schema_migrator)
      sed -e "s/{{SCHEMA_MIGRATOR_STATE_ACCOUNT}}/${migrator_account}/g" \
          "${schema_root}/schema_migrator/grants/least_privilege.sql.tmpl" | psql_run
      ;;
    keycloak)
      sed -e "s/{{KEYCLOAK_ACCOUNT}}/${keycloak_account}/g" \
          "${schema_root}/keycloak/grants/least_privilege.sql.tmpl" | psql_run
      ;;
  esac
done

# Transaction-pool clients must not depend on a one-time client connection
# initializer. Role defaults are applied whenever PgBouncer opens an upstream
# PostgreSQL session and remain correct when a transaction borrows a new one.
# The platform bootstrap normally owns these role defaults. Avoid requiring
# CREATEROLE on every reconciliation after the administrator has set them.
ensure_role_search_path "${octopus_account}" "octopus_core, atheros_search"
ensure_role_search_path "${search_account}" "atheros_search"
ensure_role_search_path "${migrator_account}" "schema_migrator"
ensure_role_search_path "${keycloak_account}" "keycloak"

for account in "${octopus_account}" "${search_account}"; do
  psql_run --tuples-only --no-align --command="
    SELECT has_schema_privilege('${account}', 'atheros_search', 'USAGE')
       AND has_schema_privilege('${account}', 'public', 'USAGE')
       AND has_type_privilege('${account}', 'public.vector', 'USAGE')" |
    grep -qx t || { echo "runtime role lacks schema/type usage: ${account}" >&2; exit 1; }
done

for account_domain in \
  "${octopus_account}:octopus_core" \
  "${octopus_account}:atheros_search" \
  "${search_account}:octopus_core" \
  "${search_account}:atheros_search" \
  "${migrator_account}:schema_migrator"; do
  account="${account_domain%%:*}"
  domain="${account_domain#*:}"
  psql_run --tuples-only --no-align --command="SELECT NOT has_schema_privilege('${account}', '${domain}', 'CREATE')" |
    grep -qx t || { echo "runtime role must not have CREATE on schema: ${account} ${domain}" >&2; exit 1; }
done

ath_version="$(awk '/^schema_version:/{print $2; exit}' "${schema_root}/atheros_search/manifest.yaml")"
ath_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/atheros_search/manifest.yaml")"
oct_version="$(awk '/^schema_version:/{print $2; exit}' "${schema_root}/octopus_core/manifest.yaml")"
oct_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/octopus_core/manifest.yaml")"
mig_version="$(awk '/^schema_version:/{print $2; exit}' "${schema_root}/schema_migrator/manifest.yaml")"
mig_sha="$(awk '/^manifest_sha256:/{print $2; exit}' "${schema_root}/schema_migrator/manifest.yaml")"

psql_run --command="UPDATE atheros_search.schema_readiness SET required_version='${ath_version}', applied_version='${ath_version}', required_checksum='${ath_sha}', applied_checksum='${ath_sha}', ready=true, checked_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE domain='atheros_search'"
psql_run --command="UPDATE octopus_core.schema_readiness SET required_version='${oct_version}', applied_version='${oct_version}', required_checksum='${oct_sha}', applied_checksum='${oct_sha}', ready=true, checked_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE domain='octopus_core'"
psql_run --command="INSERT INTO schema_migrator.state_schema_migrations(version,checksum,applied_at,applied_by) VALUES ('${mig_version}','${mig_sha}',CURRENT_TIMESTAMP,'postgres-runtime-schema') ON CONFLICT (version) DO UPDATE SET checksum=EXCLUDED.checksum, applied_at=EXCLUDED.applied_at, applied_by=EXCLUDED.applied_by"
psql_run --command="UPDATE schema_migrator.schema_readiness SET required_version='${mig_version}', applied_version='${mig_version}', required_checksum='${mig_sha}', applied_checksum='${mig_sha}', ready=true, checked_at=CURRENT_TIMESTAMP, details=jsonb_build_object('state','ready','executor','postgres-runtime-schema') WHERE domain='schema_migrator'"

echo "canonical PostgreSQL schemas applied and readiness recorded"
