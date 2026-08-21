#!/bin/sh
set -eu

tidb_host="${TIDB_HOST:?TIDB_HOST is required}"
tidb_port="${TIDB_PORT:-4000}"
root_password="${TIDB_ROOT_PASSWORD:?TIDB_ROOT_PASSWORD is required}"
schema_owner_password="${TIDB_SCHEMA_OWNER_PASSWORD:?TIDB_SCHEMA_OWNER_PASSWORD is required}"
octopus_password="${TIDB_OCTOPUS_PASSWORD:?TIDB_OCTOPUS_PASSWORD is required}"
atheros_search_password="${TIDB_ATHEROS_SEARCH_PASSWORD:?TIDB_ATHEROS_SEARCH_PASSWORD is required}"
schema_migrator_password="${TIDB_SCHEMA_MIGRATOR_PASSWORD:?TIDB_SCHEMA_MIGRATOR_PASSWORD is required}"
keycloak_password="${TIDB_KEYCLOAK_PASSWORD:?TIDB_KEYCLOAK_PASSWORD is required}"
allow_empty_root="${TIDB_ALLOW_EMPTY_ROOT_BOOTSTRAP:-false}"

case "${tidb_port}" in
  *[!0-9]*|'') echo "TIDB_PORT must be numeric" >&2; exit 2 ;;
esac
if [ "${tidb_port}" -lt 1 ] || [ "${tidb_port}" -gt 65535 ]; then
  echo "TIDB_PORT must be between 1 and 65535" >&2
  exit 2
fi
case "${allow_empty_root}" in
  true|false) ;;
  *) echo "TIDB_ALLOW_EMPTY_ROOT_BOOTSTRAP must be true or false" >&2; exit 2 ;;
esac

mysql_root() {
  MYSQL_PWD="${root_password}" mysql \
    --protocol=TCP \
    --ssl-mode=DISABLED \
    --connect-timeout=5 \
    --host="${tidb_host}" \
    --port="${tidb_port}" \
    --user=root \
    "$@"
}

mysql_blank_root() {
  env -u MYSQL_PWD mysql \
    --protocol=TCP \
    --ssl-mode=DISABLED \
    --connect-timeout=5 \
    --host="${tidb_host}" \
    --port="${tidb_port}" \
    --user=root \
    "$@"
}

sql_password_literal() {
  # Escape backslashes first, then quotes. The result is used only in a
  # single-quoted MySQL string in a mode where backslash escapes are enabled.
  printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/''/g"
}

echo "Waiting for TiDB at ${tidb_host}:${tidb_port}..."
attempt=0
while ! mysql_root --batch --skip-column-names -e "SELECT 1" >/dev/null 2>&1 && \
  ! { [ "${allow_empty_root}" = true ] && mysql_blank_root --batch --skip-column-names -e "SELECT 1" >/dev/null 2>&1; }; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 60 ]; then
    break
  fi
  sleep 2
done

if mysql_root --batch --skip-column-names -e "SELECT 1" >/dev/null 2>&1; then
  echo "Authenticated with the configured root credential."
elif [ "${allow_empty_root}" = true ] && \
  mysql_blank_root --batch --skip-column-names -e "SELECT 1" >/dev/null 2>&1; then
  application_databases="$(mysql_blank_root --batch --skip-column-names -e "
    SELECT COUNT(*)
    FROM information_schema.schemata
    WHERE schema_name NOT IN ('INFORMATION_SCHEMA','METRICS_SCHEMA','PERFORMANCE_SCHEMA','mysql','sys','test');
  ")"
  non_root_accounts="$(mysql_blank_root --batch --skip-column-names -e "
    SELECT COUNT(*) FROM mysql.user WHERE User <> 'root';
  ")"
  if [ "${application_databases}" -ne 0 ] || [ "${non_root_accounts}" -ne 0 ]; then
    echo "refusing blank-root adoption because TiDB is not empty" >&2
    exit 1
  fi

  root_literal="$(sql_password_literal "${root_password}")"
  mysql_blank_root -e "ALTER USER 'root'@'%' IDENTIFIED BY '${root_literal}';"
  unset root_literal
  if ! mysql_root --batch --skip-column-names -e "SELECT 1" >/dev/null 2>&1; then
    echo "root credential rotation did not take effect" >&2
    exit 1
  fi
  echo "Adopted the empty TiDB instance and rotated the root credential."
else
  echo "cannot authenticate with the configured root credential; blank-root adoption is unavailable or unsafe" >&2
  exit 1
fi

mysql_root -e "
  CREATE DATABASE IF NOT EXISTS octopus_core CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE DATABASE IF NOT EXISTS atheros_search CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE DATABASE IF NOT EXISTS integration_console CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE DATABASE IF NOT EXISTS schema_migrator CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE DATABASE IF NOT EXISTS keycloak CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
"

create_or_update_account() {
  account="$1"
  password="$2"
  case "${account}" in
    *[!A-Za-z0-9_]*|'') echo "invalid TiDB account name" >&2; exit 2 ;;
  esac
  password_literal="$(sql_password_literal "${password}")"
  mysql_root -e "
    CREATE USER IF NOT EXISTS '${account}'@'%' IDENTIFIED BY '${password_literal}';
    ALTER USER '${account}'@'%' IDENTIFIED BY '${password_literal}';
  "
  unset password_literal
}

create_or_update_account schema_owner "${schema_owner_password}"
create_or_update_account octopus_runtime "${octopus_password}"
create_or_update_account atheros_search_runtime "${atheros_search_password}"
create_or_update_account schema_migrator_runtime "${schema_migrator_password}"
create_or_update_account keycloak "${keycloak_password}"

# schema_owner applies canonical DDL and the checked-in least-privilege grant
# fixtures. Runtime accounts receive only temporary database-level grants;
# the schema executor narrows them after the tables exist.
mysql_root -e "
  GRANT ALL PRIVILEGES ON octopus_core.* TO 'schema_owner'@'%' WITH GRANT OPTION;
  GRANT ALL PRIVILEGES ON atheros_search.* TO 'schema_owner'@'%' WITH GRANT OPTION;
  GRANT ALL PRIVILEGES ON integration_console.* TO 'schema_owner'@'%' WITH GRANT OPTION;
  GRANT ALL PRIVILEGES ON schema_migrator.* TO 'schema_owner'@'%' WITH GRANT OPTION;
  GRANT ALL PRIVILEGES ON octopus_core.* TO 'octopus_runtime'@'%';
  GRANT ALL PRIVILEGES ON atheros_search.* TO 'octopus_runtime'@'%';
  GRANT ALL PRIVILEGES ON atheros_search.* TO 'atheros_search_runtime'@'%';
  GRANT SELECT ON octopus_core.* TO 'atheros_search_runtime'@'%';
  GRANT ALL PRIVILEGES ON schema_migrator.* TO 'schema_migrator_runtime'@'%';
  GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'%';
"

mysql_root --batch --skip-column-names -e "
  SELECT User, Host
  FROM mysql.user
  WHERE User IN ('schema_owner','octopus_runtime','atheros_search_runtime','schema_migrator_runtime','keycloak')
  ORDER BY User, Host;
"
echo "TiDB databases and account credentials are reconciled."
