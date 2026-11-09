#!/bin/sh
set -eu

# Reuse platform account creation; only the local bootstrap adds role defaults.
/bin/sh /usr/local/share/local-init/010-runtime-roles.sh

export PGPASSWORD="$(tr -d '\r\n' </run/platform-secrets/platform_admin.password)"
psql --no-psqlrc --set=ON_ERROR_STOP=1 \
  --username="${POSTGRES_USER}" --dbname="${POSTGRES_DB}" <<'SQL'
ALTER ROLE octopus_runtime IN DATABASE sync SET search_path TO octopus_core, atheros_search;
ALTER ROLE atheros_search_runtime IN DATABASE sync SET search_path TO atheros_search;
ALTER ROLE schema_migrator_runtime IN DATABASE sync SET search_path TO schema_migrator;
ALTER ROLE keycloak_runtime IN DATABASE sync SET search_path TO keycloak;
SQL
touch "${PGDATA}/local-bootstrap-complete"
