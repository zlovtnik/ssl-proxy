#!/bin/sh
set -eu

secret_dir=/run/platform-secrets
umask 077

read_secret() {
  file="$secret_dir/$1.password"
  [ -r "$file" ] || { echo "missing bootstrap secret: $file" >&2; exit 1; }
  value=$(tr -d '\r\n' <"$file")
  [ -n "$value" ] || { echo "empty bootstrap secret: $file" >&2; exit 1; }
  printf '%s' "$value"
}

export PGPASSWORD="$(read_secret platform_admin)"
export SCHEMA_OWNER_PASSWORD="$(read_secret schema_owner)"
export OCTOPUS_RUNTIME_PASSWORD="$(read_secret octopus_runtime)"
export ATHEROS_SEARCH_RUNTIME_PASSWORD="$(read_secret atheros_search_runtime)"
export SCHEMA_MIGRATOR_RUNTIME_PASSWORD="$(read_secret schema_migrator_runtime)"
export KEYCLOAK_RUNTIME_PASSWORD="$(read_secret keycloak_runtime)"

psql --no-psqlrc --set=ON_ERROR_STOP=1 --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" <<'SQL'
\getenv schema_owner_password SCHEMA_OWNER_PASSWORD
\getenv octopus_runtime_password OCTOPUS_RUNTIME_PASSWORD
\getenv atheros_search_runtime_password ATHEROS_SEARCH_RUNTIME_PASSWORD
\getenv schema_migrator_runtime_password SCHEMA_MIGRATOR_RUNTIME_PASSWORD
\getenv keycloak_runtime_password KEYCLOAK_RUNTIME_PASSWORD

CREATE ROLE schema_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'schema_owner_password';
CREATE ROLE octopus_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'octopus_runtime_password';
CREATE ROLE atheros_search_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'atheros_search_runtime_password';
CREATE ROLE schema_migrator_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'schema_migrator_runtime_password';
CREATE ROLE keycloak_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'keycloak_runtime_password';

REVOKE ALL ON DATABASE sync FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE sync TO schema_owner;
GRANT CONNECT ON DATABASE sync TO octopus_runtime, atheros_search_runtime, schema_migrator_runtime, keycloak_runtime;
SQL
