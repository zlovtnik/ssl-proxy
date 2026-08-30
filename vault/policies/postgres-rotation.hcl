# Narrow operator policy for coordinated PostgreSQL password rotation.

path "secret/data/ssl-proxy/prod/postgres-atheros-search" {
  capabilities = ["read", "update", "patch"]
}

path "secret/data/ssl-proxy/prod/postgres-keycloak" {
  capabilities = ["read", "update", "patch"]
}

path "secret/data/ssl-proxy/prod/postgres-octopus" {
  capabilities = ["read", "update", "patch"]
}

path "secret/data/ssl-proxy/prod/postgres-schema-migrator" {
  capabilities = ["read", "update", "patch"]
}

path "secret/data/ssl-proxy/prod/postgres-schema-owner" {
  capabilities = ["read", "update", "patch"]
}

path "secret/data/ssl-proxy/prod/pgbouncer-runtime-users" {
  capabilities = ["read", "update", "patch"]
}

path "secret/metadata/ssl-proxy/prod/postgres-*" {
  capabilities = ["read"]
}

path "secret/metadata/ssl-proxy/prod/pgbouncer-runtime-users" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
