#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly postgres_image="pgvector/pgvector:0.8.6-pg16-bookworm@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b"
readonly test_id="schema-executor-$PPID-$$"
readonly network_name="${test_id}-network"
readonly database_container="${test_id}-postgres"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/ssl-proxy-schema-executor.XXXXXX")"

cleanup() {
  docker rm -f "${database_container}" >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  rm -rf "${test_dir}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${test_dir}/bin"
printf '%s\n' '#!/bin/sh' 'PGSSLMODE=disable exec /usr/bin/psql "$@"' >"${test_dir}/bin/psql"
chmod 0555 "${test_dir}/bin/psql"
printf '%s\n' 'integration-test-placeholder' >"${test_dir}/ca.crt"
chmod 0444 "${test_dir}/ca.crt"

docker network create "${network_name}" >/dev/null
docker run --detach --name "${database_container}" --network "${network_name}" \
  --env POSTGRES_PASSWORD=integration-admin \
  --env POSTGRES_DB=sync \
  "${postgres_image}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${database_container}" pg_isready --username postgres --dbname sync >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${database_container}" pg_isready --username postgres --dbname sync >/dev/null

docker exec --interactive "${database_container}" psql \
  --username postgres --dbname sync --set=ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION pgcrypto;
CREATE EXTENSION vector;
CREATE EXTENSION pg_stat_statements;
CREATE ROLE schema_owner LOGIN PASSWORD 'integration-schema-owner' CREATEROLE;
CREATE ROLE octopus_runtime LOGIN;
CREATE ROLE atheros_search_runtime LOGIN;
CREATE ROLE schema_migrator_runtime LOGIN;
CREATE ROLE keycloak_runtime LOGIN;
GRANT CREATE ON DATABASE sync TO schema_owner;
SQL

run_executor() {
  docker run --rm --network "${network_name}" \
    --user 65532:65532 \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=67108864 \
    --env PATH=/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --env POSTGRES_HOST="${database_container}" \
    --env POSTGRES_PORT=5432 \
    --env POSTGRES_DATABASE=sync \
    --env POSTGRES_SCHEMA_OWNER_USER=schema_owner \
    --env POSTGRES_SCHEMA_OWNER_PASSWORD=integration-schema-owner \
    --env POSTGRES_OCTOPUS_ACCOUNT=octopus_runtime \
    --env POSTGRES_ATHEROS_SEARCH_ACCOUNT=atheros_search_runtime \
    --env POSTGRES_SCHEMA_MIGRATOR_ACCOUNT=schema_migrator_runtime \
    --env POSTGRES_KEYCLOAK_ACCOUNT=keycloak_runtime \
    --env PGSSLMODE=verify-full \
    --env POSTGRES_SSL_SERVER_NAME="${database_container}" \
    --env PGSSLROOTCERT=/test-ca/ca.crt \
    --volume "${repo_root}:/workspace:ro" \
    --volume "${test_dir}/bin:/test-bin:ro" \
    --volume "${test_dir}:/test-ca:ro" \
    --entrypoint /workspace/k8s/postgres-schema-executor/entrypoint.sh \
    "${postgres_image}"
}

run_executor
first_count="$(docker exec "${database_container}" psql --username postgres --dbname sync --tuples-only --no-align \
  --command="SELECT count(*) FROM schema_migrator.state_schema_migrations WHERE version LIKE 'runtime/%'")"
[ "${first_count}" -gt 0 ]

second_output="$(run_executor 2>&1)"
printf '%s\n' "${second_output}" | grep -q "migration already applied: runtime/atheros_search/01_tables/011_identity_graph.sql"
second_count="$(docker exec "${database_container}" psql --username postgres --dbname sync --tuples-only --no-align \
  --command="SELECT count(*) FROM schema_migrator.state_schema_migrations WHERE version LIKE 'runtime/%'")"
[ "${second_count}" = "${first_count}" ]

docker exec "${database_container}" psql --username postgres --dbname sync --set=ON_ERROR_STOP=1 \
  --command="UPDATE schema_migrator.state_schema_migrations SET checksum = repeat('0', 64) WHERE version = 'runtime/global/00_extensions/001_runtime_extensions.sql'" >/dev/null
set +e
checksum_output="$(run_executor 2>&1)"
checksum_status=$?
set -e
if [ "${checksum_status}" -eq 0 ]; then
  echo "executor accepted a changed checksum for an applied migration" >&2
  exit 1
fi
[ "${checksum_status}" -eq 3 ] || {
  echo "checksum drift exited ${checksum_status}, expected 3" >&2
  printf '%s\n' "${checksum_output}" >&2
  exit 1
}
printf '%s\n' "${checksum_output}" | grep -q "migration checksum drift"
docker exec "${database_container}" psql --username postgres --dbname sync --set=ON_ERROR_STOP=1 \
  --command="UPDATE schema_migrator.state_schema_migrations SET checksum = 'b823aa4ad731c1284f02cb38a617b834590ece5327a17525bf6362a9953189bd' WHERE version = 'runtime/global/00_extensions/001_runtime_extensions.sql'" >/dev/null

docker exec "${database_container}" psql --username postgres --dbname sync --set=ON_ERROR_STOP=1 \
  --command="ALTER TABLE atheros_search.merge_candidates OWNER TO octopus_runtime" >/dev/null
if ownership_output="$(run_executor 2>&1)"; then
  echo "executor accepted a canonical table owned by a runtime role" >&2
  exit 1
fi
printf '%s\n' "${ownership_output}" | grep -q "table atheros_search.merge_candidates is owned by octopus_runtime, expected schema_owner"

echo "PostgreSQL schema executor ledger, replay, checksum, and ownership checks passed"
