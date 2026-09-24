#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only PostgreSQL size and bloat report for the sync database.
#
# Modes:
#   docker (default)  docker exec into the platform PostgreSQL container
#   local             any psql reachable through PGHOST/PGPORT/PGUSER/PGDATABASE
#
# Usage: ops/sql/pg-size-report.sh
# Writes: <output dir>/pg-growth.csv (one row per run) next to the text report.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
report_sql="$repo_root/ops/sql/pg-size-report.sql"
output_dir="${AUDIT_OUTPUT_DIR:-$repo_root/ops/disk/snapshots}"
growth_csv="$output_dir/pg-growth.csv"
container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
psql_user="${PGUSER:-platform_admin}"
psql_db="${PGDATABASE:-sync}"

mkdir -p "$output_dir"

run_psql() {
  if [ -n "${PGHOST:-}" ] && command -v psql >/dev/null 2>&1; then
    psql -X -q --pset pager=off -v ON_ERROR_STOP=1 -U "$psql_user" -d "$psql_db" "$@"
  elif command -v docker >/dev/null 2>&1 &&
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$container"; then
    # The local socket requires SCRAM and psql has no tty under docker exec,
    # so export the password inside the container from its own secret file;
    # stdin stays reserved for the SQL.
    docker exec -i "$container" sh -eu -c \
      'PGPASSWORD=$(tr -d "\r\n" </run/platform-secrets/platform_admin.password); export PGPASSWORD; user=$1; database=$2; shift 2; exec psql -X -q --pset pager=off -v ON_ERROR_STOP=1 -U "$user" -d "$database" "$@"' \
      psql-wrap "$psql_user" "$psql_db" "$@"
  elif command -v docker >/dev/null 2>&1; then
    printf 'pg-size-report: container %s is not reachable; start it or set PGHOST with a local psql\n' "$container" >&2
    exit 1
  else
    printf 'pg-size-report: neither psql nor docker is available\n' >&2
    exit 1
  fi
}

printf 'report generated %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_psql -f - <"$report_sql"

if [ ! -f "$growth_csv" ]; then
  printf 'timestamp,database,bytes\n' >"$growth_csv"
fi
run_psql -At -c "SELECT current_database() || ',' || pg_database_size(current_database())" |
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    printf '%s,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$row" >>"$growth_csv"
  done
printf 'growth samples appended to %s\n' "$growth_csv"
