#!/usr/bin/env bash
set -Eeuo pipefail

# Gated reclaim of PostgreSQL bloat. The default mode is read-only and only
# reports what a reclaim would do. Applying requires an exact confirmation
# token and enough free disk for a copy of the target table.
#
# pg_repack is not part of the tracked extension set, so an online repack is
# only attempted when the running database actually has the extension. The
# fallback uses VACUUM (FULL), which takes an exclusive lock and still needs
# free space equal to the table size: run it only when the cluster is idle.
#
# Usage:
#   ops/sql/pg-repack.sh                       # plan
#   ops/sql/pg-repack.sh --apply --table octopus_core.sync_events \
#       --confirm REPACK-TABLE [--vacuum-full]

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
container="${POSTGRES_CONTAINER:-ssl-proxy-platform-postgres}"
psql_user="${PGUSER:-platform_admin}"
psql_db="${PGDATABASE:-sync}"
min_free_bytes="${MIN_FREE_BYTES:-2147483648}"

table=""
apply=0
vacuum_full=0
confirm=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    --vacuum-full) vacuum_full=1 ;;
    --table) table="${2:-}"; shift ;;
    --confirm) confirm="${2:-}"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) printf 'pg-repack: unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
  shift
done

run_psql() {
  if [ -n "${PGHOST:-}" ] && command -v psql >/dev/null 2>&1; then
    psql -X -q --pset pager=off -v ON_ERROR_STOP=1 -U "$psql_user" -d "$psql_db" "$@"
  elif command -v docker >/dev/null 2>&1 &&
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$container"; then
    docker exec -i "$container" psql -X -q --pset pager=off \
      -v ON_ERROR_STOP=1 -U "$psql_user" -d "$psql_db" "$@"
  elif command -v docker >/dev/null 2>&1; then
    printf 'pg-repack: container %s is not reachable; start it or set PGHOST with a local psql\n' "$container" >&2
    exit 1
  else
    printf 'pg-repack: neither psql nor docker is available\n' >&2
    exit 1
  fi
}

scalar() {
  run_psql -At -c "$1"
}

has_pg_repack() {
  [ "$(scalar "SELECT count(*) FROM pg_extension WHERE extname = 'pg_repack'")" = "1" ]
}

if ! has_pg_repack; then
  printf 'plan: pg_repack is not installed; only --vacuum-full is available\n'
fi

printf 'plan: candidate relations (dead tuples and size)\n'
run_psql -f - <"$repo_root/ops/sql/pg-size-report.sql"

printf 'plan: free space next to the data directory\n'
if [ -n "${PGHOST:-}" ] && command -v psql >/dev/null 2>&1; then
  printf 'plan: local mode - check the data directory volume yourself\n'
else
  docker exec "$container" df -B1 /var/lib/postgresql/data || true
fi

if [ "$apply" -eq 0 ]; then
  printf 'plan: nothing was changed; pass --apply --table <schema.table> --confirm REPACK-TABLE\n'
  exit 0
fi

if [ -z "$table" ] || [ "$confirm" != "REPACK-TABLE" ]; then
  printf 'pg-repack: --table <schema.table> and --confirm REPACK-TABLE are required\n' >&2
  exit 1
fi
if ! printf '%s' "$table" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$'; then
  printf 'pg-repack: invalid identifier: %s\n' "$table" >&2
  exit 1
fi

schema="${table%%.*}"
relation="${table##*.}"
exists="$(scalar "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '$schema' AND c.relname = '$relation'")"
if [ "$exists" != "1" ]; then
  printf 'pg-repack: no such relation: %s\n' "$table" >&2
  exit 1
fi

size_bytes="$(scalar "SELECT pg_total_relation_size('$schema.$relation'::regclass)")"
printf 'pg-repack: %s is %s bytes\n' "$table" "$size_bytes"

if has_pg_repack; then
  printf 'pg-repack: repacking %s online\n' "$table"
  run_psql -c "SELECT pg_repack.repack_table('$schema.$relation'::regclass)"
  exit 0
fi

if [ "$vacuum_full" -eq 0 ]; then
  printf 'pg-repack: pg_repack is unavailable; re-run with --vacuum-full to accept an exclusive lock\n' >&2
  exit 1
fi

free_bytes="$(docker exec "$container" df -B1 /var/lib/postgresql/data | awk 'NR == 2 { print $4 }')"
case "$free_bytes" in ''|*[!0-9]*)
  printf 'pg-repack: could not read free space\n' >&2
  exit 1 ;;
esac
if [ "$free_bytes" -lt "$size_bytes" ] || [ "$free_bytes" -lt "$min_free_bytes" ]; then
  printf 'pg-repack: free bytes %s < table %s (or < %s): reclaim disk first\n' \
    "$free_bytes" "$size_bytes" "$min_free_bytes" >&2
  exit 1
fi

printf 'pg-repack: running VACUUM (FULL, FREEZE) on %s with an exclusive lock\n' "$table"
run_psql -c "VACUUM (FULL, FREEZE) \"$schema\".\"$relation\""
printf 'pg-repack: verify with ops/sql/pg-size-report.sh\n'
