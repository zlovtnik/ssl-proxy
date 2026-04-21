#!/usr/bin/env sh
set -eu

STREAM_NAME="${AUDIT_STREAM_NAME:-AUDIT_STREAM}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
DATABASE_URL="${DATABASE_URL:-postgres://sync:sync@postgres:5432/sync}"

echo "== compose services =="
docker compose ps nats postgres nats-bootstrap zig-coordinator atheros-sensor

echo
echo "== nats jetstream =="
docker compose exec -T nats wget -qO- http://127.0.0.1:8222/jsz || true

echo
echo "== nats stream =="
docker compose run --rm nats-bootstrap nats --server "${SYNC_NATS_URL:-nats://nats:4222}" stream info "${STREAM_NAME}" || true

echo
echo "== nats scan consumer =="
docker compose run --rm nats-bootstrap nats --server "${SYNC_NATS_URL:-nats://nats:4222}" consumer info "${STREAM_NAME}" "${SCAN_CONSUMER}" || true

echo
echo "== postgres sync counts =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select 'sync_scan_ingest' table_name, count(*) from sync_scan_ingest
union all select 'sync_cursor', count(*) from sync_cursor
union all select 'sync_job', count(*) from sync_job
union all select 'sync_batch', count(*) from sync_batch
union all select 'sync_error', count(*) from sync_error
union all select 'audit_backlog', count(*) from audit_backlog
order by table_name;
"

echo
echo "== recent ingest =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select observed_at, stream_name, status, producer, event_kind, left(dedupe_key, 16) as dedupe
from sync_scan_ingest
order by updated_at desc
limit 10;
"
