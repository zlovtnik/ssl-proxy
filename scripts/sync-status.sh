#!/usr/bin/env sh
set -eu

SCAN_TOPIC="${SYNC_SCAN_TOPIC:-sync.scan.request}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
DATABASE_URL="${DATABASE_URL:-postgres://sync:sync@postgres:5432/sync}"
REDPANDA_BROKERS="${SYNC_REDPANDA_BOOTSTRAP_SERVERS:-redpanda:9092}"
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-ssl-proxy}"
REDPANDA_IMAGE="${REDPANDA_IMAGE:-redpandadata/redpanda:latest}"

echo "== compose services =="
docker compose ps redpanda postgres redpanda-init zig-coordinator atheros-sensor

echo
echo "== redpanda cluster =="
docker run --rm --network "${COMPOSE_PROJECT}_default" --entrypoint rpk "${REDPANDA_IMAGE}" cluster info --brokers "${REDPANDA_BROKERS}" || true

echo
echo "== redpanda topics =="
docker run --rm --network "${COMPOSE_PROJECT}_default" --entrypoint rpk "${REDPANDA_IMAGE}" topic list --brokers "${REDPANDA_BROKERS}" || true

echo
echo "== redpanda scan topic =="
docker run --rm --network "${COMPOSE_PROJECT}_default" --entrypoint rpk "${REDPANDA_IMAGE}" topic describe "${SCAN_TOPIC}" --brokers "${REDPANDA_BROKERS}" || true

echo
echo "== redpanda scan consumer group =="
docker run --rm --network "${COMPOSE_PROJECT}_default" --entrypoint rpk "${REDPANDA_IMAGE}" group describe "${SCAN_CONSUMER}" --brokers "${REDPANDA_BROKERS}" || true

echo
echo "== postgres sync counts =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select 'sync_events' table_name, count(*) from sync_events
union all select 'sync_cursors', count(*) from sync_cursors
union all select 'sync_jobs', count(*) from sync_jobs
union all select 'sync_batches', count(*) from sync_batches
union all select 'sync_errors', count(*) from sync_errors
union all select 'sync_backlog', count(*) from sync_backlog
order by table_name;
" || true

echo
echo "== recent ingest =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select observed_at, stream_name, status, producer, event_kind, left(dedupe_key, 16) as dedupe
from sync_events
order by updated_at desc
limit 10;
" || true

echo
echo "== wireless audit counts (last 24h) =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select
  status,
  stream_name,
  count(*),
  min(observed_at) as oldest,
  max(observed_at) as newest
from sync_events
where stream_name = 'wireless.audit'
  and observed_at >= now() - interval '24 hours'
group by status, stream_name
order by status;
" || true

echo
echo "== wireless audit threat detections =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select
  payload->>'ssid' as ssid,
  payload->>'source_mac' as source_mac,
  payload->'tags' as threat_tags,
  observed_at
from sync_events
where stream_name = 'wireless.audit'
  and payload::text like '%threat:%'
order by observed_at desc
limit 20;
" || true
