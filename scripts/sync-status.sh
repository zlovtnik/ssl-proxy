#!/usr/bin/env sh
set -eu

SCAN_TOPIC="${SYNC_SCAN_TOPIC:-sync.scan.request}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
if [ -z "${DATABASE_URL:-}" ]; then
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required when DATABASE_URL is unset}"
    DATABASE_URL="postgres://sync:${POSTGRES_PASSWORD}@postgres:5432/sync"
fi
REDPANDA_BROKERS="${SYNC_REDPANDA_BOOTSTRAP_SERVERS:-redpanda:9092}"
COMPOSE_PROJECT="${COMPOSE_PROJECT_NAME:-ssl-proxy}"
REDPANDA_IMAGE="${REDPANDA_IMAGE:-redpandadata/redpanda:latest}"

echo "== compose services =="
docker compose ps redpanda postgres redpanda-init java-coordinator java-coordinator-2 java-coordinator-3 atheros-sensor

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
  coalesce(ssid, payload->>'ssid') as ssid,
  coalesce(source_mac, payload->>'source_mac') as source_mac,
  case
    when tags is not null and tags <> '[]'::jsonb then tags
    when jsonb_typeof(payload->'tags') = 'array' then payload->'tags'
    else '[]'::jsonb
  end as threat_tags,
  payload_archived,
  payload_archive_uri,
  observed_at
from sync_events_expanded
where stream_name = 'wireless.audit'
  and (
    coalesce(handshake_captured, false)
    or exists (
      select 1
      from jsonb_array_elements_text(
        case
          when tags is not null and tags <> '[]'::jsonb then tags
          when jsonb_typeof(payload->'tags') = 'array' then payload->'tags'
          else '[]'::jsonb
        end
      ) tag(value)
      where tag.value like 'threat:%'
    )
  )
order by observed_at desc
limit 20;
" || true

echo
echo "== postgres retention health =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select
  hot_payload_count,
  pg_size_pretty(hot_payload_bytes) as hot_payload_size,
  unarchived_payload_count,
  oldest_unarchived_payload_at,
  archive_lag_seconds,
  archived_payload_count,
  pg_size_pretty(archived_payload_bytes) as archived_payload_size,
  tombstone_count,
  expired_tombstone_count,
  vector_rows_by_kind
from v_postgres_storage_health;
" || true

echo
echo "== postgres relation storage =="
docker compose exec -T postgres psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -c "
select
  relname as relation,
  pg_size_pretty(pg_total_relation_size(relid)) as total_size,
  pg_size_pretty(pg_relation_size(relid)) as table_size,
  pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) as index_size,
  n_live_tup as live_tuples,
  n_dead_tup as dead_tuples,
  round(
    case when n_live_tup + n_dead_tup > 0
      then n_dead_tup::numeric / nullif(n_live_tup + n_dead_tup, 0)
      else 0::numeric
    end,
    4
  ) as dead_tuple_ratio,
  last_autovacuum
from pg_stat_user_tables
where relname in (
  'sync_events',
  'wireless_frames',
  'sync_event_payload_archives',
  'sync_event_tombstones',
  'vec_embeddings',
  'vec_embedding_jobs',
  'vec_similarity_pairs'
)
order by pg_total_relation_size(relid) desc;
" || true
