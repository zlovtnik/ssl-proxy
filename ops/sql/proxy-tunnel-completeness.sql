-- psql -v window_start=2026-10-12T00:00:00Z \
--      -v window_end=2026-10-13T00:00:00Z \
--      -f ops/sql/proxy-tunnel-completeness.sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH bounds AS (
  SELECT :'window_start'::timestamptz AS window_start,
         :'window_end'::timestamptz AS window_end
),
pipeline AS (
  SELECT count(*) FILTER (WHERE status <> 'completed') AS unfinished_jobs
  FROM octopus_core.sync_jobs
  WHERE stream_name = 'proxy.events'
),
retained AS (
  SELECT min(event_time) AS first_event, max(event_time) AS last_event
  FROM octopus_core.proxy_events
),
sessions AS (
  SELECT correlation_id,
         count(*) FILTER (WHERE event_type = 'tunnel_open') AS opens,
         count(*) FILTER (WHERE event_type = 'tunnel_close') AS closes,
         min(event_time) FILTER (WHERE event_type = 'tunnel_open') AS opened_at,
         min(event_time) FILTER (WHERE event_type = 'tunnel_close') AS closed_at
  FROM octopus_core.proxy_events
  WHERE correlation_id IS NOT NULL
    AND event_type IN ('tunnel_open', 'tunnel_close')
  GROUP BY correlation_id
),
session_counts AS (
  SELECT count(*) FILTER (WHERE opens = 1 AND closes = 1) AS complete,
         count(*) FILTER (WHERE opens = 1 AND closes = 0) AS open_only,
         count(*) FILTER (WHERE opens = 0 AND closes = 1) AS close_only,
         count(*) FILTER (WHERE opens > 1 OR closes > 1) AS duplicate_lifecycle
  FROM sessions
  CROSS JOIN bounds
  WHERE coalesce(opened_at, closed_at) >= bounds.window_start
    AND coalesce(opened_at, closed_at) < bounds.window_end
)
SELECT bounds.window_start,
       bounds.window_end,
       retained.first_event,
       retained.last_event,
       pipeline.unfinished_jobs,
       session_counts.complete,
       session_counts.open_only,
       session_counts.close_only,
       session_counts.duplicate_lifecycle
FROM session_counts
CROSS JOIN bounds
CROSS JOIN pipeline
CROSS JOIN retained;
ROLLBACK;
