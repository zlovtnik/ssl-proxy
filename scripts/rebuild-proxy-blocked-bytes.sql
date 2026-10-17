-- Run with psql after proxy.events jobs have drained. This rebuilds the
-- per-retained-event blocked attempt estimate, not saved bandwidth.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';
LOCK TABLE octopus_core.proxy_events, octopus_core.proxy_blocked_host_rollups
  IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM octopus_core.sync_jobs
    WHERE stream_name = 'proxy.events' AND status <> 'completed'
  ) THEN
    RAISE EXCEPTION 'proxy.events jobs have not drained';
  END IF;
  IF EXISTS (
    WITH retained AS (
      SELECT host, count(*) AS attempts
      FROM octopus_core.proxy_events
      WHERE blocked
      GROUP BY host
    )
    SELECT 1
    FROM octopus_core.proxy_blocked_host_rollups AS rollup
    FULL OUTER JOIN retained USING (host)
    WHERE rollup.blocked_attempts IS DISTINCT FROM retained.attempts
  ) THEN
    RAISE EXCEPTION 'retained blocked events do not cover the rollups';
  END IF;
END $$;

WITH retained AS (
  SELECT host,
    sum(CASE
      WHEN (payload ->> 'blocked_bytes_delta_approx') ~ '^[0-9]{1,18}$'
        THEN (payload ->> 'blocked_bytes_delta_approx')::bigint
      WHEN (payload #>> '{metrics,blocked_bytes_delta_approx}') ~ '^[0-9]{1,18}$'
        THEN (payload #>> '{metrics,blocked_bytes_delta_approx}')::bigint
      WHEN event_type IN ('block', 'session.blocked')
        THEN 50 + octet_length(host)
      ELSE 0
    END) AS blocked_bytes
  FROM octopus_core.proxy_events
  WHERE blocked
  GROUP BY host
)
UPDATE octopus_core.proxy_blocked_host_rollups AS rollup
SET blocked_bytes = retained.blocked_bytes
FROM retained
WHERE rollup.host = retained.host
  AND rollup.blocked_bytes IS DISTINCT FROM retained.blocked_bytes;

COMMIT;
