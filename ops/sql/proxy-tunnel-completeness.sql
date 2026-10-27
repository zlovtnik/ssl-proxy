-- Required: window_start, window_end, horizon_start, horizon_end,
-- after_time, after_id, page_size, counterpart_limit, statement_timeout_ms.
-- Correlation IDs are pair candidates, not validated flow identities.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('statement_timeout', :'statement_timeout_ms', true) AS timeout_setting \gset
SET LOCAL lock_timeout = '1s';
WITH seeds AS MATERIALIZED (
  SELECT event_id, event_time, event_type, correlation_id
  FROM octopus_core.proxy_events
  WHERE event_time >= :'window_start'::timestamptz AND event_time < :'window_end'::timestamptz
    AND (event_time, event_id) > (:'after_time'::timestamptz, :'after_id')
    AND event_type IN ('tunnel_open', 'tunnel_close')
  ORDER BY event_time, event_id LIMIT :page_size
), candidates AS MATERIALIZED (
  SELECT DISTINCT correlation_id FROM seeds WHERE correlation_id ~ '[^[:space:]]'
    AND :'horizon_start'::timestamptz <= :'window_start'::timestamptz
    AND :'horizon_end'::timestamptz >= :'window_end'::timestamptz
), evidence AS (
  SELECT c.correlation_id, e.* FROM candidates c
  CROSS JOIN LATERAL (
    SELECT event_type, event_time FROM octopus_core.proxy_events p
    WHERE p.event_time >= :'horizon_start'::timestamptz AND p.event_time < :'horizon_end'::timestamptz
      AND p.correlation_id = c.correlation_id AND p.event_type IN ('tunnel_open','tunnel_close')
    ORDER BY p.event_time, p.event_id LIMIT :counterpart_limit
  ) e
), sessions AS (
  SELECT correlation_id, count(*) AS evidence_rows,
    count(*) FILTER (WHERE event_type = 'tunnel_open') AS opens,
    count(*) FILTER (WHERE event_type = 'tunnel_close') AS closes,
    min(event_time) FILTER (WHERE event_type = 'tunnel_open') AS opened_at,
    min(event_time) FILTER (WHERE event_type = 'tunnel_close') AS closed_at
  FROM evidence
  GROUP BY correlation_id
)
SELECT jsonb_build_object(
  'audit_version', 'proxy-lifecycle-v2', 'seed_rows', (SELECT count(*) FROM seeds),
  'candidate_correlations', count(*), 'counterpart_rows_returned', coalesce(sum(evidence_rows),0),
  'single_ordered_pair_within_horizon', count(*) FILTER (WHERE opens=1 AND closes=1 AND closed_at>=opened_at AND evidence_rows<:counterpart_limit),
  'cross_boundary_pairs', count(*) FILTER (WHERE opens=1 AND closes=1 AND closed_at>=opened_at AND evidence_rows<:counterpart_limit
    AND (opened_at<:'window_start'::timestamptz OR closed_at>=:'window_end'::timestamptz)),
  'duplicate_or_conflicting', count(*) FILTER (WHERE opens>1 OR closes>1 OR closed_at<opened_at),
  'counterpart_page_saturated', count(*) FILTER (WHERE evidence_rows>=:counterpart_limit),
  'missing_side_unknown_beyond_horizon', count(*) FILTER (WHERE opens=0 OR closes=0),
  'missing_correlation_observations', (SELECT count(*) FROM seeds
    WHERE correlation_id IS NULL OR correlation_id !~ '[^[:space:]]'),
  'cursor', (SELECT jsonb_build_array(event_time,event_id) FROM seeds ORDER BY event_time DESC,event_id DESC LIMIT 1),
  'horizon_start', :'horizon_start', 'horizon_end', :'horizon_end',
  'horizon_covers_window', :'horizon_start'::timestamptz <= :'window_start'::timestamptz
    AND :'horizon_end'::timestamptz >= :'window_end'::timestamptz,
  'limitation', 'candidate correlations repeat across pages; do not sum as validated flows; missing evidence outside horizon or retention remains unknown'
)
FROM sessions;
ROLLBACK;
