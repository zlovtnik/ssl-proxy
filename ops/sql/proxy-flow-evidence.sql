-- Private, read-only inspection of one correlation, including legacy schemas.
-- Required psql variables: correlation_id, window_start, window_end.
-- Bounds must be finite, increasing and no more than seven days apart.
-- A returned pair shape does not attest deployment, coverage or global conflicts.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
SET LOCAL TIME ZONE 'UTC';
WITH parameters AS (
  SELECT :'correlation_id'::text AS correlation_id,
    :'window_start'::timestamptz AS window_start,
    :'window_end'::timestamptz AS window_end
), bounds AS MATERIALIZED (
  SELECT *, CASE
    WHEN NOT isfinite(window_start) OR NOT isfinite(window_end)
      OR window_end <= window_start THEN false
    ELSE window_end - window_start <= interval '7 days'
    AND correlation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    END AS valid
  FROM parameters
), observations AS MATERIALIZED (
  SELECT p.event_id, p.event_time, p.event_type, p.event_sequence, p.host,
    p.blocked, p.bytes_up, p.bytes_down, p.duration_ms, p.payload,
    to_jsonb(p)->'source_conflicts' AS source_conflicts
  FROM octopus_core.proxy_events p CROSS JOIN bounds b
  WHERE b.valid AND p.correlation_id = b.correlation_id
    AND p.event_time >= b.window_start AND p.event_time < b.window_end
    AND p.event_type IN ('tunnel_open', 'tunnel_close')
  ORDER BY p.event_time, p.event_id
  LIMIT 101
), summary AS (
  SELECT count(*) AS rows_returned,
    count(*) FILTER (WHERE event_type = 'tunnel_open') AS opens,
    count(*) FILTER (WHERE event_type = 'tunnel_close') AS terminals,
    bool_or(source_conflicts IS NOT NULL AND source_conflicts <> '{}'::jsonb) AS has_conflict,
    bool_and(
      event_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND COALESCE(payload->>'event_id' = event_id, false)
      AND NOT blocked AND host <> ''
      AND COALESCE(event_sequence = CASE WHEN event_type = 'tunnel_open' THEN 1 ELSE 2 END, false)
    ) AS source_fields_supported,
    min(event_time) FILTER (WHERE event_type = 'tunnel_open') AS opened_at,
    min(event_time) FILTER (WHERE event_type = 'tunnel_close') AS closed_at,
    count(DISTINCT host) AS hosts
  FROM observations
)
SELECT jsonb_build_object(
  'audit_version', 'proxy-flow-evidence-v1',
  'parameters_valid', b.valid,
  'window_start', b.window_start, 'window_end', b.window_end,
  'rows_returned', s.rows_returned,
  'lookup_overflow', s.rows_returned = 101,
  'candidate_state', CASE
    WHEN NOT b.valid THEN 'invalid_parameters'
    WHEN s.has_conflict THEN 'unresolved_source_conflict'
    WHEN s.rows_returned = 101 THEN 'lookup_incomplete'
    WHEN s.rows_returned = 0 THEN 'no_retained_observations_in_window'
    WHEN s.opens > 1 OR s.terminals > 1 THEN 'ambiguous'
    WHEN NOT s.source_fields_supported THEN 'ineligible_source_fields'
    WHEN s.opens = 0 THEN 'missing_open_in_window'
    WHEN s.terminals = 0 THEN 'missing_terminal_in_window'
    WHEN s.hosts <> 1 OR s.closed_at < s.opened_at THEN 'inconsistent_pair'
    ELSE 'single_ordered_pair_candidate'
  END,
  'lifecycle_validation', 'unavailable_requires_attested_scope_coverage_horizon_and_global_conflict_reconciliation',
  'confirmed_transfer_totals', NULL,
  'observations', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'event_id', event_id, 'event_time', event_time,
      'event_type', event_type, 'event_sequence', event_sequence,
      'retained_host', host, 'blocked', blocked,
      'reported_bytes_up', bytes_up, 'reported_bytes_down', bytes_down,
      'reported_duration_ms', duration_ms,
      'producer_event_id', payload->>'event_id',
      'measurement', payload->'measurement',
      'source_conflicts', source_conflicts,
      'conflict_tracking', CASE WHEN source_conflicts IS NULL THEN 'unavailable'
        ELSE 'column_present_historical_coverage_unattested' END
    ) ORDER BY event_time, event_id) FROM observations
  ), '[]'::jsonb)
)
FROM bounds b CROSS JOIN summary s;
ROLLBACK;
