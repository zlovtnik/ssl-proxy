-- Run separately from page audits. Index endpoints, schema proof, extension and
-- cumulative server counters only. No queries, addresses or credentials exported.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
SELECT jsonb_build_object(
  'measured_at', CURRENT_TIMESTAMP,
  'session_timezone', current_setting('TimeZone'),
  'vector_extension', (SELECT extversion FROM pg_extension WHERE extname='vector'),
  'source_first', (SELECT event_time FROM octopus_core.proxy_events ORDER BY event_time,event_id LIMIT 1),
  'source_last', (SELECT event_time FROM octopus_core.proxy_events ORDER BY event_time DESC,event_id DESC LIMIT 1),
  'attestations', (SELECT jsonb_agg(to_jsonb(a)) FROM (
    SELECT domain,required_version,applied_version,required_checksum,applied_checksum,ready,checked_at
      FROM octopus_core.schema_readiness
    UNION ALL
    SELECT domain,required_version,applied_version,required_checksum,applied_checksum,ready,checked_at
      FROM atheros_search.schema_readiness
  ) a),
  'database_cumulative', (SELECT jsonb_build_object('stats_reset',stats_reset,'commits',xact_commit,
    'rollbacks',xact_rollback,'blocks_read',blks_read,'blocks_hit',blks_hit,'deadlocks',deadlocks,
    'temp_bytes',temp_bytes) FROM pg_stat_database WHERE datname=current_database()),
  'waits_snapshot', (SELECT jsonb_build_object('sessions',count(*),
    'waiting',count(*) FILTER (WHERE wait_event IS NOT NULL),
    'lock_waits',count(*) FILTER (WHERE wait_event_type='Lock'))
    FROM pg_stat_activity WHERE datname=current_database()),
  'counter_limit', 'cumulative counters require two timed samples; activity visibility depends on audit role; no rate or capacity inferred'
);
ROLLBACK;
