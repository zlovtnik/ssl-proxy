-- object: octopus_core_proxy_rollup_event_order
-- depends_on: octopus_core_proxy_source_conflicts
-- Existing rollups have no authoritative same-time winner. New observations
-- establish the deterministic (event time, event ID) ordering going forward.
ALTER TABLE octopus_core.proxy_blocked_host_rollups
  ADD COLUMN IF NOT EXISTS last_event_id varchar(255) NOT NULL DEFAULT '';

-- The executor applies each migration in a transaction, so CONCURRENTLY is
-- unavailable. Populated builds require an independently reviewed write drain,
-- measured row budget and finite statement budget inside a maintenance window.
DO $$
DECLARE
  row_budget_text text := current_setting('sslproxy.proxy_conflicts_max_rows', true);
  window_end_text text := current_setting('sslproxy.proxy_conflicts_window_end', true);
  writes_drained text := current_setting('sslproxy.proxy_conflicts_writes_drained', true);
  row_budget bigint;
  retained_rows bigint;
  statement_budget interval := current_setting('statement_timeout')::interval;
BEGIN
  IF to_regclass('octopus_core.proxy_events_source_conflicts_revision_idx') IS NOT NULL THEN
    RETURN;
  END IF;
  PERFORM set_config('lock_timeout', '1s', true);
  LOCK TABLE octopus_core.proxy_events IN SHARE MODE;
  IF to_regclass('octopus_core.proxy_events_source_conflicts_revision_idx') IS NOT NULL THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM octopus_core.proxy_events) THEN
    IF row_budget_text IS NULL OR row_budget_text !~ '^[0-9]{1,18}$'
        OR NULLIF(window_end_text, '') IS NULL OR writes_drained IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'proxy conflicts index requires reviewed proxy_conflicts_max_rows, proxy_conflicts_window_end and proxy_conflicts_writes_drained=on';
    END IF;
    row_budget := row_budget_text::bigint;
    IF statement_budget <= interval '1 second'
        OR NOT isfinite(window_end_text::timestamptz)
        OR clock_timestamp() + statement_budget > window_end_text::timestamptz THEN
      RAISE EXCEPTION 'proxy conflicts index requires finite statement_timeout > 1s within the maintenance window';
    END IF;
    SELECT count(*) INTO retained_rows FROM (
      SELECT 1 FROM octopus_core.proxy_events LIMIT row_budget + 1
    ) bounded;
    IF retained_rows > row_budget THEN
      RAISE EXCEPTION 'proxy conflicts retained rows exceed reviewed maintenance budget %', row_budget;
    END IF;
  END IF;
  CREATE INDEX IF NOT EXISTS proxy_events_source_conflicts_revision_idx
    ON octopus_core.proxy_events (observation_revision, event_id)
    WHERE source_conflicts <> '{}'::jsonb;
END $$;
