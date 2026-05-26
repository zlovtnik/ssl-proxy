-- Normalize Oracle-side timestamp defaults to America/New_York for new rows.
-- Existing rows are intentionally not backfilled; RFC3339/service payloads retain
-- offsets, and comparable database columns continue to represent instants.

DECLARE
  c_tz_timestamp CONSTANT VARCHAR2(128) := '(CAST(SYSTIMESTAMP AT TIME ZONE ''America/New_York'' AS TIMESTAMP))';
  c_tstz CONSTANT VARCHAR2(128) := '(SYSTIMESTAMP AT TIME ZONE ''America/New_York'')';

  PROCEDURE set_default(p_table IN VARCHAR2, p_column IN VARCHAR2, p_expression IN VARCHAR2) IS
  BEGIN
    EXECUTE IMMEDIATE 'ALTER TABLE ' || p_table || ' MODIFY (' || p_column || ' DEFAULT ' || p_expression || ')';
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE NOT IN (-942, -904, -1442) THEN
        RAISE;
      END IF;
  END;
BEGIN
  set_default('devices', 'first_seen', c_tz_timestamp);
  set_default('devices', 'last_seen', c_tz_timestamp);
  set_default('proxy_events', 'event_time', c_tstz);
  set_default('wg_events', 'event_time', c_tstz);
  set_default('wg_peer_samples', 'sampled_at', c_tz_timestamp);
  set_default('wg_peer_samples', 'created_at', c_tz_timestamp);
  set_default('bandwidth_samples', 'sampled_at', c_tz_timestamp);
  set_default('bandwidth_samples', 'created_at', c_tz_timestamp);
  set_default('db_query_log', 'captured_at', c_tstz);
  set_default('blocked_events', 'updated_at', c_tstz);
  set_default('blocked_events', 'first_seen', c_tstz);
  set_default('payload_audit', 'captured_at', c_tz_timestamp);
  set_default('tls_fingerprints', 'first_seen', c_tz_timestamp);
  set_default('tls_fingerprints', 'last_seen', c_tz_timestamp);
  set_default('connection_sessions', 'opened_at', c_tz_timestamp);
  set_default('connection_sessions', 'created_at', c_tz_timestamp);
  set_default('connection_sessions_close_dlq', 'captured_at', c_tz_timestamp);
  set_default('blocklist_audit', 'refreshed_at', c_tz_timestamp);
  set_default('shipper_heartbeats', 'reported_at', c_tstz);
  set_default('dlq_errors', 'captured_at', c_tz_timestamp);
END;
/
