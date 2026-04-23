-- =============================================================================
-- Views — correlated network + database activity for Kibana / Grafana panels
-- =============================================================================

-- ---------------------------------------------------------------------------
-- V_HOST_THREAT_SCORE  — 7-day rolling risk score per host
-- Combines block frequency, total bytes attempted, and recency decay.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_host_threat_score AS
SELECT
    pe.host,
    COUNT(*)                                                    AS total_blocks_7d,
    SUM(pe.bytes_up + pe.bytes_down)                            AS total_bytes_7d,
    ROUND(
        COUNT(*) * AVG(pe.bytes_up + pe.bytes_down + 1)
        -- recency weight: events in the last 24 h count 3x
        * (1 + 2 * SUM(CASE WHEN pe.event_time >= SYSTIMESTAMP - INTERVAL '1' DAY THEN 1 ELSE 0 END)
                   / NULLIF(COUNT(*), 0)),
    2)                                                          AS threat_score,
    MAX(pe.event_time)                                          AS last_seen
FROM proxy_events pe
WHERE pe.blocked = 1
  AND pe.event_time >= SYSTIMESTAMP - INTERVAL '7' DAY
GROUP BY pe.host
ORDER BY threat_score DESC;

-- ---------------------------------------------------------------------------
-- V_MALICIOUS_ACTORS  — auto-flagging view for alerting and dashboard
-- Joins the 7-day rolling threat score with the live Rust-flushed verdict.
-- Labels are intentionally coarse: consumers filter on intelligence_label.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_malicious_actors AS
SELECT
    ts.host,
    ts.total_blocks_7d,
    ts.total_bytes_7d,
    ts.threat_score,
    ts.last_seen,
    be.frequency_hz,
    be.verdict                                          AS live_verdict,
    be.blocked_attempts                                 AS lifetime_attempts,
    CASE
        WHEN ts.threat_score >= 1000 AND be.frequency_hz > 8 THEN 'MALICIOUS_AGGRESSIVE'
        WHEN ts.threat_score >= 500                          THEN 'SUSPICIOUS_HIGH_VOLUME'
        ELSE                                                      'MONITORED'
    END                                                 AS intelligence_label
FROM v_host_threat_score ts
JOIN blocked_events be ON be.host = ts.host
WHERE ts.total_blocks_7d > 1
ORDER BY ts.threat_score DESC;

CREATE OR REPLACE VIEW v_blocked_hosts_24h AS
SELECT
    host,
    COUNT(*)                                        AS block_count,
    MIN(event_time)                                 AS first_seen,
    MAX(event_time)                                 AS last_seen
FROM proxy_events
WHERE blocked = 1
  AND event_time >= SYSTIMESTAMP - INTERVAL '24' HOUR
GROUP BY host
ORDER BY block_count DESC;

-- ---------------------------------------------------------------------------
-- V_TUNNEL_THROUGHPUT  — per-minute bandwidth (last hour)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_tunnel_throughput AS
SELECT
    TRUNC(event_time, 'MI')                         AS minute,
    SUM(bytes_up)                                   AS total_bytes_up,
    SUM(bytes_down)                                 AS total_bytes_down,
    COUNT(*)                                        AS tunnel_count
FROM proxy_events
WHERE event_type = 'tunnel_close'
  AND event_time >= SYSTIMESTAMP - INTERVAL '1' HOUR
GROUP BY TRUNC(event_time, 'MI')
ORDER BY minute;

-- ---------------------------------------------------------------------------
-- V_WG_PEER_TIMELINE  — WireGuard handshake + traffic per peer (last 24 h)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_wg_peer_timeline AS
SELECT
    wg_pubkey                                                  AS peer_pubkey,
    COUNT(*)                                                   AS sample_count,
    SUM(rx_bytes_delta)                                        AS total_rx,
    SUM(tx_bytes_delta)                                        AS total_tx,
    MAX(last_handshake_at)                                     AS last_seen,
    MAX(sessions_active)                                       AS max_sessions_active
FROM wg_peer_samples
WHERE sampled_at >= SYSTIMESTAMP - INTERVAL '24' HOUR
GROUP BY wg_pubkey;

-- ---------------------------------------------------------------------------
-- V_CORRELATED_ACTIVITY  — join proxy blocks with concurrent WG handshakes
-- (±5 s window) to surface suspicious correlation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_correlated_activity AS
SELECT
    pe.event_time                                   AS proxy_time,
    pe.host                                         AS blocked_host,
    pe.peer_ip                                      AS client_ip,
    we.event_time                                   AS wg_time,
    we.peer_pubkey,
    we.endpoint_ip,
    ABS(
        EXTRACT(DAY    FROM (pe.event_time - we.event_time)) * 86400
      + EXTRACT(HOUR   FROM (pe.event_time - we.event_time)) * 3600
      + EXTRACT(MINUTE FROM (pe.event_time - we.event_time)) * 60
      + EXTRACT(SECOND FROM (pe.event_time - we.event_time))
    ) AS delta_seconds
FROM proxy_events pe
JOIN wg_events we
  ON we.event_time BETWEEN pe.event_time - INTERVAL '5' SECOND
                       AND pe.event_time + INTERVAL '5' SECOND
 AND pe.peer_ip = we.endpoint_ip
WHERE pe.blocked = 1
  AND pe.event_time >= SYSTIMESTAMP - INTERVAL '1' HOUR;

-- ---------------------------------------------------------------------------
-- V_SLOW_QUERIES  — top 50 slowest queries in the last hour
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_slow_queries AS
SELECT *
FROM (
    SELECT
        captured_at,
        client_ip,
        db_user,
        elapsed_ms,
        rows_examined,
        rows_returned,
        SUBSTR(sql_text, 1, 200)                    AS sql_preview
    FROM db_query_log
    WHERE captured_at >= SYSTIMESTAMP - INTERVAL '1' HOUR
    ORDER BY elapsed_ms DESC
)
WHERE ROWNUM <= 50;

-- ---------------------------------------------------------------------------
-- V_PIPELINE_HEALTH  — shipper lag summary for ops alerting
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_pipeline_health AS
SELECT
    agent_name,
    host_fqdn,
    MAX(reported_at)                                AS last_heartbeat,
    AVG(lag_seconds)                                AS avg_lag_s,
    MAX(lag_seconds)                                AS max_lag_s,
    SUM(events_sent)                                AS total_events_sent,
    CASE
        WHEN MAX(reported_at) < SYSTIMESTAMP - INTERVAL '5' MINUTE THEN 'STALE'
        WHEN MAX(lag_seconds) > 30                                  THEN 'LAGGING'
        ELSE 'OK'
    END                                             AS health_status
FROM shipper_heartbeats
WHERE reported_at >= SYSTIMESTAMP - INTERVAL '1' HOUR
GROUP BY agent_name, host_fqdn;

-- ---------------------------------------------------------------------------
-- V_FOX_TRAFFIC  — Obfuscated traffic aggregation for Grafana panels
-- Aggregates events by host, hour and obfuscation profile
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_fox_traffic AS
SELECT
    TRUNC(event_time, 'HH24')                     AS hour,
    host,
    obfuscation_profile,
    COUNT(*)                                      AS event_count,
    SUM(bytes_up)                                 AS total_bytes_up,
    SUM(bytes_down)                               AS total_bytes_down
FROM proxy_events
WHERE obfuscation_profile IS NOT NULL
  AND event_time >= SYSTIMESTAMP - INTERVAL '7' DAY
GROUP BY TRUNC(event_time, 'HH24'), host, obfuscation_profile
ORDER BY hour DESC, event_count DESC;

-- ---------------------------------------------------------------------------
-- V_SESSION_TIMELINE  — latest session shape with device identity
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_session_timeline AS
SELECT
    cs.session_id,
    cs.correlation_id,
    cs.host,
    cs.peer_ip,
    cs.wg_pubkey,
    cs.device_id,
    cs.identity_source,
    cs.peer_hostname,
    cs.client_ua,
    cs.tunnel_kind,
    cs.opened_at,
    cs.closed_at,
    cs.duration_ms,
    cs.bytes_up,
    cs.bytes_down,
    cs.blocked,
    cs.tarpitted,
    cs.tarpit_held_ms,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.tls_ver,
    cs.alpn,
    cs.ja3_lite,
    cs.resolved_ip,
    cs.asn_org,
    cs.reason,
    d.display_name,
    d.username,
    COALESCE(pe_agg.event_count, 0) AS event_count
FROM connection_sessions cs
LEFT JOIN devices d
  ON d.device_id = cs.device_id
LEFT JOIN (
    SELECT
        correlation_id,
        COUNT(*) AS event_count
    FROM proxy_events
    WHERE event_time >= SYSTIMESTAMP - INTERVAL '7' DAY
    GROUP BY correlation_id
) pe_agg
  ON pe_agg.correlation_id = cs.correlation_id
WHERE cs.opened_at >= SYSTIMESTAMP - INTERVAL '7' DAY;

-- ---------------------------------------------------------------------------
-- V_PAYLOAD_AUDIT_READABLE  — masked operational payload metadata
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_payload_audit_readable AS
SELECT
    pa.id,
    pa.correlation_id,
    pa.host,
    pa.direction,
    pa.captured_at,
    pa.content_type,
    pa.http_method,
    pa.http_status,
    pa.http_path,
    pa.is_encrypted,
    pa.truncated,
    pa.notes,
    cs.tunnel_kind,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.reason,
    cs.opened_at AS session_opened_at,
    cs.bytes_up  AS session_bytes_up,
    cs.bytes_down AS session_bytes_down
FROM payload_audit pa
LEFT JOIN connection_sessions cs
  ON cs.correlation_id = pa.correlation_id;

-- ---------------------------------------------------------------------------
-- V_PAYLOAD_AUDIT_SENSITIVE  — full payload and peer/session identity
-- Owner-only by default; no public grants are applied here.
-- Any access should be granted by DBAs through least-privilege roles with
-- database-native SELECT auditing enabled outside this repo.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_payload_audit_sensitive AS
SELECT
    pa.id,
    pa.correlation_id,
    pa.host,
    pa.direction,
    pa.captured_at,
    pa.content_type,
    pa.http_method,
    pa.http_status,
    pa.http_path,
    pa.is_encrypted,
    pa.truncated,
    pa.peer_ip,
    pa.notes,
    pa.payload_bytes,
    cs.device_id,
    cs.wg_pubkey,
    cs.identity_source,
    cs.peer_hostname,
    cs.client_ua,
    cs.tunnel_kind,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.reason,
    cs.opened_at AS session_opened_at,
    cs.bytes_up  AS session_bytes_up,
    cs.bytes_down AS session_bytes_down
FROM payload_audit pa
LEFT JOIN connection_sessions cs
  ON cs.correlation_id = pa.correlation_id;

CREATE OR REPLACE PACKAGE payload_audit_security AS
  FUNCTION sensitive_view_predicate(
    p_schema_name IN VARCHAR2,
    p_object_name IN VARCHAR2
  ) RETURN VARCHAR2;
END payload_audit_security;
/

CREATE OR REPLACE PACKAGE BODY payload_audit_security AS
  FUNCTION sensitive_view_predicate(
    p_schema_name IN VARCHAR2,
    p_object_name IN VARCHAR2
  ) RETURN VARCHAR2 IS
    v_allow VARCHAR2(1);
    v_corr_id VARCHAR2(64);
    v_device_id VARCHAR2(64);
    v_predicate VARCHAR2(4000) := '1=0';
  BEGIN
    v_allow := NVL(SYS_CONTEXT('APP_CTX', 'ALLOW_SENSITIVE_AUDIT'), '0');
    IF v_allow != '1' THEN
      RETURN '1=0';
    END IF;

    v_corr_id := SYS_CONTEXT('APP_CTX', 'ALLOWED_CORRELATION_ID');
    v_device_id := SYS_CONTEXT('APP_CTX', 'ALLOWED_DEVICE_ID');

    IF v_corr_id IS NOT NULL THEN
      v_predicate := 'correlation_id = ' || DBMS_ASSERT.ENQUOTE_LITERAL(v_corr_id);
    END IF;
    IF v_device_id IS NOT NULL THEN
      IF v_predicate = '1=0' THEN
        v_predicate := 'device_id = ' || DBMS_ASSERT.ENQUOTE_LITERAL(v_device_id);
      ELSE
        v_predicate := '(' || v_predicate || ' OR device_id = ' ||
          DBMS_ASSERT.ENQUOTE_LITERAL(v_device_id) || ')';
      END IF;
    END IF;
    RETURN v_predicate;
  END sensitive_view_predicate;
END payload_audit_security;
/

BEGIN
  BEGIN
    DBMS_FGA.DROP_POLICY(
      object_schema => USER,
      object_name => 'V_PAYLOAD_AUDIT_SENSITIVE',
      policy_name => 'FGA_V_PAYLOAD_AUDIT_SENSITIVE'
    );
  EXCEPTION
    WHEN OTHERS THEN NULL;
  END;

  DBMS_FGA.ADD_POLICY(
    object_schema => USER,
    object_name => 'V_PAYLOAD_AUDIT_SENSITIVE',
    policy_name => 'FGA_V_PAYLOAD_AUDIT_SENSITIVE',
    audit_condition => '1=1',
    statement_types => 'SELECT',
    enable => TRUE
  );
END;
/

BEGIN
  BEGIN
    DBMS_RLS.DROP_POLICY(
      object_schema => USER,
      object_name => 'V_PAYLOAD_AUDIT_SENSITIVE',
      policy_name => 'RLS_V_PAYLOAD_AUDIT_SENSITIVE'
    );
  EXCEPTION
    WHEN OTHERS THEN NULL;
  END;

  DBMS_RLS.ADD_POLICY(
    object_schema => USER,
    object_name => 'V_PAYLOAD_AUDIT_SENSITIVE',
    policy_name => 'RLS_V_PAYLOAD_AUDIT_SENSITIVE',
    function_schema => USER,
    policy_function => 'PAYLOAD_AUDIT_SECURITY.SENSITIVE_VIEW_PREDICATE',
    statement_types => 'SELECT',
    update_check => FALSE,
    enable => TRUE
  );
END;
/

-- ---------------------------------------------------------------------------
-- V_PAYLOAD_AUDIT_RECENT  — masked payload metadata limited to recent history
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_payload_audit_recent AS
SELECT
    pa.id,
    pa.correlation_id,
    pa.host,
    pa.direction,
    pa.captured_at,
    pa.content_type,
    pa.http_method,
    pa.http_status,
    pa.http_path,
    pa.is_encrypted,
    pa.truncated,
    pa.notes,
    cs.tunnel_kind,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.reason,
    cs.opened_at AS session_opened_at,
    cs.bytes_up  AS session_bytes_up,
    cs.bytes_down AS session_bytes_down
FROM payload_audit pa
LEFT JOIN connection_sessions cs
  ON cs.correlation_id = pa.correlation_id
WHERE pa.captured_at >= SYSTIMESTAMP - INTERVAL '90' DAY;

-- ---------------------------------------------------------------------------
-- V_PEER_IDENTITY  — registry rows plus most recent runtime hints
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_peer_identity AS
SELECT
    d.device_id,
    d.wg_pubkey,
    d.display_name,
    d.username,
    d.hostname AS registered_hostname,
    d.os_hint,
    d.mac_hint,
    d.first_seen,
    d.last_seen,
    MAX(cs.peer_hostname) KEEP (DENSE_RANK LAST ORDER BY cs.opened_at NULLS FIRST) AS last_peer_hostname,
    MAX(cs.client_ua) KEEP (DENSE_RANK LAST ORDER BY cs.opened_at NULLS FIRST) AS last_client_ua,
    MAX(cs.opened_at) AS last_session_at,
    COUNT(cs.session_id) AS session_count
FROM devices d
LEFT JOIN connection_sessions cs
  ON cs.device_id = d.device_id
GROUP BY
    d.device_id,
    d.wg_pubkey,
    d.display_name,
    d.username,
    d.hostname,
    d.os_hint,
    d.mac_hint,
    d.first_seen,
    d.last_seen;

-- ---------------------------------------------------------------------------
-- V_BANDWIDTH_TREND  — per-minute bandwidth grouped by peer and device
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_bandwidth_trend AS
SELECT
    TRUNC(bs.sampled_at, 'MI')                AS bucket_minute,
    bs.wg_pubkey,
    bs.device_id,
    d.display_name,
    d.username,
    SUM(bs.bytes_up_delta)                    AS bytes_up_delta,
    SUM(bs.bytes_down_delta)                  AS bytes_down_delta,
    SUM(bs.blocked_bytes_delta)               AS blocked_bytes_delta,
    SUM(bs.allowed_bytes_delta)               AS allowed_bytes_delta,
    SUM(bs.blocked_count_delta)               AS blocked_count_delta,
    SUM(bs.allowed_count_delta)               AS allowed_count_delta,
    MAX(bs.sessions_active)                   AS sessions_active,
    MAX(bs.blocked_bytes_is_approx)           AS blocked_bytes_is_approx
FROM bandwidth_samples bs
LEFT JOIN devices d
  ON d.device_id = bs.device_id
WHERE bs.sampled_at >= SYSTIMESTAMP - INTERVAL '24' HOUR
GROUP BY
    TRUNC(bs.sampled_at, 'MI'),
    bs.wg_pubkey,
    bs.device_id,
    d.display_name,
    d.username;
