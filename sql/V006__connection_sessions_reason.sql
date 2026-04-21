-- V006: persist policy reason for connection sessions and expose it in readable views.

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS'
    AND column_name = 'REASON';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (reason VARCHAR2(64))';
  END IF;
END;
/

CREATE OR REPLACE VIEW v_session_timeline AS
SELECT
    cs.session_id,
    cs.correlation_id,
    cs.host,
    cs.peer_ip,
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
    (SELECT COUNT(*) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id) AS event_count,
    (SELECT MAX(pe.bytes_up) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id) AS max_event_bytes_up,
    (SELECT MAX(pe.status_code) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id
     AND pe.status_code IS NOT NULL) AS max_status_code
FROM connection_sessions cs
/

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
    pa.peer_ip,
    pa.notes,
    pa.payload_bytes,
    cs.tunnel_kind,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.reason,
    cs.opened_at AS session_opened_at,
    cs.bytes_up  AS session_bytes_up,
    cs.bytes_down AS session_bytes_down
FROM payload_audit pa
LEFT JOIN connection_sessions cs ON cs.correlation_id = pa.correlation_id
/

COMMIT;
