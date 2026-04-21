-- V007: device registry and peer identity enrichment.
-- Safe to rerun: all DDL is guarded by existence checks.

-- ── 1. DEVICES ───────────────────────────────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables
  WHERE table_name = 'DEVICES';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE devices (
        device_id         VARCHAR2(36)   NOT NULL,
        wg_pubkey         VARCHAR2(64),
        claim_token_hash  VARCHAR2(128),
        display_name      VARCHAR2(128),
        username          VARCHAR2(128),
        hostname          VARCHAR2(253),
        os_hint           VARCHAR2(64),
        mac_hint          VARCHAR2(17),
        first_seen        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        last_seen         TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        notes             VARCHAR2(512),
        CONSTRAINT devices_pk PRIMARY KEY (device_id)
      )
    ]';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'DEVICES_WG_PUBKEY_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX devices_wg_pubkey_idx ON devices(wg_pubkey)';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'DEVICES_USERNAME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX devices_username_idx ON devices(username, last_seen DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'DEVICES_CLAIM_TOKEN_UQ';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE UNIQUE INDEX devices_claim_token_uq ON devices(claim_token_hash)';
  END IF;
END;
/

-- ── 2. CONNECTION_SESSIONS identity columns ─────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS' AND column_name = 'WG_PUBKEY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (wg_pubkey VARCHAR2(64))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS' AND column_name = 'DEVICE_ID';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (device_id VARCHAR2(36))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS' AND column_name = 'IDENTITY_SOURCE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (identity_source VARCHAR2(16) DEFAULT ''unknown'')';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS' AND column_name = 'PEER_HOSTNAME';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (peer_hostname VARCHAR2(253))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'CONNECTION_SESSIONS' AND column_name = 'CLIENT_UA';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD (client_ua VARCHAR2(512))';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_constraints
  WHERE constraint_name = 'CS_DEVICE_FK';
  IF v_count > 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions DROP CONSTRAINT cs_device_fk';
  END IF;
  EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions ADD CONSTRAINT cs_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'CS_DEVICE_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX cs_device_idx ON connection_sessions(device_id, opened_at DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'CS_WG_PUBKEY_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX cs_wg_pubkey_idx ON connection_sessions(wg_pubkey, opened_at DESC)';
  END IF;
END;
/

-- ── 3. PROXY_EVENTS identity columns ────────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'WG_PUBKEY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (wg_pubkey VARCHAR2(64))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'DEVICE_ID';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (device_id VARCHAR2(36))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'IDENTITY_SOURCE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (identity_source VARCHAR2(16) DEFAULT ''unknown'')';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'PEER_HOSTNAME';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (peer_hostname VARCHAR2(253))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'CLIENT_UA';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (client_ua VARCHAR2(512))';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_constraints
  WHERE constraint_name = 'PE_DEVICE_FK';
  IF v_count > 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events DROP CONSTRAINT pe_device_fk';
  END IF;
  EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD CONSTRAINT pe_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'PE_DEVICE_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX pe_device_time_idx ON proxy_events(device_id, event_time DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'PE_WG_PUBKEY_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX pe_wg_pubkey_time_idx ON proxy_events(wg_pubkey, event_time DESC)';
  END IF;
END;
/

-- ── 4. Views refreshed with identity columns ────────────────────────────────
CREATE OR REPLACE VIEW v_peer_identity AS
SELECT
    d.device_id,
    d.wg_pubkey,
    d.display_name,
    d.username,
    d.hostname                             AS registered_hostname,
    d.os_hint,
    d.mac_hint,
    d.first_seen,
    d.last_seen,
    MAX(cs.peer_hostname) KEEP (DENSE_RANK LAST ORDER BY cs.opened_at NULLS FIRST) AS last_peer_hostname,
    MAX(cs.client_ua) KEEP (DENSE_RANK LAST ORDER BY cs.opened_at NULLS FIRST) AS last_client_ua,
    MAX(cs.opened_at)                      AS last_session_at,
    COUNT(cs.session_id)                   AS session_count
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
    d.last_seen
/

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
    COALESCE(pe_agg.event_count, 0)              AS event_count,
    pe_agg.max_event_bytes_up,
    pe_status.last_status_code
FROM connection_sessions cs
LEFT JOIN (
    SELECT
        correlation_id,
        COUNT(*) AS event_count,
        MAX(bytes_up) AS max_event_bytes_up
    FROM proxy_events
    GROUP BY correlation_id
) pe_agg
  ON pe_agg.correlation_id = cs.correlation_id
LEFT JOIN (
    SELECT
        correlation_id,
        MAX(status_code) KEEP (DENSE_RANK LAST ORDER BY event_time NULLS FIRST, id NULLS FIRST) AS last_status_code
    FROM proxy_events
    WHERE status_code IS NOT NULL
    GROUP BY correlation_id
) pe_status
  ON pe_status.correlation_id = cs.correlation_id
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
  ON cs.correlation_id = pa.correlation_id
/

COMMIT;
