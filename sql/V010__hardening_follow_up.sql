-- V010: hardening follow-up for integrity, session close DLQ, and reporting corrections.

DECLARE
  v_default user_tab_columns.data_default%TYPE;
  v_null_count INTEGER := 0;
BEGIN
  SELECT data_default INTO v_default
  FROM user_tab_columns
  WHERE table_name = 'BANDWIDTH_SAMPLES'
    AND column_name = 'SAMPLED_AT';

  SELECT COUNT(*) INTO v_null_count
  FROM bandwidth_samples
  WHERE sampled_at IS NULL;
  IF v_null_count > 0 THEN
    UPDATE bandwidth_samples
    SET sampled_at = SYSTIMESTAMP
    WHERE sampled_at IS NULL;
    COMMIT;
  END IF;

  IF v_default IS NULL OR UPPER(TRIM(v_default)) != 'SYSTIMESTAMP' THEN
    EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples MODIFY (sampled_at DEFAULT SYSTIMESTAMP NOT NULL)';
  END IF;
EXCEPTION
  WHEN NO_DATA_FOUND THEN NULL;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables
  WHERE table_name = 'CONNECTION_SESSIONS_CLOSE_DLQ';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE connection_sessions_close_dlq (
        id                  NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        captured_at         TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        session_id          VARCHAR2(36)   NOT NULL,
        reason              VARCHAR2(64)   NOT NULL,
        duration_ms         NUMBER(12,0),
        bytes_up            NUMBER(18,0),
        bytes_down          NUMBER(18,0),
        blocked             NUMBER(1,0),
        tarpitted           NUMBER(1,0),
        tarpit_held_ms      NUMBER(10,0),
        verdict             VARCHAR2(32),
        category            VARCHAR2(64),
        obfuscation_profile VARCHAR2(32),
        tls_ver             VARCHAR2(16),
        alpn                VARCHAR2(64),
        ja3_lite            VARCHAR2(512),
        resolved_ip         VARCHAR2(45),
        asn_org             VARCHAR2(128),
        wg_pubkey           VARCHAR2(64),
        device_id           VARCHAR2(36),
        identity_source     VARCHAR2(16),
        peer_hostname       VARCHAR2(253),
        client_ua           VARCHAR2(512)
      )
    ]';
    EXECUTE IMMEDIATE
      'CREATE INDEX cs_close_dlq_session_idx ON connection_sessions_close_dlq(session_id, captured_at DESC)';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
  v_payload_b64_count INTEGER := 0;
  v_payload_b64_type VARCHAR2(128);
  v_remaining_null_count INTEGER := 0;
BEGIN
  SELECT COUNT(*) INTO v_payload_b64_count
  FROM user_tab_columns
  WHERE table_name = 'PAYLOAD_AUDIT'
    AND column_name = 'PAYLOAD_B64';

  IF v_payload_b64_count > 0 THEN
    SELECT data_type INTO v_payload_b64_type
    FROM user_tab_columns
    WHERE table_name = 'PAYLOAD_AUDIT'
      AND column_name = 'PAYLOAD_B64';

    BEGIN
      IF v_payload_b64_type = 'CLOB' THEN
        EXECUTE IMMEDIATE q'[
          UPDATE payload_audit
          SET payload_bytes = UTL_ENCODE.BASE64_DECODE(
            UTL_RAW.CAST_TO_RAW(DBMS_LOB.SUBSTR(payload_b64, 32767, 1))
          )
          WHERE payload_bytes IS NULL
            AND payload_b64 IS NOT NULL
        ]';
      ELSE
        EXECUTE IMMEDIATE q'[
          UPDATE payload_audit
          SET payload_bytes = UTL_ENCODE.BASE64_DECODE(
            UTL_RAW.CAST_TO_RAW(payload_b64)
          )
          WHERE payload_bytes IS NULL
            AND payload_b64 IS NOT NULL
        ]';
      END IF;
      COMMIT;
    EXCEPTION
      WHEN OTHERS THEN
        ROLLBACK;
        log_migration_audit(
          p_migration_name => 'V010__hardening_follow_up.sql',
          p_sqlcode => SQLCODE,
          p_sqlerrm => SQLERRM,
          p_context => 'payload_audit payload_b64 backfill failed'
        );
        RAISE;
    END;
  END IF;

  SELECT COUNT(*) INTO v_remaining_null_count
  FROM payload_audit
  WHERE payload_bytes IS NULL;
  IF v_remaining_null_count > 0 THEN
    log_migration_audit(
      p_migration_name => 'V010__hardening_follow_up.sql',
      p_sqlcode => -20010,
      p_sqlerrm => 'payload_audit has rows without payload_bytes',
      p_context => 'payload_audit_payload_present_ck validation blocked'
    );
    RAISE_APPLICATION_ERROR(
      -20010,
      'Cannot add payload_audit_payload_present_ck: ' ||
      TO_CHAR(v_remaining_null_count) || ' rows have NULL payload_bytes'
    );
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_constraints
  WHERE table_name = 'PAYLOAD_AUDIT'
    AND constraint_name = 'PAYLOAD_AUDIT_PAYLOAD_PRESENT_CK';

  IF v_count > 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE payload_audit DROP CONSTRAINT payload_audit_payload_present_ck';
  END IF;
  EXECUTE IMMEDIATE q'[
    ALTER TABLE payload_audit
    ADD CONSTRAINT payload_audit_payload_present_ck
    CHECK (payload_bytes IS NOT NULL)
    ENABLE VALIDATE
  ]';
END;
/

MERGE INTO data_retention_policy t
USING (
  SELECT 'PAYLOAD_AUDIT' AS table_name, 30 AS retention_days, 'CAPTURED_AT' AS date_column,
         '30-day compliance window' AS notes
  FROM dual
) s
ON (t.table_name = s.table_name)
WHEN MATCHED THEN UPDATE
  SET t.retention_days = s.retention_days,
      t.date_column = s.date_column,
      t.notes = s.notes
WHEN NOT MATCHED THEN INSERT
  (table_name, retention_days, date_column, notes)
  VALUES (s.table_name, s.retention_days, s.date_column, s.notes)
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_scheduler_jobs
  WHERE job_name = 'JOB_REFRESH_MVS';

  IF v_count > 0 THEN
    DBMS_SCHEDULER.SET_ATTRIBUTE(
      name      => 'JOB_REFRESH_MVS',
      attribute => 'job_action',
      value     => q'[DECLARE
        PROCEDURE log_mv_refresh_error(p_mv_name IN VARCHAR2, p_error_msg IN VARCHAR2) IS
          PRAGMA AUTONOMOUS_TRANSACTION;
        BEGIN
          INSERT INTO mv_refresh_log (log_time, mv_name, error_msg)
          VALUES (SYSTIMESTAMP, p_mv_name, p_error_msg);
          COMMIT;
        END log_mv_refresh_error;
      BEGIN
        BEGIN
          DBMS_MVIEW.REFRESH(''MV_DAILY_BLOCKED'', ''C'');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error(''MV_DAILY_BLOCKED'', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH(''MV_PEER_IP_SUMMARY'', ''C'');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error(''MV_PEER_IP_SUMMARY'', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH(''MV_HOURLY_BANDWIDTH'', ''C'');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error(''MV_HOURLY_BANDWIDTH'', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH(''MV_DAILY_PEER_STATS'', ''C'');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error(''MV_DAILY_PEER_STATS'', SQLERRM);
        END;
      END;]'
    );
  END IF;
END;
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
  ON pe_agg.correlation_id = cs.correlation_id;
/

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
/

COMMENT ON VIEW v_payload_audit_sensitive IS
  'Owner-only payload audit view. Grant access only through DBA-managed least-privilege roles with database-native SELECT auditing enabled.'
/

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
        v_predicate := v_predicate || ' OR ';
        v_predicate := v_predicate || 'device_id = ' || DBMS_ASSERT.ENQUOTE_LITERAL(v_device_id);
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

CREATE OR REPLACE PACKAGE BODY pkg_proxy_bulk AS
  e_bulk_errors EXCEPTION;
  PRAGMA EXCEPTION_INIT(e_bulk_errors, -24381);

  PROCEDURE log_dlq(
    p_procedure_name IN VARCHAR2,
    p_error_code     IN NUMBER,
    p_error_msg      IN VARCHAR2,
    p_row_data       IN CLOB
  ) IS
    PRAGMA AUTONOMOUS_TRANSACTION;
  BEGIN
    INSERT INTO dlq_errors (procedure_name, error_code, error_msg, row_data)
    VALUES (SUBSTR(p_procedure_name, 1, 64), p_error_code, SUBSTR(p_error_msg, 1, 512), p_row_data);
    COMMIT;
  EXCEPTION
    WHEN OTHERS THEN
      ROLLBACK;
      BEGIN
        SYS.DBMS_SYSTEM.KSDWRT(
          2,
          'pkg_proxy_bulk.log_dlq failed (proc=' || SUBSTR(p_procedure_name, 1, 64) ||
          ', row=' || SUBSTR(p_row_data, 1, 256) ||
          ', sqlcode=' || SQLCODE ||
          ', sqlerrm=' || SUBSTR(SQLERRM, 1, 512) || ')'
        );
      EXCEPTION
        WHEN OTHERS THEN NULL;
      END;
      RAISE;
  END log_dlq;

  FUNCTION escape_json_string(p_val IN VARCHAR2) RETURN VARCHAR2 IS
    l_val VARCHAR2(4000) := NVL(p_val, '');
  BEGIN
    l_val := REPLACE(l_val, '\', '\\');
    l_val := REPLACE(l_val, '"', '\"');
    l_val := REPLACE(l_val, CHR(10), '\n');
    l_val := REPLACE(l_val, CHR(13), '\r');
    l_val := REPLACE(l_val, CHR(9), '\t');
    RETURN l_val;
  END escape_json_string;

  PROCEDURE insert_proxy_events_bulk(
    p_event_type           IN t_varchar2_list,
    p_host                 IN t_varchar2_list,
    p_peer_ip              IN t_varchar2_list,
    p_wg_pubkey            IN t_varchar2_list,
    p_device_id            IN t_varchar2_list,
    p_identity_source      IN t_varchar2_list,
    p_peer_hostname        IN t_varchar2_list,
    p_client_ua            IN t_varchar2_list,
    p_bytes_up             IN t_number_list,
    p_bytes_down           IN t_number_list,
    p_status_code          IN t_number_list,
    p_blocked              IN t_number_list,
    p_obfuscation_profile  IN t_varchar2_list,
    p_correlation_id       IN t_varchar2_list,
    p_parent_event_id      IN t_varchar2_list,
    p_event_sequence       IN t_number_list,
    p_duration_ms          IN t_number_list,
    p_reason               IN t_varchar2_list,
    p_raw_json             IN t_clob_list
  ) IS
  BEGIN
    FORALL i IN 1 .. p_event_type.COUNT SAVE EXCEPTIONS
      INSERT INTO proxy_events (
        event_type, host, peer_ip, wg_pubkey, device_id, identity_source,
        peer_hostname, client_ua, bytes_up, bytes_down, status_code, blocked,
        obfuscation_profile, correlation_id, parent_event_id, event_sequence,
        duration_ms, reason, raw_json
      )
      VALUES (
        p_event_type(i), p_host(i), p_peer_ip(i), p_wg_pubkey(i), p_device_id(i),
        COALESCE(p_identity_source(i), 'unknown'), p_peer_hostname(i), p_client_ua(i),
        NVL(p_bytes_up(i), 0), NVL(p_bytes_down(i), 0), p_status_code(i), NVL(p_blocked(i), 0),
        p_obfuscation_profile(i), p_correlation_id(i), p_parent_event_id(i), p_event_sequence(i),
        p_duration_ms(i), p_reason(i), p_raw_json(i)
      );
  EXCEPTION
    WHEN e_bulk_errors THEN
      FOR j IN 1 .. SQL%BULK_EXCEPTIONS.COUNT LOOP
        log_dlq(
          'insert_proxy_events_bulk',
          SQL%BULK_EXCEPTIONS(j).ERROR_CODE,
          SQLERRM(-SQL%BULK_EXCEPTIONS(j).ERROR_CODE),
          '{"host":"' || escape_json_string(p_host(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) ||
          '","event_type":"' || escape_json_string(p_event_type(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) || '"}'
        );
      END LOOP;
  END insert_proxy_events_bulk;

  PROCEDURE insert_payload_audit_bulk(
    p_correlation_id  IN t_varchar2_list,
    p_host            IN t_varchar2_list,
    p_direction       IN t_varchar2_list,
    p_byte_offset     IN t_number_list,
    p_payload_bytes   IN t_raw_list,
    p_content_type    IN t_varchar2_list,
    p_http_method     IN t_varchar2_list,
    p_http_status     IN t_number_list,
    p_http_path       IN t_varchar2_list,
    p_is_encrypted    IN t_number_list,
    p_truncated       IN t_number_list,
    p_peer_ip         IN t_varchar2_list,
    p_notes           IN t_varchar2_list
  ) IS
  BEGIN
    FORALL i IN 1 .. p_correlation_id.COUNT SAVE EXCEPTIONS
      INSERT INTO payload_audit (
        correlation_id, host, direction, byte_offset, payload_bytes,
        content_type, http_method, http_status, http_path, is_encrypted, truncated,
        peer_ip, notes
      )
      VALUES (
        p_correlation_id(i), p_host(i), p_direction(i), NVL(p_byte_offset(i), 0),
        p_payload_bytes(i), p_content_type(i), p_http_method(i),
        p_http_status(i), p_http_path(i), NVL(p_is_encrypted(i), 0), NVL(p_truncated(i), 0),
        p_peer_ip(i), p_notes(i)
      );
  EXCEPTION
    WHEN e_bulk_errors THEN
      FOR j IN 1 .. SQL%BULK_EXCEPTIONS.COUNT LOOP
        log_dlq(
          'insert_payload_audit_bulk',
          SQL%BULK_EXCEPTIONS(j).ERROR_CODE,
          SQLERRM(-SQL%BULK_EXCEPTIONS(j).ERROR_CODE),
          '{"correlation_id":"' || escape_json_string(p_correlation_id(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) ||
          '","host":"' || escape_json_string(p_host(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) || '"}'
        );
      END LOOP;
  END insert_payload_audit_bulk;

  PROCEDURE upsert_tls_fingerprints_bulk(
    p_ja3_lite      IN t_varchar2_list,
    p_tls_ver       IN t_varchar2_list,
    p_alpn          IN t_varchar2_list,
    p_cipher_count  IN t_number_list,
    p_verdict_hint  IN t_varchar2_list
  ) IS
  BEGIN
    FOR i IN 1 .. p_ja3_lite.COUNT LOOP
      BEGIN
        UPDATE tls_fingerprints
        SET last_seen = SYSTIMESTAMP,
            seen_count = seen_count + 1,
            tls_ver = COALESCE(p_tls_ver(i), tls_ver),
            alpn = COALESCE(p_alpn(i), alpn),
            cipher_count = COALESCE(p_cipher_count(i), cipher_count),
            verdict_hint = COALESCE(p_verdict_hint(i), verdict_hint)
        WHERE ja3_lite = p_ja3_lite(i);

        IF SQL%ROWCOUNT = 0 THEN
          BEGIN
            INSERT INTO tls_fingerprints (
              ja3_lite, first_seen, last_seen, seen_count, tls_ver, alpn, cipher_count, verdict_hint
            ) VALUES (
              p_ja3_lite(i), SYSTIMESTAMP, SYSTIMESTAMP, 1, p_tls_ver(i), p_alpn(i), p_cipher_count(i), p_verdict_hint(i)
            );
          EXCEPTION
            WHEN DUP_VAL_ON_INDEX THEN
              UPDATE tls_fingerprints
              SET last_seen = SYSTIMESTAMP,
                  seen_count = seen_count + 1,
                  tls_ver = COALESCE(p_tls_ver(i), tls_ver),
                  alpn = COALESCE(p_alpn(i), alpn),
                  cipher_count = COALESCE(p_cipher_count(i), cipher_count),
                  verdict_hint = COALESCE(p_verdict_hint(i), verdict_hint)
              WHERE ja3_lite = p_ja3_lite(i);
          END;
        END IF;
      EXCEPTION
        WHEN OTHERS THEN
          log_dlq(
            'upsert_tls_fingerprints_bulk',
            SQLCODE,
            SQLERRM,
            '{"ja3_lite":"' || escape_json_string(p_ja3_lite(i)) || '"}'
          );
      END;
    END LOOP;
  END upsert_tls_fingerprints_bulk;

  PROCEDURE insert_connection_session_open_bulk(
    p_session_id            IN t_varchar2_list,
    p_correlation_id        IN t_varchar2_list,
    p_host                  IN t_varchar2_list,
    p_peer_ip               IN t_varchar2_list,
    p_wg_pubkey             IN t_varchar2_list,
    p_device_id             IN t_varchar2_list,
    p_identity_source       IN t_varchar2_list,
    p_peer_hostname         IN t_varchar2_list,
    p_client_ua             IN t_varchar2_list,
    p_tunnel_kind           IN t_varchar2_list,
    p_blocked               IN t_number_list,
    p_tarpitted             IN t_number_list,
    p_verdict               IN t_varchar2_list,
    p_category              IN t_varchar2_list,
    p_obfuscation_profile   IN t_varchar2_list,
    p_tls_ver               IN t_varchar2_list,
    p_alpn                  IN t_varchar2_list,
    p_ja3_lite              IN t_varchar2_list,
    p_resolved_ip           IN t_varchar2_list,
    p_asn_org               IN t_varchar2_list,
    p_reason                IN t_varchar2_list
  ) IS
  BEGIN
    FORALL i IN 1 .. p_session_id.COUNT SAVE EXCEPTIONS
      INSERT INTO connection_sessions (
        session_id, correlation_id, host, peer_ip, wg_pubkey, device_id, identity_source,
        peer_hostname, client_ua, tunnel_kind, opened_at, blocked, tarpitted, verdict,
        category, obfuscation_profile, tls_ver, alpn, ja3_lite, resolved_ip, asn_org,
        reason, created_at
      ) VALUES (
        p_session_id(i), p_correlation_id(i), p_host(i), p_peer_ip(i), p_wg_pubkey(i),
        p_device_id(i), COALESCE(p_identity_source(i), 'unknown'), p_peer_hostname(i),
        p_client_ua(i), p_tunnel_kind(i), SYSTIMESTAMP, NVL(p_blocked(i), 0), NVL(p_tarpitted(i), 0),
        p_verdict(i), p_category(i), p_obfuscation_profile(i), p_tls_ver(i), p_alpn(i),
        p_ja3_lite(i), p_resolved_ip(i), p_asn_org(i), p_reason(i), SYSTIMESTAMP
      );
  EXCEPTION
    WHEN e_bulk_errors THEN
      FOR j IN 1 .. SQL%BULK_EXCEPTIONS.COUNT LOOP
        log_dlq(
          'insert_connection_session_open_bulk',
          SQL%BULK_EXCEPTIONS(j).ERROR_CODE,
          SQLERRM(-SQL%BULK_EXCEPTIONS(j).ERROR_CODE),
          '{"session_id":"' || escape_json_string(p_session_id(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) ||
          '","host":"' || escape_json_string(p_host(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) || '"}'
        );
      END LOOP;
  END insert_connection_session_open_bulk;

  PROCEDURE update_connection_session_close_bulk(
    p_session_id            IN t_varchar2_list,
    p_duration_ms           IN t_number_list,
    p_bytes_up              IN t_number_list,
    p_bytes_down            IN t_number_list,
    p_blocked               IN t_number_list,
    p_tarpitted             IN t_number_list,
    p_tarpit_held_ms        IN t_number_list,
    p_verdict               IN t_varchar2_list,
    p_category              IN t_varchar2_list,
    p_obfuscation_profile   IN t_varchar2_list,
    p_tls_ver               IN t_varchar2_list,
    p_alpn                  IN t_varchar2_list,
    p_ja3_lite              IN t_varchar2_list,
    p_resolved_ip           IN t_varchar2_list,
    p_asn_org               IN t_varchar2_list,
    p_reason                IN t_varchar2_list,
    p_wg_pubkey             IN t_varchar2_list,
    p_device_id             IN t_varchar2_list,
    p_identity_source       IN t_varchar2_list,
    p_peer_hostname         IN t_varchar2_list,
    p_client_ua             IN t_varchar2_list
  ) IS
  BEGIN
    FOR i IN 1 .. p_session_id.COUNT LOOP
      BEGIN
        UPDATE connection_sessions
        SET closed_at = SYSTIMESTAMP,
            duration_ms = p_duration_ms(i),
            bytes_up = NVL(p_bytes_up(i), 0),
            bytes_down = NVL(p_bytes_down(i), 0),
            blocked = NVL(p_blocked(i), 0),
            tarpitted = NVL(p_tarpitted(i), 0),
            tarpit_held_ms = p_tarpit_held_ms(i),
            verdict = p_verdict(i),
            category = p_category(i),
            obfuscation_profile = p_obfuscation_profile(i),
            tls_ver = p_tls_ver(i),
            alpn = p_alpn(i),
            ja3_lite = p_ja3_lite(i),
            resolved_ip = p_resolved_ip(i),
            asn_org = p_asn_org(i),
            reason = p_reason(i),
            wg_pubkey = COALESCE(p_wg_pubkey(i), wg_pubkey),
            device_id = COALESCE(p_device_id(i), device_id),
            identity_source = COALESCE(p_identity_source(i), identity_source),
            peer_hostname = COALESCE(p_peer_hostname(i), peer_hostname),
            client_ua = COALESCE(p_client_ua(i), client_ua)
        WHERE session_id = p_session_id(i);

        IF SQL%ROWCOUNT = 0 THEN
          INSERT INTO connection_sessions_close_dlq (
            session_id, reason, duration_ms, bytes_up, bytes_down, blocked, tarpitted,
            tarpit_held_ms, verdict, category, obfuscation_profile, tls_ver, alpn,
            ja3_lite, resolved_ip, asn_org, wg_pubkey, device_id, identity_source,
            peer_hostname, client_ua
          ) VALUES (
            p_session_id(i), 'session_not_found', p_duration_ms(i), NVL(p_bytes_up(i), 0),
            NVL(p_bytes_down(i), 0), NVL(p_blocked(i), 0), NVL(p_tarpitted(i), 0),
            p_tarpit_held_ms(i), p_verdict(i), p_category(i), p_obfuscation_profile(i),
            p_tls_ver(i), p_alpn(i), p_ja3_lite(i), p_resolved_ip(i), p_asn_org(i),
            p_wg_pubkey(i), p_device_id(i), p_identity_source(i), p_peer_hostname(i), p_client_ua(i)
          );
        END IF;
      EXCEPTION
        WHEN OTHERS THEN
          log_dlq(
            'update_connection_session_close_bulk',
            SQLCODE,
            SQLERRM,
            '{"session_id":"' || escape_json_string(p_session_id(i)) || '"}'
          );
      END;
    END LOOP;
  END update_connection_session_close_bulk;

  PROCEDURE insert_bandwidth_samples_bulk(
    p_sampled_at              IN t_timestamp_list,
    p_wg_pubkey               IN t_varchar2_list,
    p_device_id               IN t_varchar2_list,
    p_bytes_up_delta          IN t_number_list,
    p_bytes_down_delta        IN t_number_list,
    p_sessions_active         IN t_number_list,
    p_blocked_bytes_delta     IN t_number_list,
    p_allowed_bytes_delta     IN t_number_list,
    p_blocked_count_delta     IN t_number_list,
    p_allowed_count_delta     IN t_number_list,
    p_blocked_bytes_is_approx IN t_number_list
  ) IS
  BEGIN
    FORALL i IN 1 .. p_sampled_at.COUNT SAVE EXCEPTIONS
      INSERT INTO bandwidth_samples (
        sampled_at, wg_pubkey, device_id, bytes_up_delta, bytes_down_delta,
        sessions_active, blocked_bytes_delta, allowed_bytes_delta,
        blocked_count_delta, allowed_count_delta, blocked_bytes_is_approx
      ) VALUES (
        p_sampled_at(i), p_wg_pubkey(i), p_device_id(i), NVL(p_bytes_up_delta(i), 0),
        NVL(p_bytes_down_delta(i), 0), NVL(p_sessions_active(i), 0),
        NVL(p_blocked_bytes_delta(i), 0), NVL(p_allowed_bytes_delta(i), 0),
        NVL(p_blocked_count_delta(i), 0), NVL(p_allowed_count_delta(i), 0),
        NVL(p_blocked_bytes_is_approx(i), 1)
      );
  EXCEPTION
    WHEN e_bulk_errors THEN
      FOR j IN 1 .. SQL%BULK_EXCEPTIONS.COUNT LOOP
        log_dlq(
          'insert_bandwidth_samples_bulk',
          SQL%BULK_EXCEPTIONS(j).ERROR_CODE,
          SQLERRM(-SQL%BULK_EXCEPTIONS(j).ERROR_CODE),
          '{"wg_pubkey":"' || escape_json_string(p_wg_pubkey(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) || '"}'
        );
      END LOOP;
  END insert_bandwidth_samples_bulk;

  PROCEDURE insert_wg_peer_samples_bulk(
    p_sampled_at        IN t_timestamp_list,
    p_interface         IN t_varchar2_list,
    p_wg_pubkey         IN t_varchar2_list,
    p_device_id         IN t_varchar2_list,
    p_peer_ip           IN t_varchar2_list,
    p_peer_hostname     IN t_varchar2_list,
    p_last_handshake_at IN t_timestamp_list,
    p_rx_bytes_total    IN t_number_list,
    p_tx_bytes_total    IN t_number_list,
    p_rx_bytes_delta    IN t_number_list,
    p_tx_bytes_delta    IN t_number_list,
    p_sessions_active   IN t_number_list
  ) IS
  BEGIN
    FORALL i IN 1 .. p_sampled_at.COUNT SAVE EXCEPTIONS
      INSERT INTO wg_peer_samples (
        sampled_at, interface, wg_pubkey, device_id, peer_ip, peer_hostname,
        last_handshake_at, rx_bytes_total, tx_bytes_total, rx_bytes_delta,
        tx_bytes_delta, sessions_active
      ) VALUES (
        p_sampled_at(i), p_interface(i), p_wg_pubkey(i), p_device_id(i),
        p_peer_ip(i), p_peer_hostname(i), p_last_handshake_at(i),
        NVL(p_rx_bytes_total(i), 0), NVL(p_tx_bytes_total(i), 0),
        NVL(p_rx_bytes_delta(i), 0), NVL(p_tx_bytes_delta(i), 0),
        NVL(p_sessions_active(i), 0)
      );
  EXCEPTION
    WHEN e_bulk_errors THEN
      FOR j IN 1 .. SQL%BULK_EXCEPTIONS.COUNT LOOP
        log_dlq(
          'insert_wg_peer_samples_bulk',
          SQL%BULK_EXCEPTIONS(j).ERROR_CODE,
          SQLERRM(-SQL%BULK_EXCEPTIONS(j).ERROR_CODE),
          '{"wg_pubkey":"' || escape_json_string(p_wg_pubkey(SQL%BULK_EXCEPTIONS(j).ERROR_INDEX)) || '"}'
        );
      END LOOP;
  END insert_wg_peer_samples_bulk;

  PROCEDURE insert_proxy_event(
    p_event_type           IN VARCHAR2,
    p_host                 IN VARCHAR2,
    p_peer_ip              IN VARCHAR2,
    p_wg_pubkey            IN VARCHAR2,
    p_device_id            IN VARCHAR2,
    p_identity_source      IN VARCHAR2,
    p_peer_hostname        IN VARCHAR2,
    p_client_ua            IN VARCHAR2,
    p_bytes_up             IN NUMBER,
    p_bytes_down           IN NUMBER,
    p_status_code          IN NUMBER,
    p_blocked              IN NUMBER,
    p_obfuscation_profile  IN VARCHAR2,
    p_correlation_id       IN VARCHAR2,
    p_parent_event_id      IN VARCHAR2,
    p_event_sequence       IN NUMBER,
    p_duration_ms          IN NUMBER,
    p_reason               IN VARCHAR2,
    p_raw_json             IN CLOB
  ) IS
    l_event_type          t_varchar2_list := t_varchar2_list(p_event_type);
    l_host                t_varchar2_list := t_varchar2_list(p_host);
    l_peer_ip             t_varchar2_list := t_varchar2_list(p_peer_ip);
    l_wg_pubkey           t_varchar2_list := t_varchar2_list(p_wg_pubkey);
    l_device_id           t_varchar2_list := t_varchar2_list(p_device_id);
    l_identity_source     t_varchar2_list := t_varchar2_list(p_identity_source);
    l_peer_hostname       t_varchar2_list := t_varchar2_list(p_peer_hostname);
    l_client_ua           t_varchar2_list := t_varchar2_list(p_client_ua);
    l_bytes_up            t_number_list := t_number_list(p_bytes_up);
    l_bytes_down          t_number_list := t_number_list(p_bytes_down);
    l_status_code         t_number_list := t_number_list(p_status_code);
    l_blocked             t_number_list := t_number_list(p_blocked);
    l_obfuscation_profile t_varchar2_list := t_varchar2_list(p_obfuscation_profile);
    l_correlation_id      t_varchar2_list := t_varchar2_list(p_correlation_id);
    l_parent_event_id     t_varchar2_list := t_varchar2_list(p_parent_event_id);
    l_event_sequence      t_number_list := t_number_list(p_event_sequence);
    l_duration_ms         t_number_list := t_number_list(p_duration_ms);
    l_reason              t_varchar2_list := t_varchar2_list(p_reason);
    l_raw_json            t_clob_list := t_clob_list(p_raw_json);
  BEGIN
    insert_proxy_events_bulk(l_event_type, l_host, l_peer_ip, l_wg_pubkey, l_device_id,
      l_identity_source, l_peer_hostname, l_client_ua, l_bytes_up, l_bytes_down,
      l_status_code, l_blocked, l_obfuscation_profile, l_correlation_id, l_parent_event_id,
      l_event_sequence, l_duration_ms, l_reason, l_raw_json);
  END insert_proxy_event;

  PROCEDURE insert_payload_audit(
    p_correlation_id  IN VARCHAR2,
    p_host            IN VARCHAR2,
    p_direction       IN VARCHAR2,
    p_byte_offset     IN NUMBER,
    p_payload_bytes   IN RAW,
    p_content_type    IN VARCHAR2,
    p_http_method     IN VARCHAR2,
    p_http_status     IN NUMBER,
    p_http_path       IN VARCHAR2,
    p_is_encrypted    IN NUMBER,
    p_truncated       IN NUMBER,
    p_peer_ip         IN VARCHAR2,
    p_notes           IN VARCHAR2
  ) IS
  BEGIN
    insert_payload_audit_bulk(
      t_varchar2_list(p_correlation_id), t_varchar2_list(p_host), t_varchar2_list(p_direction),
      t_number_list(p_byte_offset), t_raw_list(p_payload_bytes),
      t_varchar2_list(p_content_type), t_varchar2_list(p_http_method), t_number_list(p_http_status),
      t_varchar2_list(p_http_path), t_number_list(p_is_encrypted), t_number_list(p_truncated),
      t_varchar2_list(p_peer_ip), t_varchar2_list(p_notes)
    );
  END insert_payload_audit;

  PROCEDURE upsert_tls_fingerprint(
    p_ja3_lite      IN VARCHAR2,
    p_tls_ver       IN VARCHAR2,
    p_alpn          IN VARCHAR2,
    p_cipher_count  IN NUMBER,
    p_verdict_hint  IN VARCHAR2
  ) IS
  BEGIN
    upsert_tls_fingerprints_bulk(
      t_varchar2_list(p_ja3_lite), t_varchar2_list(p_tls_ver), t_varchar2_list(p_alpn),
      t_number_list(p_cipher_count), t_varchar2_list(p_verdict_hint)
    );
  END upsert_tls_fingerprint;

  PROCEDURE insert_connection_session_open(
    p_session_id            IN VARCHAR2,
    p_correlation_id        IN VARCHAR2,
    p_host                  IN VARCHAR2,
    p_peer_ip               IN VARCHAR2,
    p_wg_pubkey             IN VARCHAR2,
    p_device_id             IN VARCHAR2,
    p_identity_source       IN VARCHAR2,
    p_peer_hostname         IN VARCHAR2,
    p_client_ua             IN VARCHAR2,
    p_tunnel_kind           IN VARCHAR2,
    p_blocked               IN NUMBER,
    p_tarpitted             IN NUMBER,
    p_verdict               IN VARCHAR2,
    p_category              IN VARCHAR2,
    p_obfuscation_profile   IN VARCHAR2,
    p_tls_ver               IN VARCHAR2,
    p_alpn                  IN VARCHAR2,
    p_ja3_lite              IN VARCHAR2,
    p_resolved_ip           IN VARCHAR2,
    p_asn_org               IN VARCHAR2,
    p_reason                IN VARCHAR2
  ) IS
  BEGIN
    insert_connection_session_open_bulk(
      t_varchar2_list(p_session_id), t_varchar2_list(p_correlation_id), t_varchar2_list(p_host),
      t_varchar2_list(p_peer_ip), t_varchar2_list(p_wg_pubkey), t_varchar2_list(p_device_id),
      t_varchar2_list(p_identity_source), t_varchar2_list(p_peer_hostname),
      t_varchar2_list(p_client_ua), t_varchar2_list(p_tunnel_kind), t_number_list(p_blocked),
      t_number_list(p_tarpitted), t_varchar2_list(p_verdict), t_varchar2_list(p_category),
      t_varchar2_list(p_obfuscation_profile), t_varchar2_list(p_tls_ver), t_varchar2_list(p_alpn),
      t_varchar2_list(p_ja3_lite), t_varchar2_list(p_resolved_ip), t_varchar2_list(p_asn_org),
      t_varchar2_list(p_reason)
    );
  END insert_connection_session_open;

  PROCEDURE update_connection_session_close(
    p_session_id            IN VARCHAR2,
    p_duration_ms           IN NUMBER,
    p_bytes_up              IN NUMBER,
    p_bytes_down            IN NUMBER,
    p_blocked               IN NUMBER,
    p_tarpitted             IN NUMBER,
    p_tarpit_held_ms        IN NUMBER,
    p_verdict               IN VARCHAR2,
    p_category              IN VARCHAR2,
    p_obfuscation_profile   IN VARCHAR2,
    p_tls_ver               IN VARCHAR2,
    p_alpn                  IN VARCHAR2,
    p_ja3_lite              IN VARCHAR2,
    p_resolved_ip           IN VARCHAR2,
    p_asn_org               IN VARCHAR2,
    p_reason                IN VARCHAR2,
    p_wg_pubkey             IN VARCHAR2,
    p_device_id             IN VARCHAR2,
    p_identity_source       IN VARCHAR2,
    p_peer_hostname         IN VARCHAR2,
    p_client_ua             IN VARCHAR2
  ) IS
  BEGIN
    update_connection_session_close_bulk(
      t_varchar2_list(p_session_id), t_number_list(p_duration_ms), t_number_list(p_bytes_up),
      t_number_list(p_bytes_down), t_number_list(p_blocked), t_number_list(p_tarpitted),
      t_number_list(p_tarpit_held_ms), t_varchar2_list(p_verdict), t_varchar2_list(p_category),
      t_varchar2_list(p_obfuscation_profile), t_varchar2_list(p_tls_ver), t_varchar2_list(p_alpn),
      t_varchar2_list(p_ja3_lite), t_varchar2_list(p_resolved_ip), t_varchar2_list(p_asn_org),
      t_varchar2_list(p_reason), t_varchar2_list(p_wg_pubkey), t_varchar2_list(p_device_id),
      t_varchar2_list(p_identity_source), t_varchar2_list(p_peer_hostname), t_varchar2_list(p_client_ua)
    );
  END update_connection_session_close;

  PROCEDURE insert_bandwidth_sample(
    p_sampled_at              IN TIMESTAMP,
    p_wg_pubkey               IN VARCHAR2,
    p_device_id               IN VARCHAR2,
    p_bytes_up_delta          IN NUMBER,
    p_bytes_down_delta        IN NUMBER,
    p_sessions_active         IN NUMBER,
    p_blocked_bytes_delta     IN NUMBER,
    p_allowed_bytes_delta     IN NUMBER,
    p_blocked_count_delta     IN NUMBER,
    p_allowed_count_delta     IN NUMBER,
    p_blocked_bytes_is_approx IN NUMBER
  ) IS
  BEGIN
    insert_bandwidth_samples_bulk(
      t_timestamp_list(p_sampled_at), t_varchar2_list(p_wg_pubkey), t_varchar2_list(p_device_id),
      t_number_list(p_bytes_up_delta), t_number_list(p_bytes_down_delta), t_number_list(p_sessions_active),
      t_number_list(p_blocked_bytes_delta), t_number_list(p_allowed_bytes_delta),
      t_number_list(p_blocked_count_delta), t_number_list(p_allowed_count_delta),
      t_number_list(p_blocked_bytes_is_approx)
    );
  END insert_bandwidth_sample;

  PROCEDURE insert_wg_peer_sample(
    p_sampled_at        IN TIMESTAMP,
    p_interface         IN VARCHAR2,
    p_wg_pubkey         IN VARCHAR2,
    p_device_id         IN VARCHAR2,
    p_peer_ip           IN VARCHAR2,
    p_peer_hostname     IN VARCHAR2,
    p_last_handshake_at IN TIMESTAMP,
    p_rx_bytes_total    IN NUMBER,
    p_tx_bytes_total    IN NUMBER,
    p_rx_bytes_delta    IN NUMBER,
    p_tx_bytes_delta    IN NUMBER,
    p_sessions_active   IN NUMBER
  ) IS
  BEGIN
    insert_wg_peer_samples_bulk(
      t_timestamp_list(p_sampled_at), t_varchar2_list(p_interface), t_varchar2_list(p_wg_pubkey),
      t_varchar2_list(p_device_id), t_varchar2_list(p_peer_ip), t_varchar2_list(p_peer_hostname),
      t_timestamp_list(p_last_handshake_at), t_number_list(p_rx_bytes_total), t_number_list(p_tx_bytes_total),
      t_number_list(p_rx_bytes_delta), t_number_list(p_tx_bytes_delta), t_number_list(p_sessions_active)
    );
  END insert_wg_peer_sample;
END pkg_proxy_bulk;
/

COMMIT;
