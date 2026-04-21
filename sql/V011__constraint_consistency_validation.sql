-- V011: normalize device FK delete rules and validate hardening constraints.

DECLARE
  v_delete_rule VARCHAR2(16);
BEGIN
  BEGIN
    SELECT delete_rule INTO v_delete_rule
    FROM user_constraints
    WHERE table_name = 'WG_PEER_SAMPLES'
      AND constraint_name = 'WGPS_DEVICE_FK';

    IF v_delete_rule != 'CASCADE' THEN
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples DROP CONSTRAINT wgps_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples ADD CONSTRAINT wgps_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
    END IF;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples ADD CONSTRAINT wgps_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
  END;

  SELECT delete_rule INTO v_delete_rule
  FROM user_constraints
  WHERE table_name = 'WG_PEER_SAMPLES'
    AND constraint_name = 'WGPS_DEVICE_FK';
  IF v_delete_rule != 'CASCADE' THEN
    RAISE_APPLICATION_ERROR(-20011, 'wgps_device_fk must use ON DELETE CASCADE');
  END IF;
END;
/

DECLARE
  v_delete_rule VARCHAR2(16);
BEGIN
  BEGIN
    SELECT delete_rule INTO v_delete_rule
    FROM user_constraints
    WHERE table_name = 'BANDWIDTH_SAMPLES'
      AND constraint_name = 'BWS_DEVICE_FK';

    IF v_delete_rule != 'CASCADE' THEN
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples DROP CONSTRAINT bws_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples ADD CONSTRAINT bws_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
    END IF;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples ADD CONSTRAINT bws_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
  END;

  SELECT delete_rule INTO v_delete_rule
  FROM user_constraints
  WHERE table_name = 'BANDWIDTH_SAMPLES'
    AND constraint_name = 'BWS_DEVICE_FK';
  IF v_delete_rule != 'CASCADE' THEN
    RAISE_APPLICATION_ERROR(-20012, 'bws_device_fk must use ON DELETE CASCADE');
  END IF;
END;
/

DECLARE
  v_data_length NUMBER;
BEGIN
  SELECT data_length INTO v_data_length
  FROM user_tab_columns
  WHERE table_name = 'CONNECTION_SESSIONS'
    AND column_name = 'SESSION_ID';

  IF v_data_length < 36 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE connection_sessions MODIFY (session_id VARCHAR2(36))';
  END IF;
EXCEPTION
  WHEN NO_DATA_FOUND THEN
    RAISE_APPLICATION_ERROR(
      -20014,
      'Cannot validate constraint consistency: CONNECTION_SESSIONS.SESSION_ID was not found'
    );
END;
/

DECLARE
  v_payload_b64_count INTEGER := 0;
  v_payload_b64_type VARCHAR2(128);
  v_oversized_b64_count INTEGER := 0;
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
          SELECT COUNT(*)
          FROM payload_audit
          WHERE payload_bytes IS NULL
            AND payload_b64 IS NOT NULL
            AND DBMS_LOB.GETLENGTH(payload_b64) > 10924
        ]' INTO v_oversized_b64_count;
        IF v_oversized_b64_count > 0 THEN
          log_migration_audit(
            p_migration_name => 'V011__constraint_consistency_validation.sql',
            p_sqlcode => -20015,
            p_sqlerrm => 'payload_audit payload_b64 exceeds RAW(8192) backfill limit',
            p_context => 'payload_audit payload_b64 backfill blocked'
          );
          RAISE_APPLICATION_ERROR(
            -20015,
            'Cannot backfill payload_audit.payload_bytes: ' ||
            TO_CHAR(v_oversized_b64_count) ||
            ' payload_b64 CLOB rows exceed RAW(8192) capacity'
          );
        END IF;
        EXECUTE IMMEDIATE q'[
          UPDATE payload_audit
          SET payload_bytes = UTL_ENCODE.BASE64_DECODE(
            UTL_RAW.CAST_TO_RAW(DBMS_LOB.SUBSTR(payload_b64, 10924, 1))
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
    EXCEPTION
      WHEN OTHERS THEN
        ROLLBACK;
        log_migration_audit(
          p_migration_name => 'V011__constraint_consistency_validation.sql',
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
      p_migration_name => 'V011__constraint_consistency_validation.sql',
      p_sqlcode => -20013,
      p_sqlerrm => 'payload_audit has rows without payload_bytes',
      p_context => 'payload_audit_payload_present_ck validation blocked'
    );
    RAISE_APPLICATION_ERROR(
      -20013,
      'Cannot validate payload_audit_payload_present_ck: ' ||
      TO_CHAR(v_remaining_null_count) || ' rows have NULL payload_bytes'
    );
  END IF;

  BEGIN
    EXECUTE IMMEDIATE 'ALTER TABLE payload_audit DROP CONSTRAINT payload_audit_payload_present_ck';
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE != -2443 THEN
        RAISE;
      END IF;
  END;

  EXECUTE IMMEDIATE q'[
    ALTER TABLE payload_audit
    ADD CONSTRAINT payload_audit_payload_present_ck
    CHECK (payload_bytes IS NOT NULL)
    ENABLE VALIDATE
  ]';
END;
/

COMMIT;
