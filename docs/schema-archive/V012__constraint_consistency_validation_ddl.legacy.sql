-- V012: normalize FK/column constraints and validate payload_audit hardening constraints.

DECLARE
  v_delete_rule VARCHAR2(16);
BEGIN
  BEGIN
    SELECT delete_rule INTO v_delete_rule
    FROM user_constraints
    WHERE table_name = 'WG_PEER_SAMPLES'
      AND constraint_name = 'WGPS_DEVICE_FK';

    IF v_delete_rule != 'CASCADE' THEN
      BEGIN
        EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples DROP CONSTRAINT wgps_device_fk_swap';
      EXCEPTION
        WHEN OTHERS THEN
          IF SQLCODE != -2443 THEN
            RAISE;
          END IF;
      END;

      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples ADD CONSTRAINT wgps_device_fk_swap FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE DISABLE NOVALIDATE';
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples DROP CONSTRAINT wgps_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples RENAME CONSTRAINT wgps_device_fk_swap TO wgps_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples ENABLE VALIDATE CONSTRAINT wgps_device_fk';
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
      BEGIN
        EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples DROP CONSTRAINT bws_device_fk_swap';
      EXCEPTION
        WHEN OTHERS THEN
          IF SQLCODE != -2443 THEN
            RAISE;
          END IF;
      END;

      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples ADD CONSTRAINT bws_device_fk_swap FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE DISABLE NOVALIDATE';
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples DROP CONSTRAINT bws_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples RENAME CONSTRAINT bws_device_fk_swap TO bws_device_fk';
      EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples ENABLE VALIDATE CONSTRAINT bws_device_fk';
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
  v_char_used CHAR(1);
  v_char_length NUMBER;
BEGIN
  SELECT data_length, char_used, char_length
    INTO v_data_length, v_char_used, v_char_length
  FROM user_tab_columns
  WHERE table_name = 'CONNECTION_SESSIONS'
    AND column_name = 'SESSION_ID';

  IF (v_char_used = 'C' AND v_char_length < 36) OR
     ((v_char_used = 'B' OR v_char_used IS NULL) AND v_data_length < 36) THEN
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
  v_remaining_backfill_count INTEGER := 0;
  v_both_null_count INTEGER := 0;
BEGIN
  SELECT COUNT(*) INTO v_remaining_backfill_count
  FROM payload_audit
  WHERE payload_bytes IS NULL
    AND payload_b64 IS NOT NULL;
  IF v_remaining_backfill_count > 0 THEN
    log_migration_audit(
      p_migration_name => 'V012__constraint_consistency_validation_ddl.sql',
      p_sqlcode => -20013,
      p_sqlerrm => 'payload_audit has rows with payload_b64 but missing payload_bytes backfill',
      p_context => 'payload_audit_payload_present_ck validation blocked'
    );
    RAISE_APPLICATION_ERROR(
      -20013,
      'Cannot validate payload_audit_payload_present_ck: ' ||
      TO_CHAR(v_remaining_backfill_count) ||
      ' rows with payload_b64 are missing backfilled payload_bytes'
    );
  END IF;

  SELECT COUNT(*) INTO v_both_null_count
  FROM payload_audit
  WHERE payload_bytes IS NULL
    AND payload_b64 IS NULL;
  IF v_both_null_count > 0 THEN
    log_migration_audit(
      p_migration_name => 'V012__constraint_consistency_validation_ddl.sql',
      p_sqlcode => -20016,
      p_sqlerrm => 'payload_audit has rows with both payload_bytes and payload_b64 NULL',
      p_context => 'payload_audit_payload_present_ck validation blocked'
    );
    RAISE_APPLICATION_ERROR(
      -20016,
      'Cannot validate payload_audit_payload_present_ck: ' ||
      TO_CHAR(v_both_null_count) ||
      ' rows have both payload_bytes and payload_b64 NULL'
    );
  END IF;

  BEGIN
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
  EXCEPTION
    WHEN OTHERS THEN
      log_migration_audit(
        p_migration_name => 'V012__constraint_consistency_validation_ddl.sql',
        p_sqlcode => SQLCODE,
        p_sqlerrm => SQLERRM,
        p_context => 'payload_audit_payload_present_ck DDL failed'
      );
      RAISE;
  END;
END;
/
