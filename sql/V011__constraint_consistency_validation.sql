-- V011: payload_audit payload_b64 -> payload_bytes backfill (DML only).

DECLARE
  v_payload_b64_count INTEGER := 0;
  v_payload_b64_type VARCHAR2(128);
  v_oversized_b64_count INTEGER := 0;
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
            AND LENGTH(payload_b64) <= 10924
        ]';
      END IF;
      COMMIT;
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
END;
/
