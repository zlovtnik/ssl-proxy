-- V011: payload_audit payload_b64 -> payload_bytes backfill (DML only).

DECLARE
  v_payload_b64_count INTEGER := 0;
  v_payload_b64_type VARCHAR2(128);
  v_oversized_b64_count INTEGER := 0;
  v_rows_processed INTEGER := 0;
  v_batch_size CONSTANT PLS_INTEGER := 500;
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
        SELECT COUNT(*) INTO v_oversized_b64_count
        FROM payload_audit
        WHERE payload_bytes IS NULL
          AND payload_b64 IS NOT NULL
          AND DBMS_LOB.GETLENGTH(payload_b64) > 10924;

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

        LOOP
          v_rows_processed := 0;
          FOR rec IN (
            SELECT rid, payload_b64
            FROM (
              SELECT ROWID AS rid, payload_b64
              FROM payload_audit
              WHERE payload_bytes IS NULL
                AND payload_b64 IS NOT NULL
                AND DBMS_LOB.GETLENGTH(payload_b64) <= 10924
              ORDER BY ROWID
            )
            WHERE ROWNUM <= v_batch_size
          ) LOOP
            DECLARE
              v_payload_b64 CLOB;
              v_amount PLS_INTEGER;
              v_chunk VARCHAR2(32767);
              v_raw RAW(32767);
            BEGIN
              v_payload_b64 := rec.payload_b64;
              v_amount := DBMS_LOB.GETLENGTH(v_payload_b64);
              IF v_amount = 0 THEN
                CONTINUE;
              END IF;

              DBMS_LOB.OPEN(v_payload_b64, DBMS_LOB.LOB_READONLY);
              DBMS_LOB.READ(v_payload_b64, v_amount, 1, v_chunk);
              DBMS_LOB.CLOSE(v_payload_b64);

              v_raw := UTL_RAW.CAST_TO_RAW(v_chunk);
              UPDATE payload_audit
              SET payload_bytes = UTL_ENCODE.BASE64_DECODE(v_raw)
              WHERE ROWID = rec.rid;
              v_rows_processed := v_rows_processed + SQL%ROWCOUNT;
            EXCEPTION
              WHEN OTHERS THEN
                IF DBMS_LOB.ISOPEN(v_payload_b64) = 1 THEN
                  DBMS_LOB.CLOSE(v_payload_b64);
                END IF;
                RAISE;
            END;
          END LOOP;
          EXIT WHEN v_rows_processed = 0;
        END LOOP;
      ELSE
        SELECT COUNT(*) INTO v_oversized_b64_count
        FROM payload_audit
        WHERE payload_bytes IS NULL
          AND payload_b64 IS NOT NULL
          AND LENGTH(payload_b64) > 4000;

        IF v_oversized_b64_count > 0 THEN
          log_migration_audit(
            p_migration_name => 'V011__constraint_consistency_validation.sql',
            p_sqlcode => -20015,
            p_sqlerrm => 'payload_audit payload_b64 exceeds safe VARCHAR2 backfill limit',
            p_context => 'payload_audit payload_b64 backfill blocked'
          );
          RAISE_APPLICATION_ERROR(
            -20015,
            'Cannot backfill payload_audit.payload_bytes: ' ||
            TO_CHAR(v_oversized_b64_count) ||
            ' payload_b64 rows exceed safe VARCHAR2 decode limit'
          );
        END IF;

        LOOP
          UPDATE payload_audit
          SET payload_bytes = UTL_ENCODE.BASE64_DECODE(
            UTL_RAW.CAST_TO_RAW(payload_b64)
          )
          WHERE ROWID IN (
            SELECT rid
            FROM (
              SELECT ROWID AS rid
              FROM payload_audit
              WHERE payload_bytes IS NULL
                AND payload_b64 IS NOT NULL
                AND LENGTH(payload_b64) <= 4000
              ORDER BY ROWID
            )
            WHERE ROWNUM <= v_batch_size
          );
          v_rows_processed := SQL%ROWCOUNT;
          EXIT WHEN v_rows_processed = 0;
        END LOOP;
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
