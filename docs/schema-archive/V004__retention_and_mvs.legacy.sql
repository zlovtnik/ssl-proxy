-- V004: Retention, partitioning helpers, and materialized views
-- Run after V002 and V003. All idempotent.

-- ── 1. PROXY_EVENTS — add event_time if missing (used by V_HOURLY_TRAFFIC) ──
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'EVENT_TIME';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'ALTER TABLE proxy_events ADD (event_time TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL)';
  END IF;
END;
/

-- ── 2. PROXY_EVENTS — index on event_time for range scans ───────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_EVENT_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_event_time_idx ON proxy_events(event_time)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_HOST_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_host_time_idx ON proxy_events(host, event_time)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_BLOCKED_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_blocked_idx ON proxy_events(blocked, event_time)';
  END IF;
END;
/

-- ── 3. DATA_RETENTION_POLICY ─────────────────────────────────────────────────
-- Configuration table so retention periods are data-driven, not hardcoded.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'DATA_RETENTION_POLICY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE data_retention_policy (
        table_name        VARCHAR2(128)  NOT NULL,
        retention_days    NUMBER(6,0)    NOT NULL,
        date_column       VARCHAR2(128)  NOT NULL,
        enabled           NUMBER(1,0)    DEFAULT 1 NOT NULL,
        last_purge_at     TIMESTAMP,
        last_purge_rows   NUMBER(12,0),
        notes             VARCHAR2(512),
        CONSTRAINT drp_pk PRIMARY KEY (table_name)
      )
    ';
    -- Seed default retention rules
    EXECUTE IMMEDIATE q'[
      INSERT ALL
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('PROXY_EVENTS',       90,  'EVENT_TIME',   '90-day rolling window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('PAYLOAD_AUDIT',      30,  'CAPTURED_AT',  '30-day compliance window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('CONNECTION_SESSIONS',90,  'OPENED_AT',    '90-day rolling window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('BLOCKLIST_AUDIT',   365,  'REFRESHED_AT', '1-year audit trail')
      SELECT 1 FROM DUAL
    ]';
  END IF;
END;
/

MERGE INTO data_retention_policy t
USING (
  SELECT 'WG_PEER_SAMPLES' AS table_name, 30 AS retention_days, 'SAMPLED_AT' AS date_column,
         '30-day raw WireGuard peer samples' AS notes
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

MERGE INTO data_retention_policy t
USING (
  SELECT 'BANDWIDTH_SAMPLES' AS table_name, 30 AS retention_days, 'SAMPLED_AT' AS date_column,
         '30-day raw per-minute bandwidth samples' AS notes
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
  FROM user_tables WHERE table_name = 'MIGRATION_AUDIT_LOG';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE migration_audit_log (
        id              NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        logged_at       TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
        migration_name  VARCHAR2(128) NOT NULL,
        sqlcode         NUMBER,
        sqlerrm         VARCHAR2(4000),
        context         VARCHAR2(512)
      )
    ';
  END IF;
END;
/

CREATE OR REPLACE PROCEDURE log_migration_audit(
  p_migration_name IN VARCHAR2,
  p_sqlcode IN NUMBER,
  p_sqlerrm IN VARCHAR2,
  p_context IN VARCHAR2 DEFAULT NULL
) AS
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  INSERT INTO migration_audit_log (migration_name, sqlcode, sqlerrm, context)
  VALUES (
    p_migration_name,
    p_sqlcode,
    SUBSTR(p_sqlerrm, 1, 4000),
    SUBSTR(p_context, 1, 512)
  );
  COMMIT;
EXCEPTION
  WHEN OTHERS THEN NULL;
END;
/

-- ── 4. PURGE_OLD_EVENTS procedure ────────────────────────────────────────────
-- Call from a DBMS_SCHEDULER job (or manually) to enforce retention policy.
CREATE OR REPLACE PROCEDURE purge_old_events AS
  v_sql    VARCHAR2(1024);
  v_rows   NUMBER;
  v_batch_rows NUMBER;
  v_cutoff TIMESTAMP;
  v_table_name VARCHAR2(128);
  v_date_column VARCHAR2(128);
  c_batch_size CONSTANT PLS_INTEGER := 1000;
BEGIN
  FOR rec IN (
    SELECT table_name, retention_days, date_column
    FROM data_retention_policy
    WHERE enabled = 1
  ) LOOP
    v_cutoff := SYSTIMESTAMP - rec.retention_days;
    v_table_name := DBMS_ASSERT.SIMPLE_SQL_NAME(rec.table_name);
    v_date_column := DBMS_ASSERT.SIMPLE_SQL_NAME(rec.date_column);
    v_sql := 'DELETE FROM ' || v_table_name ||
             ' WHERE ' || v_date_column || ' < :1 AND ROWNUM <= :2';
    v_rows := 0;

    LOOP
      BEGIN
        EXECUTE IMMEDIATE v_sql USING v_cutoff, c_batch_size;
        v_batch_rows := SQL%ROWCOUNT;
      EXCEPTION
        WHEN OTHERS THEN
          log_migration_audit(
            p_migration_name => 'V004__retention_and_mvs.sql',
            p_sqlcode => SQLCODE,
            p_sqlerrm => SQLERRM,
            p_context => 'Delete failed for: ' || v_table_name
          );
          v_batch_rows := 0;
          EXIT;
      END;
      v_rows := v_rows + v_batch_rows;
      COMMIT;
      EXIT WHEN v_batch_rows = 0;
    END LOOP;

    UPDATE data_retention_policy
    SET last_purge_at   = SYSTIMESTAMP,
        last_purge_rows = v_rows
    WHERE table_name = rec.table_name;
    COMMIT;
  END LOOP;
END;
/

-- ── 5. MATERIALIZED VIEW: MV_DAILY_BLOCKED ───────────────────────────────────
-- Pre-aggregated daily blocking stats. Refresh nightly via scheduler.
-- Dropped and recreated only if not present (no ALTER MV needed for schema).
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_objects WHERE object_type = 'MATERIALIZED VIEW'
  AND object_name = 'MV_DAILY_BLOCKED';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_daily_blocked
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      ENABLE QUERY REWRITE
      AS
      SELECT
        TRUNC(updated_at) AS day_dt,
        category,
        verdict,
        COUNT(*)          AS host_count,
        SUM(blocked_attempts) AS total_blocks,
        SUM(blocked_bytes)    AS total_bytes,
        SUM(tarpit_held_ms)   AS total_tarpit_ms,
        AVG(risk_score)       AS avg_risk_score,
        MAX(risk_score)       AS max_risk_score
      FROM blocked_events
      GROUP BY TRUNC(updated_at), category, verdict
    ]';
  END IF;
END;
/

-- ── 6. MATERIALIZED VIEW: MV_PEER_IP_SUMMARY ────────────────────────────────
-- Per-client-IP session summary. Useful for detecting compromised devices.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_objects WHERE object_type = 'MATERIALIZED VIEW'
  AND object_name = 'MV_PEER_IP_SUMMARY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_peer_ip_summary
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
      SELECT
        peer_ip,
        COUNT(*)                                    AS total_sessions,
        SUM(CASE WHEN blocked   = 1 THEN 1 ELSE 0 END) AS blocked_sessions,
        SUM(CASE WHEN tarpitted = 1 THEN 1 ELSE 0 END) AS tarpitted_sessions,
        SUM(bytes_up)                               AS total_bytes_up,
        SUM(bytes_down)                             AS total_bytes_down,
        COUNT(DISTINCT host)                        AS distinct_hosts,
        MIN(opened_at)                              AS first_seen,
        MAX(opened_at)                              AS last_seen,
        -- Most-used tunnel kind
        STATS_MODE(tunnel_kind)                     AS primary_tunnel_kind
      FROM connection_sessions
      WHERE peer_ip IS NOT NULL
      GROUP BY peer_ip
    ]';
  END IF;
END;
/

-- ── 7. DBMS_SCHEDULER job for nightly purge ──────────────────────────────────
-- Only created if it doesn't exist already.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_scheduler_jobs
  WHERE job_name = 'JOB_PURGE_OLD_EVENTS';
  IF v_count = 0 THEN
    DBMS_SCHEDULER.CREATE_JOB(
      job_name        => 'JOB_PURGE_OLD_EVENTS',
      job_type        => 'STORED_PROCEDURE',
      job_action      => 'PURGE_OLD_EVENTS',
      start_date      => SYSTIMESTAMP,
      repeat_interval => 'FREQ=DAILY;BYHOUR=2;BYMINUTE=0',
      enabled         => TRUE,
      comments        => 'Nightly data retention purge per DATA_RETENTION_POLICY table'
    );
  END IF;
END;
/

-- ── 8. DBMS_SCHEDULER job for MV refresh ─────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_scheduler_jobs
  WHERE job_name = 'JOB_REFRESH_MVS';
  IF v_count = 0 THEN
    DBMS_SCHEDULER.CREATE_JOB(
      job_name        => 'JOB_REFRESH_MVS',
      job_type        => 'PLSQL_BLOCK',
      job_action      => q'[BEGIN
        DECLARE
          v_exists INTEGER;
        BEGIN
          SELECT COUNT(*) INTO v_exists FROM user_objects
          WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_BLOCKED';
          IF v_exists = 1 THEN
            DBMS_MVIEW.REFRESH('MV_DAILY_BLOCKED', 'C');
          END IF;

          SELECT COUNT(*) INTO v_exists FROM user_objects
          WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_PEER_IP_SUMMARY';
          IF v_exists = 1 THEN
            DBMS_MVIEW.REFRESH('MV_PEER_IP_SUMMARY', 'C');
          END IF;

          SELECT COUNT(*) INTO v_exists FROM user_objects
          WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_HOURLY_BANDWIDTH';
          IF v_exists = 1 THEN
            DBMS_MVIEW.REFRESH('MV_HOURLY_BANDWIDTH', 'C');
          END IF;

          SELECT COUNT(*) INTO v_exists FROM user_objects
          WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_PEER_STATS';
          IF v_exists = 1 THEN
            DBMS_MVIEW.REFRESH('MV_DAILY_PEER_STATS', 'C');
          END IF;
        END;
      END;]',
      start_date      => SYSTIMESTAMP,
      repeat_interval => 'FREQ=DAILY;BYHOUR=3;BYMINUTE=0',
      enabled         => TRUE,
      comments        => 'Nightly refresh of pre-aggregated materialized views'
    );
  END IF;
END;
/

BEGIN
  DBMS_SCHEDULER.SET_ATTRIBUTE(
    name      => 'JOB_REFRESH_MVS',
    attribute => 'job_action',
    value     => q'[BEGIN
      DECLARE
        v_exists INTEGER;
      BEGIN
        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_BLOCKED';
        IF v_exists = 1 THEN
          DBMS_MVIEW.REFRESH('MV_DAILY_BLOCKED', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_PEER_IP_SUMMARY';
        IF v_exists = 1 THEN
          DBMS_MVIEW.REFRESH('MV_PEER_IP_SUMMARY', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_HOURLY_BANDWIDTH';
        IF v_exists = 1 THEN
          DBMS_MVIEW.REFRESH('MV_HOURLY_BANDWIDTH', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_PEER_STATS';
        IF v_exists = 1 THEN
          DBMS_MVIEW.REFRESH('MV_DAILY_PEER_STATS', 'C');
        END IF;
      END;
    END;]'
  );
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE = -27475 THEN
      log_migration_audit(
        p_migration_name => 'V004__retention_and_mvs.sql',
        p_sqlcode => SQLCODE,
        p_sqlerrm => SQLERRM,
        p_context => 'JOB_REFRESH_MVS not present while updating job action'
      );
    ELSE
      log_migration_audit(
        p_migration_name => 'V004__retention_and_mvs.sql',
        p_sqlcode => SQLCODE,
        p_sqlerrm => SQLERRM,
        p_context => 'Failed to update JOB_REFRESH_MVS'
      );
      RAISE_APPLICATION_ERROR(
        -20004,
        'V004 JOB_REFRESH_MVS update failed (' || TO_CHAR(SQLCODE) || '): ' || SQLERRM
      );
    END IF;
END;
/

COMMIT;
