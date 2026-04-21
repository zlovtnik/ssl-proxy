-- V008: WireGuard peer sampling, bandwidth rollups, and retention wiring.
-- Safe to rerun: all DDL is guarded by existence checks.

-- ── 1. WG_PEER_SAMPLES ──────────────────────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables
  WHERE table_name = 'WG_PEER_SAMPLES';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE wg_peer_samples (
        sample_id         NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        sampled_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        interface         VARCHAR2(16)   NOT NULL,
        wg_pubkey         VARCHAR2(64)   NOT NULL,
        device_id         VARCHAR2(36),
        peer_ip           VARCHAR2(45),
        peer_hostname     VARCHAR2(253),
        last_handshake_at TIMESTAMP,
        rx_bytes_total    NUMBER(20,0)   DEFAULT 0 NOT NULL,
        tx_bytes_total    NUMBER(20,0)   DEFAULT 0 NOT NULL,
        rx_bytes_delta    NUMBER(20,0)   DEFAULT 0 NOT NULL,
        tx_bytes_delta    NUMBER(20,0)   DEFAULT 0 NOT NULL,
        sessions_active   NUMBER(10,0)   DEFAULT 0 NOT NULL,
        created_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL
      )
    ]';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_constraints
  WHERE constraint_name = 'WGPS_DEVICE_FK';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples ADD CONSTRAINT wgps_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'WGPS_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX wgps_time_idx ON wg_peer_samples(sampled_at DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'WGPS_PUBKEY_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX wgps_pubkey_time_idx ON wg_peer_samples(wg_pubkey, sampled_at DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'WGPS_DEVICE_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX wgps_device_time_idx ON wg_peer_samples(device_id, sampled_at DESC)';
  END IF;
END;
/

-- ── 2. BANDWIDTH_SAMPLES ────────────────────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables
  WHERE table_name = 'BANDWIDTH_SAMPLES';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE bandwidth_samples (
        sample_id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        sampled_at              TIMESTAMP      NOT NULL,
        wg_pubkey               VARCHAR2(64)   NOT NULL,
        device_id               VARCHAR2(36),
        bytes_up_delta          NUMBER(20,0)   DEFAULT 0 NOT NULL,
        bytes_down_delta        NUMBER(20,0)   DEFAULT 0 NOT NULL,
        sessions_active         NUMBER(10,0)   DEFAULT 0 NOT NULL,
        blocked_bytes_delta     NUMBER(20,0)   DEFAULT 0 NOT NULL,
        allowed_bytes_delta     NUMBER(20,0)   DEFAULT 0 NOT NULL,
        blocked_count_delta     NUMBER(20,0)   DEFAULT 0 NOT NULL,
        allowed_count_delta     NUMBER(20,0)   DEFAULT 0 NOT NULL,
        blocked_bytes_is_approx NUMBER(1,0)    DEFAULT 1 NOT NULL,
        created_at              TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL
      )
    ]';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_constraints
  WHERE constraint_name = 'BWS_DEVICE_FK';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples ADD CONSTRAINT bws_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'BWS_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX bws_time_idx ON bandwidth_samples(sampled_at DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'BWS_PUBKEY_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX bws_pubkey_time_idx ON bandwidth_samples(wg_pubkey, sampled_at DESC)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'BWS_DEVICE_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX bws_device_time_idx ON bandwidth_samples(device_id, sampled_at DESC)';
  END IF;
END;
/

-- ── 3. Retention rows for sample tables ─────────────────────────────────────
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

-- ── 4. Materialized views and rollup view ───────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_objects
  WHERE object_type = 'MATERIALIZED VIEW'
    AND object_name = 'MV_HOURLY_BANDWIDTH';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_hourly_bandwidth
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
      SELECT
        TRUNC(sampled_at, 'HH24')                 AS bucket_hour,
        wg_pubkey,
        device_id,
        SUM(bytes_up_delta)                       AS bytes_up_delta,
        SUM(bytes_down_delta)                     AS bytes_down_delta,
        SUM(blocked_bytes_delta)                  AS blocked_bytes_delta,
        SUM(allowed_bytes_delta)                  AS allowed_bytes_delta,
        SUM(blocked_count_delta)                  AS blocked_count_delta,
        SUM(allowed_count_delta)                  AS allowed_count_delta,
        MAX(sessions_active)                      AS max_sessions_active,
        MAX(blocked_bytes_is_approx)              AS blocked_bytes_is_approx
      FROM bandwidth_samples
      GROUP BY TRUNC(sampled_at, 'HH24'), wg_pubkey, device_id
    ]';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM user_objects
  WHERE object_type = 'MATERIALIZED VIEW'
    AND object_name = 'MV_DAILY_PEER_STATS';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_daily_peer_stats
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
      SELECT
        TRUNC(sampled_at)                         AS bucket_day,
        wg_pubkey,
        device_id,
        SUM(bytes_up_delta)                       AS bytes_up_delta,
        SUM(bytes_down_delta)                     AS bytes_down_delta,
        SUM(blocked_bytes_delta)                  AS blocked_bytes_delta,
        SUM(allowed_bytes_delta)                  AS allowed_bytes_delta,
        SUM(blocked_count_delta)                  AS blocked_count_delta,
        SUM(allowed_count_delta)                  AS allowed_count_delta,
        MAX(sessions_active)                      AS max_sessions_active
      FROM bandwidth_samples
      GROUP BY TRUNC(sampled_at), wg_pubkey, device_id
    ]';
  END IF;
END;
/

CREATE OR REPLACE VIEW v_bandwidth_trend AS
SELECT
    TRUNC(bs.sampled_at, 'MI')                    AS bucket_minute,
    bs.wg_pubkey,
    bs.device_id,
    d.display_name,
    d.username,
    SUM(bs.bytes_up_delta)                        AS bytes_up_delta,
    SUM(bs.bytes_down_delta)                      AS bytes_down_delta,
    SUM(bs.blocked_bytes_delta)                   AS blocked_bytes_delta,
    SUM(bs.allowed_bytes_delta)                   AS allowed_bytes_delta,
    SUM(bs.blocked_count_delta)                   AS blocked_count_delta,
    SUM(bs.allowed_count_delta)                   AS allowed_count_delta,
    MAX(bs.sessions_active)                       AS sessions_active,
    MAX(bs.blocked_bytes_is_approx)               AS blocked_bytes_is_approx
FROM bandwidth_samples bs
LEFT JOIN devices d
  ON d.device_id = bs.device_id
GROUP BY
    TRUNC(bs.sampled_at, 'MI'),
    bs.wg_pubkey,
    bs.device_id,
    d.display_name,
    d.username
/

-- ── 5. Refresh error log table ───────────────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables
  WHERE table_name = 'MV_REFRESH_LOG';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE mv_refresh_log (
        log_time   TIMESTAMP    DEFAULT SYSTIMESTAMP NOT NULL,
        mv_name    VARCHAR2(64) NOT NULL,
        error_msg  VARCHAR2(4000)
      )
    ]';
  END IF;
END;
/

-- ── 6. Refresh job widened to new rollups ───────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_scheduler_jobs
  WHERE job_name = 'JOB_REFRESH_MVS';

  IF v_count = 0 THEN
    DBMS_SCHEDULER.CREATE_JOB(
      job_name        => 'JOB_REFRESH_MVS',
      job_type        => 'PLSQL_BLOCK',
      job_action      => q'[DECLARE
        PROCEDURE log_mv_refresh_error(p_mv_name IN VARCHAR2, p_error_msg IN VARCHAR2) IS
          PRAGMA AUTONOMOUS_TRANSACTION;
        BEGIN
          INSERT INTO mv_refresh_log (log_time, mv_name, error_msg)
          VALUES (SYSTIMESTAMP, p_mv_name, p_error_msg);
          COMMIT;
        END log_mv_refresh_error;
      BEGIN
        BEGIN
          DBMS_MVIEW.REFRESH('MV_DAILY_BLOCKED', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_DAILY_BLOCKED', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_PEER_IP_SUMMARY', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_PEER_IP_SUMMARY', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_HOURLY_BANDWIDTH', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_HOURLY_BANDWIDTH', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_DAILY_PEER_STATS', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_DAILY_PEER_STATS', SQLERRM);
        END;
      END;]',
      start_date      => SYSTIMESTAMP,
      repeat_interval => 'FREQ=DAILY;BYHOUR=3;BYMINUTE=0',
      enabled         => TRUE,
      comments        => 'Nightly refresh of pre-aggregated materialized views'
    );
  ELSE
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
          DBMS_MVIEW.REFRESH('MV_DAILY_BLOCKED', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_DAILY_BLOCKED', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_PEER_IP_SUMMARY', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_PEER_IP_SUMMARY', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_HOURLY_BANDWIDTH', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_HOURLY_BANDWIDTH', SQLERRM);
        END;
        BEGIN
          DBMS_MVIEW.REFRESH('MV_DAILY_PEER_STATS', 'C');
        EXCEPTION
          WHEN OTHERS THEN
            log_mv_refresh_error('MV_DAILY_PEER_STATS', SQLERRM);
        END;
      END;]'
    );
  END IF;
END;
/

COMMIT;
