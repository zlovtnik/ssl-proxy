-- V013: Oracle observability partitioning and materialized views
-- Run after V012. All idempotent.
--
-- Changes:
-- 1. Interval-partition proxy_events, wg_events, bandwidth_samples, wg_peer_samples
-- 2. Rebuild indexes as LOCAL
-- 3. Create materialized views for expensive dashboard queries
-- 4. Add hourly rollup table for proxy_events

-- =============================================================================
-- 1. PROXY_EVENTS — interval partitioning (if not already partitioned)
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tables
  WHERE table_name = 'PROXY_EVENTS' AND partitioned = 'YES';
  IF v_count = 0 THEN
    -- Create partitioned replacement table
    EXECUTE IMMEDIATE q'[
      CREATE TABLE proxy_events_part (
        id                   NUMBER GENERATED ALWAYS AS IDENTITY,
        event_time           TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
        event_type           VARCHAR2(32)  NOT NULL,
        host                 VARCHAR2(253) NOT NULL,
        peer_ip              VARCHAR2(45),
        wg_pubkey            VARCHAR2(64),
        device_id            VARCHAR2(36),
        identity_source      VARCHAR2(16)  DEFAULT 'unknown',
        peer_hostname        VARCHAR2(253),
        client_ua            VARCHAR2(512),
        bytes_up             NUMBER(20) DEFAULT 0,
        bytes_down           NUMBER(20) DEFAULT 0,
        status_code          NUMBER(5),
        blocked              NUMBER(1)  DEFAULT 0 CHECK (blocked IN (0,1)),
        obfuscation_profile  VARCHAR2(32),
        correlation_id       VARCHAR2(36),
        parent_event_id      VARCHAR2(36),
        event_sequence       NUMBER(10,0),
        duration_ms          NUMBER(12,0),
        reason               VARCHAR2(64),
        raw_json             CLOB CHECK (raw_json IS JSON),
        CONSTRAINT pe_part_pk PRIMARY KEY (id, event_time)
      ) PARTITION BY RANGE (event_time)
        INTERVAL (NUMTOYMINTERVAL(1, 'MONTH'))
        ( PARTITION pe_bootstrap VALUES LESS THAN (TIMESTAMP '2026-01-01 00:00:00') )
    ]';

    -- Migrate recent data (90 days) into partitioned table
    EXECUTE IMMEDIATE q'[
      INSERT /*+ APPEND */ INTO proxy_events_part
      SELECT * FROM proxy_events
      WHERE event_time >= SYSTIMESTAMP - INTERVAL '90' DAY
    ]';
    COMMIT;

    -- Rename tables
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events RENAME TO proxy_events_old';
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events_part RENAME TO proxy_events';

    -- Rebuild indexes as LOCAL
    EXECUTE IMMEDIATE 'CREATE INDEX ix_pe_time ON proxy_events (event_time DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_pe_host ON proxy_events (host, event_time) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_pe_blocked ON proxy_events (blocked, event_time) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_pe_type_time ON proxy_events (event_type, event_time DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_pe_obfuscation ON proxy_events (obfuscation_profile, event_time) LOCAL';
  END IF;
END;
/

-- =============================================================================
-- 2. WG_EVENTS — interval partitioning
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tables
  WHERE table_name = 'WG_EVENTS' AND partitioned = 'YES';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE wg_events_part (
        id            NUMBER GENERATED ALWAYS AS IDENTITY,
        event_time    TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
        event_type    VARCHAR2(32)  NOT NULL,
        interface     VARCHAR2(16)  NOT NULL,
        peer_pubkey   VARCHAR2(64)  NOT NULL,
        endpoint_ip   VARCHAR2(45),
        endpoint_port NUMBER(5),
        rx_bytes      NUMBER(20) DEFAULT 0,
        tx_bytes      NUMBER(20) DEFAULT 0,
        latency_ms    NUMBER(10,3),
        raw_json      CLOB CHECK (raw_json IS JSON),
        CONSTRAINT wg_part_pk PRIMARY KEY (id, event_time)
      ) PARTITION BY RANGE (event_time)
        INTERVAL (NUMTOYMINTERVAL(1, 'MONTH'))
        ( PARTITION wg_bootstrap VALUES LESS THAN (TIMESTAMP '2026-01-01 00:00:00') )
    ]';

    EXECUTE IMMEDIATE q'[
      INSERT /*+ APPEND */ INTO wg_events_part
      SELECT * FROM wg_events
      WHERE event_time >= SYSTIMESTAMP - INTERVAL '90' DAY
    ]';
    COMMIT;

    EXECUTE IMMEDIATE 'ALTER TABLE wg_events RENAME TO wg_events_old';
    EXECUTE IMMEDIATE 'ALTER TABLE wg_events_part RENAME TO wg_events';

    EXECUTE IMMEDIATE 'CREATE INDEX ix_wg_time ON wg_events (event_time DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_wg_peer ON wg_events (peer_pubkey, event_time DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX ix_wg_endpoint ON wg_events (endpoint_ip, event_time) LOCAL';
  END IF;
END;
/

-- =============================================================================
-- 3. BANDWIDTH_SAMPLES — interval partitioning
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tables
  WHERE table_name = 'BANDWIDTH_SAMPLES' AND partitioned = 'YES';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE bandwidth_samples_part (
        sample_id               NUMBER GENERATED ALWAYS AS IDENTITY,
        sampled_at              TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
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
        created_at              TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT bws_part_pk PRIMARY KEY (sample_id, sampled_at)
      ) PARTITION BY RANGE (sampled_at)
        INTERVAL (NUMTOYMINTERVAL(1, 'MONTH'))
        ( PARTITION bws_bootstrap VALUES LESS THAN (TIMESTAMP '2026-01-01 00:00:00') )
    ]';

    EXECUTE IMMEDIATE q'[
      INSERT /*+ APPEND */ INTO bandwidth_samples_part
      SELECT * FROM bandwidth_samples
      WHERE sampled_at >= SYSTIMESTAMP - INTERVAL '90' DAY
    ]';
    COMMIT;

    EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples RENAME TO bandwidth_samples_old';
    EXECUTE IMMEDIATE 'ALTER TABLE bandwidth_samples_part RENAME TO bandwidth_samples';

    EXECUTE IMMEDIATE 'CREATE INDEX bws_time_idx ON bandwidth_samples (sampled_at DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX bws_pubkey_time_idx ON bandwidth_samples (wg_pubkey, sampled_at DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX bws_device_time_idx ON bandwidth_samples (device_id, sampled_at DESC) LOCAL';
  END IF;
END;
/

-- =============================================================================
-- 4. WG_PEER_SAMPLES — interval partitioning
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tables
  WHERE table_name = 'WG_PEER_SAMPLES' AND partitioned = 'YES';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE wg_peer_samples_part (
        sample_id         NUMBER GENERATED ALWAYS AS IDENTITY,
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
        created_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT wgps_part_pk PRIMARY KEY (sample_id, sampled_at)
      ) PARTITION BY RANGE (sampled_at)
        INTERVAL (NUMTOYMINTERVAL(1, 'MONTH'))
        ( PARTITION wgps_bootstrap VALUES LESS THAN (TIMESTAMP '2026-01-01 00:00:00') )
    ]';

    EXECUTE IMMEDIATE q'[
      INSERT /*+ APPEND */ INTO wg_peer_samples_part
      SELECT * FROM wg_peer_samples
      WHERE sampled_at >= SYSTIMESTAMP - INTERVAL '90' DAY
    ]';
    COMMIT;

    EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples RENAME TO wg_peer_samples_old';
    EXECUTE IMMEDIATE 'ALTER TABLE wg_peer_samples_part RENAME TO wg_peer_samples';

    EXECUTE IMMEDIATE 'CREATE INDEX wgps_time_idx ON wg_peer_samples (sampled_at DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX wgps_pubkey_time_idx ON wg_peer_samples (wg_pubkey, sampled_at DESC) LOCAL';
    EXECUTE IMMEDIATE 'CREATE INDEX wgps_device_time_idx ON wg_peer_samples (device_id, sampled_at DESC) LOCAL';
  END IF;
END;
/

-- =============================================================================
-- 5. PROXY_EVENTS_HOURLY — pre-aggregated rollup table
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tables WHERE table_name = 'PROXY_EVENTS_HOURLY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE TABLE proxy_events_hourly (
        hour_dt          TIMESTAMP      NOT NULL,
        host             VARCHAR2(253)  NOT NULL,
        event_type       VARCHAR2(32)   NOT NULL,
        blocked          NUMBER(1,0)    DEFAULT 0 NOT NULL,
        obfuscation_profile VARCHAR2(32),
        category         VARCHAR2(64),
        verdict          VARCHAR2(32),
        event_count      NUMBER(12,0)   DEFAULT 0 NOT NULL,
        total_bytes_up   NUMBER(20,0)   DEFAULT 0 NOT NULL,
        total_bytes_down NUMBER(20,0)   DEFAULT 0 NOT NULL,
        avg_duration_ms  NUMBER(12,0),
        max_duration_ms  NUMBER(12,0),
        created_at       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        updated_at       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        CONSTRAINT peh_pk PRIMARY KEY (hour_dt, host, event_type, blocked)
      )
    ]';

    EXECUTE IMMEDIATE 'CREATE INDEX peh_hour_idx ON proxy_events_hourly (hour_dt DESC)';
    EXECUTE IMMEDIATE 'CREATE INDEX peh_host_idx ON proxy_events_hourly (host, hour_dt)';
  END IF;
END;
/

-- =============================================================================
-- 6. MATERIALIZED VIEW: MV_HOST_THREAT_SCORE
-- Replaces v_host_threat_score for dashboard use
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_objects
  WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_HOST_THREAT_SCORE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_host_threat_score
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
      SELECT
        pe.host,
        COUNT(*)                                                    AS total_blocks_7d,
        SUM(pe.bytes_up + pe.bytes_down)                            AS total_bytes_7d,
        ROUND(
            COUNT(*) * AVG(pe.bytes_up + pe.bytes_down + 1)
            * (1 + 2 * SUM(CASE WHEN pe.event_time >= SYSTIMESTAMP - INTERVAL '1' DAY THEN 1 ELSE 0 END)
                       / NULLIF(COUNT(*), 0)),
        2)                                                          AS threat_score,
        MAX(pe.event_time)                                          AS last_seen
      FROM proxy_events pe
      WHERE pe.blocked = 1
        AND pe.event_time >= SYSTIMESTAMP - INTERVAL '7' DAY
      GROUP BY pe.host
    ]';
  END IF;
END;
/

-- =============================================================================
-- 7. MATERIALIZED VIEW: MV_SESSION_TIMELINE
-- Replaces v_session_timeline for dashboard use
-- =============================================================================
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_objects
  WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_SESSION_TIMELINE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_session_timeline
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
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
        d.username
      FROM connection_sessions cs
      LEFT JOIN devices d ON d.device_id = cs.device_id
      WHERE cs.opened_at >= SYSTIMESTAMP - INTERVAL '7' DAY
    ]';
  END IF;
END;
/

-- =============================================================================
-- 8. Update scheduler jobs to refresh new MVs
-- =============================================================================
BEGIN
  BEGIN
    DBMS_SCHEDULER.drop_job('JOB_REFRESH_MVS');
  EXCEPTION
    WHEN OTHERS THEN NULL;
  END;

  DBMS_SCHEDULER.create_job(
    job_name        => 'JOB_REFRESH_MVS',
    job_type        => 'PLSQL_BLOCK',
    job_action      => q'[BEGIN
      DECLARE
        v_exists INTEGER;
      BEGIN
        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_BLOCKED';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_DAILY_BLOCKED', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_PEER_IP_SUMMARY';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_PEER_IP_SUMMARY', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_HOURLY_BANDWIDTH';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_HOURLY_BANDWIDTH', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_DAILY_PEER_STATS';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_DAILY_PEER_STATS', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_HOST_THREAT_SCORE';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_HOST_THREAT_SCORE', 'C');
        END IF;

        SELECT COUNT(*) INTO v_exists FROM user_objects
        WHERE object_type = 'MATERIALIZED VIEW' AND object_name = 'MV_SESSION_TIMELINE';
        IF v_exists = 1 THEN
          DBMS_MVIEW.refresh('MV_SESSION_TIMELINE', 'C');
        END IF;
      END;
    END;]',
    start_date      => SYSTIMESTAMP,
    repeat_interval => 'FREQ=DAILY;BYHOUR=3;BYMINUTE=0',
    enabled         => TRUE,
    comments        => 'Nightly refresh of pre-aggregated materialized views'
  );
END;
/

COMMIT;
