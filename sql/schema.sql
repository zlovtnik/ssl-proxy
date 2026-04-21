-- =============================================================================
-- ssl-proxy observability schema  (Oracle ADB, wallet auth)
-- Bootstrap schema matching migrations through V009.
-- =============================================================================

CREATE TABLE devices (
    device_id         VARCHAR2(36)   PRIMARY KEY,
    wg_pubkey         VARCHAR2(64),
    claim_token_hash  VARCHAR2(128),
    display_name      VARCHAR2(128),
    username          VARCHAR2(128),
    hostname          VARCHAR2(253),
    os_hint           VARCHAR2(64),
    mac_hint          VARCHAR2(17),
    first_seen        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    last_seen         TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    notes             VARCHAR2(512)
);

CREATE INDEX devices_wg_pubkey_idx ON devices (wg_pubkey);
CREATE INDEX devices_username_idx ON devices (username, last_seen DESC);
CREATE UNIQUE INDEX devices_claim_token_uq ON devices (claim_token_hash);

CREATE TABLE proxy_events (
    id                   NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    CONSTRAINT pe_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX ix_pe_time ON proxy_events (event_time DESC);
CREATE INDEX ix_pe_host ON proxy_events (host, event_time);
CREATE INDEX ix_pe_blocked ON proxy_events (blocked, event_time DESC);
CREATE INDEX pe_device_time_idx ON proxy_events (device_id, event_time DESC);
CREATE INDEX pe_wg_pubkey_time_idx ON proxy_events (wg_pubkey, event_time DESC);

CREATE TABLE wg_events (
    id            NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time    TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    event_type    VARCHAR2(32)  NOT NULL,
    interface     VARCHAR2(16)  NOT NULL,
    peer_pubkey   VARCHAR2(64)  NOT NULL,
    endpoint_ip   VARCHAR2(45),
    endpoint_port NUMBER(5),
    rx_bytes      NUMBER(20) DEFAULT 0,
    tx_bytes      NUMBER(20) DEFAULT 0,
    latency_ms    NUMBER(10,3),
    raw_json      CLOB CHECK (raw_json IS JSON)
);

CREATE INDEX ix_wg_time ON wg_events (event_time DESC);
CREATE INDEX ix_wg_peer ON wg_events (peer_pubkey, event_time DESC);

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
    created_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT wgps_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE INDEX wgps_time_idx ON wg_peer_samples (sampled_at DESC);
CREATE INDEX wgps_pubkey_time_idx ON wg_peer_samples (wg_pubkey, sampled_at DESC);
CREATE INDEX wgps_device_time_idx ON wg_peer_samples (device_id, sampled_at DESC);

CREATE TABLE bandwidth_samples (
    sample_id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    CONSTRAINT bws_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE INDEX bws_time_idx ON bandwidth_samples (sampled_at DESC);
CREATE INDEX bws_pubkey_time_idx ON bandwidth_samples (wg_pubkey, sampled_at DESC);
CREATE INDEX bws_device_time_idx ON bandwidth_samples (device_id, sampled_at DESC);

CREATE TABLE db_query_log (
    id            NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at   TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    session_id    VARCHAR2(64),
    client_ip     VARCHAR2(45),
    db_user       VARCHAR2(128),
    sql_text      CLOB NOT NULL,
    elapsed_ms    NUMBER(12,3),
    rows_examined NUMBER(20),
    rows_returned NUMBER(20),
    plan_hash     VARCHAR2(64),
    raw_json      CLOB CHECK (raw_json IS JSON)
);

CREATE INDEX ix_dql_time ON db_query_log (captured_at DESC);
CREATE INDEX ix_dql_elapsed ON db_query_log (elapsed_ms DESC);

CREATE TABLE blocked_events (
    id                 NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host               VARCHAR2(253) NOT NULL,
    blocked_attempts   NUMBER(20)    DEFAULT 0 NOT NULL,
    blocked_bytes      NUMBER(20)    DEFAULT 0 NOT NULL,
    frequency_hz       NUMBER(10,4)  DEFAULT 0 NOT NULL,
    verdict            VARCHAR2(32)  NOT NULL,
    category           VARCHAR2(64),
    risk_score         NUMBER(10,4)  DEFAULT 0,
    tarpit_held_ms     NUMBER(20)    DEFAULT 0,
    iat_ms             NUMBER(20),
    consecutive_blocks NUMBER(10)    DEFAULT 0,
    last_verdict       VARCHAR2(32),
    tls_ver            VARCHAR2(16),
    alpn               VARCHAR2(64),
    ja3_lite           VARCHAR2(512),
    resolved_ip        VARCHAR2(45),
    asn_org            VARCHAR2(128),
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    first_seen         TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX ix_be_host ON blocked_events (host);
CREATE INDEX ix_be_timestamp ON blocked_events (updated_at DESC);

CREATE TABLE payload_audit (
    id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correlation_id   VARCHAR2(36)      NOT NULL,
    host             VARCHAR2(253)     NOT NULL,
    direction        VARCHAR2(4)       NOT NULL CHECK (direction IN ('UP','DOWN')),
    captured_at      TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    byte_offset      NUMBER(10,0)      DEFAULT 0 NOT NULL,
    payload_bytes    RAW(8192),
    content_type     VARCHAR2(128),
    http_method      VARCHAR2(16),
    http_status      NUMBER(5,0),
    http_path        VARCHAR2(1024),
    is_encrypted     NUMBER(1,0)       DEFAULT 0 NOT NULL,
    truncated        NUMBER(1,0)       DEFAULT 0 NOT NULL,
    peer_ip          VARCHAR2(45),
    notes            VARCHAR2(512),
    CONSTRAINT payload_audit_payload_present_ck
      CHECK (payload_bytes IS NOT NULL)
)
PARTITION BY RANGE (captured_at)
INTERVAL (NUMTOYMINTERVAL(1, 'MONTH'))
(
    PARTITION pa_bootstrap VALUES LESS THAN (TIMESTAMP '2026-01-01 00:00:00')
);

CREATE INDEX pa_corr_idx ON payload_audit(correlation_id);
CREATE INDEX pa_host_idx ON payload_audit(host, captured_at);

CREATE TABLE tls_fingerprints (
    ja3_lite         VARCHAR2(512)  NOT NULL,
    first_seen       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    last_seen        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    seen_count       NUMBER(10,0)   DEFAULT 1 NOT NULL,
    tls_ver          VARCHAR2(16),
    alpn             VARCHAR2(64),
    cipher_count     NUMBER(3,0),
    verdict_hint     VARCHAR2(32),
    CONSTRAINT tls_fp_pk PRIMARY KEY (ja3_lite)
);

CREATE TABLE connection_sessions (
    session_id       VARCHAR2(32)   DEFAULT RAWTOHEX(SYS_GUID()) PRIMARY KEY,
    correlation_id   VARCHAR2(36),
    host             VARCHAR2(253)  NOT NULL,
    peer_ip          VARCHAR2(45),
    wg_pubkey        VARCHAR2(64),
    device_id        VARCHAR2(36),
    identity_source  VARCHAR2(16)   DEFAULT 'unknown',
    peer_hostname    VARCHAR2(253),
    client_ua        VARCHAR2(512),
    tunnel_kind      VARCHAR2(16)   NOT NULL,
    opened_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    closed_at        TIMESTAMP,
    duration_ms      NUMBER(12,0),
    bytes_up         NUMBER(18,0)   DEFAULT 0,
    bytes_down       NUMBER(18,0)   DEFAULT 0,
    blocked          NUMBER(1,0)    DEFAULT 0 NOT NULL,
    tarpitted        NUMBER(1,0)    DEFAULT 0 NOT NULL,
    tarpit_held_ms   NUMBER(10,0),
    verdict          VARCHAR2(32),
    category         VARCHAR2(64),
    obfuscation_profile VARCHAR2(32),
    tls_ver          VARCHAR2(16),
    alpn             VARCHAR2(64),
    ja3_lite         VARCHAR2(512),
    resolved_ip      VARCHAR2(45),
    asn_org          VARCHAR2(128),
    reason           VARCHAR2(64),
    created_at       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT cs_device_fk FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX cs_host_idx ON connection_sessions(host, opened_at);
CREATE INDEX cs_peer_idx ON connection_sessions(peer_ip, opened_at);
CREATE INDEX cs_corr_idx ON connection_sessions(correlation_id);
CREATE INDEX cs_device_idx ON connection_sessions(device_id, opened_at DESC);
CREATE INDEX cs_wg_pubkey_idx ON connection_sessions(wg_pubkey, opened_at DESC);

CREATE TABLE connection_sessions_close_dlq (
    id                NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    session_id        VARCHAR2(36)   NOT NULL,
    reason            VARCHAR2(64)   NOT NULL,
    duration_ms       NUMBER(12,0),
    bytes_up          NUMBER(18,0),
    bytes_down        NUMBER(18,0),
    blocked           NUMBER(1,0),
    tarpitted         NUMBER(1,0),
    tarpit_held_ms    NUMBER(10,0),
    verdict           VARCHAR2(32),
    category          VARCHAR2(64),
    obfuscation_profile VARCHAR2(32),
    tls_ver           VARCHAR2(16),
    alpn              VARCHAR2(64),
    ja3_lite          VARCHAR2(512),
    resolved_ip       VARCHAR2(45),
    asn_org           VARCHAR2(128),
    wg_pubkey         VARCHAR2(64),
    device_id         VARCHAR2(36),
    identity_source   VARCHAR2(16),
    peer_hostname     VARCHAR2(253),
    client_ua         VARCHAR2(512)
);

CREATE INDEX cs_close_dlq_session_idx ON connection_sessions_close_dlq(session_id, captured_at DESC);

CREATE TABLE blocklist_audit (
    id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    refreshed_at     TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    source_url       VARCHAR2(1024),
    entries_loaded   NUMBER(10,0),
    seed_entries     NUMBER(10,0),
    success          NUMBER(1,0) DEFAULT 1 NOT NULL,
    error_msg        VARCHAR2(512),
    duration_ms      NUMBER(10,0)
);

CREATE TABLE shipper_heartbeats (
    id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reported_at  TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    agent_name   VARCHAR2(64)  NOT NULL,
    host_fqdn    VARCHAR2(253) NOT NULL,
    version      VARCHAR2(32),
    events_sent  NUMBER(20) DEFAULT 0,
    lag_seconds  NUMBER(10,3),
    raw_json     CLOB CHECK (raw_json IS JSON)
);

CREATE TABLE data_retention_policy (
    table_name        VARCHAR2(128)  NOT NULL,
    retention_days    NUMBER(6,0)    NOT NULL,
    date_column       VARCHAR2(128)  NOT NULL,
    enabled           NUMBER(1,0)    DEFAULT 1 NOT NULL,
    last_purge_at     TIMESTAMP,
    last_purge_rows   NUMBER(12,0),
    notes             VARCHAR2(512),
    CONSTRAINT drp_pk PRIMARY KEY (table_name)
);

CREATE TABLE dlq_errors (
    id             NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at    TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
    procedure_name VARCHAR2(64)   NOT NULL,
    error_code     NUMBER,
    error_msg      VARCHAR2(512),
    row_data       CLOB
);
