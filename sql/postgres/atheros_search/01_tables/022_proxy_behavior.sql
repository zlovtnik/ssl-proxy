-- object: atheros_search_proxy_behavior
-- depends_on: atheros_search_proxy_document_scope_index
-- An attested, expiring policy is required before behavioral publication.
-- Provisioning installs no policy row; runtime cannot infer source coverage.
-- The executor wraps this file in a transaction but supplies no lock timeout.
SET LOCAL lock_timeout = '1s';
CREATE SEQUENCE IF NOT EXISTS atheros_search.proxy_behavior_revision_seq;

CREATE TABLE IF NOT EXISTS atheros_search.proxy_behavior_policy (
  singleton boolean PRIMARY KEY CHECK (singleton),
  deployment_scope varchar(128) NOT NULL CHECK (deployment_scope <> ''),
  policy_version varchar(64) NOT NULL CHECK (policy_version <> ''),
  coverage_start timestamptz NOT NULL CHECK (isfinite(coverage_start)),
  coverage_end timestamptz NOT NULL CHECK (isfinite(coverage_end)),
  coverage_attested boolean NOT NULL DEFAULT false,
  conflicts_attested boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
  pairing_horizon_seconds integer NOT NULL CHECK (pairing_horizon_seconds BETWEEN 1 AND 604800),
  window_seconds integer NOT NULL CHECK (window_seconds BETWEEN 60 AND 86400 AND 86400 % window_seconds = 0),
  lookback_seconds integer NOT NULL CHECK (lookback_seconds BETWEEN 60 AND 604800),
  max_source_rows integer NOT NULL CHECK (max_source_rows BETWEEN 1 AND 10000),
  max_windows integer NOT NULL CHECK (max_windows BETWEEN 1 AND 168),
  CHECK (coverage_start < coverage_end),
  CHECK (lookback_seconds >= window_seconds),
  CHECK ((lookback_seconds + window_seconds - 1) / window_seconds <= max_windows)
);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_flow (
  deployment_scope varchar(128) NOT NULL,
  correlation_id varchar(64) NOT NULL,
  disposition varchar(64) NOT NULL,
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  source_watermark bigint NOT NULL CHECK (source_watermark >= 0),
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  policy_version varchar(64) NOT NULL,
  calculation_version varchar(64) NOT NULL,
  calculated_at timestamptz NOT NULL,
  source_fingerprint char(64) NOT NULL,
  PRIMARY KEY (deployment_scope, correlation_id)
);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_host_window (
  deployment_scope varchar(128) NOT NULL,
  endpoint_key varchar(1024) NOT NULL,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  source_watermark bigint NOT NULL CHECK (source_watermark >= 0),
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  policy_version varchar(64) NOT NULL,
  calculation_version varchar(64) NOT NULL,
  calculated_at timestamptz NOT NULL,
  source_fingerprint char(64) NOT NULL,
  PRIMARY KEY (deployment_scope, endpoint_key, window_start),
  CHECK (window_start < window_end)
);
CREATE INDEX IF NOT EXISTS proxy_host_window_time_idx
  ON atheros_search.proxy_host_window (deployment_scope, window_start, endpoint_key);

-- No FK: historical evidence and the current pointer have independent retention.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_host_current (
  deployment_scope varchar(128) NOT NULL,
  endpoint_key varchar(1024) NOT NULL,
  latest_window_start timestamptz NOT NULL,
  PRIMARY KEY (deployment_scope, endpoint_key)
);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_behavior_status (
  singleton boolean PRIMARY KEY CHECK (singleton),
  status varchar(64) NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
  deployment_scope varchar(128),
  policy_version varchar(64),
  calculated_at timestamptz NOT NULL
);

-- Enforce future writes without scanning retained documents under this lock.
-- Migration 024 validates in its own budgeted provisioning transaction.
ALTER TABLE atheros_search.search_documents DROP CONSTRAINT search_documents_kind_ck;
ALTER TABLE atheros_search.search_documents ADD CONSTRAINT search_documents_kind_ck CHECK (
  source_kind IN ('event', 'device', 'behaviour_window', 'frame_sequence',
    'proxy_event', 'proxy_blocked_host_window', 'proxy_flow', 'device_profile', 'ap_profile',
    'identity_summary', 'observation_window')
) NOT VALID;
