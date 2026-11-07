-- object: atheros_search_proxy_behavior_scopes
-- depends_on: atheros_search_proxy_behavior
-- These bounded projections are recomputed from retained, attested evidence.
-- Scope keys are opaque references; registration evidence is not ownership.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_destination_history (
  deployment_scope varchar(128) NOT NULL,
  scope_kind varchar(32) NOT NULL CHECK (scope_kind IN ('deployment', 'registration', 'peer')),
  scope_key varchar(256) NOT NULL,
  endpoint_key varchar(1024) NOT NULL,
  first_observed_at timestamptz NOT NULL CHECK (isfinite(first_observed_at)),
  last_observed_at timestamptz NOT NULL CHECK (isfinite(last_observed_at)),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  source_watermark bigint NOT NULL CHECK (source_watermark >= 0),
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  policy_version varchar(64) NOT NULL,
  calculation_version varchar(64) NOT NULL,
  calculated_at timestamptz NOT NULL,
  source_fingerprint char(64) NOT NULL,
  PRIMARY KEY (deployment_scope, scope_kind, scope_key, endpoint_key),
  CHECK (first_observed_at <= last_observed_at)
);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_device_window (
  deployment_scope varchar(128) NOT NULL,
  scope_kind varchar(32) NOT NULL CHECK (scope_kind = 'registration'),
  scope_key varchar(256) NOT NULL,
  endpoint_key varchar(1024) NOT NULL,
  window_start timestamptz NOT NULL CHECK (isfinite(window_start)),
  window_end timestamptz NOT NULL CHECK (isfinite(window_end)),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  source_watermark bigint NOT NULL CHECK (source_watermark >= 0),
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  policy_version varchar(64) NOT NULL,
  calculation_version varchar(64) NOT NULL,
  calculated_at timestamptz NOT NULL,
  source_fingerprint char(64) NOT NULL,
  PRIMARY KEY (deployment_scope, scope_kind, scope_key, endpoint_key, window_start),
  CHECK (window_start < window_end)
);
CREATE INDEX IF NOT EXISTS proxy_device_window_time_idx
  ON atheros_search.proxy_device_window (deployment_scope, window_start, scope_key, endpoint_key);

CREATE TABLE IF NOT EXISTS atheros_search.proxy_attribution_window (
  deployment_scope varchar(128) NOT NULL,
  window_start timestamptz NOT NULL CHECK (isfinite(window_start)),
  window_end timestamptz NOT NULL CHECK (isfinite(window_end)),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
  source_watermark bigint NOT NULL CHECK (source_watermark >= 0),
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  policy_version varchar(64) NOT NULL,
  calculation_version varchar(64) NOT NULL,
  calculated_at timestamptz NOT NULL,
  source_fingerprint char(64) NOT NULL,
  PRIMARY KEY (deployment_scope, window_start),
  CHECK (window_start < window_end)
);
