-- object: atheros_search_proxy_intelligence
-- depends_on: atheros_search_proxy_behavior_scopes
-- Opt-in reviewed inputs, never installed by application runtimes.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '10s';
ALTER TABLE atheros_search.proxy_behavior_policy
  ADD COLUMN IF NOT EXISTS intelligence_policy jsonb NOT NULL DEFAULT '{}'
  CHECK (jsonb_typeof(intelligence_policy) = 'object'
    AND octet_length(intelligence_policy::text) <= 1048576);

-- Small bounded current/retracted state, separate from high-volume source facts.
-- No FK: configuration, source evidence and signal retention are independent.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_signal_state (
  deployment_scope varchar(128) NOT NULL,
  signal_id char(64) NOT NULL CHECK (signal_id ~ '^[0-9a-f]{64}$'),
  window_key text NOT NULL CHECK (octet_length(window_key) <= 4096),
  window_start timestamptz NOT NULL CHECK (isfinite(window_start)),
  window_end timestamptz NOT NULL CHECK (isfinite(window_end)),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'
    AND octet_length(evidence::text) <= 1048576),
  state varchar(16) NOT NULL CHECK (state IN ('active', 'candidate', 'retracted')),
  valid_until timestamptz NOT NULL CHECK (isfinite(valid_until)),
  retraction_reason varchar(128),
  policy_fingerprint char(64) NOT NULL,
  source_fingerprint char(64) NOT NULL,
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  calculated_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_scope, signal_id),
  CHECK (window_start < window_end)
);
CREATE INDEX IF NOT EXISTS proxy_signal_state_active_idx
  ON atheros_search.proxy_signal_state (deployment_scope, valid_until, signal_id)
  WHERE state <> 'retracted';
CREATE INDEX IF NOT EXISTS proxy_signal_state_window_idx
  ON atheros_search.proxy_signal_state (deployment_scope, window_start, signal_id);

-- First use binds a local snapshot version to its full provenance and content.
CREATE TABLE IF NOT EXISTS atheros_search.proxy_feed_snapshot_binding (
  feed_id varchar(128) NOT NULL,
  snapshot_version varchar(128) NOT NULL,
  snapshot_fingerprint char(64) NOT NULL,
  first_observed_at timestamptz NOT NULL,
  PRIMARY KEY (feed_id, snapshot_version)
);

-- Search can read only this expiry/configuration-aware surface, never raw state
-- or the privileged configuration. Feed/config revocation is visible before a
-- subsequent preparation tick, and independent of that tick's output budget.
CREATE OR REPLACE VIEW atheros_search.proxy_signal AS
SELECT signal.deployment_scope, signal.signal_id, signal.window_key,
  signal.window_start, signal.window_end, signal.evidence - 'state' - 'alert_state' AS evidence,
  CASE WHEN signal.valid_until <= statement_timestamp()
         OR policy.singleton IS NULL
         OR policy.expires_at <= statement_timestamp()
         OR signal.policy_fingerprint <> encode(sha256(convert_to(policy.intelligence_policy::text, 'UTF8')), 'hex')
         OR status.status IS DISTINCT FROM 'ready'
       THEN 'retracted' ELSE signal.state END AS state,
  signal.valid_until,
  CASE WHEN signal.valid_until <= statement_timestamp() THEN 'expired'
       WHEN policy.singleton IS NULL OR policy.expires_at <= statement_timestamp() THEN 'policy_unavailable_or_expired'
       WHEN signal.policy_fingerprint <> encode(sha256(convert_to(policy.intelligence_policy::text, 'UTF8')), 'hex') THEN 'policy_or_snapshot_changed'
       WHEN status.status IS DISTINCT FROM 'ready' THEN 'evidence_recomputing_or_unavailable'
       ELSE signal.retraction_reason END AS retraction_reason,
  signal.projection_revision, signal.calculated_at
FROM atheros_search.proxy_signal_state signal
LEFT JOIN atheros_search.proxy_behavior_policy policy
  ON policy.singleton AND policy.deployment_scope = signal.deployment_scope
LEFT JOIN atheros_search.proxy_behavior_status status
  ON status.singleton AND status.deployment_scope = signal.deployment_scope;
