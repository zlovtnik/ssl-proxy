-- object: atheros_search_projection_state
-- depends_on: atheros_search_vectors
-- Octopus owns all writes to these incrementally maintained projections.

CREATE TABLE IF NOT EXISTS atheros_search.behaviour_snapshots (
  snapshot_id      uuid NOT NULL,
  snapshot_key     VARCHAR(255) NOT NULL,
  source_mac       VARCHAR(17) NOT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  window_start     timestamptz NOT NULL,
  window_end       timestamptz NOT NULL,
  event_count      BIGINT NOT NULL DEFAULT 0,
  text_summary     TEXT NOT NULL,
  embedding_text   TEXT DEFAULT NULL,
  protocol_mix     jsonb NOT NULL,
  frame_type_distribution jsonb NOT NULL,
  signal_min_dbm   INT DEFAULT NULL,
  signal_max_dbm   INT DEFAULT NULL,
  signal_avg_dbm   DECIMAL(8,2) DEFAULT NULL,
  retry_count      BIGINT NOT NULL DEFAULT 0,
  protected_count  BIGINT NOT NULL DEFAULT 0,
  unprotected_count BIGINT NOT NULL DEFAULT 0,
  unique_bssid_count BIGINT NOT NULL DEFAULT 0,
  mac_rotation_indicators jsonb NOT NULL,
  projection_run_id uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (snapshot_id),
  CONSTRAINT behaviour_snapshots_key_uq UNIQUE (snapshot_key),
  CONSTRAINT behaviour_snapshots_window_ck CHECK (window_end > window_start)
);

CREATE INDEX IF NOT EXISTS behaviour_snapshots_mac_window_idx ON atheros_search.behaviour_snapshots (source_mac, window_start);

CREATE TABLE IF NOT EXISTS atheros_search.baseline_profiles (
  baseline_id      uuid NOT NULL,
  bssid            VARCHAR(17) NOT NULL,
  metric           VARCHAR(128) NOT NULL,
  p5               DECIMAL(24,8) NOT NULL,
  p50              DECIMAL(24,8) NOT NULL,
  p95              DECIMAL(24,8) NOT NULL,
  sample_count     BIGINT NOT NULL DEFAULT 0,
  projection_run_id uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (baseline_id),
  CONSTRAINT baseline_profiles_bssid_metric_uq UNIQUE (bssid, metric)
);

CREATE TABLE IF NOT EXISTS atheros_search.frame_sequences (
  session_key      VARCHAR(255) NOT NULL,
  source_mac       VARCHAR(17) DEFAULT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  window_start     timestamptz NOT NULL,
  window_end       timestamptz NOT NULL,
  sequence_tokens  TEXT NOT NULL,
  semantic_tokens  TEXT DEFAULT NULL,
  frame_count      BIGINT NOT NULL DEFAULT 0,
  projection_run_id uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_key),
  CONSTRAINT frame_sequences_window_ck CHECK (window_end >= window_start)
);

CREATE INDEX IF NOT EXISTS frame_sequences_mac_window_idx ON atheros_search.frame_sequences (source_mac, window_start);

CREATE TABLE IF NOT EXISTS atheros_search.sequence_transitions (
  previous_token   VARCHAR(191) NOT NULL,
  next_token       VARCHAR(191) NOT NULL,
  sequence_kind    VARCHAR(64) NOT NULL DEFAULT 'frame_sequence',
  transition_count BIGINT NOT NULL DEFAULT 0,
  previous_total   BIGINT NOT NULL DEFAULT 0,
  vocabulary_size  BIGINT NOT NULL DEFAULT 0,
  probability      double precision DEFAULT NULL,
  last_updated     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  projection_run_id uuid DEFAULT NULL,
  PRIMARY KEY (previous_token, next_token, sequence_kind)
);

CREATE INDEX IF NOT EXISTS sequence_transitions_next_idx ON atheros_search.sequence_transitions (next_token, sequence_kind);

CREATE TABLE IF NOT EXISTS atheros_search.timing_profiles (
  profile_id       uuid NOT NULL,
  profile_key      VARCHAR(255) NOT NULL,
  source_mac       VARCHAR(17) NOT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  window_start     timestamptz NOT NULL,
  window_end       timestamptz NOT NULL,
  embedding_text   TEXT DEFAULT NULL,
  tsft_p50_us      DECIMAL(24,8) DEFAULT NULL,
  tsft_p95_us      DECIMAL(24,8) DEFAULT NULL,
  tsft_jitter      DECIMAL(24,8) DEFAULT NULL,
  wall_p50_ms      DECIMAL(24,8) DEFAULT NULL,
  wall_jitter_ms   DECIMAL(24,8) DEFAULT NULL,
  beacon_interval_median_ms DECIMAL(24,8) DEFAULT NULL,
  beacon_jitter_ms DECIMAL(24,8) DEFAULT NULL,
  projection_run_id uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (profile_id),
  CONSTRAINT timing_profiles_key_uq UNIQUE (profile_key),
  CONSTRAINT timing_profiles_window_ck CHECK (window_end > window_start)
);

CREATE INDEX IF NOT EXISTS timing_profiles_mac_window_idx ON atheros_search.timing_profiles (source_mac, window_start);

CREATE TABLE IF NOT EXISTS atheros_search.similarity_pairs (
  pair_id            uuid NOT NULL,
  pair_kind          VARCHAR(64) NOT NULL,
  embedding_model    VARCHAR(128) NOT NULL,
  embedding_kind     VARCHAR(32) NOT NULL,
  left_document_id   uuid NOT NULL,
  right_document_id  uuid NOT NULL,
  left_source_table  VARCHAR(128) NOT NULL,
  left_source_key    VARCHAR(255) NOT NULL,
  left_source_mac    VARCHAR(17) DEFAULT NULL,
  left_sensor_id     VARCHAR(64) DEFAULT NULL,
  left_location_id   VARCHAR(128) DEFAULT NULL,
  left_observed_at   timestamptz DEFAULT NULL,
  right_source_table VARCHAR(128) NOT NULL,
  right_source_key   VARCHAR(255) NOT NULL,
  right_source_mac   VARCHAR(17) DEFAULT NULL,
  right_sensor_id    VARCHAR(64) DEFAULT NULL,
  right_location_id  VARCHAR(128) DEFAULT NULL,
  right_observed_at  timestamptz DEFAULT NULL,
  cosine_distance    double precision NOT NULL,
  cosine_similarity  double precision NOT NULL,
  pair_rank          INT NOT NULL DEFAULT 1,
  evidence           jsonb NOT NULL,
  computed_at        timestamptz NOT NULL,
  projection_run_id  uuid NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (pair_id),
  CONSTRAINT similarity_pairs_documents_uq UNIQUE (
    pair_kind, embedding_model, left_document_id, right_document_id
  ),
  CONSTRAINT similarity_pairs_similarity_ck CHECK (
    cosine_similarity >= -1 AND cosine_similarity <= 1
  )
);

CREATE INDEX IF NOT EXISTS similarity_pairs_left_idx ON atheros_search.similarity_pairs (left_source_key, computed_at);
CREATE INDEX IF NOT EXISTS similarity_pairs_right_idx ON atheros_search.similarity_pairs (right_source_key, computed_at);

CREATE TABLE IF NOT EXISTS atheros_search.threat_signals (
  source_key       VARCHAR(255) NOT NULL,
  near_duplicate  boolean NOT NULL DEFAULT false,
  shadow_open      boolean NOT NULL DEFAULT false,
  risk_score       double precision NOT NULL DEFAULT 0,
  ap_risk          double precision NOT NULL DEFAULT 0,
  threat_tag_count BIGINT NOT NULL DEFAULT 0,
  signal_id        uuid DEFAULT NULL,
  signal_type      VARCHAR(64) DEFAULT NULL,
  dedupe_key       VARCHAR(255) DEFAULT NULL,
  source_mac       VARCHAR(17) DEFAULT NULL,
  sensor_id        VARCHAR(64) DEFAULT NULL,
  location_id      VARCHAR(128) DEFAULT NULL,
  score            double precision DEFAULT NULL,
  severity         VARCHAR(32) DEFAULT NULL,
  explanation_text TEXT DEFAULT NULL,
  evidence         jsonb DEFAULT NULL,
  detected_at      timestamptz DEFAULT NULL,
  resolved_at      timestamptz DEFAULT NULL,
  projection_run_id uuid DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (source_key),
  CONSTRAINT threat_signals_id_uq UNIQUE (signal_id),
  CONSTRAINT threat_signals_dedupe_uq UNIQUE (signal_type, dedupe_key)
);

CREATE INDEX IF NOT EXISTS threat_signals_open_idx ON atheros_search.threat_signals (resolved_at, severity, detected_at);
CREATE INDEX IF NOT EXISTS threat_signals_source_idx ON atheros_search.threat_signals (source_mac, detected_at);

CREATE TABLE IF NOT EXISTS atheros_search.ap_risk_scores (
  bssid            VARCHAR(17) NOT NULL,
  composite_risk   double precision NOT NULL DEFAULT 0,
  signal_risk      double precision NOT NULL DEFAULT 0,
  identity_risk    double precision NOT NULL DEFAULT 0,
  behaviour_risk   double precision NOT NULL DEFAULT 0,
  evidence         jsonb NOT NULL,
  measured_at      timestamptz NOT NULL,
  projection_run_id uuid NOT NULL,
  PRIMARY KEY (bssid)
);

CREATE INDEX IF NOT EXISTS ap_risk_scores_risk_idx ON atheros_search.ap_risk_scores (composite_risk);

CREATE TABLE IF NOT EXISTS atheros_search.v_vec_similarity_audit (
  pair_id                   uuid NOT NULL,
  pair_kind                 VARCHAR(64) NOT NULL,
  embedding_model           VARCHAR(128) NOT NULL,
  embedding_kind            VARCHAR(32) NOT NULL,
  cosine_distance           double precision NOT NULL,
  cosine_similarity         double precision NOT NULL,
  rank                    INT NOT NULL,
  evidence                  jsonb NOT NULL,
  computed_at               timestamptz NOT NULL,
  left_source_table         VARCHAR(128) NOT NULL,
  left_source_key           VARCHAR(255) NOT NULL,
  left_source_mac           VARCHAR(17) DEFAULT NULL,
  left_sensor_id            VARCHAR(64) DEFAULT NULL,
  left_location_id          VARCHAR(128) DEFAULT NULL,
  left_observed_at          timestamptz DEFAULT NULL,
  left_stream_name          VARCHAR(255) DEFAULT NULL,
  left_ssid                 VARCHAR(256) DEFAULT NULL,
  left_bssid                VARCHAR(17) DEFAULT NULL,
  left_destination_bssid    VARCHAR(17) DEFAULT NULL,
  left_device_display_name  VARCHAR(255) DEFAULT NULL,
  left_snapshot_id          uuid DEFAULT NULL,
  left_window_start         timestamptz DEFAULT NULL,
  left_window_end           timestamptz DEFAULT NULL,
  right_source_table        VARCHAR(128) NOT NULL,
  right_source_key          VARCHAR(255) NOT NULL,
  right_source_mac          VARCHAR(17) DEFAULT NULL,
  right_sensor_id           VARCHAR(64) DEFAULT NULL,
  right_location_id         VARCHAR(128) DEFAULT NULL,
  right_observed_at         timestamptz DEFAULT NULL,
  right_stream_name         VARCHAR(255) DEFAULT NULL,
  right_ssid                VARCHAR(256) DEFAULT NULL,
  right_bssid               VARCHAR(17) DEFAULT NULL,
  right_destination_bssid   VARCHAR(17) DEFAULT NULL,
  right_device_display_name VARCHAR(255) DEFAULT NULL,
  right_snapshot_id         uuid DEFAULT NULL,
  right_window_start        timestamptz DEFAULT NULL,
  right_window_end          timestamptz DEFAULT NULL,
  projection_run_id         uuid NOT NULL,
  updated_at                timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (pair_id)
);

CREATE INDEX IF NOT EXISTS v_vec_similarity_audit_computed_idx ON atheros_search.v_vec_similarity_audit (computed_at);
CREATE INDEX IF NOT EXISTS v_vec_similarity_audit_left_idx ON atheros_search.v_vec_similarity_audit (left_source_key);
CREATE INDEX IF NOT EXISTS v_vec_similarity_audit_right_idx ON atheros_search.v_vec_similarity_audit (right_source_key);
