-- object: atheros_search_projection_maintenance
-- depends_on: atheros_search_projection_state
-- Additive state required for late-arrival-safe, idempotent projection rebuilds.

ALTER TABLE atheros_search.timing_profiles
  ADD COLUMN IF NOT EXISTS source_event_count BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS atheros_search.sequence_transition_contributions (
  session_key       VARCHAR(255) NOT NULL,
  previous_token    VARCHAR(191) NOT NULL,
  next_token        VARCHAR(191) NOT NULL,
  sequence_kind     VARCHAR(64) NOT NULL DEFAULT 'frame_sequence',
  transition_count  BIGINT NOT NULL DEFAULT 0,
  previous_total    BIGINT NOT NULL DEFAULT 0,
  projection_run_id uuid NOT NULL,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_key, previous_token, next_token, sequence_kind)
);

CREATE INDEX IF NOT EXISTS sequence_transition_contributions_aggregate_idx ON atheros_search.sequence_transition_contributions (previous_token, next_token, sequence_kind);

CREATE TABLE IF NOT EXISTS atheros_search.sequence_previous_totals (
  session_key       VARCHAR(255) NOT NULL,
  previous_token    VARCHAR(191) NOT NULL,
  sequence_kind     VARCHAR(64) NOT NULL DEFAULT 'frame_sequence',
  previous_total    BIGINT NOT NULL DEFAULT 0,
  projection_run_id uuid NOT NULL,
  updated_at        timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_key, previous_token, sequence_kind)
);

CREATE INDEX IF NOT EXISTS sequence_previous_totals_aggregate_idx ON atheros_search.sequence_previous_totals (previous_token, sequence_kind);
