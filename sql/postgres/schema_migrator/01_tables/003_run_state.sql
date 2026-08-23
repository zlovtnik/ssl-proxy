-- object: schema_migrator_run_state
-- depends_on: schema_migrator_repository_state

CREATE TABLE IF NOT EXISTS schema_migrator.runs (
  id               uuid NOT NULL,
  target_id        uuid NOT NULL,
  patch_id         uuid NOT NULL,
  status           VARCHAR(32) NOT NULL,
  started_at       timestamptz NOT NULL,
  ended_at         timestamptz DEFAULT NULL,
  triggered_by     VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 3,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error       TEXT DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  active_flag      smallint GENERATED ALWAYS AS (
    CASE WHEN status IN ('pending', 'running') THEN 1 ELSE NULL END
  ) STORED,
  PRIMARY KEY (id),
  CONSTRAINT runs_one_active_per_target_uq UNIQUE (target_id, active_flag),
  CONSTRAINT runs_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
);

CREATE INDEX IF NOT EXISTS runs_target_started_idx ON schema_migrator.runs (target_id, started_at);
CREATE INDEX IF NOT EXISTS runs_claim_idx ON schema_migrator.runs (status, next_attempt_at, lease_expires_at);

CREATE TABLE IF NOT EXISTS schema_migrator.run_scripts (
  run_id       uuid NOT NULL,
  script_id    uuid NOT NULL,
  filename     VARCHAR(255) NOT NULL,
  script_order INT NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error        jsonb DEFAULT NULL,
  duration_ms  BIGINT DEFAULT NULL,
  started_at   timestamptz DEFAULT NULL,
  finished_at  timestamptz DEFAULT NULL,
  PRIMARY KEY (run_id, script_id),
  CONSTRAINT run_scripts_order_uq UNIQUE (run_id, script_order)
);

CREATE TABLE IF NOT EXISTS schema_migrator.validations (
  run_id     uuid NOT NULL,
  target_id  uuid NOT NULL,
  checked_at timestamptz NOT NULL,
  status     VARCHAR(32) NOT NULL,
  PRIMARY KEY (run_id)
);

CREATE INDEX IF NOT EXISTS validations_target_checked_idx ON schema_migrator.validations (target_id, checked_at);
CREATE INDEX IF NOT EXISTS validations_status_idx ON schema_migrator.validations (status, checked_at);

CREATE TABLE IF NOT EXISTS schema_migrator.validation_issues (
  run_id      uuid NOT NULL,
  issue_order INT NOT NULL,
  object_type VARCHAR(128) NOT NULL,
  schema_name VARCHAR(255) NOT NULL,
  object_name VARCHAR(255) NOT NULL,
  error       TEXT NOT NULL,
  severity    VARCHAR(32) NOT NULL,
  PRIMARY KEY (run_id, issue_order)
);

CREATE TABLE IF NOT EXISTS schema_migrator.audit_events (
  id          uuid NOT NULL,
  actor       VARCHAR(255) NOT NULL,
  role        VARCHAR(128) NOT NULL,
  action      VARCHAR(128) NOT NULL,
  entity_type VARCHAR(128) NOT NULL,
  entity_id   VARCHAR(255) NOT NULL,
  target_id   uuid DEFAULT NULL,
  at          timestamptz NOT NULL,
  metadata    jsonb DEFAULT NULL,
  PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);

CREATE TABLE IF NOT EXISTS schema_migrator.audit_events_default
  PARTITION OF schema_migrator.audit_events DEFAULT;

CREATE INDEX IF NOT EXISTS audit_events_at_idx ON schema_migrator.audit_events (at);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON schema_migrator.audit_events (actor, at);
CREATE INDEX IF NOT EXISTS audit_events_entity_idx ON schema_migrator.audit_events (entity_type, entity_id, at);
CREATE INDEX IF NOT EXISTS audit_events_target_idx ON schema_migrator.audit_events (target_id, at);
