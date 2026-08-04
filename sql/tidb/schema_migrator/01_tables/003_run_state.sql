-- object: schema_migrator_run_state
-- depends_on: schema_migrator_repository_state

USE schema_migrator;

CREATE TABLE IF NOT EXISTS runs (
  id               CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_id        CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  patch_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status           VARCHAR(32) NOT NULL,
  started_at       DATETIME(6) NOT NULL,
  ended_at         DATETIME(6) DEFAULT NULL,
  triggered_by     VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 3,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_error       TEXT DEFAULT NULL,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  active_flag      TINYINT GENERATED ALWAYS AS (
    CASE WHEN status IN ('pending', 'running') THEN 1 ELSE NULL END
  ) STORED,
  PRIMARY KEY (id),
  UNIQUE KEY runs_one_active_per_target_uq (target_id, active_flag),
  KEY runs_target_started_idx (target_id, started_at),
  KEY runs_claim_idx (status, next_attempt_at, lease_expires_at),
  CONSTRAINT runs_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS run_scripts (
  run_id       CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  script_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  filename     VARCHAR(255) NOT NULL,
  script_order INT NOT NULL,
  status       VARCHAR(32) NOT NULL,
  error        JSON DEFAULT NULL,
  duration_ms  BIGINT DEFAULT NULL,
  started_at   DATETIME(6) DEFAULT NULL,
  finished_at  DATETIME(6) DEFAULT NULL,
  PRIMARY KEY (run_id, script_id),
  UNIQUE KEY run_scripts_order_uq (run_id, script_order)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS validations (
  run_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  checked_at DATETIME(6) NOT NULL,
  status     VARCHAR(32) NOT NULL,
  PRIMARY KEY (run_id),
  KEY validations_target_checked_idx (target_id, checked_at),
  KEY validations_status_idx (status, checked_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS validation_issues (
  run_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  issue_order INT NOT NULL,
  object_type VARCHAR(128) NOT NULL,
  schema_name VARCHAR(255) NOT NULL,
  object_name VARCHAR(255) NOT NULL,
  error       TEXT NOT NULL,
  severity    VARCHAR(32) NOT NULL,
  PRIMARY KEY (run_id, issue_order)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_events (
  id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor       VARCHAR(255) NOT NULL,
  role        VARCHAR(128) NOT NULL,
  action      VARCHAR(128) NOT NULL,
  entity_type VARCHAR(128) NOT NULL,
  entity_id   VARCHAR(255) NOT NULL,
  target_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  at          DATETIME(6) NOT NULL,
  metadata    JSON DEFAULT NULL,
  PRIMARY KEY (id),
  KEY audit_events_at_idx (at),
  KEY audit_events_actor_idx (actor, at),
  KEY audit_events_entity_idx (entity_type, entity_id, at),
  KEY audit_events_target_idx (target_id, at)
) ENGINE=InnoDB;
