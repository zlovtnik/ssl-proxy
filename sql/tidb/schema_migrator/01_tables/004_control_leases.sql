-- object: schema_migrator_control_leases
-- depends_on: schema_migrator_run_state
-- Claims use conditional UPDATE plus affected-row checks. The fence increases
-- on every successful claim; stale owners cannot complete newer work.

USE schema_migrator;

CREATE TABLE IF NOT EXISTS control_leases (
  resource_type    VARCHAR(64) NOT NULL,
  resource_id      VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  fence            BIGINT NOT NULL DEFAULT 0,
  attempt_count    INT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_error       TEXT DEFAULT NULL,
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (resource_type, resource_id),
  KEY control_leases_claim_idx (resource_type, next_attempt_at, lease_expires_at),
  CONSTRAINT control_leases_attempt_count_ck CHECK (attempt_count >= 0),
  CONSTRAINT control_leases_owner_token_ck CHECK (
    (owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (owner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
) ENGINE=InnoDB;
