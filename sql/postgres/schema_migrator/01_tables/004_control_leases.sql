-- object: schema_migrator_control_leases
-- depends_on: schema_migrator_run_state
-- Claims use conditional UPDATE schema_migrator.plus affected-row checks. The fence increases
-- on every successful claim; stale owners cannot complete newer work.

CREATE TABLE IF NOT EXISTS schema_migrator.control_leases (
  resource_type    VARCHAR(64) NOT NULL,
  resource_id      VARCHAR(255) NOT NULL,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  fence            BIGINT NOT NULL DEFAULT 0,
  attempt_count    INT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error       TEXT DEFAULT NULL,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (resource_type, resource_id),
  CONSTRAINT control_leases_attempt_count_ck CHECK (attempt_count >= 0),
  CONSTRAINT control_leases_owner_token_ck CHECK (
    (owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
    OR
    (owner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS control_leases_claim_idx ON schema_migrator.control_leases (resource_type, next_attempt_at, lease_expires_at);
