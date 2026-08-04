-- object: integration_console_commands
-- depends_on: integration_console_records
-- Octopus claims commands with a conditional UPDATE and must match owner_id,
-- lease_token, and lease_fence when acknowledging or retrying the command.

USE integration_console;

CREATE TABLE IF NOT EXISTS console_commands (
  command_id       CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  command_type     VARCHAR(64) NOT NULL,
  aggregate_type   VARCHAR(64) NOT NULL,
  aggregate_key    VARCHAR(255) NOT NULL,
  idempotency_key  VARCHAR(128) NOT NULL,
  requested_by     VARCHAR(255) NOT NULL,
  requested_at     DATETIME(6) NOT NULL,
  payload          JSON NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at DATETIME(6) DEFAULT NULL,
  last_error       TEXT DEFAULT NULL,
  completed_at     DATETIME(6) DEFAULT NULL,
  created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (command_id),
  UNIQUE KEY console_commands_idempotency_uq (idempotency_key),
  KEY console_commands_claim_idx (status, next_attempt_at, lease_expires_at),
  KEY console_commands_aggregate_idx (aggregate_type, aggregate_key, requested_at),
  CONSTRAINT console_commands_type_ck CHECK (
    command_type IN (
      'device.upsert',
      'device.delete',
      'authorized_network.upsert',
      'authorized_network.delete'
    )
  ),
  CONSTRAINT console_commands_status_ck CHECK (
    status IN ('pending', 'leased', 'succeeded', 'rejected', 'failed', 'cancelled')
  ),
  CONSTRAINT console_commands_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  ),
  CONSTRAINT console_commands_requested_by_ck CHECK (
    requested_by <> ''
  )
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS console_command_acknowledgements (
  acknowledgement_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  command_id          CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status              VARCHAR(32) NOT NULL,
  core_entity_type    VARCHAR(64) DEFAULT NULL,
  core_entity_id      VARCHAR(255) DEFAULT NULL,
  core_entity_version BIGINT DEFAULT NULL,
  result              JSON NOT NULL,
  error_code          VARCHAR(64) DEFAULT NULL,
  error_message       TEXT DEFAULT NULL,
  acknowledged_at     DATETIME(6) NOT NULL,
  created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (acknowledgement_id),
  UNIQUE KEY console_command_acknowledgements_command_uq (command_id),
  KEY console_command_acknowledgements_time_idx (acknowledged_at),
  CONSTRAINT console_command_acknowledgements_command_fk FOREIGN KEY (command_id)
    REFERENCES console_commands (command_id) ON DELETE RESTRICT,
  CONSTRAINT console_command_acknowledgements_status_ck CHECK (
    status IN ('succeeded', 'rejected', 'failed')
  )
) ENGINE=InnoDB;
