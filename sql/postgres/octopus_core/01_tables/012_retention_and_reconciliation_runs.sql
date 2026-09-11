-- object: octopus_core_maintenance
-- depends_on: octopus_core_outbox_and_processors

CREATE TABLE IF NOT EXISTS octopus_core.maintenance_runs (
  run_id         uuid NOT NULL,
  maintenance_kind VARCHAR(64) NOT NULL,
  status         VARCHAR(32) NOT NULL,
  cutoff_at      timestamptz DEFAULT NULL,
  rows_selected  BIGINT NOT NULL DEFAULT 0,
  rows_changed   BIGINT NOT NULL DEFAULT 0,
  sanitized_error TEXT DEFAULT NULL,
  started_at     timestamptz NOT NULL,
  finished_at    timestamptz DEFAULT NULL,
  created_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (run_id),
  CONSTRAINT maintenance_runs_status_ck CHECK (status IN ('running', 'completed', 'failed', 'cancelled')),
  CONSTRAINT maintenance_runs_counts_ck CHECK (rows_selected >= 0 AND rows_changed >= 0)
);

CREATE TABLE IF NOT EXISTS octopus_core.maintenance_findings (
  finding_id       uuid NOT NULL,
  maintenance_kind VARCHAR(64) NOT NULL,
  subject_kind     VARCHAR(64) NOT NULL,
  subject_id_hash  char(64) NOT NULL,
  finding_type     VARCHAR(64) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'open',
  details          jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at      timestamptz DEFAULT NULL,
  PRIMARY KEY (finding_id),
  CONSTRAINT maintenance_findings_identity_uq UNIQUE (
    maintenance_kind, subject_kind, subject_id_hash, finding_type
  ),
  CONSTRAINT maintenance_findings_status_ck CHECK (status IN ('open', 'resolved', 'ignored')),
  CONSTRAINT maintenance_findings_details_ck CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX IF NOT EXISTS maintenance_findings_open_idx
  ON octopus_core.maintenance_findings (status, last_seen_at DESC);
