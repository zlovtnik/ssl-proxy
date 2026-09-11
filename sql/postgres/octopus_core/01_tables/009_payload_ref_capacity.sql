-- object: octopus_core_payload_archives
-- depends_on: octopus_core_ingestion_work_and_failures

CREATE TABLE IF NOT EXISTS octopus_core.payload_archives (
  archive_id       uuid NOT NULL,
  source_kind      VARCHAR(64) NOT NULL,
  source_id        VARCHAR(255) NOT NULL,
  object_uri       VARCHAR(2048) NOT NULL,
  content_sha256   char(64) NOT NULL,
  payload_bytes    BIGINT NOT NULL,
  archived_at      timestamptz NOT NULL,
  storage_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (archive_id),
  CONSTRAINT payload_archives_source_uq UNIQUE (source_kind, source_id),
  CONSTRAINT payload_archives_bytes_ck CHECK (payload_bytes >= 0),
  CONSTRAINT payload_archives_metadata_ck CHECK (jsonb_typeof(storage_metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS payload_archives_time_idx
  ON octopus_core.payload_archives (archived_at DESC, archive_id);
