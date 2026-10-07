-- object: octopus_core_wireless_projection_receipts
-- depends_on: octopus_core_ingestion_work_and_failures
CREATE TABLE octopus_core.wireless_projection_receipts (
  topic varchar(255) NOT NULL,
  partition_id integer NOT NULL,
  offset_id bigint NOT NULL,
  payload_sha256 char(64) NOT NULL,
  disposition varchar(32) NOT NULL,
  observed_at timestamptz NOT NULL,
  projected_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP + INTERVAL '9 days',
  PRIMARY KEY (topic, partition_id, offset_id)
);
CREATE INDEX wireless_projection_receipts_expiry_idx
  ON octopus_core.wireless_projection_receipts (expires_at);
CREATE TABLE octopus_core.wireless_projection_hashes (
  payload_sha256 char(64) PRIMARY KEY,
  expires_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP + INTERVAL '9 days'
);
CREATE INDEX wireless_projection_hashes_expiry_idx
  ON octopus_core.wireless_projection_hashes (expires_at);
