-- object: octopus_core_wireless_projection_group_receipts
-- depends_on: octopus_core_wireless_projection_receipts
-- Keep the original receipts intact. A rebuilt broker gets a new versioned
-- consumer group; payload hashes still deduplicate effects across histories.
CREATE TABLE octopus_core.wireless_projection_group_receipts (
  group_id varchar(128) NOT NULL,
  topic varchar(255) NOT NULL,
  partition_id integer NOT NULL,
  offset_id bigint NOT NULL,
  payload_sha256 char(64) NOT NULL,
  disposition varchar(32) NOT NULL,
  observed_at timestamptz NOT NULL,
  projected_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP + INTERVAL '9 days',
  CONSTRAINT wireless_projection_group_receipts_pkey PRIMARY KEY (group_id, topic, partition_id, offset_id)
);
CREATE INDEX wireless_projection_group_receipts_expiry_idx
  ON octopus_core.wireless_projection_group_receipts (expires_at);
