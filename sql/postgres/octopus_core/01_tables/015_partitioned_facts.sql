-- object: octopus_core_partitioned_facts
-- depends_on: octopus_core_ingestion_evidence
-- Global Kafka/dedupe identity stays in the narrow unpartitioned
-- ingestion_evidence table. These append-only facts are partitioned by time.

CREATE TABLE IF NOT EXISTS octopus_core.raw_event_facts (
  evidence_id uuid NOT NULL,
  stream_name text NOT NULL,
  observed_at timestamptz NOT NULL,
  source_key text,
  payload_sha256 char(64) NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (evidence_id, observed_at)
) PARTITION BY RANGE (observed_at);

CREATE TABLE IF NOT EXISTS octopus_core.raw_event_facts_default
  PARTITION OF octopus_core.raw_event_facts DEFAULT;

CREATE INDEX IF NOT EXISTS raw_event_facts_stream_time_idx
  ON octopus_core.raw_event_facts (stream_name, observed_at DESC)
  INCLUDE (evidence_id, payload_sha256);
