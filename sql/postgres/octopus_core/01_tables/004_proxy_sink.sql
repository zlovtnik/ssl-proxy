-- object: octopus_core_proxy_events
-- depends_on: octopus_core_ingestion_work_and_failures

CREATE TABLE IF NOT EXISTS octopus_core.proxy_events (
  event_id            VARCHAR(255) NOT NULL,
  event_time          timestamptz NOT NULL,
  event_type          VARCHAR(32) NOT NULL,
  host                VARCHAR(253) NOT NULL,
  peer_ip             inet DEFAULT NULL,
  wireguard_pubkey    VARCHAR(128) DEFAULT NULL,
  registered_device_id uuid DEFAULT NULL,
  bytes_up            BIGINT NOT NULL DEFAULT 0,
  bytes_down          BIGINT NOT NULL DEFAULT 0,
  status_code         INT DEFAULT NULL,
  blocked             boolean NOT NULL DEFAULT false,
  classification      VARCHAR(32) NOT NULL DEFAULT 'unknown',
  correlation_id      VARCHAR(255) DEFAULT NULL,
  causation_id        VARCHAR(255) DEFAULT NULL,
  payload             jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id),
  CONSTRAINT proxy_events_bytes_ck CHECK (bytes_up >= 0 AND bytes_down >= 0),
  CONSTRAINT proxy_events_classification_ck CHECK (
    classification IN ('ads_tracker', 'analytics', 'cdn', 'essential_api', 'auth', 'unknown')
  ),
  CONSTRAINT proxy_events_payload_ck CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS proxy_events_time_idx ON octopus_core.proxy_events (event_time DESC, event_id);
CREATE INDEX IF NOT EXISTS proxy_events_host_time_idx ON octopus_core.proxy_events (host, event_time DESC);
CREATE INDEX IF NOT EXISTS proxy_events_device_time_idx
  ON octopus_core.proxy_events (registered_device_id, event_time DESC);
