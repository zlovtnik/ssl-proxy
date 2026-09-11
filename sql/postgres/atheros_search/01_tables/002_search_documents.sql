-- object: atheros_search_documents_jobs_devices
-- depends_on: atheros_search_schema_control

CREATE TABLE IF NOT EXISTS atheros_search.search_documents (
  document_id        uuid NOT NULL,
  source_kind        VARCHAR(32) NOT NULL,
  source_id          VARCHAR(255) NOT NULL,
  source_version     BIGINT NOT NULL DEFAULT 1,
  source_mac         VARCHAR(17) DEFAULT NULL,
  location_id        VARCHAR(128) DEFAULT NULL,
  sensor_id          VARCHAR(64) DEFAULT NULL,
  observed_at        timestamptz DEFAULT NULL,
  bssid              VARCHAR(17) DEFAULT NULL,
  ssid               VARCHAR(256) DEFAULT NULL,
  frame_subtype      VARCHAR(64) DEFAULT NULL,
  security_flags     INT NOT NULL DEFAULT 0,
  handshake_captured boolean NOT NULL DEFAULT false,
  title              VARCHAR(512) DEFAULT NULL,
  normalized_text    text NOT NULL,
  normalized_sha256  char(64) NOT NULL,
  search_vector      tsvector NOT NULL,
  filters            jsonb NOT NULL DEFAULT '{}'::jsonb,
  detail_json        jsonb NOT NULL DEFAULT '{}'::jsonb,
  status             VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (document_id),
  CONSTRAINT search_documents_source_uq UNIQUE (source_kind, source_id, source_version),
  CONSTRAINT search_documents_kind_ck CHECK (source_kind IN ('event', 'device')),
  CONSTRAINT search_documents_status_ck CHECK (status IN ('active', 'superseded', 'deleted', 'failed')),
  CONSTRAINT search_documents_filters_object_ck CHECK (jsonb_typeof(filters) = 'object'),
  CONSTRAINT search_documents_detail_object_ck CHECK (jsonb_typeof(detail_json) = 'object')
);

CREATE INDEX IF NOT EXISTS search_documents_full_text_idx
  ON atheros_search.search_documents USING gin (search_vector);
CREATE INDEX IF NOT EXISTS search_documents_kind_observed_idx
  ON atheros_search.search_documents (source_kind, observed_at DESC, source_id);
CREATE INDEX IF NOT EXISTS search_documents_status_idx
  ON atheros_search.search_documents (status, updated_at);
CREATE INDEX IF NOT EXISTS search_documents_filters_idx
  ON atheros_search.search_documents USING gin (filters jsonb_path_ops);

CREATE TABLE IF NOT EXISTS atheros_search.embedding_jobs (
  job_id           uuid NOT NULL,
  document_id      uuid NOT NULL,
  embedding_kind   VARCHAR(32) NOT NULL,
  embedding_model  VARCHAR(128) NOT NULL,
  content_sha256   char(64) NOT NULL,
  status           VARCHAR(32) NOT NULL DEFAULT 'pending',
  priority         INT NOT NULL DEFAULT 100,
  owner_id         VARCHAR(128) DEFAULT NULL,
  lease_token      uuid DEFAULT NULL,
  lease_fence      BIGINT NOT NULL DEFAULT 0,
  lease_expires_at timestamptz DEFAULT NULL,
  attempt_count    INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_error       TEXT DEFAULT NULL,
  completed_at     timestamptz DEFAULT NULL,
  created_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (job_id),
  CONSTRAINT embedding_jobs_document_uq UNIQUE (
    document_id, embedding_kind, embedding_model, content_sha256
  ),
  CONSTRAINT embedding_jobs_kind_ck CHECK (embedding_kind IN ('event', 'device')),
  CONSTRAINT embedding_jobs_status_ck CHECK (
    status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')
  ),
  CONSTRAINT embedding_jobs_attempts_ck CHECK (
    attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts
  ),
  CONSTRAINT embedding_jobs_lease_ck CHECK (
    (status = 'leased' AND owner_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR
    (status <> 'leased' AND owner_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS embedding_jobs_claim_idx
  ON atheros_search.embedding_jobs (priority, next_attempt_at, job_id)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS atheros_search.devices (
  mac                  VARCHAR(17) NOT NULL,
  display_name         VARCHAR(255) DEFAULT NULL,
  registered_device_id uuid DEFAULT NULL,
  owner_id             VARCHAR(255) DEFAULT NULL,
  location_id          VARCHAR(128) DEFAULT NULL,
  first_registered     timestamptz DEFAULT NULL,
  first_seen           timestamptz NOT NULL,
  last_seen            timestamptz NOT NULL,
  active               boolean NOT NULL DEFAULT true,
  registered           boolean NOT NULL DEFAULT false,
  tags                 jsonb NOT NULL DEFAULT '[]'::jsonb,
  known_macs           jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at           timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (mac),
  CONSTRAINT devices_mac_ck CHECK (mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'),
  CONSTRAINT devices_seen_ck CHECK (first_seen <= last_seen),
  CONSTRAINT devices_tags_array_ck CHECK (jsonb_typeof(tags) = 'array'),
  CONSTRAINT devices_known_macs_array_ck CHECK (jsonb_typeof(known_macs) = 'array')
);

CREATE INDEX IF NOT EXISTS devices_seen_idx ON atheros_search.devices (last_seen DESC, mac);
CREATE INDEX IF NOT EXISTS devices_location_idx ON atheros_search.devices (location_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS devices_owner_idx ON atheros_search.devices (owner_id, last_seen DESC);
