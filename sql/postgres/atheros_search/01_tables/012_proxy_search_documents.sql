-- object: atheros_search_proxy_search_documents
-- depends_on: atheros_search_identity_graph
-- Append-only proxy document fields. Proxy documents share the existing
-- event embedding kind and unified embeddings table.

ALTER TABLE atheros_search.search_documents
  ADD COLUMN IF NOT EXISTS host VARCHAR(253),
  ADD COLUMN IF NOT EXISTS proxy_device_id uuid,
  ADD COLUMN IF NOT EXISTS proxy_event_type VARCHAR(32),
  ADD COLUMN IF NOT EXISTS blocked boolean,
  ADD COLUMN IF NOT EXISTS classification VARCHAR(32),
  ADD COLUMN IF NOT EXISTS window_start timestamptz,
  ADD COLUMN IF NOT EXISTS window_end timestamptz;

ALTER TABLE atheros_search.search_documents
  DROP CONSTRAINT IF EXISTS search_documents_kind_ck;
ALTER TABLE atheros_search.search_documents
  ADD CONSTRAINT search_documents_kind_ck CHECK (
    source_kind IN (
      'event', 'device', 'behaviour_window', 'frame_sequence',
      'proxy_event', 'proxy_blocked_host_window'
    )
  );

ALTER TABLE atheros_search.search_documents
  DROP CONSTRAINT IF EXISTS search_documents_proxy_classification_ck,
  DROP CONSTRAINT IF EXISTS search_documents_proxy_window_ck;
ALTER TABLE atheros_search.search_documents
  ADD CONSTRAINT search_documents_proxy_classification_ck CHECK (
    classification IS NULL OR classification IN (
      'ads_tracker', 'analytics', 'cdn', 'essential_api', 'auth', 'unknown'
    )
  ),
  ADD CONSTRAINT search_documents_proxy_window_ck CHECK (
    (window_start IS NULL AND window_end IS NULL)
    OR (window_start IS NOT NULL AND window_end IS NOT NULL AND window_end > window_start)
  );

CREATE INDEX IF NOT EXISTS search_documents_proxy_host_time_idx
  ON atheros_search.search_documents (host, observed_at DESC, document_id)
  WHERE source_kind IN ('proxy_event', 'proxy_blocked_host_window') AND status = 'active';

CREATE INDEX IF NOT EXISTS search_documents_proxy_device_time_idx
  ON atheros_search.search_documents (proxy_device_id, observed_at DESC, document_id)
  WHERE source_kind IN ('proxy_event', 'proxy_blocked_host_window') AND status = 'active';

CREATE INDEX IF NOT EXISTS search_documents_proxy_event_type_time_idx
  ON atheros_search.search_documents (proxy_event_type, observed_at DESC, document_id)
  WHERE source_kind = 'proxy_event' AND status = 'active';
