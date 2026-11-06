-- object: atheros_search_proxy_document_scope_index
-- depends_on: atheros_search_proxy_preparation
-- Match the audit's effective timestamp and UUID keyset, including legacy
-- windows without bounds. The provisioning executor owns this index build.
CREATE INDEX IF NOT EXISTS search_documents_proxy_scope_time_idx
  ON atheros_search.search_documents (
    (CASE WHEN source_kind = 'proxy_blocked_host_window'
      THEN coalesce(window_start, observed_at) ELSE observed_at END),
    document_id
  )
  WHERE source_kind IN ('proxy_event', 'proxy_blocked_host_window') AND status = 'active';
