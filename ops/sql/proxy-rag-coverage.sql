-- Required: window_start, window_end, after_time, after_id, document_after_time,
-- document_after_id, page_size, model, statement_timeout_ms. Cursors are private audit state.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('statement_timeout', :'statement_timeout_ms', true) AS timeout_setting \gset
SET LOCAL lock_timeout = '1s';
WITH source_page AS MATERIALIZED (
  SELECT event_id, event_time, event_type, host, registered_device_id,
         blocked, classification, status_code, correlation_id, payload, bytes_up, bytes_down, observation_revision, evidence
  FROM octopus_core.proxy_events
  WHERE event_time >= :'window_start'::timestamptz AND event_time < :'window_end'::timestamptz
    AND (event_time, event_id) > (:'after_time'::timestamptz, :'after_id')
  ORDER BY event_time, event_id LIMIT :page_size
), source_ledger AS (
  SELECT s.*,
    CASE WHEN event_type NOT IN ('block','http_blocked','session.blocked','http_proxied','http_error','tunnel_open','tunnel_close') THEN 'excluded_event_type'
      WHEN host = '' THEN 'excluded_missing_host'
      WHEN host ~ '[[:cntrl:][:space:]]' THEN 'excluded_malformed_host'
      WHEN host LIKE 'hmac:%' THEN 'eligible_sanitized'
      ELSE 'eligible_unvalidated_authority' END AS disposition,
    CASE WHEN host ~ '^[\x01-\x7F]*$' THEN encode(sha256(convert_to(lower(regexp_replace(trim(normalize(
      concat_ws(' ', 'proxy event', event_type, host, classification,
        CASE WHEN blocked THEN 'blocked' ELSE 'allowed' END,
        registered_device_id::text, status_code::text), NFKC)), '\s+', ' ', 'g')), 'UTF8')), 'hex') END AS expected_legacy_sha,
    jsonb_strip_nulls(jsonb_build_object('event_id',event_id,'event_type',event_type,'host',host,
      'proxy_device_id',registered_device_id,'blocked',blocked,'classification',classification,
      'bytes_up',bytes_up,'bytes_down',bytes_down,'status_code',status_code,'correlation_id',correlation_id)) AS expected_legacy_detail
  FROM source_page s
), source_matches AS (
  SELECT s.*, d.document_id, d.normalized_sha256, d.detail_json, d.template_version, d.normalization_version, d.evidence_revision,
         count(d.document_id) OVER (PARTITION BY s.event_id) AS active_documents
  FROM source_ledger s
  LEFT JOIN atheros_search.search_documents d ON d.source_table = 'proxy_events'
    AND d.source_key = s.event_id AND d.source_kind = 'proxy_event' AND d.status = 'active'
), source_counts AS (
  SELECT event_type, disposition, date_trunc('hour',event_time) AS observed_hour, count(DISTINCT event_id) AS sources,
    count(DISTINCT event_id) FILTER (WHERE document_id IS NULL) AS absent_document,
    count(DISTINCT event_id) FILTER (WHERE document_id IS NOT NULL AND normalized_sha256 <> expected_legacy_sha) AS outdated_legacy_text,
    count(DISTINCT event_id) FILTER (WHERE document_id IS NOT NULL AND
      (template_version <> 'proxy-event-v2' OR normalization_version <> 'proxy-authority-v1'
       OR evidence_revision IS DISTINCT FROM observation_revision)) AS outdated_current_contract,
    count(DISTINCT event_id) FILTER (WHERE expected_legacy_sha IS NULL) AS unverifiable_unicode_legacy_text,
    count(DISTINCT event_id) FILTER (WHERE document_id IS NOT NULL AND NOT detail_json @> expected_legacy_detail) AS outdated_legacy_detail,
    count(DISTINCT event_id) FILTER (WHERE active_documents > 1) AS multiple_active_documents,
    count(DISTINCT event_id) FILTER (WHERE registered_device_id IS NOT NULL) AS registration_id_present,
    count(DISTINCT event_id) FILTER (WHERE correlation_id IS NOT NULL) AS correlation_present
    ,count(DISTINCT event_id) FILTER (WHERE jsonb_typeof(payload->'tls_ver')='string') AS retained_clienthello_version_present
    ,count(DISTINCT event_id) FILTER (WHERE jsonb_typeof(payload->'alpn')='string') AS retained_clienthello_alpn_present
    ,count(DISTINCT event_id) FILTER (WHERE jsonb_typeof(payload->'duration_ms')='number') AS retained_duration_value_present
    ,count(DISTINCT event_id) FILTER (WHERE jsonb_typeof(payload->'identity_source')='string') AS retained_identity_method_present
    ,count(DISTINCT event_id) FILTER (WHERE evidence->>'parse_status' IN ('valid_dns','valid_ipv4','valid_ipv6')) AS normalized_authority_valid
    ,count(DISTINCT event_id) FILTER (WHERE jsonb_typeof(evidence->'port')='number') AS explicit_port_observed
    ,count(DISTINCT event_id) FILTER (WHERE evidence->'measurement'->>'bytes_status'='measured_terminal') AS terminal_transfer_measurement_present
  FROM source_matches GROUP BY event_type, disposition, date_trunc('hour',event_time)
), document_page AS MATERIALIZED (
  SELECT document_id, source_kind, normalized_sha256, normalized_text, observed_at, metadata, input_revision,
         template_version, normalization_version
  FROM atheros_search.search_documents
  WHERE source_kind IN ('proxy_event','proxy_blocked_host_window') AND status = 'active'
    AND observed_at >= :'window_start'::timestamptz AND observed_at < :'window_end'::timestamptz
    AND (observed_at, document_id) > (:'document_after_time'::timestamptz, :'document_after_id'::uuid)
  ORDER BY observed_at, document_id LIMIT :page_size
), document_matches AS (
  SELECT d.*, j.status AS job_status, j.attempt_count, j.max_attempts,
    u.content_sha256 AS unified_sha, k.content_sha256 AS per_kind_sha,
    u.embedding IS DISTINCT FROM k.embedding AS vector_value_mismatch,
    EXISTS (SELECT 1 FROM atheros_search.embedding_jobs old_job
      WHERE old_job.document_id=d.document_id AND old_job.embedding_kind='event'
        AND old_job.embedding_model=:'model' AND old_job.content_sha256<>d.normalized_sha256 LIMIT 1) AS stale_job_content,
    EXISTS (SELECT 1 FROM atheros_search.embedding_jobs other_model
      WHERE other_model.document_id=d.document_id AND other_model.embedding_kind='event'
        AND other_model.embedding_model<>:'model' LIMIT 1) AS other_model_job,
    encode(sha256(convert_to(d.normalized_text, 'UTF8')), 'hex') = d.normalized_sha256 AS text_hash_valid
  FROM document_page d
  LEFT JOIN atheros_search.embedding_jobs j ON j.document_id = d.document_id
    AND j.embedding_kind = 'event' AND j.embedding_model = :'model' AND j.content_sha256 = d.normalized_sha256
    AND j.input_revision = d.input_revision
  LEFT JOIN atheros_search.embeddings u ON u.document_id = d.document_id
    AND u.embedding_kind = 'event' AND u.embedding_model = :'model'
    AND u.input_revision = d.input_revision
  LEFT JOIN atheros_search.search_vectors_event k ON k.document_id = d.document_id AND k.embedding_model = :'model'
    AND k.input_revision = d.input_revision
), document_counts AS (
  SELECT source_kind, date_trunc('hour',observed_at) AS observed_hour,
    CASE WHEN template_version='legacy_unknown' THEN 'unknown_legacy' ELSE template_version END AS template_version,
    CASE WHEN normalization_version='legacy_unknown' THEN 'unknown_legacy' ELSE normalization_version END AS normalization_version,
    CASE WHEN input_revision='legacy_unknown' THEN 'unknown_legacy' ELSE input_revision END AS preprocessing_version,
    normalized_sha256 AS text_checksum,
    CASE WHEN job_status IS NULL THEN 'absent'
      WHEN job_status IN ('pending','failed') AND attempt_count >= max_attempts THEN job_status || '_exhausted'
      ELSE job_status END AS job_disposition,
    count(*) AS documents, count(*) FILTER (WHERE NOT text_hash_valid) AS invalid_text_hash,
    count(*) FILTER (WHERE stale_job_content) AS stale_checksum_job_present,
    count(*) FILTER (WHERE other_model_job) AS other_model_job_present,
    count(*) FILTER (WHERE unified_sha = normalized_sha256) AS content_matching_unified,
    count(*) FILTER (WHERE per_kind_sha = normalized_sha256) AS content_matching_per_kind,
    count(*) FILTER (WHERE job_status = 'completed' AND
      (unified_sha IS DISTINCT FROM normalized_sha256 OR per_kind_sha IS DISTINCT FROM normalized_sha256)) AS completed_job_vector_gap,
    count(*) FILTER (WHERE unified_sha IS DISTINCT FROM per_kind_sha) AS vector_checksum_parity_gap,
    count(*) FILTER (WHERE unified_sha IS NOT NULL AND per_kind_sha IS NOT NULL AND vector_value_mismatch) AS vector_value_parity_gap,
    count(*) FILTER (WHERE (unified_sha IS NULL) <> (per_kind_sha IS NULL)) AS vector_presence_parity_gap
  FROM document_matches GROUP BY source_kind, date_trunc('hour',observed_at), template_version, normalization_version,
    input_revision, normalized_sha256,
    CASE WHEN job_status IS NULL THEN 'absent'
      WHEN job_status IN ('pending','failed') AND attempt_count >= max_attempts THEN job_status || '_exhausted'
      ELSE job_status END
)
SELECT jsonb_build_object(
  'audit_version', 'proxy-rag-coverage-v1', 'measured_at', CURRENT_TIMESTAMP,
  'window_start', :'window_start', 'window_end', :'window_end', 'model', :'model',
  'source_rows', (SELECT count(*) FROM source_page), 'document_rows', (SELECT count(*) FROM document_page),
  'source_page', coalesce((SELECT jsonb_agg(to_jsonb(s)) FROM source_counts s), '[]'::jsonb),
  'document_page', coalesce((SELECT jsonb_agg(to_jsonb(d)) FROM document_counts d), '[]'::jsonb),
  'availability', jsonb_build_object(
    'denominator', 'source observations; registration ID presence is not validated attribution',
    'raw_authority', 'unknown_legacy', 'explicit_port', 'unknown_legacy', 'coalesced_attempts', 'unknown_legacy',
    'terminal_measured_bytes', 'unknown_legacy', 'tls_clienthello', 'unknown_legacy',
    'validated_flows', 'unavailable_pending_lifecycle_contract'),
  'source_cursor', (SELECT jsonb_build_array(event_time,event_id) FROM source_page ORDER BY event_time DESC,event_id DESC LIMIT 1),
  'document_cursor', (SELECT jsonb_build_array(observed_at,document_id) FROM document_page ORDER BY observed_at DESC,document_id DESC LIMIT 1),
  'scope', 'bounded independent source and active-document pages; not retained totals',
  'preprocessing_gate', 'content matches do not establish current preprocessing compatibility'
);
ROLLBACK;
