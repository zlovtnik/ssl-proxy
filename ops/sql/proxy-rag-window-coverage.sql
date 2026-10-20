-- One closed UTC hour only. Required: window_start, window_end, page_size,
-- statement_timeout_ms. page_size+1 is an overflow sentinel, not a partial denominator.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('statement_timeout', :'statement_timeout_ms', true) AS timeout_setting \gset
SET LOCAL lock_timeout = '1s';
SET LOCAL timezone = 'UTC';
WITH bounded AS MATERIALIZED (
  SELECT host, coalesce(registered_device_id::text,'') AS device_key,
    event_type, classification, coalesce(status_code::text,'none') AS status_key,
    bytes_up, bytes_down, event_time
  FROM octopus_core.proxy_events
  WHERE blocked=true AND event_time>=:'window_start'::timestamptz AND event_time<:'window_end'::timestamptz
  ORDER BY event_time,event_id LIMIT (:page_size + 1)
), base AS MATERIALIZED (
  SELECT * FROM bounded WHERE (SELECT count(*) FROM bounded)<=:page_size
    AND :'window_end'::timestamptz=:'window_start'::timestamptz+interval '1 hour'
    AND :'window_start'::timestamptz=date_trunc('hour',:'window_start'::timestamptz)
    AND :'window_end'::timestamptz<=date_trunc('hour',CURRENT_TIMESTAMP)
), totals AS (
  SELECT host,device_key,count(*) AS observations,sum(bytes_up)+sum(bytes_down) AS legacy_bytes
  FROM base GROUP BY host,device_key
), types AS (
  SELECT host,device_key,jsonb_object_agg(event_type,n ORDER BY event_type) AS counts
  FROM (SELECT host,device_key,event_type,count(*) n FROM base GROUP BY host,device_key,event_type) t
  GROUP BY host,device_key
), classes AS (
  SELECT host,device_key,jsonb_object_agg(classification,n ORDER BY classification) AS counts
  FROM (SELECT host,device_key,classification,count(*) n FROM base GROUP BY host,device_key,classification) t
  GROUP BY host,device_key
), statuses AS (
  SELECT host,device_key,jsonb_object_agg(status_key,n ORDER BY status_key) AS counts
  FROM (SELECT host,device_key,status_key,count(*) n FROM base GROUP BY host,device_key,status_key) t
  GROUP BY host,device_key
), expected AS (
  SELECT totals.host,
    'proxy-window:'||md5(jsonb_build_array(totals.host,device_key,:'window_start'::timestamptz)::text) AS source_key,
    encode(sha256(convert_to(lower(regexp_replace(trim(normalize(concat_ws(' ',
      'blocked proxy host window',totals.host,nullif(device_key,''),types.counts::text,
      classes.counts::text,statuses.counts::text,'blocked attempts',observations::text,
      'total bytes',legacy_bytes::text),NFKC)), '\s+',' ','g')),'UTF8')),'hex') AS legacy_text_sha
  FROM totals JOIN types USING(host,device_key) JOIN classes USING(host,device_key) JOIN statuses USING(host,device_key)
), matches AS (
  SELECT e.*,d.document_id,d.normalized_sha256 FROM expected e
  LEFT JOIN atheros_search.search_documents d ON d.source_table='proxy_events' AND d.source_key=e.source_key
    AND d.source_kind='proxy_blocked_host_window' AND d.status='active'
)
SELECT jsonb_build_object(
  'audit_version','proxy-window-coverage-v1','window_start',:'window_start','window_end',:'window_end',
  'scanned_rows',(SELECT count(*) FROM bounded),
  'complete_input',(SELECT count(*) FROM bounded)<=:page_size
    AND :'window_end'::timestamptz=:'window_start'::timestamptz+interval '1 hour'
    AND :'window_start'::timestamptz=date_trunc('hour',:'window_start'::timestamptz)
    AND :'window_end'::timestamptz<=date_trunc('hour',CURRENT_TIMESTAMP),
  'groups',count(DISTINCT source_key),
  'absent_document',count(DISTINCT source_key) FILTER(WHERE document_id IS NULL),
  'outdated_legacy_text',count(DISTINCT source_key) FILTER(WHERE document_id IS NOT NULL
    AND host ~ '^[\x01-\x7F]*$' AND normalized_sha256<>legacy_text_sha),
  'unicode_text_unverifiable',count(DISTINCT source_key) FILTER(WHERE host !~ '^[\x01-\x7F]*$'),
  'limitation','legacy UTC source-key/template comparison only; saturated input has no denominator; retained observations are not attempts; legacy byte sums are not measured transfer'
) FROM matches;
ROLLBACK;
