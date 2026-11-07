-- object: atheros_search_proxy_document_kind_validation
-- depends_on: atheros_search_proxy_behavior_scopes
-- Kept separate from migration 022: validation scans retained documents under
-- SHARE UPDATE EXCLUSIVE, which permits writes. Only provisioning applies DDL.
DO $$
DECLARE
  row_budget_text text := current_setting('sslproxy.proxy_kind_validation_max_rows', true);
  window_end_text text := current_setting('sslproxy.proxy_kind_validation_window_end', true);
  row_budget bigint;
  retained_rows bigint;
  statement_budget interval := current_setting('statement_timeout')::interval;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint
      WHERE conrelid = 'atheros_search.search_documents'::regclass
        AND conname = 'search_documents_kind_ck' AND convalidated) THEN
    RETURN;
  END IF;
  PERFORM set_config('lock_timeout', '1s', true);
  LOCK TABLE atheros_search.search_documents IN SHARE UPDATE EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM atheros_search.search_documents) THEN
    IF row_budget_text IS NULL OR row_budget_text !~ '^[0-9]{1,18}$'
        OR NULLIF(window_end_text, '') IS NULL THEN
      RAISE EXCEPTION 'proxy kind validation requires reviewed proxy_kind_validation_max_rows and proxy_kind_validation_window_end';
    END IF;
    row_budget := row_budget_text::bigint;
    IF statement_budget <= interval '1 second'
        OR NOT isfinite(window_end_text::timestamptz)
        OR clock_timestamp() + statement_budget > window_end_text::timestamptz THEN
      RAISE EXCEPTION 'proxy kind validation requires finite statement_timeout > 1s within the maintenance window';
    END IF;
    SELECT count(*) INTO retained_rows FROM (
      SELECT 1 FROM atheros_search.search_documents LIMIT row_budget + 1
    ) bounded;
    IF retained_rows > row_budget THEN
      RAISE EXCEPTION 'proxy kind validation retained rows exceed reviewed maintenance budget %', row_budget;
    END IF;
  END IF;
  ALTER TABLE atheros_search.search_documents VALIDATE CONSTRAINT search_documents_kind_ck;
END $$;
