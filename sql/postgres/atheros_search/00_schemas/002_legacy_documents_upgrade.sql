-- object: atheros_search_legacy_documents_upgrade
-- depends_on: atheros_search_schema
-- Run before the table baseline: CREATE TABLE IF NOT EXISTS cannot upgrade an
-- existing table, and the baseline indexes already reference these columns.
-- The legacy source key and all document/job identities remain unchanged.

DO $$
BEGIN
  IF to_regclass('atheros_search.search_documents') IS NOT NULL THEN
    ALTER TABLE atheros_search.search_documents
      ADD COLUMN IF NOT EXISTS source_id VARCHAR(255),
      ADD COLUMN IF NOT EXISTS search_vector tsvector NOT NULL DEFAULT ''::tsvector,
      ADD COLUMN IF NOT EXISTS filters jsonb NOT NULL DEFAULT '{}'::jsonb;

    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'atheros_search' AND table_name = 'search_documents'
        AND column_name = 'source_key'
    ) THEN
      UPDATE atheros_search.search_documents
      SET source_id = source_key,
          search_vector = to_tsvector('simple', normalized_text)
      WHERE source_id IS NULL;
    END IF;

    ALTER TABLE atheros_search.search_documents
      ALTER COLUMN source_id SET NOT NULL;
  END IF;
END $$;
