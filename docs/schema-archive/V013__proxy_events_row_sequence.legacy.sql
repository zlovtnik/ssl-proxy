-- V013: add proxy_events.batch_id and row_sequence for Oracle deployments
-- that predate the bootstrap schema. This keeps the worker's batch dedupe key
-- available on existing databases without changing the current insert contract.

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS'
    AND column_name = 'BATCH_ID';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (batch_id VARCHAR2(36))';
  END IF;

  EXECUTE IMMEDIATE q'[
    UPDATE proxy_events
    SET batch_id = LOWER(RAWTOHEX(SYS_GUID()))
    WHERE batch_id IS NULL
  ]';

  EXECUTE IMMEDIATE 'ALTER TABLE proxy_events MODIFY (batch_id NOT NULL)';

  SELECT COUNT(*) INTO v_count
  FROM user_tab_cols
  WHERE table_name = 'PROXY_EVENTS'
    AND column_name = 'ROW_SEQUENCE';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (row_sequence NUMBER(10,0))';
  END IF;

  EXECUTE IMMEDIATE q'[
    UPDATE proxy_events pe
    SET row_sequence = (
      SELECT rn
      FROM (
        SELECT rowid AS rid,
               ROW_NUMBER() OVER (
                 PARTITION BY batch_id
                 ORDER BY event_time, id
               ) AS rn
        FROM proxy_events
      ) ranked
      WHERE ranked.rid = pe.rowid
    )
    WHERE row_sequence IS NULL
  ]';

  EXECUTE IMMEDIATE 'ALTER TABLE proxy_events MODIFY (row_sequence NOT NULL)';
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_indexes
  WHERE index_name = 'PROXY_EVENTS_BATCH_ROW_IDX';

  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE UNIQUE INDEX proxy_events_batch_row_idx ON proxy_events (batch_id, row_sequence)';
  END IF;
END;
/
