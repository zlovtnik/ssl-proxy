-- object: atheros_search_vector_tiflash_ready_gate
-- depends_on: atheros_search_vector_tiflash_replicas
-- Gate contract: do not apply the HNSW file until this query returns exactly
-- ready_table_count=4 and expected_table_count=4.

SELECT
  SUM(CASE WHEN AVAILABLE = 1 THEN 1 ELSE 0 END) AS ready_table_count,
  4 AS expected_table_count
FROM INFORMATION_SCHEMA.TIFLASH_REPLICA
WHERE TABLE_SCHEMA = 'atheros_search'
  AND TABLE_NAME IN (
    'search_vectors_event',
    'search_vectors_device',
    'search_vectors_behaviour',
    'search_vectors_sequence'
  );
