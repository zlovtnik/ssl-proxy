-- object: atheros_search_vector_tiflash_replicas
-- depends_on: atheros_search_vectors
-- Apply this file, then poll the gate query until ready_table_count is 4.

ALTER TABLE atheros_search.search_vectors_event SET TIFLASH REPLICA 1;
ALTER TABLE atheros_search.search_vectors_device SET TIFLASH REPLICA 1;
ALTER TABLE atheros_search.search_vectors_behaviour SET TIFLASH REPLICA 1;
ALTER TABLE atheros_search.search_vectors_sequence SET TIFLASH REPLICA 1;
