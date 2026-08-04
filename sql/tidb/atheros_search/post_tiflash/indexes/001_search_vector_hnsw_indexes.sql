-- object: atheros_search_vector_hnsw_indexes
-- depends_on: atheros_search_vector_tiflash_ready_gate
-- TiDB v8.5+ vector indexes remain beta. Validate this exact cluster/version.

CREATE VECTOR INDEX search_vectors_event_embedding_hnsw_idx
  ON atheros_search.search_vectors_event
  ((VEC_COSINE_DISTANCE(embedding))) USING HNSW;

CREATE VECTOR INDEX search_vectors_device_embedding_hnsw_idx
  ON atheros_search.search_vectors_device
  ((VEC_COSINE_DISTANCE(embedding))) USING HNSW;

CREATE VECTOR INDEX search_vectors_behaviour_embedding_hnsw_idx
  ON atheros_search.search_vectors_behaviour
  ((VEC_COSINE_DISTANCE(embedding))) USING HNSW;

CREATE VECTOR INDEX search_vectors_sequence_embedding_hnsw_idx
  ON atheros_search.search_vectors_sequence
  ((VEC_COSINE_DISTANCE(embedding))) USING HNSW;
