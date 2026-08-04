-- object: atheros_search_vectors
-- depends_on: atheros_search_documents
-- HNSW indexes are intentionally absent here. Apply post_tiflash only after
-- each table reports AVAILABLE=1 in INFORMATION_SCHEMA.TIFLASH_REPLICA.

USE atheros_search;

CREATE TABLE IF NOT EXISTS search_vectors_event (
  vector_id       BIGINT NOT NULL AUTO_INCREMENT,
  document_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     DATETIME(6) NOT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (vector_id),
  UNIQUE KEY search_vectors_event_document_uq (document_id, embedding_model),
  KEY search_vectors_event_embedded_idx (embedded_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_vectors_device (
  vector_id       BIGINT NOT NULL AUTO_INCREMENT,
  document_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     DATETIME(6) NOT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (vector_id),
  UNIQUE KEY search_vectors_device_document_uq (document_id, embedding_model),
  KEY search_vectors_device_embedded_idx (embedded_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_vectors_behaviour (
  vector_id       BIGINT NOT NULL AUTO_INCREMENT,
  document_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     DATETIME(6) NOT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (vector_id),
  UNIQUE KEY search_vectors_behaviour_document_uq (document_id, embedding_model),
  KEY search_vectors_behaviour_embedded_idx (embedded_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS search_vectors_sequence (
  vector_id       BIGINT NOT NULL AUTO_INCREMENT,
  document_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding_model VARCHAR(128) NOT NULL,
  content_sha256  CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  embedding       VECTOR(768) NOT NULL,
  embedded_at     DATETIME(6) NOT NULL,
  created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (vector_id),
  UNIQUE KEY search_vectors_sequence_document_uq (document_id, embedding_model),
  KEY search_vectors_sequence_embedded_idx (embedded_at)
) ENGINE=InnoDB;
