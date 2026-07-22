-- object: atheros_search_worker_heartbeat
-- depends_on: atheros_search_search_vectors

USE atheros_search;

CREATE TABLE IF NOT EXISTS worker_heartbeat (
  worker_id    VARCHAR(128) NOT NULL,
  worker_type  VARCHAR(64)  NOT NULL DEFAULT 'embedding',
  last_seen_at DATETIME(6)  NOT NULL,
  metadata     JSON,
  PRIMARY KEY (worker_id),
  KEY worker_heartbeat_type_idx (worker_type, last_seen_at)
) ENGINE=InnoDB;
