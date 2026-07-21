-- object: sync_cursors
-- depends_on:

CREATE TABLE IF NOT EXISTS sync_cursors (
  stream_name   VARCHAR(255) NOT NULL,
  cursor_value  TEXT NOT NULL,
  updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (stream_name)
);
