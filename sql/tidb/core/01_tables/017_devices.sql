-- object: devices
-- depends_on:

CREATE TABLE IF NOT EXISTS devices (
  mac_id        VARCHAR(17) NOT NULL,
  wg_pubkey     TEXT,
  claim_token_hash TEXT,
  display_name  TEXT,
  username      TEXT,
  hostname      TEXT,
  os_hint       TEXT,
  mac_hint      VARCHAR(17) NOT NULL,
  first_seen    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  notes         TEXT,
  PRIMARY KEY (mac_id)
);
