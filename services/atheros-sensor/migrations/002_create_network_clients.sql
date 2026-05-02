-- Cross-reference table linking client MACs to all probed SSIDs (not just authorized networks)
CREATE TABLE IF NOT EXISTS network_clients (
  ssid TEXT NOT NULL,
  client_mac TEXT NOT NULL,
  known_bssid TEXT,  -- nullable: only populated if SSID matches authorized_wireless_networks
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  probe_count INTEGER NOT NULL DEFAULT 1,
  location_id TEXT,
  PRIMARY KEY (ssid, client_mac)
);

CREATE INDEX IF NOT EXISTS idx_network_clients_client_mac ON network_clients(client_mac);
CREATE INDEX IF NOT EXISTS idx_network_clients_last_seen ON network_clients(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_network_clients_known_bssid ON network_clients(known_bssid) WHERE known_bssid IS NOT NULL;

COMMENT ON TABLE network_clients IS 
  'Passive client inventory: tracks ALL SSIDs probed by each client MAC, with optional BSSID linkage for known networks';

COMMENT ON COLUMN network_clients.ssid IS 
  'SSID from probe request frame (all SSIDs tracked, not just authorized)';

COMMENT ON COLUMN network_clients.client_mac IS 
  'Client MAC address observed in probe request frame';

COMMENT ON COLUMN network_clients.known_bssid IS 
  'BSSID from authorized_wireless_networks if SSID matches; NULL for unknown networks';
