class CreateNetworkClients < ActiveRecord::Migration[7.2]
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS network_clients (
        ssid TEXT NOT NULL,
        client_mac TEXT NOT NULL,
        known_bssid TEXT,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        probe_count INTEGER NOT NULL DEFAULT 1,
        location_id TEXT,
        PRIMARY KEY (ssid, client_mac)
      )
    SQL

    execute "CREATE INDEX IF NOT EXISTS idx_network_clients_client_mac ON network_clients (client_mac)"
    execute "CREATE INDEX IF NOT EXISTS idx_network_clients_last_seen ON network_clients (last_seen DESC)"
    execute <<~SQL
      CREATE INDEX IF NOT EXISTS idx_network_clients_known_bssid
        ON network_clients (known_bssid)
        WHERE known_bssid IS NOT NULL
    SQL
  end

  def down
    drop_table :network_clients, if_exists: true
  end
end
