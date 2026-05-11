class CreateWirelessProbeObservations < ActiveRecord::Migration[7.2]
  def up
    execute <<~SQL
      CREATE TABLE IF NOT EXISTS wireless_probe_observations (
        mac_address TEXT NOT NULL,
        ssid TEXT,
        bssid TEXT,
        rssi INTEGER,
        frequency INTEGER,
        location_id TEXT,
        sensor_id TEXT,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        observation_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (mac_address, ssid, bssid)
      )
    SQL

    execute "CREATE INDEX IF NOT EXISTS idx_probe_observations_mac ON wireless_probe_observations (mac_address)"
    execute "CREATE INDEX IF NOT EXISTS idx_probe_observations_last_seen ON wireless_probe_observations (last_seen DESC)"
    execute "CREATE INDEX IF NOT EXISTS idx_probe_observations_location ON wireless_probe_observations (location_id)"
    execute "CREATE INDEX IF NOT EXISTS idx_probe_observations_sensor ON wireless_probe_observations (sensor_id)"
  end

  def down
    drop_table :wireless_probe_observations, if_exists: true
  end
end