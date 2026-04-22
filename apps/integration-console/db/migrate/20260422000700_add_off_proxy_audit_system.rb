class AddOffProxyAuditSystem < ActiveRecord::Migration[7.2]
  def change
    add_column :sync_scan_ingest, :source_mac, :text, if_not_exists: true
    add_column :sync_scan_ingest, :bssid, :text, if_not_exists: true
    add_column :sync_scan_ingest, :destination_bssid, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ssid, :text, if_not_exists: true
    add_column :sync_scan_ingest, :signal_dbm, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :raw_len, :integer, null: false, default: 0, if_not_exists: true
    add_column :sync_scan_ingest, :frame_control_flags, :integer, null: false, default: 0, if_not_exists: true
    add_column :sync_scan_ingest, :more_data, :boolean, null: false, default: false, if_not_exists: true
    add_column :sync_scan_ingest, :retry, :boolean, null: false, default: false, if_not_exists: true
    add_column :sync_scan_ingest, :power_save, :boolean, null: false, default: false, if_not_exists: true
    add_column :sync_scan_ingest, :protected, :boolean, null: false, default: false, if_not_exists: true

    create_table :authorized_wireless_networks, if_not_exists: true do |t|
      t.text :ssid
      t.text :bssid
      t.text :location_id
      t.text :label
      t.boolean :enabled, null: false, default: true
      t.text :notes

      t.timestamps
    end

    add_check_constraint :authorized_wireless_networks,
      "NULLIF(TRIM(COALESCE(ssid, '')), '') IS NOT NULL OR NULLIF(TRIM(COALESCE(bssid, '')), '') IS NOT NULL",
      name: "authorized_wireless_network_identity_chk",
      if_not_exists: true

    add_index :authorized_wireless_networks,
      "COALESCE(lower(ssid), ''), COALESCE(lower(bssid), ''), COALESCE(location_id, '')",
      unique: true,
      name: "authorized_wireless_networks_match_idx",
      if_not_exists: true

    add_index :authorized_wireless_networks,
      [:enabled, :location_id],
      name: "authorized_wireless_networks_enabled_idx",
      if_not_exists: true

    create_table :shadow_it_alerts, primary_key: :alert_id, if_not_exists: true do |t|
      t.text :dedupe_key, null: false
      t.timestamptz :observed_at, null: false
      t.text :source_mac, null: false
      t.text :destination_bssid
      t.text :ssid
      t.text :sensor_id
      t.text :location_id
      t.integer :signal_dbm
      t.text :reason, null: false
      t.jsonb :evidence, null: false, default: {}
      t.timestamptz :resolved_at
      t.timestamptz :created_at, null: false, default: -> { "now()" }
      t.timestamptz :updated_at, null: false, default: -> { "now()" }
    end

    add_index :shadow_it_alerts, :dedupe_key, unique: true, if_not_exists: true
    add_index :shadow_it_alerts,
      :observed_at,
      order: { observed_at: :desc },
      where: "resolved_at IS NULL",
      name: "shadow_it_alerts_open_idx",
      if_not_exists: true
    add_index :shadow_it_alerts,
      "lower(source_mac), observed_at DESC",
      name: "shadow_it_alerts_source_idx",
      if_not_exists: true

    reversible do |dir|
      dir.up do
        refresh_wireless_audit_view
        refresh_shadow_alerts_view
      end
    end
  end

  private

  def refresh_wireless_audit_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT
        ssi.dedupe_key,
        ssi.observed_at,
        ssi.stream_name,
        ssi.status,
        ssi.producer,
        ssi.event_kind,
        COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
        ssi.payload->>'transmitter_mac' AS transmitter_mac,
        ssi.payload->>'receiver_mac' AS receiver_mac,
        COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
        COALESCE(ssi.destination_bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
        COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
        ssi.payload->>'frame_subtype' AS frame_subtype,
        COALESCE(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') AS signal_dbm,
        ssi.payload->>'noise_dbm' AS noise_dbm,
        ssi.payload->>'frequency_mhz' AS frequency_mhz,
        ssi.payload->>'data_rate_kbps' AS data_rate_kbps,
        COALESCE(ssi.raw_len::text, ssi.payload->>'raw_len') AS raw_len,
        COALESCE(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') AS frame_control_flags,
        COALESCE(ssi.more_data::text, ssi.payload->>'more_data') AS more_data,
        COALESCE(ssi.retry::text, ssi.payload->>'retry') AS retry,
        COALESCE(ssi.power_save::text, ssi.payload->>'power_save') AS power_save,
        COALESCE(ssi.protected::text, ssi.payload->>'protected') AS protected,
        ssi.payload->>'location_id' AS location_id,
        ssi.payload->>'sensor_id' AS sensor_id,
        ssi.payload->>'identity_source' AS identity_source,
        ssi.payload->>'username' AS username,
        ssi.payload->'tags' AS tags,
        ssi.security_flags,
        ssi.wps_device_name,
        ssi.wps_manufacturer,
        ssi.wps_model_name,
        ssi.device_fingerprint,
        ssi.handshake_captured,
        COALESCE(d_src.device_id, d_bssid.device_id) AS device_id,
        COALESCE(d_src.display_name, d_bssid.display_name) AS display_name,
        COALESCE(d_src.username, d_bssid.username) AS registered_username,
        COALESCE(d_src.os_hint, d_bssid.os_hint) AS os_hint,
        COALESCE(d_src.hostname, d_bssid.hostname) AS hostname
      FROM sync_scan_ingest ssi
      LEFT JOIN devices d_src
        ON lower(d_src.mac_hint) = lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac'))
      LEFT JOIN devices d_bssid
        ON lower(d_bssid.mac_hint) = lower(COALESCE(ssi.bssid, ssi.payload->>'bssid'))
      WHERE ssi.stream_name = 'wireless.audit'
    SQL
  end

  def refresh_shadow_alerts_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_shadow_it_alerts AS
      SELECT
        alert_id,
        dedupe_key,
        observed_at,
        source_mac,
        destination_bssid,
        ssid,
        sensor_id,
        location_id,
        signal_dbm,
        reason,
        evidence,
        resolved_at,
        created_at,
        updated_at
      FROM shadow_it_alerts
      ORDER BY observed_at DESC
    SQL
  end
end
