class AddWirelessSecurityFields < ActiveRecord::Migration[7.2]
  def change
    add_column :sync_scan_ingest, :security_flags, :integer, null: false, default: 0, if_not_exists: true
    add_column :sync_scan_ingest, :wps_device_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :wps_manufacturer, :text, if_not_exists: true
    add_column :sync_scan_ingest, :wps_model_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :device_fingerprint, :text, if_not_exists: true
    add_column :sync_scan_ingest, :handshake_captured, :boolean, null: false, default: false, if_not_exists: true

    add_index :sync_scan_ingest,
      [:device_fingerprint, :observed_at],
      order: { observed_at: :desc },
      where: "stream_name = 'wireless.audit' AND device_fingerprint IS NOT NULL",
      name: "ssi_wireless_device_fingerprint_idx",
      if_not_exists: true

    add_index :sync_scan_ingest,
      [:security_flags, :observed_at],
      order: { observed_at: :desc },
      where: "stream_name = 'wireless.audit' AND security_flags <> 0",
      name: "ssi_wireless_security_flags_idx",
      if_not_exists: true

    add_index :sync_scan_ingest,
      :observed_at,
      order: { observed_at: :desc },
      where: "stream_name = 'wireless.audit' AND handshake_captured",
      name: "ssi_wireless_handshake_captured_idx",
      if_not_exists: true

    reversible do |dir|
      dir.up { refresh_wireless_audit_view }
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
        ssi.payload->>'source_mac' AS source_mac,
        ssi.payload->>'transmitter_mac' AS transmitter_mac,
        ssi.payload->>'receiver_mac' AS receiver_mac,
        ssi.payload->>'bssid' AS bssid,
        ssi.payload->>'ssid' AS ssid,
        ssi.payload->>'frame_subtype' AS frame_subtype,
        ssi.payload->>'signal_dbm' AS signal_dbm,
        ssi.payload->>'noise_dbm' AS noise_dbm,
        ssi.payload->>'frequency_mhz' AS frequency_mhz,
        ssi.payload->>'data_rate_kbps' AS data_rate_kbps,
        ssi.payload->>'retry' AS retry,
        ssi.payload->>'protected' AS protected,
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
        ON lower(d_src.mac_hint) = lower(ssi.payload->>'source_mac')
      LEFT JOIN devices d_bssid
        ON lower(d_bssid.mac_hint) = lower(ssi.payload->>'bssid')
      WHERE ssi.stream_name = 'wireless.audit'
    SQL
  end
end
