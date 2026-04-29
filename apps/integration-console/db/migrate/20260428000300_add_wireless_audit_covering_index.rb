class AddWirelessAuditCoveringIndex < ActiveRecord::Migration[7.2]
  disable_ddl_transaction!

  def up
    execute <<~SQL
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ssi_wireless_audit_cover_idx
        ON sync_scan_ingest (observed_at DESC)
        INCLUDE (
          dedupe_key, sensor_id, location_id, frame_subtype,
          source_mac, bssid, destination_bssid, ssid,
          signal_dbm, raw_len, frame_control_flags, security_flags,
          device_fingerprint, handshake_captured, frame_type, wps_device_name
        )
        WHERE stream_name = 'wireless.audit'
    SQL
  end

  def down
    execute "DROP INDEX CONCURRENTLY IF EXISTS ssi_wireless_audit_cover_idx"
  end
end

