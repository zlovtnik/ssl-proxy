class AddWirelessAuditTrgmSearchIndexes < ActiveRecord::Migration[7.2]
  disable_ddl_transaction!

  def up
    enable_extension "pg_trgm"

    trgm_indexes.each do |index_name, (expression, predicate)|
      execute <<~SQL
        CREATE INDEX CONCURRENTLY IF NOT EXISTS #{index_name}
          ON sync_scan_ingest USING gin (#{expression} gin_trgm_ops)
          WHERE stream_name = 'wireless.audit' AND #{predicate}
      SQL
    end
  end

  def down
    trgm_indexes.each_key do |index_name|
      execute "DROP INDEX CONCURRENTLY IF EXISTS #{index_name}"
    end
  end

  private

  def trgm_indexes
    {
      "ssi_wireless_sensor_id_trgm_idx" => ["lower(sensor_id)", "sensor_id IS NOT NULL"],
      "ssi_wireless_source_mac_trgm_idx" => ["lower(source_mac)", "source_mac IS NOT NULL"],
      "ssi_wireless_bssid_trgm_idx" => ["lower(bssid)", "bssid IS NOT NULL"],
      "ssi_wireless_destination_bssid_trgm_idx" => ["lower(destination_bssid)", "destination_bssid IS NOT NULL"],
      "ssi_wireless_ssid_trgm_idx" => ["lower(ssid)", "ssid IS NOT NULL"],
      "ssi_wireless_device_fingerprint_trgm_idx" => ["lower(device_fingerprint)", "device_fingerprint IS NOT NULL"],
      "ssi_wireless_wps_device_name_trgm_idx" => ["lower(wps_device_name)", "wps_device_name IS NOT NULL"],
      "ssi_wireless_wps_manufacturer_trgm_idx" => ["lower(wps_manufacturer)", "wps_manufacturer IS NOT NULL"],
      "ssi_wireless_wps_model_name_trgm_idx" => ["lower(wps_model_name)", "wps_model_name IS NOT NULL"],
      "ssi_wireless_app_protocol_trgm_idx" => ["lower(app_protocol)", "app_protocol IS NOT NULL"],
      "ssi_wireless_src_ip_trgm_idx" => ["lower(src_ip)", "src_ip IS NOT NULL"],
      "ssi_wireless_dst_ip_trgm_idx" => ["lower(dst_ip)", "dst_ip IS NOT NULL"],
      "ssi_wireless_username_trgm_idx" => ["lower(username)", "username IS NOT NULL"]
    }
  end
end
