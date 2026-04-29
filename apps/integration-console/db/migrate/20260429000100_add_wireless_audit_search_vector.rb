class AddWirelessAuditSearchVector < ActiveRecord::Migration[7.2]
  disable_ddl_transaction!

  SEARCH_VECTOR_SQL = <<~SQL.squish.freeze
    to_tsvector(
      'simple'::regconfig,
      lower(
        COALESCE(sensor_id, '') || ' ' ||
        COALESCE(source_mac, '') || ' ' ||
        COALESCE(bssid, '') || ' ' ||
        COALESCE(destination_bssid, '') || ' ' ||
        COALESCE(ssid, '') || ' ' ||
        COALESCE(wps_device_name, '') || ' ' ||
        COALESCE(wps_manufacturer, '') || ' ' ||
        COALESCE(wps_model_name, '') || ' ' ||
        COALESCE(device_fingerprint, '') || ' ' ||
        COALESCE(app_protocol, '') || ' ' ||
        COALESCE(src_ip, '') || ' ' ||
        COALESCE(dst_ip, '') || ' ' ||
        COALESCE(username, '')
      )
    )
  SQL

  def up
    execute <<~SQL
      ALTER TABLE sync_scan_ingest
      ADD COLUMN IF NOT EXISTS wireless_search_tsv tsvector
      GENERATED ALWAYS AS (#{SEARCH_VECTOR_SQL}) STORED
    SQL

    execute <<~SQL
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ssi_wireless_search_tsv_idx
        ON sync_scan_ingest USING gin (wireless_search_tsv)
        WHERE stream_name = 'wireless.audit'
    SQL

    execute <<~SQL
      CREATE INDEX CONCURRENTLY IF NOT EXISTS ssi_wireless_common_search_idx
        ON sync_scan_ingest USING gin (
          (
            lower(COALESCE(sensor_id, '')) || ' ' ||
            lower(COALESCE(source_mac, '')) || ' ' ||
            lower(COALESCE(ssid, ''))
          ) gin_trgm_ops
        )
        WHERE stream_name = 'wireless.audit'
    SQL
  end

  def down
    execute "DROP INDEX CONCURRENTLY IF EXISTS ssi_wireless_common_search_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS ssi_wireless_search_tsv_idx"
    remove_column :sync_scan_ingest, :wireless_search_tsv, if_exists: true
  end
end
