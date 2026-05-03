module HeatmapHelpers
  def ensure_wireless_heatmap_materialized_view
    sync_connection.execute(<<~SQL)
      CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wireless_heatmap AS
      SELECT
        COALESCE(location_id, payload->>'location_id') AS location_id,
        count(*) AS event_count,
        avg(COALESCE(signal_dbm, CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END)) AS avg_signal_dbm,
        count(DISTINCT lower(COALESCE(source_mac, payload->>'source_mac'))) AS unique_devices,
        max(observed_at) AS last_seen_at
      FROM sync_scan_ingest
      WHERE stream_name = 'wireless.audit'
        AND COALESCE(location_id, payload->>'location_id') IS NOT NULL
      GROUP BY COALESCE(location_id, payload->>'location_id')
      WITH NO DATA
    SQL
    sync_connection.execute(<<~SQL)
      CREATE UNIQUE INDEX IF NOT EXISTS mv_wireless_heatmap_location_idx
        ON mv_wireless_heatmap (location_id)
    SQL
  end

  def refresh_wireless_heatmap_materialized_view
    sync_connection.execute("REFRESH MATERIALIZED VIEW mv_wireless_heatmap")
  end

  def ensure_wireless_audit_search_vector
    sync_connection.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    sync_connection.execute(<<~SQL)
      ALTER TABLE sync_scan_ingest
      ADD COLUMN IF NOT EXISTS wireless_search_tsv tsvector
      GENERATED ALWAYS AS (
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
      ) STORED
    SQL
  end
end
