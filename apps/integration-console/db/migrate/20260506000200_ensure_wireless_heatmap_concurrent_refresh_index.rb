class EnsureWirelessHeatmapConcurrentRefreshIndex < ActiveRecord::Migration[7.2]
  disable_ddl_transaction!

  INDEX_NAME = "mv_wireless_heatmap_location_idx".freeze

  def up
    execute <<~SQL
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

    execute "DROP INDEX CONCURRENTLY IF EXISTS #{INDEX_NAME}"
    execute <<~SQL
      CREATE UNIQUE INDEX CONCURRENTLY #{INDEX_NAME}
        ON mv_wireless_heatmap (location_id)
    SQL
    execute "REFRESH MATERIALIZED VIEW mv_wireless_heatmap"
  end

  def down
    execute "DROP MATERIALIZED VIEW IF EXISTS mv_wireless_heatmap CASCADE"
  end
end
