class PerformanceRestructure < ActiveRecord::Migration[7.2]
  def up
    enable_extension "pg_trgm" unless extension_enabled?("pg_trgm")

    create_wireless_audit_hourly_summary
    create_sync_scan_ingest_staging
    create_materialized_views
    add_performance_indexes
    create_refresh_functions
  end

  def down
    execute "DROP MATERIALIZED VIEW IF EXISTS mv_wireless_device_inventory"
    execute "DROP MATERIALIZED VIEW IF EXISTS mv_wireless_audit_hourly_summary"
    execute "DROP FUNCTION IF EXISTS refresh_wireless_materialized_views()"
    drop_table :wireless_audit_hourly_summary, if_exists: true
    drop_table :sync_scan_ingest_staging, if_exists: true
    remove_index :sync_scan_ingest, name: "idx_ssi_wireless_hot", if_exists: true
    remove_index :shadow_it_alerts, name: "idx_shadow_it_alerts_trgm_search", if_exists: true
  end

  private

  def create_wireless_audit_hourly_summary
    create_table :wireless_audit_hourly_summary, if_not_exists: true do |t|
      t.timestamptz :hour, null: false
      t.text :source_mac, null: false
      t.text :location_id
      t.text :sensor_id
      t.text :destination_bssid
      t.integer :frame_count, null: false, default: 0
      t.integer :protected_frame_count, null: false, default: 0
      t.integer :open_frame_count, null: false, default: 0
      t.integer :distinct_ssid_count, null: false, default: 0
      t.integer :distinct_bssid_count, null: false, default: 0
      t.integer :avg_signal_dbm
      t.integer :max_signal_dbm
      t.integer :min_signal_dbm
      t.integer :handshake_captured_count, null: false, default: 0
      t.timestamptz :created_at, null: false, default: -> { "now()" }
      t.timestamptz :updated_at, null: false, default: -> { "now()" }
    end

    add_index :wireless_audit_hourly_summary,
      [:hour, :source_mac, :location_id],
      name: "idx_wahs_hour_mac_location",
      unique: true,
      if_not_exists: true

    add_index :wireless_audit_hourly_summary,
      [:location_id, :hour],
      name: "idx_wahs_location_hour",
      if_not_exists: true

    add_index :wireless_audit_hourly_summary,
      [:sensor_id, :hour],
      name: "idx_wahs_sensor_hour",
      if_not_exists: true
  end

  def create_sync_scan_ingest_staging
    execute <<~SQL
      CREATE UNLOGGED TABLE IF NOT EXISTS sync_scan_ingest_staging (
        dedupe_key TEXT NOT NULL PRIMARY KEY,
        stream_name TEXT NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        payload_ref TEXT NOT NULL,
        payload JSONB,
        payload_sha256 TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        producer TEXT NOT NULL DEFAULT 'unknown',
        event_kind TEXT,
        schema_version INTEGER NOT NULL DEFAULT 1,
        frame_type TEXT,
        source_mac TEXT,
        bssid TEXT,
        destination_bssid TEXT,
        ssid TEXT,
        signal_dbm INTEGER,
        raw_len INTEGER NOT NULL DEFAULT 0,
        frame_control_flags INTEGER NOT NULL DEFAULT 0,
        more_data BOOLEAN NOT NULL DEFAULT FALSE,
        retry BOOLEAN NOT NULL DEFAULT FALSE,
        power_save BOOLEAN NOT NULL DEFAULT FALSE,
        protected BOOLEAN NOT NULL DEFAULT FALSE,
        security_flags INTEGER NOT NULL DEFAULT 0,
        wps_device_name TEXT,
        wps_manufacturer TEXT,
        wps_model_name TEXT,
        device_fingerprint TEXT,
        handshake_captured BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    SQL

    add_index :sync_scan_ingest_staging, :observed_at, name: "idx_ssis_observed_at", if_not_exists: true
    add_index :sync_scan_ingest_staging, [:stream_name, :observed_at], name: "idx_ssis_stream_observed", if_not_exists: true
    add_index :sync_scan_ingest_staging, :status, name: "idx_ssis_status", if_not_exists: true
  end

  def create_materialized_views
    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wireless_device_inventory AS
      SELECT
        MD5(COALESCE(LOWER(source_mac), '') || '|' || COALESCE(location_id, '')) AS inventory_key,
        LOWER(source_mac) AS source_mac,
        MAX(location_id) AS location_id,
        MIN(observed_at) AS first_seen,
        MAX(observed_at) AS last_seen,
        MAX(ssid) AS ssid,
        MAX(destination_bssid) AS destination_bssid,
        STRING_AGG(DISTINCT src_ip, ', ') FILTER (WHERE src_ip IS NOT NULL) AS ip_addresses,
        STRING_AGG(DISTINCT hostname, ', ') FILTER (WHERE hostname IS NOT NULL) AS hostnames,
        STRING_AGG(DISTINCT app_protocol, ', ') FILTER (WHERE app_protocol IS NOT NULL) AS services,
        STRING_AGG(DISTINCT dns_query_name, ', ') FILTER (WHERE dns_query_name IS NOT NULL) AS dns_names,
        COUNT(*) AS frame_count,
        SUM(CASE WHEN protected THEN 1 ELSE 0 END) AS protected_frame_count,
        SUM(CASE WHEN NOT protected THEN 1 ELSE 0 END) AS open_frame_count
      FROM (
        SELECT
          observed_at,
          COALESCE(source_mac, payload->>'source_mac') AS source_mac,
          payload->>'location_id' AS location_id,
          COALESCE(ssid, payload->>'ssid') AS ssid,
          COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') AS destination_bssid,
          COALESCE(src_ip, payload->>'src_ip') AS src_ip,
          COALESCE(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') AS hostname,
          COALESCE(app_protocol, payload->>'app_protocol') AS app_protocol,
          COALESCE(dns_query_name, payload->>'dns_query_name') AS dns_query_name,
          COALESCE(protected, FALSE) AS protected
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
          AND observed_at >= NOW() - INTERVAL '7 days'
      ) inventory
      WHERE source_mac IS NOT NULL
      GROUP BY LOWER(source_mac), location_id
    SQL

    add_index :mv_wireless_device_inventory, :inventory_key, unique: true, name: "idx_mv_wdi_inventory_key", if_not_exists: true
    add_index :mv_wireless_device_inventory, :source_mac, name: "idx_mv_wdi_source_mac", if_not_exists: true
    add_index :mv_wireless_device_inventory, :location_id, name: "idx_mv_wdi_location_id", if_not_exists: true

    execute <<~SQL
      CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wireless_audit_hourly_summary AS
      SELECT
        DATE_TRUNC('hour', observed_at) AS hour,
        LOWER(COALESCE(source_mac, payload->>'source_mac')) AS source_mac,
        payload->>'location_id' AS location_id,
        payload->>'sensor_id' AS sensor_id,
        COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') AS destination_bssid,
        COUNT(*) AS frame_count,
        SUM(CASE WHEN COALESCE(protected, FALSE) THEN 1 ELSE 0 END) AS protected_frame_count,
        SUM(CASE WHEN NOT COALESCE(protected, FALSE) THEN 1 ELSE 0 END) AS open_frame_count,
        COUNT(DISTINCT COALESCE(ssid, payload->>'ssid')) AS distinct_ssid_count,
        COUNT(DISTINCT COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid')) AS distinct_bssid_count,
        ROUND(AVG(COALESCE(signal_dbm, (payload->>'signal_dbm')::integer)))::integer AS avg_signal_dbm,
        MAX(COALESCE(signal_dbm, (payload->>'signal_dbm')::integer)) AS max_signal_dbm,
        MIN(COALESCE(signal_dbm, (payload->>'signal_dbm')::integer)) AS min_signal_dbm,
        SUM(CASE WHEN handshake_captured THEN 1 ELSE 0 END) AS handshake_captured_count
      FROM sync_scan_ingest
      WHERE stream_name = 'wireless.audit'
        AND observed_at >= NOW() - INTERVAL '7 days'
      GROUP BY DATE_TRUNC('hour', observed_at),
        LOWER(COALESCE(source_mac, payload->>'source_mac')),
        payload->>'location_id',
        payload->>'sensor_id',
        COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid')
    SQL

    add_index :mv_wireless_audit_hourly_summary, [:hour, :source_mac, :location_id], name: "idx_mv_wahs_hour_mac_location", if_not_exists: true
    add_index :mv_wireless_audit_hourly_summary, [:location_id, :hour], name: "idx_mv_wahs_location_hour", if_not_exists: true
  end

  def add_performance_indexes
    add_index :sync_scan_ingest,
      [:stream_name, :observed_at],
      name: "idx_ssi_wireless_hot",
      where: "stream_name = 'wireless.audit'",
      if_not_exists: true

    add_index :shadow_it_alerts,
      "dedupe_key || ' ' || source_mac || ' ' || COALESCE(ssid, '') || ' ' || reason",
      name: "idx_shadow_it_alerts_trgm_search",
      using: :gin,
      opclass: :gin_trgm_ops,
      if_not_exists: true
  end

  def create_refresh_functions
    execute <<~SQL
      CREATE OR REPLACE FUNCTION refresh_wireless_materialized_views()
      RETURNS void AS $$
      BEGIN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_wireless_device_inventory;
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_wireless_audit_hourly_summary;
      END;
      $$ LANGUAGE plpgsql;
    SQL
  end
end
