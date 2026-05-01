class BoundWirelessDeviceInventoryView < ActiveRecord::Migration[7.2]
  RECENT_WIRELESS_ROWS = 20_000

  def up
    refresh_wireless_device_inventory_view
  end

  def down
    refresh_wireless_device_inventory_view
  end

  private

  def refresh_wireless_device_inventory_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_device_inventory AS
      WITH recent_ingest AS MATERIALIZED (
        SELECT *
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
          AND COALESCE(source_mac, payload->>'source_mac') IS NOT NULL
        ORDER BY observed_at DESC
        LIMIT #{RECENT_WIRELESS_ROWS}
      ),
      base AS (
        SELECT
          ssi.dedupe_key,
          ssi.observed_at,
          lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac')) AS source_mac,
          COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
          COALESCE(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
          COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
          COALESCE(ssi.signal_dbm, CASE WHEN ssi.payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (ssi.payload->>'signal_dbm')::integer END) AS signal_dbm,
          COALESCE(ssi.location_id, ssi.payload->>'location_id') AS location_id,
          COALESCE(ssi.sensor_id, ssi.payload->>'sensor_id') AS sensor_id,
          COALESCE(ssi.username, ssi.payload->>'username') AS username,
          COALESCE(ssi.src_ip, ssi.payload->>'src_ip') AS src_ip,
          COALESCE(ssi.dst_ip, ssi.payload->>'dst_ip') AS dst_ip,
          COALESCE(ssi.dhcp_hostname, ssi.mdns_name, ssi.payload->>'dhcp_hostname', ssi.payload->>'mdns_name') AS hostname,
          COALESCE(ssi.app_protocol, ssi.payload->>'app_protocol') AS app_protocol,
          COALESCE(ssi.dns_query_name, ssi.payload->>'dns_query_name') AS dns_query_name,
          COALESCE(ssi.protected, FALSE) AS protected,
          ssi.wps_device_name,
          ssi.wps_manufacturer,
          ssi.wps_model_name,
          ssi.device_fingerprint
        FROM recent_ingest ssi
      ),
      latest AS (
        SELECT *
        FROM (
          SELECT base.*, row_number() OVER (PARTITION BY source_mac ORDER BY observed_at DESC, dedupe_key DESC) AS row_number
          FROM base
        ) ranked
        WHERE row_number = 1
      ),
      rollup AS (
        SELECT
          source_mac,
          min(observed_at) AS first_occurred_at,
          max(observed_at) AS last_occurred_at,
          count(*)::bigint AS occurrence_count,
          string_agg(DISTINCT src_ip, ', ') FILTER (WHERE src_ip IS NOT NULL) AS ip_addresses,
          string_agg(DISTINCT hostname, ', ') FILTER (WHERE hostname IS NOT NULL) AS hostnames,
          string_agg(DISTINCT app_protocol, ', ') FILTER (WHERE app_protocol IS NOT NULL) AS services,
          string_agg(DISTINCT dns_query_name, ', ') FILTER (WHERE dns_query_name IS NOT NULL) AS dns_names,
          sum(CASE WHEN protected THEN 1 ELSE 0 END)::bigint AS protected_frame_count,
          sum(CASE WHEN NOT protected THEN 1 ELSE 0 END)::bigint AS open_frame_count
        FROM base
        GROUP BY source_mac
      )
      SELECT
        rollup.source_mac AS inventory_key,
        rollup.source_mac,
        rollup.first_occurred_at,
        rollup.last_occurred_at,
        rollup.first_occurred_at AS first_seen,
        rollup.last_occurred_at AS last_seen,
        rollup.last_occurred_at AS observed_at,
        rollup.occurrence_count,
        rollup.occurrence_count AS frame_count,
        latest.location_id,
        latest.sensor_id,
        latest.bssid,
        latest.destination_bssid,
        latest.ssid,
        latest.signal_dbm::text AS signal_dbm,
        latest.username,
        rollup.ip_addresses,
        rollup.hostnames,
        rollup.services,
        rollup.dns_names,
        rollup.protected_frame_count,
        rollup.open_frame_count,
        latest.wps_device_name,
        latest.wps_manufacturer,
        latest.wps_model_name,
        latest.device_fingerprint,
        devices.mac_id AS device_id,
        devices.display_name,
        devices.username AS registered_username,
        devices.os_hint,
        COALESCE(devices.hostname, latest.hostname) AS hostname
      FROM rollup
      JOIN latest ON latest.source_mac = rollup.source_mac
      LEFT JOIN devices ON devices.mac_id = rollup.source_mac
    SQL
  end
end
