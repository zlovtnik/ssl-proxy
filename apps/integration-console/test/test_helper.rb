ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "minitest/mock"
require "securerandom"

class ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  SYNC_SCAN_INGEST_MANAGED_COLUMNS = %w[
    dedupe_key
    stream_name
    observed_at
    payload_ref
    payload
    payload_sha256
    status
    attempt_count
    last_error
    producer
    event_kind
    created_at
    updated_at
  ].freeze

  parallelize(workers: 1)

  teardown do
    travel_back
    Rails.cache.clear
  end

  def sync_connection
    SyncRecord.connection
  end

  def clear_sync_tables(*tables)
    tables.each do |table|
      sync_connection.execute("DELETE FROM #{table}")
    end
  end

  def insert_sync_ingest(dedupe_key:, observed_at:, payload:, stream_name: "wireless.audit", status: "pending")
    attributes = {
      "dedupe_key" => dedupe_key,
      "stream_name" => stream_name,
      "observed_at" => observed_at,
      "payload_ref" => "payload://#{dedupe_key}",
      "payload" => payload,
      "payload_sha256" => SecureRandom.hex(16),
      "status" => status,
      "producer" => "test",
      "event_kind" => "test",
      "destination_bssid" => payload["destination_bssid"] || payload["bssid"]
    }.compact

    sync_scan_ingest_promoted_columns.each_value do |column|
      next if attributes.key?(column.name)
      next unless payload.key?(column.name)

      attributes[column.name] = cast_sync_scan_ingest_value(column, payload[column.name])
    end

    columns_sql = attributes.keys.map { |name| sync_connection.quote_column_name(name) }.join(", ")
    values_sql = attributes.map { |name, value| quote_sync_scan_ingest_value(name, value) }.join(", ")

    sync_connection.execute("INSERT INTO sync_scan_ingest (#{columns_sql}) VALUES (#{values_sql})")
  end

  def insert_backlog(dedupe_key:, status:, updated_at: Time.current)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO audit_backlog
        (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, 'sync.scan.request', '{}', #{sync_connection.quote(status)}, 0, now(), #{sync_connection.quote(updated_at)})
    SQL
  end

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

  def ensure_wireless_audit_views
    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT
        ssi.dedupe_key,
        ssi.observed_at,
        ssi.stream_name,
        ssi.status,
        ssi.producer,
        ssi.event_kind,
        COALESCE(ssi.schema_version, CASE WHEN ssi.payload->>'schema_version' ~ '^[0-9]+$' THEN (ssi.payload->>'schema_version')::integer END, 1) AS schema_version,
        COALESCE(ssi.frame_type, ssi.payload->>'frame_type') AS frame_type,
        COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
        COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
        COALESCE(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
        COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
        COALESCE(ssi.frame_subtype, ssi.payload->>'frame_subtype') AS frame_subtype,
        COALESCE(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') AS signal_dbm,
        COALESCE(ssi.src_ip, ssi.payload->>'src_ip') AS src_ip,
        COALESCE(ssi.dst_ip, ssi.payload->>'dst_ip') AS dst_ip,
        COALESCE(ssi.app_protocol, ssi.payload->>'app_protocol') AS app_protocol,
        COALESCE(ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS hostname,
        COALESCE(ssi.location_id, ssi.payload->>'location_id') AS location_id,
        COALESCE(ssi.sensor_id, ssi.payload->>'sensor_id') AS sensor_id,
        COALESCE(ssi.username, ssi.payload->>'username') AS username,
        NULL::text AS registered_username,
        NULL::text AS display_name,
        NULL::text AS device_id,
        ssi.wps_device_name,
        ssi.wps_manufacturer,
        ssi.wps_model_name,
        ssi.device_fingerprint
      FROM sync_scan_ingest ssi
      WHERE ssi.stream_name = 'wireless.audit'
    SQL

    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE VIEW v_wireless_device_inventory AS
      SELECT
        md5(COALESCE(lower(source_mac), '') || '|' || COALESCE(location_id, '')) AS inventory_key,
        lower(source_mac) AS source_mac,
        max(location_id) AS location_id,
        min(observed_at) AS first_seen,
        max(observed_at) AS last_seen,
        max(ssid) AS ssid,
        max(destination_bssid) AS destination_bssid,
        string_agg(DISTINCT src_ip, ', ') FILTER (WHERE src_ip IS NOT NULL) AS ip_addresses,
        string_agg(DISTINCT hostname, ', ') FILTER (WHERE hostname IS NOT NULL) AS hostnames,
        string_agg(DISTINCT app_protocol, ', ') FILTER (WHERE app_protocol IS NOT NULL) AS services,
        string_agg(DISTINCT dns_query_name, ', ') FILTER (WHERE dns_query_name IS NOT NULL) AS dns_names,
        count(*) AS frame_count,
        sum(CASE WHEN protected THEN 1 ELSE 0 END) AS protected_frame_count,
        sum(CASE WHEN NOT protected THEN 1 ELSE 0 END) AS open_frame_count
      FROM (
        SELECT
          observed_at,
          COALESCE(source_mac, payload->>'source_mac') AS source_mac,
          COALESCE(location_id, payload->>'location_id') AS location_id,
          COALESCE(ssid, payload->>'ssid') AS ssid,
          COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') AS destination_bssid,
          COALESCE(src_ip, payload->>'src_ip') AS src_ip,
          COALESCE(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') AS hostname,
          COALESCE(app_protocol, payload->>'app_protocol') AS app_protocol,
          COALESCE(dns_query_name, payload->>'dns_query_name') AS dns_query_name,
          COALESCE(protected, FALSE) AS protected
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
      ) inventory
      WHERE source_mac IS NOT NULL
      GROUP BY lower(source_mac), location_id
    SQL
  end

  def ensure_wireless_audit_cleanup_function
    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE FUNCTION normalize_wireless_audit_minutes(
        p_from timestamptz DEFAULT NULL,
        p_to timestamptz DEFAULT NULL
      )
      RETURNS TABLE(normalized_count bigint, deleted_count bigint)
      LANGUAGE plpgsql
      AS $$
      BEGIN
        WITH scoped AS (
          SELECT
            dedupe_key,
            (date_trunc('minute', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS minute_observed_at
          FROM sync_scan_ingest
          WHERE stream_name = 'wireless.audit'
            AND (p_from IS NULL OR observed_at >= p_from)
            AND (p_to IS NULL OR observed_at < p_to)
        ),
        normalized AS (
          UPDATE sync_scan_ingest target
          SET observed_at = scoped.minute_observed_at,
              updated_at = now()
          FROM scoped
          WHERE target.dedupe_key = scoped.dedupe_key
            AND target.observed_at <> scoped.minute_observed_at
          RETURNING target.dedupe_key
        )
        SELECT count(*) INTO normalized_count FROM normalized;

        WITH ranked AS (
          SELECT
            dedupe_key,
            row_number() OVER (
              PARTITION BY
                (date_trunc('minute', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),
                lower(COALESCE(source_mac, payload->>'source_mac', '')),
                lower(COALESCE(bssid, payload->>'bssid', '')),
                lower(COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid', '')),
                lower(COALESCE(ssid, payload->>'ssid', '')),
                lower(COALESCE(sensor_id, payload->>'sensor_id', '')),
                lower(COALESCE(location_id, payload->>'location_id', '')),
                lower(COALESCE(frame_subtype, payload->>'frame_subtype', '')),
                lower(COALESCE(app_protocol, payload->>'app_protocol', '')),
                COALESCE(src_ip, payload->>'src_ip', ''),
                COALESCE(dst_ip, payload->>'dst_ip', ''),
                COALESCE(src_port::text, payload->>'src_port', ''),
                COALESCE(dst_port::text, payload->>'dst_port', ''),
                lower(COALESCE(session_key, payload->>'session_key', '')),
                lower(COALESCE(frame_fingerprint, payload->>'frame_fingerprint', '')),
                lower(COALESCE(device_fingerprint, payload->>'device_fingerprint', ''))
              ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, dedupe_key DESC
            ) AS duplicate_rank
          FROM sync_scan_ingest
          WHERE stream_name = 'wireless.audit'
            AND (p_from IS NULL OR observed_at >= p_from)
            AND (p_to IS NULL OR observed_at < p_to)
        ),
        deleted AS (
          DELETE FROM sync_scan_ingest target
          USING ranked
          WHERE target.dedupe_key = ranked.dedupe_key
            AND ranked.duplicate_rank > 1
          RETURNING target.dedupe_key
        )
        SELECT count(*) INTO deleted_count FROM deleted;

        RETURN NEXT;
      END;
      $$;
    SQL
  end

  private

  def sync_scan_ingest_promoted_columns
    @sync_scan_ingest_promoted_columns ||= sync_connection.columns("sync_scan_ingest").each_with_object({}) do |column, memo|
      next if SYNC_SCAN_INGEST_MANAGED_COLUMNS.include?(column.name)

      memo[column.name] = column
    end.freeze
  end

  def cast_sync_scan_ingest_value(column, value)
    return if value.nil?

    case column.type
    when :boolean
      ActiveModel::Type::Boolean.new.cast(value)
    when :integer, :bigint
      value.to_i
    when :float
      value.to_f
    else
      value
    end
  end

  def quote_sync_scan_ingest_value(column_name, value)
    return "#{sync_connection.quote(value.to_json)}::jsonb" if column_name == "payload"

    sync_connection.quote(value)
  end
end
