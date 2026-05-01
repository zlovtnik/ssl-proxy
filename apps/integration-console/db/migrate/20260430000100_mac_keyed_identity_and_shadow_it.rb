class MacKeyedIdentityAndShadowIt < ActiveRecord::Migration[7.2]
  def up
    execute "DROP VIEW IF EXISTS v_sync_plane_health"
    execute "DROP VIEW IF EXISTS v_shadow_it_alerts"
    execute "DROP VIEW IF EXISTS v_wireless_audit_with_devices"
    execute "DROP VIEW IF EXISTS v_wireless_device_inventory"

    execute "DROP TABLE IF EXISTS shadow_it_alerts CASCADE"
    execute "DROP TABLE IF EXISTS devices CASCADE"

    create_devices_table
    create_shadow_it_alerts_table
    refresh_wireless_identity_views
    refresh_shadow_it_alerts_view
    refresh_sync_plane_health_view
  end

  def down
    execute "DROP VIEW IF EXISTS v_sync_plane_health"
    execute "DROP VIEW IF EXISTS v_shadow_it_alerts"
    execute "DROP VIEW IF EXISTS v_wireless_audit_with_devices"
    execute "DROP VIEW IF EXISTS v_wireless_device_inventory"

    execute "DROP TABLE IF EXISTS shadow_it_alerts CASCADE"
    execute "DROP TABLE IF EXISTS devices CASCADE"

    create_table :devices, primary_key: :device_id, id: :text do |t|
      t.text :wg_pubkey
      t.text :claim_token_hash
      t.text :display_name
      t.text :username
      t.text :hostname
      t.text :os_hint
      t.text :mac_hint
      t.timestamptz :first_seen, null: false, default: -> { "now()" }
      t.timestamptz :last_seen, null: false, default: -> { "now()" }
      t.text :notes
    end

    add_index :devices, "lower(mac_hint)", name: "devices_mac_hint_idx"
    add_index :devices, :wg_pubkey, name: "devices_wg_pubkey_idx"
    add_index :devices, [:username, :last_seen], order: { last_seen: :desc }, name: "devices_username_idx"

    create_table :shadow_it_alerts, primary_key: :alert_id do |t|
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

    add_index :shadow_it_alerts, :dedupe_key, unique: true
    add_index :shadow_it_alerts, :observed_at, order: { observed_at: :desc }, where: "resolved_at IS NULL", name: "shadow_it_alerts_open_idx"
    add_index :shadow_it_alerts, "lower(source_mac), observed_at DESC", name: "shadow_it_alerts_source_idx"
  end

  private

  def create_devices_table
    create_table :devices, id: false do |t|
      t.text :mac_id, null: false
      t.text :wg_pubkey
      t.text :claim_token_hash
      t.text :display_name
      t.text :username
      t.text :hostname
      t.text :os_hint
      t.text :mac_hint, null: false
      t.timestamptz :first_seen, null: false, default: -> { "now()" }
      t.timestamptz :last_seen, null: false, default: -> { "now()" }
      t.text :notes
    end

    execute "ALTER TABLE devices ADD CONSTRAINT devices_pk PRIMARY KEY (mac_id)"
    add_check_constraint :devices,
      "mac_id ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' AND lower(mac_hint) = mac_id",
      name: "devices_mac_id_format_chk"
    add_index :devices, :wg_pubkey, name: "devices_wg_pubkey_idx"
    add_index :devices, [:username, :last_seen], order: { last_seen: :desc }, name: "devices_username_idx"
  end

  def create_shadow_it_alerts_table
    create_table :shadow_it_alerts, id: false do |t|
      t.text :source_mac, null: false
      t.timestamptz :first_occurred_at, null: false
      t.timestamptz :last_occurred_at, null: false
      t.bigint :occurrence_count, null: false, default: 1
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

    execute "ALTER TABLE shadow_it_alerts ADD CONSTRAINT shadow_it_alerts_pk PRIMARY KEY (source_mac)"
    add_check_constraint :shadow_it_alerts,
      "source_mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'",
      name: "shadow_it_alerts_source_mac_format_chk"
    add_index :shadow_it_alerts, :last_occurred_at, order: { last_occurred_at: :desc }, where: "resolved_at IS NULL", name: "shadow_it_alerts_open_idx"
  end

  def refresh_wireless_identity_views
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_device_inventory AS
      WITH base AS (
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
        FROM sync_scan_ingest ssi
        WHERE ssi.stream_name = 'wireless.audit'
          AND COALESCE(ssi.source_mac, ssi.payload->>'source_mac') IS NOT NULL
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

  def refresh_shadow_it_alerts_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_shadow_it_alerts AS
      SELECT
        source_mac AS alert_id,
        source_mac AS dedupe_key,
        source_mac,
        first_occurred_at,
        last_occurred_at,
        last_occurred_at AS observed_at,
        occurrence_count,
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
      ORDER BY last_occurred_at DESC
    SQL
  end

  def refresh_sync_plane_health_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_sync_plane_health AS
      WITH ingest_status AS (
        SELECT status, count(*)::bigint AS row_count
        FROM sync_scan_ingest
        GROUP BY status
      ),
      wireless_ingest_status AS (
        SELECT status, count(*)::bigint AS row_count
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
        GROUP BY status
      ),
      ingest_time AS (
        SELECT
          count(*) FILTER (WHERE stream_name = 'wireless.audit' AND observed_at >= now() - interval '24 hours')::bigint AS wireless_events_24h_count,
          max(observed_at) FILTER (WHERE stream_name = 'wireless.audit') AS wireless_last_observed_at
        FROM sync_scan_ingest
      ),
      batch_status AS (
        SELECT status, count(*)::bigint AS row_count
        FROM sync_batch
        GROUP BY status
      ),
      job_batch_rollup AS (
        SELECT
          job.job_id,
          job.status AS stored_status,
          job.created_at,
          count(batch.batch_id)::bigint AS batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status IN ('pending', 'processing', 'dispatched'))::bigint AS open_batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status = 'failed')::bigint AS failed_batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status = 'completed')::bigint AS completed_batch_count
        FROM sync_job job
        LEFT JOIN sync_batch batch ON batch.job_id = job.job_id
        GROUP BY job.job_id, job.status, job.created_at
      ),
      job_effective_status AS (
        SELECT
          CASE
            WHEN open_batch_count > 0 THEN stored_status
            WHEN failed_batch_count > 0 THEN 'failed'
            WHEN completed_batch_count > 0 THEN 'completed'
            WHEN stored_status IN ('pending', 'running') AND created_at < now() - interval '5 minutes' THEN 'orphaned'
            ELSE stored_status
          END AS effective_status,
          stored_status,
          count(*)::bigint AS row_count
        FROM job_batch_rollup
        GROUP BY
          CASE
            WHEN open_batch_count > 0 THEN stored_status
            WHEN failed_batch_count > 0 THEN 'failed'
            WHEN completed_batch_count > 0 THEN 'completed'
            WHEN stored_status IN ('pending', 'running') AND created_at < now() - interval '5 minutes' THEN 'orphaned'
            ELSE stored_status
          END,
          stored_status
      ),
      backlog_status AS (
        SELECT status, count(*)::bigint AS row_count
        FROM audit_backlog
        GROUP BY status
      ),
      shadow_status AS (
        SELECT
          count(*) FILTER (WHERE resolved_at IS NULL)::bigint AS open_alert_count,
          max(last_occurred_at) FILTER (WHERE resolved_at IS NULL) AS last_open_alert_at
        FROM shadow_it_alerts
      )
      SELECT
        now() AS measured_at,
        coalesce((SELECT wireless_events_24h_count FROM ingest_time), 0)::bigint AS wireless_events_24h_count,
        (SELECT wireless_last_observed_at FROM ingest_time) AS wireless_last_observed_at,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'pending'), 0)::bigint AS wireless_ingest_pending_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'processing'), 0)::bigint AS wireless_ingest_processing_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'batched'), 0)::bigint AS wireless_ingest_batched_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'failed'), 0)::bigint AS wireless_ingest_failed_count,
        coalesce((SELECT sum(row_count) FROM wireless_ingest_status), 0)::bigint AS wireless_ingest_total_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'pending'), 0)::bigint AS ingest_pending_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'processing'), 0)::bigint AS ingest_processing_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'batched'), 0)::bigint AS ingest_batched_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'failed'), 0)::bigint AS ingest_failed_count,
        coalesce((SELECT sum(row_count) FROM ingest_status), 0)::bigint AS ingest_total_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'pending'), 0)::bigint AS batch_pending_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'processing'), 0)::bigint AS batch_processing_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'dispatched'), 0)::bigint AS batch_dispatched_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'completed'), 0)::bigint AS batch_completed_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'failed'), 0)::bigint AS batch_failed_count,
        coalesce((SELECT sum(row_count) FROM batch_status), 0)::bigint AS batch_total_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'pending'), 0)::bigint AS job_stored_pending_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'running'), 0)::bigint AS job_stored_running_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'completed'), 0)::bigint AS job_stored_completed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'failed'), 0)::bigint AS job_stored_failed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status), 0)::bigint AS job_total_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'pending'), 0)::bigint AS job_effective_pending_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'running'), 0)::bigint AS job_effective_running_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'completed'), 0)::bigint AS job_effective_completed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'failed'), 0)::bigint AS job_effective_failed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'orphaned'), 0)::bigint AS job_orphaned_count,
        coalesce((SELECT row_count FROM backlog_status WHERE status = 'pending'), 0)::bigint AS backlog_pending_count,
        coalesce((SELECT sum(row_count) FROM backlog_status WHERE status IN ('sync_failed', 'failed')), 0)::bigint AS backlog_failed_count,
        coalesce((SELECT open_alert_count FROM shadow_status), 0)::bigint AS open_shadow_it_alert_count,
        (SELECT last_open_alert_at FROM shadow_status) AS last_shadow_it_alert_at,
        (SELECT cursor_value FROM sync_cursor WHERE stream_name = 'wireless.audit') AS wireless_cursor_value,
        (SELECT updated_at FROM sync_cursor WHERE stream_name = 'wireless.audit') AS wireless_cursor_updated_at
    SQL
  end
end
