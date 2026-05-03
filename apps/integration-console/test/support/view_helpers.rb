module ViewHelpers
  def ensure_wireless_audit_views
    sync_connection.execute("DROP VIEW IF EXISTS v_wireless_audit_with_devices")
    sync_connection.execute("DROP VIEW IF EXISTS v_wireless_device_inventory")
    ensure_sync_devices_table

    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE VIEW v_wireless_device_inventory AS
      WITH recent_ingest AS MATERIALIZED (
        SELECT *
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
          AND COALESCE(source_mac, payload->>'source_mac') IS NOT NULL
        ORDER BY observed_at DESC
        LIMIT 20000
      ),
      base AS (
        SELECT
          dedupe_key,
          observed_at,
          lower(COALESCE(source_mac, payload->>'source_mac')) AS source_mac,
          COALESCE(bssid, payload->>'bssid') AS bssid,
          COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') AS destination_bssid,
          COALESCE(location_id, payload->>'location_id') AS location_id,
          COALESCE(sensor_id, payload->>'sensor_id') AS sensor_id,
          COALESCE(ssid, payload->>'ssid') AS ssid,
          COALESCE(signal_dbm, CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END) AS signal_dbm,
          COALESCE(username, payload->>'username') AS username,
          COALESCE(src_ip, payload->>'src_ip') AS src_ip,
          COALESCE(dst_ip, payload->>'dst_ip') AS dst_ip,
          COALESCE(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') AS hostname,
          COALESCE(app_protocol, payload->>'app_protocol') AS app_protocol,
          COALESCE(dns_query_name, payload->>'dns_query_name') AS dns_query_name,
          COALESCE(protected, FALSE) AS protected,
          wps_device_name,
          wps_manufacturer,
          wps_model_name,
          device_fingerprint
        FROM recent_ingest
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

    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT * FROM v_wireless_device_inventory
    SQL
  end

  def ensure_sync_devices_table
    mac_id_present = sync_connection.select_value(<<~SQL.squish)
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'devices'
          AND column_name = 'mac_id'
      )
    SQL

    return if mac_id_present

    sync_connection.execute("DROP TABLE IF EXISTS devices CASCADE")
    sync_connection.execute(<<~SQL)
      CREATE TABLE devices (
        mac_id text PRIMARY KEY,
        wg_pubkey text,
        claim_token_hash text,
        display_name text,
        username text,
        hostname text,
        os_hint text,
        mac_hint text NOT NULL,
        first_seen timestamptz NOT NULL DEFAULT now(),
        last_seen timestamptz NOT NULL DEFAULT now(),
        notes text
      )
    SQL
  end

  def ensure_shadow_it_alerts_table
    last_occurred_present = sync_connection.select_value(<<~SQL.squish)
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'shadow_it_alerts'
          AND column_name = 'last_occurred_at'
      )
    SQL

    return if last_occurred_present

    sync_connection.execute("DROP VIEW IF EXISTS v_shadow_it_alerts")
    sync_connection.execute("DROP TABLE IF EXISTS shadow_it_alerts CASCADE")
    sync_connection.execute(<<~SQL)
      CREATE TABLE shadow_it_alerts (
        source_mac text PRIMARY KEY,
        first_occurred_at timestamptz NOT NULL,
        last_occurred_at timestamptz NOT NULL,
        occurrence_count bigint NOT NULL DEFAULT 1,
        destination_bssid text,
        ssid text,
        sensor_id text,
        location_id text,
        signal_dbm integer,
        reason text NOT NULL,
        evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
        resolved_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      )
    SQL
    sync_connection.execute(<<~SQL)
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

  def ensure_sync_plane_health_view
    sync_connection.execute(<<~SQL)
      DROP VIEW IF EXISTS v_sync_plane_health;

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

  def ensure_wireless_audit_cleanup_function
    sync_connection.execute(<<~SQL)
      CREATE OR REPLACE FUNCTION normalize_wireless_audit_minutes(
        p_from timestamptz DEFAULT NULL,
        p_to timestamptz DEFAULT NULL
      )
      RETURNS TABLE(normalized_count bigint, deleted_count bigint)
      LANGUAGE plpgsql
      AS $$
      DECLARE
        v_first_observed_at timestamptz;
        v_last_observed_at timestamptz;
        v_window_start timestamptz;
        v_window_end timestamptz;
        v_stop timestamptz;
        v_normalized_count bigint;
        v_deleted_count bigint;
      BEGIN
        normalized_count := 0;
        deleted_count := 0;

        SELECT min(observed_at), max(observed_at)
        INTO v_first_observed_at, v_last_observed_at
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
          AND (p_from IS NULL OR observed_at >= p_from)
          AND (p_to IS NULL OR observed_at < p_to);

        IF v_first_observed_at IS NULL THEN
          RETURN NEXT;
          RETURN;
        END IF;

        CREATE TEMP TABLE IF NOT EXISTS wireless_audit_cleanup_scope (
          dedupe_key text PRIMARY KEY,
          minute_observed_at timestamptz NOT NULL,
          orig_updated_at timestamptz NOT NULL
        ) ON COMMIT DROP;

        v_window_start := COALESCE(p_from, date_trunc('hour', v_first_observed_at));
        v_stop := COALESCE(p_to, v_last_observed_at + interval '1 microsecond');

        WHILE v_window_start < v_stop LOOP
          v_window_end := LEAST(v_window_start + interval '1 hour', v_stop);

          TRUNCATE TABLE wireless_audit_cleanup_scope;

          INSERT INTO wireless_audit_cleanup_scope (dedupe_key, minute_observed_at, orig_updated_at)
          SELECT
            dedupe_key,
            (date_trunc('minute', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS minute_observed_at,
            updated_at AS orig_updated_at
          FROM sync_scan_ingest
          WHERE stream_name = 'wireless.audit'
            AND observed_at >= v_window_start
            AND observed_at < v_window_end;

          UPDATE sync_scan_ingest target
          SET observed_at = wireless_audit_cleanup_scope.minute_observed_at,
              updated_at = now()
          FROM wireless_audit_cleanup_scope
          WHERE target.dedupe_key = wireless_audit_cleanup_scope.dedupe_key
            AND target.observed_at <> wireless_audit_cleanup_scope.minute_observed_at;

          GET DIAGNOSTICS v_normalized_count = ROW_COUNT;
          normalized_count := normalized_count + v_normalized_count;

          WITH ranked AS (
            SELECT
              target.dedupe_key,
              row_number() OVER (
                PARTITION BY
                  wireless_audit_cleanup_scope.minute_observed_at,
                  lower(COALESCE(target.source_mac, target.payload->>'source_mac', '')),
                  lower(COALESCE(target.bssid, target.payload->>'bssid', '')),
                  lower(COALESCE(target.destination_bssid, target.bssid, target.payload->>'destination_bssid', target.payload->>'bssid', '')),
                  lower(COALESCE(target.ssid, target.payload->>'ssid', '')),
                  lower(COALESCE(target.sensor_id, target.payload->>'sensor_id', '')),
                  lower(COALESCE(target.location_id, target.payload->>'location_id', '')),
                  lower(COALESCE(target.frame_subtype, target.payload->>'frame_subtype', '')),
                  lower(COALESCE(target.app_protocol, target.payload->>'app_protocol', '')),
                  COALESCE(target.src_ip, target.payload->>'src_ip', ''),
                  COALESCE(target.dst_ip, target.payload->>'dst_ip', ''),
                  COALESCE(target.src_port::text, target.payload->>'src_port', ''),
                  COALESCE(target.dst_port::text, target.payload->>'dst_port', ''),
                  lower(COALESCE(target.session_key, target.payload->>'session_key', '')),
                  lower(COALESCE(target.frame_fingerprint, target.payload->>'frame_fingerprint', '')),
                  lower(COALESCE(target.device_fingerprint, target.payload->>'device_fingerprint', ''))
                ORDER BY wireless_audit_cleanup_scope.orig_updated_at DESC NULLS LAST, target.created_at DESC NULLS LAST, target.dedupe_key DESC
              ) AS duplicate_rank
            FROM sync_scan_ingest target
            JOIN wireless_audit_cleanup_scope
              ON target.dedupe_key = wireless_audit_cleanup_scope.dedupe_key
            WHERE target.stream_name = 'wireless.audit'
          ),
          deleted AS (
            DELETE FROM sync_scan_ingest target
            USING ranked
            WHERE target.dedupe_key = ranked.dedupe_key
              AND ranked.duplicate_rank > 1
            RETURNING target.dedupe_key
          )
          SELECT count(*) INTO v_deleted_count FROM deleted;

          deleted_count := deleted_count + v_deleted_count;
          v_window_start := v_window_end;
        END LOOP;

        RETURN NEXT;
      END;
      $$;
    SQL
  end
end
