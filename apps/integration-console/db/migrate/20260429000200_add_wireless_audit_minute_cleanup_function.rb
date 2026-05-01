class AddWirelessAuditMinuteCleanupFunction < ActiveRecord::Migration[7.2]
  def up
    execute <<~SQL
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

  def down
    execute "DROP FUNCTION IF EXISTS normalize_wireless_audit_minutes(timestamptz, timestamptz)"
  end
end
