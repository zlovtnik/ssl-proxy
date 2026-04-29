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

  def down
    execute "DROP FUNCTION IF EXISTS normalize_wireless_audit_minutes(timestamptz, timestamptz)"
  end
end
