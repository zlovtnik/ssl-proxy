class RepairSyncUpdateIdentitiesForMacKeyedDevices < ActiveRecord::Migration[7.2]
  def up
    execute <<~SQL
      DO $$
      BEGIN
        IF to_regclass('public.sync_scan_ingest') IS NULL
          OR to_regclass('public.devices') IS NULL
          OR NOT EXISTS (
            SELECT 1
            FROM pg_proc
            WHERE proname = 'sync_update_identities'
              AND pronamespace = 'public'::regnamespace
          )
        THEN
          RETURN;
        END IF;

        CREATE OR REPLACE FUNCTION sync_update_identities()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        DECLARE
          v_source_mac_lower text;
          v_device_id text;
          v_display_name text;
        BEGIN
          v_source_mac_lower := lower(NULLIF(COALESCE(NEW.source_mac, NEW.payload->>'source_mac'), ''));

          IF v_source_mac_lower IS NULL THEN
            RETURN NEW;
          END IF;

          SELECT d.mac_id, d.display_name
            INTO v_device_id, v_display_name
            FROM devices d
           WHERE d.mac_id = v_source_mac_lower
              OR lower(d.mac_hint) = v_source_mac_lower
           LIMIT 1;

          IF v_device_id IS NOT NULL THEN
            NEW.payload := jsonb_set(COALESCE(NEW.payload, '{}'::jsonb), '{device_id}', to_jsonb(v_device_id), true);

            IF v_display_name IS NOT NULL THEN
              NEW.payload := jsonb_set(NEW.payload, '{display_name}', to_jsonb(v_display_name), true);
            END IF;
          END IF;

          RETURN NEW;
        END;
        $function$;
      END $$;
    SQL
  end

  def down
    # This migration repairs a stale live trigger function that referenced the
    # removed devices.device_id column. Reintroducing that broken body on rollback
    # would make ingest fail again, so rollback intentionally leaves it repaired.
  end
end
