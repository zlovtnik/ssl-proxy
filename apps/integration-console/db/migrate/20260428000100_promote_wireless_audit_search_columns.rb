class PromoteWirelessAuditSearchColumns < ActiveRecord::Migration[7.2]
  def up
    # Postgres will not allow ALTER TABLE on columns used in views.
    # Drop view first, make schema changes, then recreate view.
    execute "DROP VIEW IF EXISTS v_wireless_audit_with_devices"

    add_column :sync_scan_ingest, :sensor_id, :text, if_not_exists: true
    add_column :sync_scan_ingest, :location_id, :text, if_not_exists: true
    add_column :sync_scan_ingest, :frame_subtype, :text, if_not_exists: true
    add_column :sync_scan_ingest, :username, :text, if_not_exists: true

    execute <<~SQL.squish
      UPDATE sync_scan_ingest
      SET sensor_id = COALESCE(sensor_id, payload->>'sensor_id'),
          location_id = COALESCE(location_id, payload->>'location_id'),
          frame_subtype = COALESCE(frame_subtype, payload->>'frame_subtype'),
          username = COALESCE(username, payload->>'username')
      WHERE stream_name = 'wireless.audit'
        AND (
          (sensor_id IS NULL AND payload->>'sensor_id' IS NOT NULL)
          OR (location_id IS NULL AND payload->>'location_id' IS NOT NULL)
          OR (frame_subtype IS NULL AND payload->>'frame_subtype' IS NOT NULL)
          OR (username IS NULL AND payload->>'username' IS NOT NULL)
        )
    SQL

    refresh_wireless_audit_view
  end

  def down
    execute "DROP VIEW IF EXISTS v_wireless_audit_with_devices"

    add_column :sync_scan_ingest, :sensor_id, :text, if_not_exists: true
    add_column :sync_scan_ingest, :location_id, :text, if_not_exists: true
    add_column :sync_scan_ingest, :frame_subtype, :text, if_not_exists: true
    add_column :sync_scan_ingest, :username, :text, if_not_exists: true

    refresh_legacy_wireless_audit_view
  end

  private

  def refresh_wireless_audit_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT
        ssi.dedupe_key,
        ssi.observed_at,
        ssi.stream_name,
        ssi.status,
        ssi.producer,
        ssi.event_kind,
        COALESCE(
          ssi.schema_version,
          CASE WHEN ssi.payload->>'schema_version' ~ '^[0-9]+$' THEN (ssi.payload->>'schema_version')::integer END,
          1
        ) AS schema_version,
        COALESCE(ssi.frame_type, ssi.payload->>'frame_type') AS frame_type,
        COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
        ssi.payload->>'transmitter_mac' AS transmitter_mac,
        ssi.payload->>'receiver_mac' AS receiver_mac,
        COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
        COALESCE(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
        COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
        COALESCE(ssi.frame_subtype, ssi.payload->>'frame_subtype') AS frame_subtype,
        COALESCE(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') AS signal_dbm,
        ssi.payload->>'noise_dbm' AS noise_dbm,
        ssi.payload->>'frequency_mhz' AS frequency_mhz,
        COALESCE(ssi.channel_number::text, ssi.payload->>'channel_number') AS channel_number,
        COALESCE(ssi.signal_status, ssi.payload->>'signal_status') AS signal_status,
        COALESCE(ssi.qos_tid::text, ssi.payload->>'qos_tid') AS qos_tid,
        COALESCE(ssi.ethertype::text, ssi.payload->>'ethertype') AS ethertype,
        COALESCE(ssi.src_ip, ssi.payload->>'src_ip') AS src_ip,
        COALESCE(ssi.dst_ip, ssi.payload->>'dst_ip') AS dst_ip,
        COALESCE(ssi.src_port::text, ssi.payload->>'src_port') AS src_port,
        COALESCE(ssi.dst_port::text, ssi.payload->>'dst_port') AS dst_port,
        COALESCE(ssi.app_protocol, ssi.payload->>'app_protocol') AS app_protocol,
        COALESCE(ssi.session_key, ssi.payload->>'session_key') AS session_key,
        COALESCE(ssi.retransmit_key, ssi.payload->>'retransmit_key') AS retransmit_key,
        COALESCE(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') AS frame_fingerprint,
        COALESCE(ssi.payload_visibility, ssi.payload->>'payload_visibility') AS payload_visibility,
        COALESCE(ssi.large_frame::text, ssi.payload->>'large_frame') AS large_frame,
        COALESCE(ssi.mixed_encryption::text, ssi.payload->>'mixed_encryption') AS mixed_encryption,
        COALESCE(ssi.dedupe_or_replay_suspect::text, ssi.payload->>'dedupe_or_replay_suspect') AS dedupe_or_replay_suspect,
        COALESCE(ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS dhcp_hostname,
        COALESCE(ssi.dns_query_name, ssi.payload->>'dns_query_name') AS dns_query_name,
        COALESCE(ssi.mdns_name, ssi.payload->>'mdns_name') AS mdns_name,
        COALESCE(ssi.raw_len::text, ssi.payload->>'raw_len') AS raw_len,
        COALESCE(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') AS frame_control_flags,
        COALESCE(ssi.more_data::text, ssi.payload->>'more_data') AS more_data,
        COALESCE(ssi.retry::text, ssi.payload->>'retry') AS retry,
        COALESCE(ssi.power_save::text, ssi.payload->>'power_save') AS power_save,
        COALESCE(ssi.protected::text, ssi.payload->>'protected') AS protected,
        COALESCE(ssi.location_id, ssi.payload->>'location_id') AS location_id,
        COALESCE(ssi.sensor_id, ssi.payload->>'sensor_id') AS sensor_id,
        ssi.payload->>'identity_source' AS identity_source,
        COALESCE(ssi.username, ssi.payload->>'username') AS username,
        ssi.payload->'tags' AS tags,
        ssi.security_flags,
        ssi.wps_device_name,
        ssi.wps_manufacturer,
        ssi.wps_model_name,
        ssi.device_fingerprint,
        ssi.handshake_captured,
        COALESCE(d_src.device_id, d_bssid.device_id) AS device_id,
        COALESCE(d_src.display_name, d_bssid.display_name) AS display_name,
        COALESCE(d_src.username, d_bssid.username) AS registered_username,
        COALESCE(d_src.os_hint, d_bssid.os_hint) AS os_hint,
        COALESCE(d_src.hostname, d_bssid.hostname, ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS hostname
      FROM sync_scan_ingest ssi
      LEFT JOIN devices d_src
        ON lower(d_src.mac_hint) = lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac'))
      LEFT JOIN devices d_bssid
        ON lower(d_bssid.mac_hint) = lower(COALESCE(ssi.bssid, ssi.payload->>'bssid'))
      WHERE ssi.stream_name = 'wireless.audit'
    SQL
  end

  def refresh_legacy_wireless_audit_view
    execute <<~SQL
      DROP VIEW IF EXISTS v_wireless_audit_with_devices CASCADE;
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT
        ssi.dedupe_key,
        ssi.observed_at,
        ssi.stream_name,
        ssi.status,
        ssi.producer,
        ssi.event_kind,
        COALESCE(
          ssi.schema_version,
          CASE WHEN ssi.payload->>'schema_version' ~ '^[0-9]+$' THEN (ssi.payload->>'schema_version')::integer END,
          1
        ) AS schema_version,
        COALESCE(ssi.frame_type, ssi.payload->>'frame_type') AS frame_type,
        COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
        ssi.payload->>'transmitter_mac' AS transmitter_mac,
        ssi.payload->>'receiver_mac' AS receiver_mac,
        COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
        COALESCE(ssi.destination_bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
        COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
        ssi.payload->>'frame_subtype' AS frame_subtype,
        COALESCE(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') AS signal_dbm,
        ssi.payload->>'noise_dbm' AS noise_dbm,
        ssi.payload->>'frequency_mhz' AS frequency_mhz,
        COALESCE(ssi.channel_number::text, ssi.payload->>'channel_number') AS channel_number,
        COALESCE(ssi.signal_status, ssi.payload->>'signal_status') AS signal_status,
        COALESCE(ssi.qos_tid::text, ssi.payload->>'qos_tid') AS qos_tid,
        COALESCE(ssi.ethertype::text, ssi.payload->>'ethertype') AS ethertype,
        COALESCE(ssi.src_ip, ssi.payload->>'src_ip') AS src_ip,
        COALESCE(ssi.dst_ip, ssi.payload->>'dst_ip') AS dst_ip,
        COALESCE(ssi.src_port::text, ssi.payload->>'src_port') AS src_port,
        COALESCE(ssi.dst_port::text, ssi.payload->>'dst_port') AS dst_port,
        COALESCE(ssi.app_protocol, ssi.payload->>'app_protocol') AS app_protocol,
        COALESCE(ssi.session_key, ssi.payload->>'session_key') AS session_key,
        COALESCE(ssi.retransmit_key, ssi.payload->>'retransmit_key') AS retransmit_key,
        COALESCE(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') AS frame_fingerprint,
        COALESCE(ssi.payload_visibility, ssi.payload->>'payload_visibility') AS payload_visibility,
        COALESCE(ssi.large_frame::text, ssi.payload->>'large_frame') AS large_frame,
        COALESCE(ssi.mixed_encryption::text, ssi.payload->>'mixed_encryption') AS mixed_encryption,
        COALESCE(ssi.dedupe_or_replay_suspect::text, ssi.payload->>'dedupe_or_replay_suspect') AS dedupe_or_replay_suspect,
        COALESCE(ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS dhcp_hostname,
        COALESCE(ssi.dns_query_name, ssi.payload->>'dns_query_name') AS dns_query_name,
        COALESCE(ssi.mdns_name, ssi.payload->>'mdns_name') AS mdns_name,
        COALESCE(ssi.raw_len::text, ssi.payload->>'raw_len') AS raw_len,
        COALESCE(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') AS frame_control_flags,
        COALESCE(ssi.more_data::text, ssi.payload->>'more_data') AS more_data,
        COALESCE(ssi.retry::text, ssi.payload->>'retry') AS retry,
        COALESCE(ssi.power_save::text, ssi.payload->>'power_save') AS power_save,
        COALESCE(ssi.protected::text, ssi.payload->>'protected') AS protected,
        ssi.payload->>'location_id' AS location_id,
        ssi.payload->>'sensor_id' AS sensor_id,
        ssi.payload->>'identity_source' AS identity_source,
        ssi.payload->>'username' AS username,
        ssi.payload->'tags' AS tags,
        ssi.security_flags,
        ssi.wps_device_name,
        ssi.wps_manufacturer,
        ssi.wps_model_name,
        ssi.device_fingerprint,
        ssi.handshake_captured,
        COALESCE(d_src.device_id, d_bssid.device_id) AS device_id,
        COALESCE(d_src.display_name, d_bssid.display_name) AS display_name,
        COALESCE(d_src.username, d_bssid.username) AS registered_username,
        COALESCE(d_src.os_hint, d_bssid.os_hint) AS os_hint,
        COALESCE(d_src.hostname, d_bssid.hostname, ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS hostname
      FROM sync_scan_ingest ssi
      LEFT JOIN devices d_src
        ON lower(d_src.mac_hint) = lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac'))
      LEFT JOIN devices d_bssid
        ON lower(d_bssid.mac_hint) = lower(COALESCE(ssi.bssid, ssi.payload->>'bssid'))
      WHERE ssi.stream_name = 'wireless.audit'
    SQL
  end
end
