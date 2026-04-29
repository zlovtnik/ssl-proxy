class AddWirelessParserExpansionFields < ActiveRecord::Migration[7.2]
  def change
    add_column :sync_scan_ingest, :schema_version, :integer, null: false, default: 1, if_not_exists: true
    add_column :sync_scan_ingest, :frame_type, :text, if_not_exists: true
    add_column :sync_scan_ingest, :fragment_number, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :channel_number, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :signal_status, :text, if_not_exists: true
    add_column :sync_scan_ingest, :adjacent_mac_hint, :text, if_not_exists: true
    add_column :sync_scan_ingest, :qos_tid, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :qos_eosp, :boolean, if_not_exists: true
    add_column :sync_scan_ingest, :qos_ack_policy, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :qos_ack_policy_label, :text, if_not_exists: true
    add_column :sync_scan_ingest, :qos_amsdu, :boolean, if_not_exists: true
    add_column :sync_scan_ingest, :llc_oui, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ethertype, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :ethertype_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :src_ip, :text, if_not_exists: true
    add_column :sync_scan_ingest, :dst_ip, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ip_ttl, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :ip_protocol, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :ip_protocol_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :src_port, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :dst_port, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :transport_protocol, :text, if_not_exists: true
    add_column :sync_scan_ingest, :transport_length, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :transport_checksum, :integer, if_not_exists: true
    add_column :sync_scan_ingest, :app_protocol, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ssdp_message_type, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ssdp_st, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ssdp_mx, :text, if_not_exists: true
    add_column :sync_scan_ingest, :ssdp_usn, :text, if_not_exists: true
    add_column :sync_scan_ingest, :dhcp_requested_ip, :text, if_not_exists: true
    add_column :sync_scan_ingest, :dhcp_hostname, :text, if_not_exists: true
    add_column :sync_scan_ingest, :dhcp_vendor_class, :text, if_not_exists: true
    add_column :sync_scan_ingest, :dns_query_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :mdns_name, :text, if_not_exists: true
    add_column :sync_scan_ingest, :session_key, :text, if_not_exists: true
    add_column :sync_scan_ingest, :retransmit_key, :text, if_not_exists: true
    add_column :sync_scan_ingest, :frame_fingerprint, :text, if_not_exists: true
    add_column :sync_scan_ingest, :payload_visibility, :text, if_not_exists: true
    add_column :sync_scan_ingest, :tsft_delta_us, :bigint, if_not_exists: true
    add_column :sync_scan_ingest, :wall_clock_delta_ms, :bigint, if_not_exists: true
    add_column :sync_scan_ingest, :large_frame, :boolean, null: false, default: false, if_not_exists: true
    add_column :sync_scan_ingest, :mixed_encryption, :boolean, if_not_exists: true
    add_column :sync_scan_ingest, :dedupe_or_replay_suspect, :boolean, null: false, default: false, if_not_exists: true

    add_index :sync_scan_ingest,
      [:schema_version, :observed_at],
      name: "ssi_wireless_schema_version_idx",
      where: "stream_name = 'wireless.audit'",
      if_not_exists: true

    add_index :sync_scan_ingest,
      [:session_key, :observed_at],
      name: "ssi_wireless_session_key_idx",
      where: "stream_name = 'wireless.audit' AND session_key IS NOT NULL",
      if_not_exists: true

    add_index :sync_scan_ingest,
      [:app_protocol, :observed_at],
      name: "ssi_wireless_app_protocol_idx",
      where: "stream_name = 'wireless.audit' AND app_protocol IS NOT NULL",
      if_not_exists: true

    add_index :sync_scan_ingest,
      :frame_fingerprint,
      name: "ssi_wireless_frame_fingerprint_idx",
      where: "stream_name = 'wireless.audit' AND frame_fingerprint IS NOT NULL",
      if_not_exists: true

    add_index :sync_scan_ingest,
      :src_ip,
      name: "ssi_wireless_src_ip_idx",
      where: "stream_name = 'wireless.audit' AND src_ip IS NOT NULL",
      if_not_exists: true

    add_index :sync_scan_ingest,
      :dst_ip,
      name: "ssi_wireless_dst_ip_idx",
      where: "stream_name = 'wireless.audit' AND dst_ip IS NOT NULL",
      if_not_exists: true

    reversible do |dir|
      dir.up do
        refresh_wireless_audit_view
        refresh_wireless_session_timeline_view
        refresh_wireless_device_inventory_view
        refresh_wireless_anomalies_view
      end
      dir.down do
        execute "DROP VIEW IF EXISTS v_wireless_anomalies"
        execute "DROP VIEW IF EXISTS v_wireless_session_timeline"
        execute "DROP VIEW IF EXISTS v_wireless_device_inventory"
        refresh_legacy_wireless_audit_view
      end
    end
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
        COALESCE(ssi.schema_version, NULLIF(ssi.payload->>'schema_version', '')::integer, 1) AS schema_version,
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

  def refresh_wireless_session_timeline_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_session_timeline AS
      WITH base AS (
        SELECT
          ssi.dedupe_key,
          ssi.observed_at,
          COALESCE(ssi.session_key, ssi.payload->>'session_key') AS session_key,
          COALESCE(ssi.retransmit_key, ssi.payload->>'retransmit_key') AS retransmit_key,
          COALESCE(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') AS frame_fingerprint,
          COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
          COALESCE(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
          COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
          COALESCE(ssi.protected, FALSE) AS protected,
          COALESCE(ssi.large_frame, FALSE) AS large_frame,
          COALESCE(ssi.dedupe_or_replay_suspect, FALSE) AS dedupe_or_replay_suspect,
          NULLIF(ssi.payload->>'tsft', '')::bigint AS tsft
        FROM sync_scan_ingest ssi
        WHERE ssi.stream_name = 'wireless.audit'
      )
      SELECT
        dedupe_key,
        observed_at,
        session_key,
        retransmit_key,
        frame_fingerprint,
        source_mac,
        destination_bssid,
        ssid,
        protected,
        large_frame,
        dedupe_or_replay_suspect,
        tsft,
        CASE
          WHEN lag(tsft) OVER session_window IS NOT NULL AND tsft IS NOT NULL
            THEN tsft - lag(tsft) OVER session_window
        END AS tsft_delta_us,
        CASE
          WHEN lag(observed_at) OVER session_window IS NOT NULL
            THEN ROUND(EXTRACT(EPOCH FROM (observed_at - lag(observed_at) OVER session_window)) * 1000)
        END AS wall_clock_delta_ms,
        (COUNT(DISTINCT CASE WHEN protected THEN 'protected' ELSE 'open' END) OVER session_partition) > 1 AS mixed_encryption
      FROM base
      WINDOW
        session_partition AS (PARTITION BY session_key),
        session_window AS (PARTITION BY session_key ORDER BY observed_at)
    SQL
  end

  def refresh_wireless_device_inventory_view
    execute <<~SQL
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
      ) inventory
      WHERE source_mac IS NOT NULL
      GROUP BY lower(source_mac), location_id
    SQL
  end

  def refresh_wireless_anomalies_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_anomalies AS
      SELECT
        timeline.dedupe_key,
        timeline.observed_at,
        timeline.session_key,
        timeline.source_mac,
        timeline.destination_bssid,
        timeline.ssid,
        timeline.tsft_delta_us,
        timeline.wall_clock_delta_ms,
        timeline.mixed_encryption,
        timeline.large_frame,
        timeline.dedupe_or_replay_suspect,
        ARRAY_REMOVE(ARRAY[
          CASE WHEN timeline.large_frame THEN 'large_frame' END,
          CASE WHEN timeline.mixed_encryption THEN 'mixed_encryption' END,
          CASE WHEN timeline.dedupe_or_replay_suspect THEN 'dedupe_or_replay_suspect' END
        ], NULL) AS reasons
      FROM v_wireless_session_timeline timeline
      WHERE timeline.large_frame
         OR timeline.mixed_encryption
         OR timeline.dedupe_or_replay_suspect
    SQL
  end

  def refresh_legacy_wireless_audit_view
    execute <<~SQL
      CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
      SELECT
        ssi.dedupe_key,
        ssi.observed_at,
        ssi.stream_name,
        ssi.status,
        ssi.producer,
        ssi.event_kind,
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
        ssi.payload->>'data_rate_kbps' AS data_rate_kbps,
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
        COALESCE(d_src.hostname, d_bssid.hostname) AS hostname
      FROM sync_scan_ingest ssi
      LEFT JOIN devices d_src
        ON lower(d_src.mac_hint) = lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac'))
      LEFT JOIN devices d_bssid
        ON lower(d_bssid.mac_hint) = lower(COALESCE(ssi.bssid, ssi.payload->>'bssid'))
      WHERE ssi.stream_name = 'wireless.audit'
    SQL
  end
end
