ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "minitest/mock"
require "securerandom"

class ActiveSupport::TestCase
  parallelize(workers: 1)

  def sync_connection
    SyncRecord.connection
  end

  def clear_sync_tables(*tables)
    tables.each do |table|
      sync_connection.execute("DELETE FROM #{table}")
    end
  end

  def insert_sync_ingest(dedupe_key:, observed_at:, payload:, stream_name: "wireless.audit", status: "pending")
    quoted_payload = sync_connection.quote(payload.to_json)
    schema_version = payload.fetch("schema_version", 1).to_i
    frame_type = payload["frame_type"]
    security_flags = payload.fetch("security_flags", 0).to_i
    wps_device_name = payload["wps_device_name"]
    wps_manufacturer = payload["wps_manufacturer"]
    wps_model_name = payload["wps_model_name"]
    device_fingerprint = payload["device_fingerprint"]
    handshake_captured = payload.fetch("handshake_captured", false) ? "TRUE" : "FALSE"
    source_mac = payload["source_mac"]
    bssid = payload["bssid"]
    destination_bssid = payload["destination_bssid"] || bssid
    ssid = payload["ssid"]
    signal_dbm = payload["signal_dbm"]
    fragment_number = payload["fragment_number"]
    channel_number = payload["channel_number"]
    signal_status = payload["signal_status"]
    qos_tid = payload["qos_tid"]
    qos_eosp = payload.key?("qos_eosp") ? (payload["qos_eosp"] ? "TRUE" : "FALSE") : "NULL"
    qos_ack_policy = payload["qos_ack_policy"]
    qos_ack_policy_label = payload["qos_ack_policy_label"]
    qos_amsdu = payload.key?("qos_amsdu") ? (payload["qos_amsdu"] ? "TRUE" : "FALSE") : "NULL"
    llc_oui = payload["llc_oui"]
    ethertype = payload["ethertype"]
    ethertype_name = payload["ethertype_name"]
    src_ip = payload["src_ip"]
    dst_ip = payload["dst_ip"]
    ip_ttl = payload["ip_ttl"]
    ip_protocol = payload["ip_protocol"]
    ip_protocol_name = payload["ip_protocol_name"]
    src_port = payload["src_port"]
    dst_port = payload["dst_port"]
    transport_protocol = payload["transport_protocol"]
    transport_length = payload["transport_length"]
    transport_checksum = payload["transport_checksum"]
    app_protocol = payload["app_protocol"]
    ssdp_message_type = payload["ssdp_message_type"]
    ssdp_st = payload["ssdp_st"]
    ssdp_mx = payload["ssdp_mx"]
    ssdp_usn = payload["ssdp_usn"]
    dhcp_requested_ip = payload["dhcp_requested_ip"]
    dhcp_hostname = payload["dhcp_hostname"]
    dhcp_vendor_class = payload["dhcp_vendor_class"]
    dns_query_name = payload["dns_query_name"]
    mdns_name = payload["mdns_name"]
    session_key = payload["session_key"]
    retransmit_key = payload["retransmit_key"]
    frame_fingerprint = payload["frame_fingerprint"]
    payload_visibility = payload["payload_visibility"]
    large_frame = payload.fetch("large_frame", false) ? "TRUE" : "FALSE"
    mixed_encryption = payload.key?("mixed_encryption") ? (payload["mixed_encryption"] ? "TRUE" : "FALSE") : "NULL"
    dedupe_or_replay_suspect = payload.fetch("dedupe_or_replay_suspect", false) ? "TRUE" : "FALSE"
    raw_len = payload.fetch("raw_len", 0).to_i
    frame_control_flags = payload.fetch("frame_control_flags", 0).to_i
    more_data = payload.fetch("more_data", false) ? "TRUE" : "FALSE"
    retry_value = payload.fetch("retry", false) ? "TRUE" : "FALSE"
    power_save = payload.fetch("power_save", false) ? "TRUE" : "FALSE"
    protected_value = payload.fetch("protected", false) ? "TRUE" : "FALSE"
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_scan_ingest
        (dedupe_key, stream_name, observed_at, payload_ref, payload, payload_sha256, status, producer, event_kind, schema_version, frame_type, source_mac, bssid, destination_bssid, ssid, signal_dbm, fragment_number, channel_number, signal_status, qos_tid, qos_eosp, qos_ack_policy, qos_ack_policy_label, qos_amsdu, llc_oui, ethertype, ethertype_name, src_ip, dst_ip, ip_ttl, ip_protocol, ip_protocol_name, src_port, dst_port, transport_protocol, transport_length, transport_checksum, app_protocol, ssdp_message_type, ssdp_st, ssdp_mx, ssdp_usn, dhcp_requested_ip, dhcp_hostname, dhcp_vendor_class, dns_query_name, mdns_name, session_key, retransmit_key, frame_fingerprint, payload_visibility, large_frame, mixed_encryption, dedupe_or_replay_suspect, raw_len, frame_control_flags, more_data, retry, power_save, protected, security_flags, wps_device_name, wps_manufacturer, wps_model_name, device_fingerprint, handshake_captured, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, #{sync_connection.quote(stream_name)}, #{sync_connection.quote(observed_at)}, #{sync_connection.quote("payload://#{dedupe_key}")}, #{quoted_payload}::jsonb, #{sync_connection.quote(SecureRandom.hex(16))}, #{sync_connection.quote(status)}, 'test', 'test', #{schema_version}, #{sync_connection.quote(frame_type)}, #{sync_connection.quote(source_mac)}, #{sync_connection.quote(bssid)}, #{sync_connection.quote(destination_bssid)}, #{sync_connection.quote(ssid)}, #{signal_dbm.nil? ? "NULL" : signal_dbm.to_i}, #{fragment_number.nil? ? "NULL" : fragment_number.to_i}, #{channel_number.nil? ? "NULL" : channel_number.to_i}, #{sync_connection.quote(signal_status)}, #{qos_tid.nil? ? "NULL" : qos_tid.to_i}, #{qos_eosp}, #{qos_ack_policy.nil? ? "NULL" : qos_ack_policy.to_i}, #{sync_connection.quote(qos_ack_policy_label)}, #{qos_amsdu}, #{sync_connection.quote(llc_oui)}, #{ethertype.nil? ? "NULL" : ethertype.to_i}, #{sync_connection.quote(ethertype_name)}, #{sync_connection.quote(src_ip)}, #{sync_connection.quote(dst_ip)}, #{ip_ttl.nil? ? "NULL" : ip_ttl.to_i}, #{ip_protocol.nil? ? "NULL" : ip_protocol.to_i}, #{sync_connection.quote(ip_protocol_name)}, #{src_port.nil? ? "NULL" : src_port.to_i}, #{dst_port.nil? ? "NULL" : dst_port.to_i}, #{sync_connection.quote(transport_protocol)}, #{transport_length.nil? ? "NULL" : transport_length.to_i}, #{transport_checksum.nil? ? "NULL" : transport_checksum.to_i}, #{sync_connection.quote(app_protocol)}, #{sync_connection.quote(ssdp_message_type)}, #{sync_connection.quote(ssdp_st)}, #{sync_connection.quote(ssdp_mx)}, #{sync_connection.quote(ssdp_usn)}, #{sync_connection.quote(dhcp_requested_ip)}, #{sync_connection.quote(dhcp_hostname)}, #{sync_connection.quote(dhcp_vendor_class)}, #{sync_connection.quote(dns_query_name)}, #{sync_connection.quote(mdns_name)}, #{sync_connection.quote(session_key)}, #{sync_connection.quote(retransmit_key)}, #{sync_connection.quote(frame_fingerprint)}, #{sync_connection.quote(payload_visibility)}, #{large_frame}, #{mixed_encryption}, #{dedupe_or_replay_suspect}, #{raw_len}, #{frame_control_flags}, #{more_data}, #{retry_value}, #{power_save}, #{protected_value}, #{security_flags}, #{sync_connection.quote(wps_device_name)}, #{sync_connection.quote(wps_manufacturer)}, #{sync_connection.quote(wps_model_name)}, #{sync_connection.quote(device_fingerprint)}, #{handshake_captured}, now(), now())
    SQL
  end

  def insert_backlog(dedupe_key:, status:, updated_at: Time.current)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO audit_backlog
        (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, 'sync.scan.request', '{}', #{sync_connection.quote(status)}, 0, now(), #{sync_connection.quote(updated_at)})
    SQL
  end
end
