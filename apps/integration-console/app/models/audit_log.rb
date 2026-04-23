require "base64"

class AuditLog < SyncRecord
  self.table_name = "sync_scan_ingest"
  self.primary_key = "dedupe_key"

  scope :recent, -> { where(stream_name: "wireless.audit").order(observed_at: :desc) }
  scope :search, ->(query) {
    where(
      "payload->>'sensor_id' ILIKE :q OR payload->>'source_mac' ILIKE :q OR payload->>'bssid' ILIKE :q OR payload->>'destination_bssid' ILIKE :q OR payload->>'ssid' ILIKE :q OR payload->>'username' ILIKE :q OR device_fingerprint ILIKE :q OR wps_device_name ILIKE :q OR wps_manufacturer ILIKE :q OR wps_model_name ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }

  def schema_version = integer_payload_value("schema_version", default: 1)
  def sensor_id = payload_value("sensor_id")
  def location_id = payload_value("location_id")
  def event_type = payload_value("event_type")
  def channel = integer_payload_value("channel")
  def frame_type = payload_value("frame_type")
  def frame_subtype = payload_value("frame_subtype")
  def source_mac = payload_value("source_mac")
  def bssid = payload_value("bssid")
  def destination_bssid = payload_value("destination_bssid") || bssid
  def ssid = payload_value("ssid")
  def tsft = payload_value("tsft")
  def signal_dbm = payload_value("signal_dbm")
  def frequency_mhz = payload_value("frequency_mhz")
  def channel_number = integer_payload_value("channel_number")
  def channel_flags = payload_value("channel_flags")
  def data_rate_kbps = payload_value("data_rate_kbps")
  def antenna_id = payload_value("antenna_id")
  def fragment_number = integer_payload_value("fragment_number")
  def signal_status = payload_value("signal_status")
  def adjacent_mac_hint = payload_value("adjacent_mac_hint")
  def qos_tid = integer_payload_value("qos_tid")
  def qos_ack_policy = integer_payload_value("qos_ack_policy")
  def qos_ack_policy_label = payload_value("qos_ack_policy_label")
  def qos_amsdu = ActiveModel::Type::Boolean.new.cast(payload_value("qos_amsdu"))
  def llc_oui = payload_value("llc_oui")
  def ethertype = integer_payload_value("ethertype")
  def ethertype_name = payload_value("ethertype_name")
  def src_ip = payload_value("src_ip")
  def dst_ip = payload_value("dst_ip")
  def ip_ttl = integer_payload_value("ip_ttl")
  def ip_protocol = integer_payload_value("ip_protocol")
  def ip_protocol_name = payload_value("ip_protocol_name")
  def src_port = integer_payload_value("src_port")
  def dst_port = integer_payload_value("dst_port")
  def transport_protocol = payload_value("transport_protocol")
  def transport_length = integer_payload_value("transport_length")
  def transport_checksum = integer_payload_value("transport_checksum")
  def app_protocol = payload_value("app_protocol")
  def ssdp_message_type = payload_value("ssdp_message_type")
  def ssdp_st = payload_value("ssdp_st")
  def ssdp_mx = payload_value("ssdp_mx")
  def ssdp_usn = payload_value("ssdp_usn")
  def dhcp_requested_ip = payload_value("dhcp_requested_ip")
  def dhcp_hostname = payload_value("dhcp_hostname")
  def dhcp_vendor_class = payload_value("dhcp_vendor_class")
  def dns_query_name = payload_value("dns_query_name")
  def mdns_name = payload_value("mdns_name")
  def session_key = payload_value("session_key")
  def retransmit_key = payload_value("retransmit_key")
  def frame_fingerprint = payload_value("frame_fingerprint")
  def payload_visibility = payload_value("payload_visibility")
  def large_frame = ActiveModel::Type::Boolean.new.cast(payload_value("large_frame"))
  def mixed_encryption = ActiveModel::Type::Boolean.new.cast(payload_value("mixed_encryption"))
  def dedupe_or_replay_suspect = ActiveModel::Type::Boolean.new.cast(payload_value("dedupe_or_replay_suspect"))
  def anomaly_reasons = Array(payload_value("anomaly_reasons")).compact
  def mac_layer = payload_value("mac")
  def rf_layer = payload_value("rf")
  def qos_layer = payload_value("qos")
  def llc_snap_layer = payload_value("llc_snap")
  def network_layer = payload_value("network")
  def transport_layer = payload_value("transport")
  def application_layer = payload_value("application")
  def correlation_layer = payload_value("correlation")
  def anomalies_layer = payload_value("anomalies")
  def username = payload_value("username")
  def raw_frame = payload_value("raw_frame")
  def raw_len = payload_value("raw_len").presence.to_i
  def frame_control_flags = payload_value("frame_control_flags").presence.to_i
  def more_data = ActiveModel::Type::Boolean.new.cast(payload_value("more_data"))
  def retry_flag = ActiveModel::Type::Boolean.new.cast(payload_value("retry"))
  def power_save = ActiveModel::Type::Boolean.new.cast(payload_value("power_save"))
  def protected = ActiveModel::Type::Boolean.new.cast(payload_value("protected"))
  def security_flags = payload_value("security_flags").presence.to_i
  def wps_device_name = payload_value("wps_device_name")
  def wps_manufacturer = payload_value("wps_manufacturer")
  def wps_model_name = payload_value("wps_model_name")
  def device_fingerprint = payload_value("device_fingerprint")
  def handshake_captured = ActiveModel::Type::Boolean.new.cast(payload_value("handshake_captured"))

  def security_labels
    flags = security_flags
    labels = []
    labels << "WPA" if flags & 0x01 != 0
    labels << "RSN/WPA2" if flags & 0x02 != 0
    labels << "WPA3" if flags & 0x04 != 0
    labels << "WPS" if flags & 0x08 != 0
    labels << "PMF required" if flags & 0x10 != 0
    labels
  end

  def compact_security_label
    security_labels.presence&.join(", ")
  end

  def frame_flags_label
    labels = []
    labels << "more data" if more_data
    labels << "retry" if retry_flag
    labels << "power save" if power_save
    labels << "protected" if protected
    labels.presence&.join(", ")
  end

  def protocol_summary
    [app_protocol, transport_protocol, ip_protocol_name].compact.uniq.join(" / ").presence
  end

  def raw_frame_bytes
    return if raw_frame.blank?

    Base64.strict_decode64(raw_frame)
  rescue ArgumentError
    nil
  end

  def raw_frame_hex_dump
    bytes = raw_frame_bytes
    return unless bytes

    bytes.bytes.each_slice(16).with_index.map do |slice, index|
      offset = index * 16
      hex = slice.map { |byte| format("%02x", byte) }.join(" ")
      ascii = slice.map { |byte| byte.between?(32, 126) ? byte.chr : "." }.join
      format("%04x  %-47s  |%s|", offset, hex, ascii)
    end.join("\n")
  end

  # For aggregate query results
  def event_count
    read_attribute(:event_count)
  end

  def avg_signal_dbm
    read_attribute(:avg_signal_dbm)
  end

  private

  def payload_value(key)
    # First check if we already have this attribute loaded directly from SELECT
    if has_attribute?(key)
      value = read_attribute(key)
      return value unless value.nil?
    end
    # Otherwise fall back to extracting from payload jsonb
    payload.is_a?(Hash) ? payload[key] : nil
  end

  def integer_payload_value(key, default: nil)
    value = payload_value(key)
    return default if value.nil? || value == ""

    value.to_i
  end
end
