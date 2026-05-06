require "base64"

class AuditLog < SyncRecord
  self.table_name = "sync_scan_ingest"
  self.primary_key = "dedupe_key"

  # Scopes
  scope :wireless, -> { where(stream_name: "wireless.audit") }
  scope :recent, -> { wireless.where("observed_at > ?", 24.hours.ago).order(observed_at: :desc) }
  scope :search, ->(query) {
    sanitized = query.to_s.strip
    sanitized.blank? ? none : where("wireless_search_tsv @@ websearch_to_tsquery('simple', ?)", sanitized)
  }

  # Columns promoted from payload to table columns. If a running database has not
  # applied every promotion migration yet, fall back to the payload value.
  # Accessors such as retry and protected can collide with Ruby keywords or
  # visibility helpers, so callers should prefer public_send(:retry) style calls.
  PROMOTED_COLUMNS = %w[
    schema_version frame_type frame_subtype source_mac bssid destination_bssid
    ssid signal_dbm channel_number fragment_number signal_status adjacent_mac_hint
    qos_tid qos_eosp qos_ack_policy qos_ack_policy_label qos_amsdu
    llc_oui ethertype ethertype_name src_ip dst_ip ip_ttl ip_protocol ip_protocol_name
    src_port dst_port transport_protocol transport_length transport_checksum
    app_protocol ssdp_message_type ssdp_st ssdp_mx ssdp_usn
    dhcp_requested_ip dhcp_hostname dhcp_vendor_class dns_query_name mdns_name
    session_key retransmit_key frame_fingerprint payload_visibility
    tsft_delta_us wall_clock_delta_ms large_frame mixed_encryption dedupe_or_replay_suspect
    raw_len frame_control_flags more_data retry power_save protected
    security_flags wps_device_name wps_manufacturer wps_model_name
    device_fingerprint handshake_captured sensor_id location_id username
  ].freeze

  SECURITY_FLAG_MASKS = {
    "WPA" => 0x01,
    "RSN/WPA2" => 0x02,
    "WPA3" => 0x04,
    "WPS" => 0x08,
    "PMF required" => 0x10
  }.freeze

  INTEGER_PROMOTED_COLUMNS = %w[
    raw_len frame_control_flags security_flags
  ].freeze

  BOOLEAN_PROMOTED_COLUMNS = %w[
    more_data retry power_save protected handshake_captured large_frame dedupe_or_replay_suspect
  ].freeze

  PROMOTED_COLUMNS.each do |field|
    define_method(field) { payload_value(field) }
  end

  # Fields still in payload only (not yet promoted to columns)
  PAYLOAD_ONLY_FIELDS = %w[
    raw_frame tsft frequency_mhz channel_flags data_rate_kbps antenna_id
    transmitter_mac receiver_mac noise_dbm identity_source tags
    qos_tid_label fragment_offset ip_id ip_flags tcp_flags tcp_seq tcp_ack
    udp_length icmp_type icmp_code arp_opcode arp_sender_ip arp_target_ip
    dhcp_message_type dhcp_client_id dhcp_server_id
    ssdp_server ssdp_location ssdp_nt ssdp_nts
    mdns_type mdns_class mdns_ttl
    anomaly_reasons event_type
    mac rf qos llc_snap network transport application correlation anomalies
  ].freeze

  # Accessors for payload-only fields
  PAYLOAD_ONLY_FIELDS.each do |field|
    define_method(field) { payload_value(field) }
  end

  # Special accessors for nested payload structures (layers)
  def mac_layer = payload_value("mac")
  def rf_layer = payload_value("rf")
  def qos_layer = payload_value("qos")
  def llc_snap_layer = payload_value("llc_snap")
  def network_layer = payload_value("network")
  def transport_layer = payload_value("transport")
  def application_layer = payload_value("application")
  def correlation_layer = payload_value("correlation")
  def anomalies_layer = payload_value("anomalies")

  # Special handling for array fields
  def anomaly_reasons
    Array(payload_value("anomaly_reasons")).compact
  end

  # Legacy field still in payload (channel vs channel_number)
  def channel
    payload_value("channel")&.to_i
  end

  def destination_bssid
    payload_value("destination_bssid") || bssid
  end

  def security_labels
    flags = security_flags.to_i
    SECURITY_FLAG_MASKS.filter_map do |label, mask|
      label if flags & mask != 0
    end
  end

  def frame_flags_label
    labels = []
    labels << "more data" if public_send(:more_data)
    labels << "retry" if public_send(:retry)
    labels << "power save" if public_send(:power_save)
    labels << "protected" if public_send(:protected)
    labels.presence&.join(", ")
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
    if PROMOTED_COLUMNS.include?(key)
      return promoted_payload_value(key) unless has_attribute?(key)

      value = read_attribute(key)
      fallback = promoted_payload_value(key)
      return fallback if promoted_column_placeholder?(key, value, fallback)

      return value
    end

    payload.is_a?(Hash) ? payload[key] : nil
  end

  def promoted_payload_value(key)
    payload.is_a?(Hash) ? payload[key] : nil
  end

  def promoted_column_placeholder?(key, value, fallback)
    return false if fallback.nil?
    return true if value.nil?
    return true if value == ""

    if INTEGER_PROMOTED_COLUMNS.include?(key)
      value.to_i.zero? && fallback.to_i.nonzero?
    elsif BOOLEAN_PROMOTED_COLUMNS.include?(key)
      value == false && ActiveModel::Type::Boolean.new.cast(fallback) == true
    else
      false
    end
  end
end
