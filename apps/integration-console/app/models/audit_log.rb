require "base64"

class AuditLog < SyncRecord
  self.table_name = "sync_scan_ingest"
  self.primary_key = "dedupe_key"

  scope :recent, -> { where(stream_name: "wireless.audit").order(observed_at: :desc) }
  scope :search, ->(query) {
    where(
      "payload->>'sensor_id' ILIKE :q OR payload->>'source_mac' ILIKE :q OR payload->>'bssid' ILIKE :q OR payload->>'ssid' ILIKE :q OR payload->>'username' ILIKE :q OR device_fingerprint ILIKE :q OR wps_device_name ILIKE :q OR wps_manufacturer ILIKE :q OR wps_model_name ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }

  def sensor_id = payload_value("sensor_id")
  def location_id = payload_value("location_id")
  def event_type = payload_value("event_type")
  def frame_subtype = payload_value("frame_subtype")
  def source_mac = payload_value("source_mac")
  def bssid = payload_value("bssid")
  def destination_bssid = payload_value("destination_bssid") || bssid
  def ssid = payload_value("ssid")
  def tsft = payload_value("tsft")
  def signal_dbm = payload_value("signal_dbm")
  def frequency_mhz = payload_value("frequency_mhz")
  def channel_flags = payload_value("channel_flags")
  def data_rate_kbps = payload_value("data_rate_kbps")
  def antenna_id = payload_value("antenna_id")
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
end
