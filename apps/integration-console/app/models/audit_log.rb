require "base64"

class AuditLog < SyncRecord
  self.table_name = "sync_scan_ingest"
  self.primary_key = "dedupe_key"

  scope :recent, -> { where(stream_name: "wireless.audit").order(observed_at: :desc) }
  scope :search, ->(query) {
    where(
      "payload->>'sensor_id' ILIKE :q OR payload->>'source_mac' ILIKE :q OR payload->>'bssid' ILIKE :q OR payload->>'ssid' ILIKE :q OR payload->>'username' ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }

  def sensor_id = payload_value("sensor_id")
  def location_id = payload_value("location_id")
  def event_type = payload_value("event_type")
  def frame_subtype = payload_value("frame_subtype")
  def source_mac = payload_value("source_mac")
  def bssid = payload_value("bssid")
  def ssid = payload_value("ssid")
  def tsft = payload_value("tsft")
  def signal_dbm = payload_value("signal_dbm")
  def frequency_mhz = payload_value("frequency_mhz")
  def channel_flags = payload_value("channel_flags")
  def data_rate_kbps = payload_value("data_rate_kbps")
  def antenna_id = payload_value("antenna_id")
  def username = payload_value("username")
  def raw_frame = payload_value("raw_frame")

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
    return read_attribute(key) if has_attribute?(key)
    # Otherwise fall back to extracting from payload jsonb
    payload.is_a?(Hash) ? payload[key] : nil
  end
end
