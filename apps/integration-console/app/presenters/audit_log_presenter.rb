require "base64"

class AuditLogPresenter
  def initialize(entry)
    @entry = entry
  end

  def security_labels
    flags = @entry.security_flags
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
    labels << "more data" if @entry.more_data
    labels << "retry" if @entry.retry
    labels << "power save" if @entry.power_save
    labels << "protected" if @entry.protected
    labels.presence&.join(", ")
  end

  def protocol_summary
    [
      @entry.app_protocol,
      @entry.transport_protocol,
      @entry.ip_protocol_name
    ].compact.uniq.join(" / ").presence
  end

  def raw_frame_bytes
    return if @entry.raw_frame.blank?

    Base64.strict_decode64(@entry.raw_frame)
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

  # Delegate all data access methods to the entry
  delegate :dedupe_key, :observed_at, :sensor_id, :location_id, :event_type,
           :channel, :frame_type, :frame_subtype, :source_mac, :bssid,
           :destination_bssid, :ssid, :signal_dbm, :channel_number,
           :app_protocol, :session_key, :frame_fingerprint, :device_fingerprint,
           :wps_device_name, :wps_manufacturer, :wps_model_name,
           :handshake_captured, :more_data, :retry, :power_save, :protected,
           :security_flags, :raw_len, :frame_control_flags, :large_frame,
           :src_ip, :dst_ip, :src_port, :dst_port, :transport_protocol,
           :ip_protocol_name, :payload_visibility, :raw_frame, :schema_version,
           to: :@entry
end
