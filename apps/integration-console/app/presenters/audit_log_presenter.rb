require "base64"

class AuditLogPresenter
  ENTRY_DELEGATES = (
    %i[dedupe_key observed_at channel event_count avg_signal_dbm] +
    AuditLog::PROMOTED_COLUMNS.map(&:to_sym) +
    AuditLog::PAYLOAD_ONLY_FIELDS.map(&:to_sym)
  ).uniq.freeze

  def initialize(entry)
    @entry = entry
  end

  def security_labels
    flags = @entry.security_flags.to_i
    AuditLog::SECURITY_FLAG_MASKS.filter_map do |label, mask|
      label if flags & mask != 0
    end
  end

  def compact_security_label
    security_labels.presence&.join(", ")
  end

  def frame_flags_label
    labels = []
    labels << "more data" if @entry.public_send(:more_data)
    labels << "retry" if @entry.public_send(:retry)
    labels << "power save" if @entry.public_send(:power_save)
    labels << "protected" if @entry.public_send(:protected)
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

  delegate(*ENTRY_DELEGATES, to: :@entry)
end
