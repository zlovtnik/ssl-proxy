class SensorAlert < ApplicationRecord
  ALLOWED_PAYLOAD_KEYS = %w[
    sensor_id
    location_id
    interface
    bssid
    client_mac
    source_mac
    destination_bssid
    ssid
    signal_dbm
    observed_at
    frame_subtype
    reason
    tags
  ].freeze

  after_commit { DashboardCache.expire! }

  validates :sensor_id, :alert_type, :severity, :message, presence: true

  scope :open, -> { where(resolved_at: nil) }

  def self.sanitize_payload(payload)
    return {} unless payload.respond_to?(:to_h)

    payload.to_h.each_with_object({}) do |(key, value), sanitized|
      key = key.to_s
      next unless ALLOWED_PAYLOAD_KEYS.include?(key)
      next if value.nil?

      sanitized[key] = key == "tags" ? Array(value).select { |tag| tag.is_a?(String) } : value
    end
  end
end
