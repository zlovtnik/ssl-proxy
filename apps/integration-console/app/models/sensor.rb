class Sensor < ApplicationRecord
  STALE_AFTER = 5.minutes

  validates :sensor_id, presence: true, uniqueness: true
  validates :location_id, presence: true

  scope :active, -> { where("last_seen_at >= ?", STALE_AFTER.ago) }
  scope :stale, -> { where("last_seen_at IS NULL OR last_seen_at < ?", STALE_AFTER.ago) }

  def mark_seen!(payload)
    update!(
      location_id: payload["location_id"].presence || location_id,
      interface: payload["interface"].presence || interface,
      channel: payload["channel"].presence || channel,
      last_signal_dbm: payload["signal_dbm"].presence || last_signal_dbm,
      last_seen_at: Time.zone.parse(payload["observed_at"].to_s) || Time.current,
      status: "online"
    )
  rescue ArgumentError
    update!(last_seen_at: Time.current, status: "online")
  end

  def stale?
    last_seen_at.blank? || last_seen_at < STALE_AFTER.ago
  end
end
