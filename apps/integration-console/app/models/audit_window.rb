class AuditWindow < ApplicationRecord
  VALID_DAY = /\A(mon|tue|wed|thu|fri|sat|sun)(,(mon|tue|wed|thu|fri|sat|sun))*\z/

  validates :location_id, presence: true, uniqueness: true
  validates :timezone, presence: true
  validates :days, format: { with: VALID_DAY, allow_blank: true }

  def payload
    {
      location_id: location_id,
      timezone: timezone,
      days: days,
      start_time: start_time&.strftime("%H:%M:%S"),
      end_time: end_time&.strftime("%H:%M:%S"),
      enabled: enabled
    }.compact
  end
end
