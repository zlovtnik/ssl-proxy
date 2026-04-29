class SensorAlert < ApplicationRecord
  after_commit { DashboardCache.expire! }

  validates :sensor_id, :alert_type, :severity, :message, presence: true

  scope :open, -> { where(resolved_at: nil) }
end
