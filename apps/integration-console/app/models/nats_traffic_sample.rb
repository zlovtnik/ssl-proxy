class NatsTrafficSample < ApplicationRecord
  validates :subject, presence: true
  validates :sampled_at, presence: true
  validates :event_count, numericality: { greater_than_or_equal_to: 0 }

  scope :recent, -> { where("sampled_at >= ?", 5.minutes.ago) }

  def self.increment!(subject:, sensor_id:, sampled_at: Time.current)
    timestamp = sampled_at.change(sec: 0)
    sample = find_or_initialize_by(subject: subject, sensor_id: sensor_id, sampled_at: timestamp)
    sample.event_count ||= 0
    sample.event_count += 1
    sample.save!
    sample
  end
end
