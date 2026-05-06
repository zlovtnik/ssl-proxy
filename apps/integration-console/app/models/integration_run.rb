class IntegrationRun < ApplicationRecord
  class InvalidTransitionError < StandardError; end

  STATUSES = %w[pending running completed failed cancelled].freeze
  TRIGGERED_BY = %w[schedule manual replay].freeze
  RANGE_TYPES = %w[cursor datetime].freeze

  attribute :params_snapshot, :json, default: -> { {} }
  encrypts :params_snapshot

  belongs_to :integration_config

  validates :status, inclusion: { in: STATUSES }
  validates :triggered_by, inclusion: { in: TRIGGERED_BY }
  validates :range_type, inclusion: { in: RANGE_TYPES }
  validate :datetime_range_order

  scope :latest, -> { order(created_at: :desc) }
  scope :pending, -> { where(status: "pending") }
  scope :failed, -> { where(status: "failed") }
  scope :for_config, ->(id) { where(integration_config_id: id) }

  def duration_seconds
    return nil unless started_at

    ((finished_at || Time.current) - started_at).to_i
  end

  def cancellable?
    status.in?(%w[pending running])
  end

  def cancel!
    finished_at = Time.current
    rows_affected = self.class.where(id: id, status: %w[pending running]).update_all(
      status: "cancelled",
      finished_at: finished_at,
      updated_at: finished_at
    )
    raise InvalidTransitionError, "Run cannot be cancelled from #{status}" if rows_affected.zero?

    self.status = "cancelled"
    self.finished_at = finished_at
    begin
      broadcast_status
    rescue StandardError => error
      Rails.logger.warn("Failed to broadcast integration run #{id} cancellation: #{error.class} - #{error.message}")
    end
  end

  def stream_payload
    {
      id: id,
      integration_config_id: integration_config_id,
      status: status,
      triggered_by: triggered_by,
      from_value: from_value,
      to_value: to_value,
      duration_seconds: duration_seconds,
      started_at: started_at,
      finished_at: finished_at,
      error_summary: error_summary
    }
  end

  def broadcast_status(batch: nil)
    IntegrationRunBroadcastJob.perform_later(id, batch)
  end

  private

  def datetime_range_order
    return unless range_type == "datetime"
    return if from_value.blank? || to_value.blank?

    from_time = Time.iso8601(from_value)
    to_time = Time.iso8601(to_value)
    errors.add(:base, "from must be before to") unless from_time < to_time
  rescue ArgumentError
    errors.add(:base, "from and to must be valid ISO 8601 datetimes")
  end
end
