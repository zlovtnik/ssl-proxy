class AlertsController < ApplicationController
  SORTS = {
    "created_at" => :created_at,
    "sensor_id" => :sensor_id,
    "alert_type" => :alert_type,
    "severity" => :severity,
    "message" => :message,
    "resolved_at" => :resolved_at
  }.freeze

  def index
    @alerts = SensorAlert.all
    @alerts = apply_sort(@alerts, SORTS, default_sort: :created_at)
    @alerts = paginate(@alerts)

    respond_to do |format|
      format.html
      format.json { render json: alerts_payload }
    end
  end

  private

  def alerts_payload
    {
      rows: @alerts.map { |alert| alert_json(alert) },
      totalCount: @total_count,
      currentPage: @current_page,
      perPage: @per_page
    }
  end

  def alert_json(alert)
    {
      id: alert.id,
      sensor_id: alert.sensor_id,
      alert_type: alert.alert_type,
      severity: alert.severity,
      message: alert.message,
      payload: alert.payload,
      created_at: alert.created_at&.iso8601,
      resolved_at: alert.resolved_at&.iso8601
    }
  end
end
