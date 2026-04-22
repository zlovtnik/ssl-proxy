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
  end
end
