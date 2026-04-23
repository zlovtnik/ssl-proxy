class DashboardController < ApplicationController
  SENSOR_SORTS = {
    "sensor_id" => :sensor_id,
    "location_id" => :location_id,
    "last_seen_at" => :last_seen_at,
    "last_signal_dbm" => :last_signal_dbm,
    "status" => :status
  }.freeze

  def index
    @sensors = Sensor.all
    @sensors = apply_sort(@sensors, SENSOR_SORTS, default_sort: :last_seen_at)
    @sensors = paginate(@sensors, per_page: 25)
    @active_sensors = Sensor.active.count
    @stale_sensors = Sensor.stale.count
    @pending_backlog = BacklogStatus.pending_count
    @failed_backlog = BacklogStatus.failed_count
    @recent_samples = NatsTrafficSample.recent.group(:subject).sum(:event_count)
    @recent_alerts = SensorAlert.order(created_at: :desc).limit(5)
  end
end
