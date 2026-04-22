class DashboardController < ApplicationController
  def index
    @sensors = Sensor.order(last_seen_at: :desc).limit(50)
    @active_sensors = Sensor.active.count
    @stale_sensors = Sensor.stale.count
    @pending_backlog = BacklogStatus.pending_count
    @failed_backlog = BacklogStatus.failed_count
    @recent_samples = NatsTrafficSample.recent.group(:subject).sum(:event_count)
    @recent_alerts = SensorAlert.order(created_at: :desc).limit(5)
  end
end
