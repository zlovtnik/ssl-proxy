class DashboardController < ApplicationController
  CACHE_TTL = 30.seconds

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
    @active_sensors = cached_aggregate("dashboard:active_sensors") { Sensor.active.count }
    @stale_sensors = cached_aggregate("dashboard:stale_sensors") { Sensor.stale.count }
    @pending_backlog = cached_aggregate("dashboard:pending_backlog") { BacklogStatus.pending_count }
    @failed_backlog = cached_aggregate("dashboard:failed_backlog") { BacklogStatus.failed_count }
    @recent_samples = cached_aggregate("dashboard:recent_samples") do
      NatsTrafficSample.recent.group(:subject).sum(:event_count)
    end
    @recent_alerts = SensorAlert.order(created_at: :desc).limit(5)
  end

  private

  def cached_aggregate(key, &block)
    return yield unless Rails.cache

    Rails.cache.fetch(key, expires_in: CACHE_TTL, &block)
  rescue Redis::BaseError
    yield
  end
end
