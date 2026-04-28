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

    respond_to do |format|
      format.html { @dashboard_cards_payload = dashboard_cards_payload }
      format.json { render json: dashboard_cards_payload }
    end
  end

  private

  def dashboard_cards_payload
    {
      cards: [
        {
          label: "Active Sensors",
          value: @active_sensors,
          status: @active_sensors.positive? ? "ok" : "neutral",
          trend: "flat",
          trendLabel: "current",
          icon: "sensor",
          sparkline: [@active_sensors]
        },
        {
          label: "Stale Sensors",
          value: @stale_sensors,
          status: @stale_sensors.positive? ? "warn" : "ok",
          trend: @stale_sensors.positive? ? "up" : "flat",
          trendLabel: "#{@stale_sensors} stale",
          icon: "wifi",
          sparkline: [@stale_sensors]
        },
        {
          label: "Backlog Pending / Failed",
          value: "#{@pending_backlog} / #{@failed_backlog}",
          subValue: "#{@failed_backlog} failed",
          status: @failed_backlog.positive? ? "alert" : (@pending_backlog.positive? ? "warn" : "ok"),
          trend: @failed_backlog.positive? ? "up" : "flat",
          trendLabel: "queue depth",
          icon: @failed_backlog.positive? ? "alert" : "backlog",
          sparkline: [@pending_backlog, @failed_backlog]
        }
      ],
      endpoint: root_path
    }
  end
end
