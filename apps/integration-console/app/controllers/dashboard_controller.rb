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
    @dashboard_cards_payload = DashboardCache.fetch { dashboard_cards_payload }
    apply_dashboard_counts(@dashboard_cards_payload)
    @recent_samples = NatsTrafficSample.recent.group(:subject).sum(:event_count)
    @recent_alerts = SensorAlert.order(created_at: :desc).limit(5)

    respond_to do |format|
      format.html
      format.json do
        ttl = IntegrationConsole::CacheTtl.dashboard
        expires_in ttl, public: true
        if stale?(etag: @dashboard_cards_payload, last_modified: cache_bucket_time(ttl.to_i), public: true)
          render json: @dashboard_cards_payload
        end
      end
    end
  end

  private

  def dashboard_cards_payload
    counts = dashboard_counts

    {
      cards: [
        {
          label: "Active Sensors",
          value: counts[:active_sensors],
          status: counts[:active_sensors].positive? ? "ok" : "neutral",
          trend: "flat",
          trendLabel: "current",
          icon: "sensor",
          sparkline: [counts[:active_sensors]]
        },
        {
          label: "Stale Sensors",
          value: counts[:stale_sensors],
          status: counts[:stale_sensors].positive? ? "warn" : "ok",
          trend: counts[:stale_sensors].positive? ? "up" : "flat",
          trendLabel: "#{counts[:stale_sensors]} stale",
          icon: "wifi",
          sparkline: [counts[:stale_sensors]]
        },
        {
          label: "Backlog Pending / Failed",
          value: "#{counts[:pending_backlog]} / #{counts[:failed_backlog]}",
          subValue: "#{counts[:failed_backlog]} failed",
          status: counts[:failed_backlog].positive? ? "alert" : (counts[:pending_backlog].positive? ? "warn" : "ok"),
          trend: counts[:failed_backlog].positive? ? "up" : "flat",
          trendLabel: "queue depth",
          icon: counts[:failed_backlog].positive? ? "alert" : "backlog",
          sparkline: [counts[:pending_backlog], counts[:failed_backlog]]
        }
      ],
      counts: counts,
      endpoint: root_path(format: :json)
    }
  end

  def dashboard_counts
    backlog_counts = BacklogStatus.status_counts

    {
      active_sensors: Sensor.active.count,
      stale_sensors: Sensor.stale.count,
      pending_backlog: backlog_counts[:pending_count],
      failed_backlog: backlog_counts[:failed_count]
    }
  end

  def apply_dashboard_counts(payload)
    counts = payload[:counts] || payload["counts"] || {}
    @active_sensors = (counts[:active_sensors] || counts["active_sensors"]).to_i
    @stale_sensors = (counts[:stale_sensors] || counts["stale_sensors"]).to_i
    @pending_backlog = (counts[:pending_backlog] || counts["pending_backlog"]).to_i
    @failed_backlog = (counts[:failed_backlog] || counts["failed_backlog"]).to_i
  end
end
