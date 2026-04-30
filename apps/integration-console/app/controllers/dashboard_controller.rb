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
    if request.format.html?
      @sync_health = sync_health_snapshot
      @sync_data_rows = sync_data_rows(@sync_health)
      @sync_relation_rows = SyncPlaneHealth.important_relations
    end
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
        },
        {
          label: "Wireless Events 24h",
          value: counts[:wireless_events_24h],
          subValue: counts[:wireless_last_observed_at]&.to_fs(:db),
          status: counts[:wireless_events_24h].positive? ? "ok" : "neutral",
          trend: "flat",
          trendLabel: "audit volume",
          icon: "wifi",
          sparkline: [counts[:wireless_events_24h]]
        },
        {
          label: "Ingest Pending",
          value: counts[:pending_ingest],
          subValue: "#{counts[:processing_ingest]} processing",
          status: counts[:failed_ingest].positive? ? "alert" : (counts[:pending_ingest].positive? ? "warn" : "ok"),
          trend: counts[:pending_ingest].positive? ? "up" : "flat",
          trendLabel: "#{counts[:failed_ingest]} failed",
          icon: counts[:failed_ingest].positive? ? "alert" : "backlog",
          sparkline: [counts[:pending_ingest], counts[:processing_ingest], counts[:failed_ingest]]
        },
        {
          label: "Open Shadow IT",
          value: counts[:open_shadow_it_alerts],
          subValue: counts[:last_shadow_it_alert_at]&.to_fs(:db),
          status: counts[:open_shadow_it_alerts].positive? ? "alert" : "ok",
          trend: counts[:open_shadow_it_alerts].positive? ? "up" : "flat",
          trendLabel: "unresolved",
          icon: "alert",
          sparkline: [counts[:open_shadow_it_alerts]]
        },
        {
          label: "Job Orphans",
          value: counts[:job_orphans],
          subValue: "#{counts[:job_effective_completed]} completed by batch",
          status: counts[:job_orphans].positive? ? "alert" : "ok",
          trend: counts[:job_orphans].positive? ? "up" : "flat",
          trendLabel: "derived status",
          icon: counts[:job_orphans].positive? ? "alert" : "backlog",
          sparkline: [counts[:job_orphans], counts[:job_effective_running], counts[:job_effective_completed]]
        }
      ],
      counts: counts,
      endpoint: root_path(format: :json)
    }
  end

  def dashboard_counts
    backlog_counts = BacklogStatus.status_counts
    sync_health = sync_health_snapshot

    {
      active_sensors: Sensor.active.count,
      stale_sensors: Sensor.stale.count,
      pending_backlog: backlog_counts[:pending_count],
      failed_backlog: backlog_counts[:failed_count],
      wireless_events_24h: sync_health.wireless_events_24h_count.to_i,
      wireless_last_observed_at: sync_health.wireless_last_observed_at,
      pending_ingest: sync_health.ingest_pending_count.to_i,
      processing_ingest: sync_health.ingest_processing_count.to_i,
      failed_ingest: sync_health.ingest_failed_count.to_i,
      open_shadow_it_alerts: sync_health.open_shadow_it_alert_count.to_i,
      last_shadow_it_alert_at: sync_health.last_shadow_it_alert_at,
      job_orphans: sync_health.job_orphaned_count.to_i,
      job_effective_running: sync_health.job_effective_running_count.to_i,
      job_effective_completed: sync_health.job_effective_completed_count.to_i
    }
  end

  def apply_dashboard_counts(payload)
    counts = payload[:counts] || payload["counts"] || {}
    @active_sensors = (counts[:active_sensors] || counts["active_sensors"]).to_i
    @stale_sensors = (counts[:stale_sensors] || counts["stale_sensors"]).to_i
    @pending_backlog = (counts[:pending_backlog] || counts["pending_backlog"]).to_i
    @failed_backlog = (counts[:failed_backlog] || counts["failed_backlog"]).to_i
  end

  def sync_health_snapshot
    cache_key = "dashboard:sync_plane_health"
    snapshot = SyncPlaneHealth.snapshot
    attributes = snapshot.attributes
    default_attributes = SyncPlaneHealth.from_attributes({}).attributes

    if attributes == default_attributes
      cached_attributes = Rails.cache.read(cache_key)
      attributes = cached_attributes if cached_attributes.present?
    else
      Rails.cache.write(cache_key, attributes, expires_in: IntegrationConsole::CacheTtl.dashboard)
    end

    SyncPlaneHealth.from_attributes(attributes)
  end

  def sync_data_rows(sync_health)
    [
      {
        label: "Wireless ingest",
        source: "sync_scan_ingest",
        value: sync_health.wireless_ingest_total_count.to_i,
        detail: "#{sync_health.wireless_ingest_pending_count.to_i} pending, #{sync_health.wireless_ingest_processing_count.to_i} processing, #{sync_health.wireless_ingest_failed_count.to_i} failed",
        last_seen: sync_health.wireless_last_observed_at
      },
      {
        label: "Oracle batches",
        source: "sync_batch",
        value: sync_health.batch_total_count.to_i,
        detail: "#{sync_health.batch_pending_count.to_i} pending, #{sync_health.batch_dispatched_count.to_i} dispatched, #{sync_health.batch_failed_count.to_i} failed",
        last_seen: nil
      },
      {
        label: "Coordinator jobs",
        source: "sync_job + sync_batch",
        value: sync_health.job_total_count.to_i,
        detail: "#{sync_health.job_effective_running_count.to_i} running, #{sync_health.job_effective_completed_count.to_i} completed, #{sync_health.job_orphaned_count.to_i} orphaned",
        last_seen: nil
      },
      {
        label: "Sensor backlog",
        source: "audit_backlog",
        value: sync_health.backlog_pending_count.to_i,
        detail: "#{sync_health.backlog_failed_count.to_i} failed",
        last_seen: nil
      },
      {
        label: "Shadow IT",
        source: "shadow_it_alerts",
        value: sync_health.open_shadow_it_alert_count.to_i,
        detail: "open alerts",
        last_seen: sync_health.last_shadow_it_alert_at
      },
      {
        label: "Wireless cursor",
        source: "sync_cursor",
        value: sync_health.wireless_cursor_value.presence || "unset",
        detail: "stream wireless.audit",
        last_seen: sync_health.wireless_cursor_updated_at
      }
    ]
  end
end
