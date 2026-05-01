class HealthController < ApplicationController
  around_action :with_health_statement_timeout, only: :sync_data

  SENSOR_SORTS = {
    "sensor_id" => :sensor_id,
    "location_id" => :location_id,
    "last_seen_at" => :last_seen_at,
    "last_signal_dbm" => :last_signal_dbm,
    "status" => :status
  }.freeze

  SENSOR_FILTERS = {
    "sensor_id" => :sensor_id,
    "location_id" => :location_id,
    "last_seen_at" => { column: :last_seen_at, type: :date },
    "last_signal_dbm" => { column: :last_signal_dbm, type: :number },
    "status" => :status
  }.freeze

  def show
    checks = {
      redis: redis_status,
      minio: minio_status,
      heatmap: heatmap_status
    }
    status = checks.values.all? { |check| check[:ok] } ? "ok" : "degraded"

    render json: { status: status, checks: checks }, status: status == "ok" ? :ok : :service_unavailable
  end

  def sync_data
    payload = Rails.cache.fetch("health:sync_data", expires_in: IntegrationConsole::CacheTtl.dashboard) do
      health = SyncPlaneHealth.snapshot
      {
        syncDataRows: sync_data_rows(health),
        syncRelationRows: sync_relation_rows,
        fetchedAt: Time.current.iso8601
      }
    end

    render_cached_json(payload, browser_ttl: IntegrationConsole::CacheTtl.dashboard)
  end

  def sensors
    scope = apply_grid_filters(Sensor.all, SENSOR_FILTERS)
    scope = apply_sort(scope, SENSOR_SORTS, default_sort: :last_seen_at)
    sensors = paginate(scope, per_page: 25)
    payload = {
      rows: sensors.map { |sensor| sensor_payload(sensor) },
      totalCount: @total_count,
      currentPage: @current_page,
      perPage: @per_page,
      sortKey: @sort,
      sortDirection: @direction,
      filters: parsed_grid_filters
    }

    render_cached_json(payload, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  end

  def nats_samples
    payload = Rails.cache.fetch("health:nats_samples", expires_in: IntegrationConsole::CacheTtl.audit_recent) do
      {
        samples: NatsTrafficSample.recent.group(:subject).sum(:event_count).map do |subject, count|
          { subject: subject, eventCount: count }
        end,
        fetchedAt: Time.current.iso8601
      }
    end

    render_cached_json(payload, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  end

  def recent_alerts
    payload = Rails.cache.fetch("health:recent_alerts", expires_in: IntegrationConsole::CacheTtl.audit_recent) do
      {
        alerts: SensorAlert.order(created_at: :desc).limit(5).map do |alert|
          {
            id: alert.id,
            message: alert.message,
            severity: alert.severity,
            statusClass: helpers.status_class(alert.severity),
            createdAt: alert.created_at&.iso8601
          }
        end,
        fetchedAt: Time.current.iso8601
      }
    end

    render_cached_json(payload, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  end

  private

  def redis_status
    redis = Redis.new(url: ENV.fetch("INTEGRATION_CONSOLE_REDIS_URL", "redis://127.0.0.1:6379/1"))
    pong = redis.ping
    { ok: pong == "PONG", message: pong }
  rescue StandardError => error
    { ok: false, message: error.message }
  ensure
    redis&.close
  end

  def minio_status
    Aws::S3::Client.new.head_bucket(bucket: IntegrationConsole::Minio.bucket)
    { ok: true, bucket: IntegrationConsole::Minio.bucket }
  rescue StandardError => error
    { ok: false, bucket: IntegrationConsole::Minio.bucket, message: error.message }
  end

  def heatmap_status
    last_refreshed_at = WirelessHeatmap.last_refreshed_at
    {
      ok: true,
      lastRefreshedAt: last_refreshed_at&.iso8601,
      staleSeconds: last_refreshed_at ? (Time.current - last_refreshed_at).to_i : nil
    }
  rescue StandardError => error
    { ok: false, message: error.message }
  end

  def sync_data_rows(sync_health)
    [
      {
        label: "Wireless ingest",
        source: "sync_scan_ingest",
        value: sync_health.wireless_ingest_total_count.to_i,
        detail: "#{sync_health.wireless_ingest_pending_count.to_i} pending, #{sync_health.wireless_ingest_processing_count.to_i} processing, #{sync_health.wireless_ingest_failed_count.to_i} failed",
        lastSeen: sync_health.wireless_last_observed_at&.to_fs(:db)
      },
      {
        label: "Oracle batches",
        source: "sync_batch",
        value: sync_health.batch_total_count.to_i,
        detail: "#{sync_health.batch_pending_count.to_i} pending, #{sync_health.batch_dispatched_count.to_i} dispatched, #{sync_health.batch_failed_count.to_i} failed",
        lastSeen: nil
      },
      {
        label: "Coordinator jobs",
        source: "sync_job + sync_batch",
        value: sync_health.job_total_count.to_i,
        detail: "#{sync_health.job_effective_running_count.to_i} running, #{sync_health.job_effective_completed_count.to_i} completed, #{sync_health.job_orphaned_count.to_i} orphaned",
        lastSeen: nil
      },
      {
        label: "Sensor backlog",
        source: "audit_backlog",
        value: sync_health.backlog_pending_count.to_i,
        detail: "#{sync_health.backlog_failed_count.to_i} failed",
        lastSeen: nil
      },
      {
        label: "Shadow IT",
        source: "shadow_it_alerts",
        value: sync_health.open_shadow_it_alert_count.to_i,
        detail: "open alerts",
        lastSeen: sync_health.last_shadow_it_alert_at&.to_fs(:db)
      },
      {
        label: "Wireless cursor",
        source: "sync_cursor",
        value: sync_health.wireless_cursor_value.presence || "unset",
        detail: "stream wireless.audit",
        lastSeen: sync_health.wireless_cursor_updated_at&.to_fs(:db)
      }
    ]
  end

  def sync_relation_rows
    SyncPlaneHealth.important_relations.map do |row|
      {
        name: row[:name],
        kind: row[:kind],
        role: row[:role],
        estimatedRows: row[:estimated_rows],
        totalSize: row[:total_size]
      }
    end
  end

  def sensor_payload(sensor)
    {
      sensorId: sensor.sensor_id,
      locationId: sensor.location_id,
      lastSeenAt: sensor.last_seen_at&.to_fs(:db),
      lastSignalDbm: sensor.last_signal_dbm,
      status: sensor.status
    }
  end

  def with_health_statement_timeout
    connection = ActiveRecord::Base.connection
    previous_timeout = connection.select_value("SHOW statement_timeout")
    connection.execute("SET statement_timeout TO '8000ms'")
    yield
  ensure
    connection&.execute("SET statement_timeout TO #{connection.quote(previous_timeout)}") if previous_timeout
  end
end
