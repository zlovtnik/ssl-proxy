class HealthController < ApplicationController
  def show
    checks = {
      redis: redis_status,
      minio: minio_status,
      heatmap: heatmap_status
    }
    status = checks.values.all? { |check| check[:ok] } ? "ok" : "degraded"

    render json: { status: status, checks: checks }, status: status == "ok" ? :ok : :service_unavailable
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
end
