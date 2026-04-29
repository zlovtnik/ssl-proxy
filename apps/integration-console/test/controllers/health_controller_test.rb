require "test_helper"

class HealthControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
    ensure_wireless_heatmap_materialized_view
    insert_sync_ingest(
      dedupe_key: "health-heatmap",
      observed_at: Time.current,
      payload: {
        "location_id" => "health-lab",
        "signal_dbm" => "-40"
      }
    )
    refresh_wireless_heatmap_materialized_view
  end

  test "health reports redis minio and heatmap status" do
    redis = Object.new
    def redis.ping = "PONG"
    def redis.close = true

    s3 = Object.new
    def s3.head_bucket(bucket:) = true

    Redis.stub(:new, redis) do
      Aws::S3::Client.stub(:new, s3) do
        get health_url(format: :json)
      end
    end

    assert_response :success
    payload = JSON.parse(response.body)
    assert_equal "ok", payload.fetch("status")
    assert payload.dig("checks", "redis", "ok")
    assert payload.dig("checks", "minio", "ok")
    assert payload.dig("checks", "heatmap", "lastRefreshedAt").present?
  end
end
