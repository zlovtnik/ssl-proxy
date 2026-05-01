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

  test "sync data endpoint returns async panel payload" do
    snapshot = SyncPlaneHealth.from_attributes({})
    SyncPlaneHealth.stub(:snapshot, snapshot) do
      SyncPlaneHealth.stub(:important_relations, []) do
        get health_sync_data_url(format: :json)
      end
    end

    assert_response :success
    payload = JSON.parse(response.body)
    assert payload.fetch("syncDataRows").any? { |row| row.fetch("label") == "Wireless ingest" }
    assert payload.key?("syncRelationRows")
  end

  test "sensors endpoint paginates and sorts sensor rows" do
    Sensor.delete_all
    2.times do |index|
      Sensor.create!(
        sensor_id: "health-sensor-#{index}",
        location_id: "lab",
        last_seen_at: index.minutes.ago,
        last_signal_dbm: -40 - index,
        status: "online"
      )
    end

    get health_sensors_url(format: :json, sort: "sensor_id", direction: "asc", per_page: 1)

    assert_response :success
    payload = JSON.parse(response.body)
    assert_equal 1, payload.fetch("rows").length
    assert_equal 2, payload.fetch("totalCount")
    assert_equal "sensor_id", payload.fetch("sortKey")
  end

  test "nats samples endpoint returns recent grouped samples" do
    NatsTrafficSample.delete_all
    NatsTrafficSample.create!(
      subject: "wireless.audit",
      sensor_id: "sensor-1",
      sampled_at: Time.current,
      event_count: 2
    )

    get health_nats_samples_url(format: :json)

    assert_response :success
    payload = JSON.parse(response.body)
    assert_equal "wireless.audit", payload.fetch("samples").first.fetch("subject")
  end

  test "recent alerts endpoint returns last five alerts" do
    SensorAlert.delete_all
    6.times do |index|
      SensorAlert.create!(
        sensor_id: "sensor-#{index}",
        alert_type: "heartbeat",
        severity: "pending",
        message: "alert #{index}"
      )
    end

    get health_recent_alerts_url(format: :json)

    assert_response :success
    payload = JSON.parse(response.body)
    assert_equal 5, payload.fetch("alerts").length
    assert_equal "alert 5", payload.fetch("alerts").first.fetch("message")
  end
end
