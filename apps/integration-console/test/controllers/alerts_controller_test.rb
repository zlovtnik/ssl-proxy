require "test_helper"

class AlertsControllerTest < ActionDispatch::IntegrationTest
  setup do
    Sensor.delete_all
    SensorAlert.delete_all
  end

  test "index does not run heartbeat monitor" do
    Sensor.create!(sensor_id: "sensor-1", location_id: "lab", last_seen_at: 10.minutes.ago, status: "online")

    assert_no_difference -> { SensorAlert.count } do
      get alerts_url
    end

    assert_response :success
  end

  test "index paginates alerts" do
    51.times do |index|
      SensorAlert.create!(
        sensor_id: format("sensor-%02d", index),
        alert_type: "offline",
        severity: "critical",
        message: format("alert-%02d", index),
        created_at: index.minutes.ago
      )
    end

    get alerts_url(page: 2)

    assert_response :success
    assert_includes response.body, "alert-50"
    assert_includes response.body, "Page 2 of 2"
  end

  test "index json includes persisted alert payload" do
    SensorAlert.create!(
      sensor_id: "sensor-1",
      alert_type: "handshake_captured",
      severity: "critical",
      message: "handshake alert",
      payload: {
        "tags" => ["threat:harvest"],
        "bssid" => "10:20:30:40:50:60"
      }
    )

    get alerts_url(format: :json)

    assert_response :success
    payload = JSON.parse(response.body)
    row = payload.fetch("rows").first
    assert_equal "handshake alert", row.fetch("message")
    assert_equal ["threat:harvest"], row.fetch("payload").fetch("tags")
    assert_equal "10:20:30:40:50:60", row.fetch("payload").fetch("bssid")
  end
end
