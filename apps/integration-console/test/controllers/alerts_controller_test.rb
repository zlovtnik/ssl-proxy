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
end
