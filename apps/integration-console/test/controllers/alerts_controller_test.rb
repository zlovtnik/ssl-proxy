require "test_helper"

class AlertsControllerTest < ActionDispatch::IntegrationTest
  test "index does not run heartbeat monitor" do
    Sensor.create!(sensor_id: "sensor-1", location_id: "lab", last_seen_at: 10.minutes.ago, status: "online")

    assert_no_difference -> { SensorAlert.count } do
      get alerts_url
    end

    assert_response :success
  end
end
