require "test_helper"

class SensorHeartbeatMonitorTest < ActiveSupport::TestCase
  test "creates missing heartbeat alert for stale sensor" do
    Sensor.create!(sensor_id: "sensor-1", location_id: "lab", last_seen_at: 10.minutes.ago, status: "online")

    assert_difference -> { SensorAlert.count }, 1 do
      SensorHeartbeatMonitor.new.call
    end

    assert_equal "stale", Sensor.find_by!(sensor_id: "sensor-1").status
    assert_equal "Sensor sensor-1 has not reported for more than 5 minutes", SensorAlert.last.message
  end
end
