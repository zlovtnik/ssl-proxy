require "test_helper"

class SensorTest < ActiveSupport::TestCase
  test "mark seen preserves payload fields when observed_at is invalid" do
    sensor = Sensor.create!(sensor_id: "sensor-1", location_id: "old", status: "unknown")

    sensor.mark_seen!(
      "location_id" => "lab",
      "interface" => "wlan0",
      "channel" => 11,
      "signal_dbm" => -42,
      "observed_at" => "not-a-time"
    )

    assert_equal "lab", sensor.location_id
    assert_equal "wlan0", sensor.interface
    assert_equal 11, sensor.channel
    assert_equal(-42, sensor.last_signal_dbm)
    assert_equal "online", sensor.status
    assert sensor.last_seen_at.present?
  end
end
