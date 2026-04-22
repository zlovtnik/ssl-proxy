require "test_helper"

class NatsSubscriberTest < ActiveSupport::TestCase
  test "wireless audit updates sensor and throughput sample" do
    payload = {
      sensor_id: "00:11:22:33:44:55",
      location_id: "lab",
      interface: "wlan0",
      channel: 11,
      signal_dbm: -42,
      observed_at: Time.current.iso8601
    }.to_json

    assert_difference -> { Sensor.count }, 1 do
      Nats::Subscriber.new.handle("wireless.audit", payload)
    end

    assert_equal 1, NatsTrafficSample.sum(:event_count)
    assert_equal "online", Sensor.find_by!(sensor_id: "00:11:22:33:44:55").status
  end

  test "wireless audit preserves existing sensor location when payload omits it" do
    Sensor.create!(sensor_id: "sensor-1", location_id: "lab")

    payload = {
      sensor_id: "sensor-1",
      interface: "wlan0",
      observed_at: Time.current.iso8601
    }.to_json

    Nats::Subscriber.new.handle("wireless.audit", payload)

    assert_equal "lab", Sensor.find_by!(sensor_id: "sensor-1").location_id
  end
end
