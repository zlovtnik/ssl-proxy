require "test_helper"

class NatsTrafficSampleTest < ActiveSupport::TestCase
  test "increment uses a single sample row" do
    sampled_at = Time.zone.parse("2026-04-22 12:34:56")

    NatsTrafficSample.increment!(subject: "wireless.audit", sensor_id: nil, sampled_at: sampled_at)
    sample = NatsTrafficSample.increment!(subject: "wireless.audit", sensor_id: nil, sampled_at: sampled_at)

    assert_equal 1, NatsTrafficSample.count
    assert_equal "unknown", sample.sensor_id
    assert_equal 2, sample.event_count
    assert_equal sampled_at.change(sec: 0), sample.sampled_at
  end
end
