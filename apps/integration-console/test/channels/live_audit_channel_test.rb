require "test_helper"

class LiveAuditChannelTest < ActionCable::Channel::TestCase
  test "subscribes" do
    subscribe

    assert subscription.confirmed?
    assert_has_stream "live_audit"
  end
end
