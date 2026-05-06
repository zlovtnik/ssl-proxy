require "test_helper"

class IntegrationRunChannelTest < ActionCable::Channel::TestCase
  test "subscribes to run stream" do
    subscribe run_id: "run-1"

    assert subscription.confirmed?
    assert_has_stream "integration_run:run-1"
  end

  test "rejects missing run id" do
    subscribe

    assert subscription.rejected?
  end
end
