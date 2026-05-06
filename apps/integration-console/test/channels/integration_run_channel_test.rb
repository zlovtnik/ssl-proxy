require "test_helper"

class IntegrationRunChannelTest < ActionCable::Channel::TestCase
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
    @config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres")
  end

  test "subscribes to run stream" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")

    subscribe run_id: run.id

    assert subscription.confirmed?
    assert_has_stream "integration_run:#{run.id}"
  end

  test "rejects missing run id" do
    subscribe

    assert subscription.rejected?
  end

  test "rejects unknown run id" do
    subscribe run_id: SecureRandom.uuid

    assert subscription.rejected?
  end
end
