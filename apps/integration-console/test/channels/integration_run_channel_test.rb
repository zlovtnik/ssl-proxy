require "test_helper"

class IntegrationRunChannelTest < ActionCable::Channel::TestCase
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
    @config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres")
  end

  test "rejects run stream without authorization path" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")

    subscribe run_id: run.id

    assert subscription.rejected?
  end

  test "subscribes to run stream when policy allows" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")
    previous_policy = Object.const_get(:IntegrationRunPolicy) if defined?(IntegrationRunPolicy)
    policy = Class.new do
      def initialize(_user, _run); end
      def show? = true
    end
    Object.send(:remove_const, :IntegrationRunPolicy) if defined?(IntegrationRunPolicy)
    Object.const_set(:IntegrationRunPolicy, policy)

    subscribe run_id: run.id

    assert subscription.confirmed?
    assert_has_stream "integration_run:#{run.id}"
  ensure
    Object.send(:remove_const, :IntegrationRunPolicy) if defined?(IntegrationRunPolicy)
    Object.const_set(:IntegrationRunPolicy, previous_policy) if defined?(previous_policy) && previous_policy
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
