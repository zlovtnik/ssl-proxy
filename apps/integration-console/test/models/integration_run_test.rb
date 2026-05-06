require "test_helper"

class IntegrationRunTest < ActiveSupport::TestCase
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
    @config = IntegrationConfig.create!(
      name: "Wireless Sync",
      source_type: "nats",
      destination_type: "postgres",
      stream_name: "wireless.audit",
      params: { "subject" => "wireless.audit" }
    )
  end

  test "cancels only pending or running runs" do
    run = IntegrationRun.create!(integration_config: @config, status: "pending", triggered_by: "manual")

    run.cancel!

    assert_equal "cancelled", run.reload.status
    assert_not_nil run.finished_at

    running_run = IntegrationRun.create!(integration_config: @config, status: "running", triggered_by: "manual")

    running_run.cancel!

    assert_equal "cancelled", running_run.reload.status
    assert_not_nil running_run.finished_at
  end

  test "rejects cancel from completed run" do
    run = IntegrationRun.create!(integration_config: @config, status: "completed", triggered_by: "manual")

    assert_raises(IntegrationRun::InvalidTransitionError) { run.cancel! }
  end

  test "validates datetime range order" do
    run = IntegrationRun.new(
      integration_config: @config,
      triggered_by: "replay",
      range_type: "datetime",
      from_value: "2026-05-06T12:00:00Z",
      to_value: "2026-05-06T11:00:00Z"
    )

    assert_not run.valid?
    assert_includes run.errors.full_messages.join, "from must be before to"
  end
end
