require "test_helper"

class IntegrationRunsControllerTest < ActionDispatch::IntegrationTest
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
    @config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres")
  end

  test "index renders svelte root and json payload" do
    IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")

    get integration_runs_url

    assert_response :success
    assert_includes response.body, "integration-runs-svelte-root"

    get integration_runs_url(format: :json)

    assert_response :success
    assert_equal ["Wireless Sync"], JSON.parse(response.body).fetch("rows").map { |row| row["integration_name"] }
  end

  test "show renders run detail payload" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")

    get integration_run_url(run)

    assert_response :success
    assert_includes response.body, "integration-run-svelte-root"
  end

  test "cancel transitions pending run" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "pending")

    post cancel_integration_run_url(run), as: :json

    assert_response :success
    assert_equal "cancelled", run.reload.status
  end

  test "cancel rejects completed run" do
    run = IntegrationRun.create!(integration_config: @config, triggered_by: "manual", status: "completed")

    post cancel_integration_run_url(run), as: :json

    assert_response :unprocessable_entity
  end
end
