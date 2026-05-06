require "test_helper"

class IntegrationsControllerTest < ActionDispatch::IntegrationTest
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
  end

  test "index renders svelte root and json payload" do
    IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres", stream_name: "wireless.audit")

    get integrations_url

    assert_response :success
    assert_includes response.body, "integrations-svelte-root"

    get integrations_url(format: :json)

    assert_response :success
    assert_equal ["Wireless Sync"], JSON.parse(response.body).fetch("rows").map { |row| row["name"] }
  end

  test "create returns detail redirect" do
    post integrations_url, params: {
      integration_config: {
        name: "Warehouse Sync",
        source_type: "nats",
        destination_type: "postgres",
        stream_name: "wireless.audit",
        params: { subject: "wireless.audit" }
      }
    }, as: :json

    assert_response :created
    payload = JSON.parse(response.body)
    assert_equal "warehouse-sync", payload.dig("integration", "slug")
    assert_match %r{/integrations/}, payload.fetch("redirectUrl")
  end

  test "destroy soft disables integration" do
    config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres")

    delete integration_url(config), as: :json

    assert_response :success
    assert_not config.reload.enabled
  end

  test "trigger creates run and publishes nats request" do
    config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres", stream_name: "wireless.audit")
    publisher = Object.new
    def publisher.call = true

    IntegrationRunPublisher.stub(:new, ->(_run) { publisher }) do
      post trigger_integration_url(config), params: {
        integration_run: {
          range_type: "datetime",
          from_value: "2026-05-06T10:00:00Z",
          to_value: "2026-05-06T11:00:00Z"
        }
      }, as: :json
    end

    assert_response :created
    run = IntegrationRun.last
    assert_equal "manual", run.triggered_by
    assert_equal "2026-05-06T10:00:00Z", run.from_value
  end

  test "trigger accepts browser datetime local values" do
    config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres", stream_name: "wireless.audit")
    publisher = Object.new
    def publisher.call = true

    IntegrationRunPublisher.stub(:new, ->(_run) { publisher }) do
      post trigger_integration_url(config), params: {
        integration_run: {
          range_type: "datetime",
          from_value: "2026-05-06T08:20",
          to_value: "2026-05-06T09:20"
        }
      }, as: :json
    end

    assert_response :created
    run = IntegrationRun.last
    assert_equal Time.utc(2026, 5, 6, 12, 20), run.from_value.to_time.utc
    assert_equal Time.utc(2026, 5, 6, 13, 20), run.to_value.to_time.utc
  end

  test "replay rejects invalid date range" do
    config = IntegrationConfig.create!(name: "Wireless Sync", source_type: "nats", destination_type: "postgres")

    post replay_integration_url(config), params: {
      integration_run: {
        range_type: "datetime",
        from_value: "2026-05-06T12:00:00Z",
        to_value: "2026-05-06T11:00:00Z"
      }
    }, as: :json

    assert_response :unprocessable_entity
    assert_match "from must be before to", response.body
  end

  test "lineage returns empty state" do
    get lineage_integrations_url(format: :json)

    assert_response :success
    assert_equal({ "nodes" => [], "edges" => [] }, JSON.parse(response.body))
  end
end
