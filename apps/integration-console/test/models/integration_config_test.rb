require "test_helper"

class IntegrationConfigTest < ActiveSupport::TestCase
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
  end

  test "generates and validates slug" do
    config = IntegrationConfig.create!(
      name: "Warehouse Sync",
      source_type: "nats",
      destination_type: "postgres",
      params: { "url" => "nats://127.0.0.1:4222" }
    )

    assert_equal "warehouse-sync", config.slug
    assert_predicate config, :enabled
  end

  test "validates params against registered schema" do
    config = IntegrationConfig.new(
      name: "Bad",
      source_type: "http",
      destination_type: "postgres",
      params: { "method" => "PATCH" }
    )

    assert_not config.valid?
    assert_includes config.errors.full_messages.join, "method must be one of"
  end

  test "encrypts params at rest" do
    config = IntegrationConfig.create!(
      name: "Secret Sync",
      source_type: "postgres",
      destination_type: "http",
      params: { "url" => "postgres://secret@example/db" }
    )

    raw = IntegrationConfig.connection.select_value(
      "SELECT params FROM integration_configs WHERE id = #{IntegrationConfig.connection.quote(config.id)}"
    )

    assert_equal "postgres://secret@example/db", config.reload.params.fetch("url")
    assert_not_includes raw, "postgres://secret@example/db"
  end
end
