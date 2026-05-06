require "test_helper"
require Rails.root.join("db/migrate/20260506000400_seed_frontend_nats_subject_integrations").to_s

class FrontendNatsSubjectSeedTest < ActiveSupport::TestCase
  setup do
    IntegrationRun.delete_all
    IntegrationConfig.delete_all
  end

  test "seed migration creates valid frontend nats subject integrations" do
    SeedFrontendNatsSubjectIntegrations.new.up

    seeded_rows = IntegrationConfig.where(slug: seeded_slugs).order(:slug).to_a

    assert_equal SeedFrontendNatsSubjectIntegrations::SUBJECT_INTEGRATIONS.length, seeded_rows.length
    seeded_rows.each do |config|
      expected = seed_for(config.slug)

      assert_predicate config, :valid?
      assert_match(/\A[a-z0-9-]+\z/, config.slug)
      assert_predicate config, :enabled?
      assert_equal "nats", config.source_type
      assert_equal "postgres", config.destination_type
      assert_equal expected.fetch(:stream_name), config.stream_name
      assert_equal expected.fetch(:subject), config.params.fetch("subject")
    end

    raw_params = IntegrationConfig.connection.select_value(
      "SELECT params FROM integration_configs WHERE slug = #{IntegrationConfig.connection.quote("proxy-payload-audit")}"
    )
    assert_not_nil raw_params
    assert_not_includes raw_params, "proxy.payload_audit"
  end

  test "seed migration is idempotent" do
    2.times { SeedFrontendNatsSubjectIntegrations.new.up }

    assert_equal SeedFrontendNatsSubjectIntegrations::SUBJECT_INTEGRATIONS.length,
      IntegrationConfig.where(slug: seeded_slugs).count
  end

  private

  def seeded_slugs
    SeedFrontendNatsSubjectIntegrations::SUBJECT_INTEGRATIONS.map { |integration| integration.fetch(:slug) }
  end

  def seed_for(slug)
    SeedFrontendNatsSubjectIntegrations::SUBJECT_INTEGRATIONS.find { |integration| integration.fetch(:slug) == slug }
  end
end
