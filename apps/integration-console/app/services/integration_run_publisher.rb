class IntegrationRunPublisher
  SUBJECT = "sync.scan.request"

  def initialize(run, publisher: Nats::Publisher.new)
    @run = run
    @publisher = publisher
  end

  def call
    @publisher.publish(SUBJECT, payload)
  end

  private

  def payload
    config = @run.integration_config

    {
      integration_run_id: @run.id,
      integration_config_id: config.id,
      stream_name: config.stream_name,
      source_type: config.source_type,
      destination_type: config.destination_type,
      triggered_by: @run.triggered_by,
      range_type: @run.range_type,
      from_value: @run.from_value,
      to_value: @run.to_value,
      params: IntegrationParamSchema.safe_overrides(config.source_type, @run.params_snapshot)
    }.compact
  end
end
