class IntegrationsController < ApplicationController
  SORTS = {
    "name" => :name,
    "source_type" => :source_type,
    "destination_type" => :destination_type,
    "enabled" => :enabled,
    "updated_at" => :updated_at
  }.freeze

  FILTERS = {
    "name" => :name,
    "slug" => :slug,
    "source_type" => :source_type,
    "destination_type" => :destination_type,
    "stream_name" => :stream_name,
    "enabled" => { column: :enabled, type: :boolean }
  }.freeze

  def index
    integrations = apply_grid_filters(search_scope(IntegrationConfig.all), FILTERS)
    integrations = apply_sort(integrations, SORTS, default_sort: :name, default_direction: :asc)
    rows = paginate(integrations)
    @integrations_page_payload = integrations_page_payload(rows)

    respond_to do |format|
      format.html
      format.json { render json: @integrations_page_payload }
    end
  end

  def show
    integration = IntegrationConfig.find(params[:id])
    @integration_detail_payload = integration_detail_payload(integration)

    respond_to do |format|
      format.html
      format.json { render json: @integration_detail_payload }
    end
  end

  def new
    integration = IntegrationConfig.new(enabled: true, source_type: "nats", destination_type: "postgres")
    @integration_detail_payload = integration_detail_payload(integration, mode: "new")
    render :show
  end

  def create
    integration = IntegrationConfig.new(config_params_with_preserved_secrets)

    if integration.save
      render json: { integration: integration_payload(integration), redirectUrl: integration_path(integration) }, status: :created
    else
      render json: { errors: integration.errors.full_messages, integration: integration_payload(integration) }, status: :unprocessable_entity
    end
  end

  def edit
    show
  end

  def update
    integration = IntegrationConfig.find(params[:id])

    if integration.update(config_params_with_preserved_secrets(integration))
      render json: { integration: integration_payload(integration), redirectUrl: integration_path(integration) }
    else
      render json: { errors: integration.errors.full_messages, integration: integration_payload(integration) }, status: :unprocessable_entity
    end
  end

  def destroy
    integration = IntegrationConfig.find(params[:id])
    integration.update!(enabled: false)

    respond_to do |format|
      format.html { redirect_to integrations_path, notice: "Integration disabled", status: :see_other }
      format.json { render json: { integration: integration_payload(integration) } }
    end
  end

  def trigger
    publish_operator_run("manual")
  end

  def replay
    publish_operator_run("replay")
  end

  def param_types
    render json: { schemas: IntegrationParamSchema::SCHEMAS }
  end

  def lineage
    render json: lineage_payload
  end

  private

  def search_scope(scope)
    query = params[:q].to_s.strip
    return scope if query.blank?

    pattern = "%#{ActiveRecord::Base.sanitize_sql_like(query.downcase)}%"
    scope.where("LOWER(name) LIKE ? OR LOWER(slug) LIKE ? OR LOWER(stream_name) LIKE ?", pattern, pattern, pattern)
  end

  def config_params_with_preserved_secrets(existing = nil)
    attrs = params.require(:integration_config).permit(
      :name,
      :slug,
      :source_type,
      :destination_type,
      :stream_name,
      :enabled,
      :schedule_cron,
      :cursor_field,
      params: {}
    ).to_h
    attrs["params"] = preserved_params(existing, attrs["source_type"], attrs["params"] || {})
    attrs
  end

  def preserved_params(existing, source_type, submitted)
    submitted = submitted.to_h.transform_keys(&:to_s)
    return submitted unless existing

    type = source_type.presence || existing.source_type
    submitted.each_with_object({}) do |(key, value), memo|
      memo[key] = value == "********" && IntegrationParamSchema.sensitive_key?(type, key) ? existing.params.to_h[key] : value
    end
  end

  def build_operator_run(triggered_by)
    integration = IntegrationConfig.find(params[:id])
    run_params = params.fetch(:integration_run, {}).permit(:range_type, :from_value, :to_value, param_overrides: {}).to_h
    overrides = run_params.fetch("param_overrides", {})
    snapshot = integration.combined_params(overrides)
    range_type = run_params["range_type"].presence || "cursor"

    IntegrationRun.create!(
      integration_config: integration,
      triggered_by: triggered_by,
      status: "pending",
      range_type: range_type,
      from_value: normalized_range_value(range_type, run_params["from_value"]),
      to_value: normalized_range_value(range_type, run_params["to_value"]),
      params_snapshot: snapshot
    )
  end

  def publish_operator_run(triggered_by)
    run = build_operator_run(triggered_by)
    publish_run(run)
  rescue ActiveRecord::RecordInvalid => error
    render json: { errors: error.record.errors.full_messages, error: error.record.errors.full_messages.to_sentence }, status: :unprocessable_entity
  end

  def normalized_range_value(range_type, value)
    value = value.to_s.strip
    return nil if value.blank?
    return value unless range_type == "datetime"
    return value if iso8601_datetime?(value)

    Time.zone.parse(value)&.iso8601 || value
  rescue ArgumentError
    value
  end

  def iso8601_datetime?(value)
    Time.iso8601(value)
    true
  rescue ArgumentError
    false
  end

  def publish_run(run)
    IntegrationRunPublisher.new(run).call
    run.broadcast_status
    render json: { run: integration_run_payload(run), redirectUrl: integration_run_path(run) }, status: :created
  rescue StandardError => error
    mark_publish_failed(run, error)
    broadcast_run_status(run)
    render json: { error: "Run could not be published.", run: safe_integration_run_payload(run) }, status: :service_unavailable
  end

  def integrations_page_payload(rows)
    last_runs_by_config = last_runs_for_integrations(rows)
    batches_by_job_id = sync_batches_for_runs(last_runs_by_config.values.compact)

    {
      rows: rows.map do |integration|
        integration_payload_with_run(
          integration,
          last_run: last_runs_by_config[integration.id],
          batches_by_job_id: batches_by_job_id
        )
      end,
      summary: integrations_summary,
      schemas: IntegrationParamSchema::SCHEMAS,
      sortKey: @sort || "name",
      sortDirection: @direction || "asc",
      filters: parsed_grid_filters,
      totalCount: @total_count,
      totalPages: @total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      endpoints: {
        index: integrations_path,
        create: integrations_path,
        paramTypes: param_types_integrations_path(format: :json),
        lineage: lineage_integrations_path(format: :json)
      }
    }
  end

  def integration_detail_payload(integration, mode: "show")
    runs = integration.persisted? ? integration.integration_runs.latest.limit(30).includes(:integration_config).to_a : []
    batches_by_job_id = sync_batches_for_runs(runs)
    last_run = runs.first

    {
      mode: mode,
      integration: integration_payload_with_run(integration, last_run: last_run, batches_by_job_id: batches_by_job_id),
      runs: runs.map { |run| integration_run_payload(run, batches_by_job_id: batches_by_job_id) },
      schemas: IntegrationParamSchema::SCHEMAS,
      lineage: integration.persisted? ? lineage_payload(integration: integration) : empty_lineage_payload,
      endpoints: {
        index: integrations_path,
        create: integrations_path,
        update: integration.persisted? ? integration_path(integration) : nil,
        trigger: integration.persisted? ? trigger_integration_path(integration) : nil,
        replay: integration.persisted? ? replay_integration_path(integration) : nil,
        runs: integration_runs_path
      }
    }
  end

  def integration_payload(integration)
    last_run = integration.persisted? ? integration.integration_runs.latest.first : nil
    integration_payload_with_run(integration, last_run: last_run)
  end

  def integration_payload_with_run(integration, last_run: nil, batches_by_job_id: {})
    {
      id: integration.id,
      name: integration.name,
      slug: integration.slug,
      source_type: integration.source_type,
      destination_type: integration.destination_type,
      stream_name: integration.stream_name,
      enabled: integration.enabled,
      schedule_cron: integration.schedule_cron,
      params: integration.masked_params,
      param_schema: integration.param_schema,
      cursor_field: integration.cursor_field,
      created_at: integration.created_at,
      updated_at: integration.updated_at,
      show_url: integration.persisted? ? integration_path(integration) : nil,
      update_url: integration.persisted? ? integration_path(integration) : nil,
      delete_url: integration.persisted? ? integration_path(integration) : nil,
      trigger_url: integration.persisted? ? trigger_integration_path(integration) : nil,
      replay_url: integration.persisted? ? replay_integration_path(integration) : nil,
      last_run: last_run && integration_run_payload(last_run, batches_by_job_id: batches_by_job_id)
    }
  end

  def integration_run_payload(run, batches_by_job_id: nil)
    batches = batches_by_job_id ? batches_by_job_id.fetch(run.sync_job_id, []) : sync_batches_for(run)
    row_count = 0
    completed_count = 0
    failed_count = 0

    batches.each do |batch|
      rows = batch.row_count.to_i
      row_count += rows
      if batch.status == "completed"
        completed_count += rows
      elsif batch.status == "failed"
        failed_count += rows
      end
    end

    run.stream_payload.merge(
      integration_name: run.integration_config.name,
      integration_slug: run.integration_config.slug,
      sync_job_id: run.sync_job_id,
      rows_read: row_count,
      rows_written: completed_count,
      rows_errored: failed_count,
      batch_count: batches.length,
      show_url: integration_run_path(run)
    )
  end

  def safe_integration_run_payload(run)
    return nil unless run

    integration_run_payload(run)
  rescue StandardError
    {
      id: run.id,
      status: run.status,
      error_summary: run.error_summary,
      created_at: run.created_at,
      finished_at: run.finished_at
    }
  end

  def mark_publish_failed(run, error)
    return unless run&.persisted?

    run.update(status: "failed", error_summary: "Publish failed: #{error.message}", finished_at: Time.current)
  rescue StandardError => update_error
    Rails.logger.warn("Failed to mark integration run #{run.id} failed: #{update_error.class} - #{update_error.message}")
  end

  def broadcast_run_status(run)
    run&.broadcast_status
  rescue StandardError => broadcast_error
    Rails.logger.warn("Failed to broadcast integration run #{run.id} status: #{broadcast_error.class} - #{broadcast_error.message}")
  end

  def sync_batches_for(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.where(job_id: run.sync_job_id).order(:batch_no).to_a
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    []
  end

  def sync_batches_for_runs(runs)
    job_ids = runs.map(&:sync_job_id).compact
    return {} if job_ids.empty?

    SyncBatch.where(job_id: job_ids).order(:batch_no).to_a.group_by(&:job_id)
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    {}
  end

  def last_runs_for_integrations(integrations)
    integration_ids = integrations.map(&:id).compact
    return {} if integration_ids.empty?

    IntegrationRun
      .includes(:integration_config)
      .where(integration_config_id: integration_ids)
      .select("DISTINCT ON (integration_config_id) integration_runs.*")
      .order("integration_config_id, created_at DESC")
      .index_by(&:integration_config_id)
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    {}
  end

  def integrations_summary
    since = 24.hours.ago
    runs = IntegrationRun.where("created_at >= ?", since)
    finished = runs.where.not(started_at: nil).to_a
    avg_duration = finished.filter_map(&:duration_seconds)

    {
      total_enabled: IntegrationConfig.enabled.count,
      runs_24h: runs.count,
      failed_24h: runs.failed.count,
      avg_duration_24h: avg_duration.any? ? (avg_duration.sum / avg_duration.length) : 0
    }
  end

  def lineage_payload(integration: nil)
    configs = integration ? [integration] : IntegrationConfig.enabled.ordered.to_a
    return empty_lineage_payload if configs.empty?

    aggregates = lineage_aggregates(configs)
    nodes = []
    edges = []
    configs.each do |config|
      source_id = "source-#{config.id}"
      stream_id = "stream-#{config.stream_name.presence || config.slug}"
      destination_id = "destination-#{config.id}"
      stats = lineage_stats(config, aggregates)

      nodes << { id: source_id, label: "#{config.source_type} #{config.stream_name.presence || config.slug}", type: "source", event_count_24h: stats[:event_count_24h], last_seen_at: stats[:last_seen_at] }
      nodes << { id: stream_id, label: config.stream_name.presence || "manual stream", type: "store", row_count: stats[:stream_row_count], last_seen_at: stats[:cursor_updated_at] }
      nodes << { id: destination_id, label: config.destination_type, type: "destination", event_count_24h: stats[:completed_runs_24h], last_seen_at: stats[:last_run_at] }
      edges << { from: source_id, to: stream_id, label: "#{stats[:event_count_24h]} rows/24h", status: stats[:health] }
      edges << { from: stream_id, to: destination_id, label: "#{stats[:completed_runs_24h]} runs/24h", status: stats[:health] }
    end

    { nodes: nodes.uniq { |node| node[:id] }, edges: edges }
  end

  def empty_lineage_payload
    { nodes: [], edges: [] }
  end

  def lineage_aggregates(configs)
    since = 24.hours.ago
    streams = configs.filter_map { |config| config.stream_name.presence }
    event_scope = SyncScanIngest.where("observed_at >= ?", since)
    run_counts = IntegrationRun.where("created_at >= ?", since).group(:integration_config_id, :status).count

    {
      event_counts: event_scope.group(:stream_name).count,
      event_last_seen: event_scope.group(:stream_name).maximum(:observed_at),
      total_event_count: event_scope.count,
      total_event_last_seen: event_scope.maximum(:observed_at),
      run_counts: run_counts,
      last_run_at: IntegrationRun.where(integration_config_id: configs.map(&:id)).group(:integration_config_id).maximum(:created_at),
      cursors: streams.empty? ? {} : SyncCursor.where(stream_name: streams).index_by(&:stream_name)
    }
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    nil
  end

  def lineage_stats(config, aggregates)
    return fallback_lineage_stats unless aggregates

    if config.stream_name.present?
      event_count = aggregates[:event_counts].fetch(config.stream_name, 0)
      last_seen_at = aggregates[:event_last_seen][config.stream_name]
      cursor = aggregates[:cursors][config.stream_name]
    else
      event_count = aggregates[:total_event_count]
      last_seen_at = aggregates[:total_event_last_seen]
      cursor = nil
    end

    total_runs = IntegrationRun::STATUSES.sum do |status|
      aggregates[:run_counts].fetch([config.id, status], 0)
    end
    failed_runs = aggregates[:run_counts].fetch([config.id, "failed"], 0)
    failure_rate = total_runs.zero? ? 0 : (failed_runs.to_f / total_runs)
    health =
      if failure_rate > 0.20
        "error"
      elsif failure_rate >= 0.05
        "warn"
      else
        "ok"
      end

    {
      event_count_24h: event_count,
      stream_row_count: event_count,
      completed_runs_24h: aggregates[:run_counts].fetch([config.id, "completed"], 0),
      last_seen_at: last_seen_at,
      cursor_updated_at: cursor&.updated_at,
      last_run_at: aggregates[:last_run_at][config.id],
      health: health
    }
  end

  def fallback_lineage_stats
    {
      event_count_24h: 0,
      stream_row_count: 0,
      completed_runs_24h: 0,
      last_seen_at: nil,
      cursor_updated_at: nil,
      last_run_at: nil,
      health: "warn"
    }
  end
end
