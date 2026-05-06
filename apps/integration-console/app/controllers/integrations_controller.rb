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
    run = build_operator_run("manual")
    publish_run(run)
  end

  def replay
    run = build_operator_run("replay")
    publish_run(run)
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

    IntegrationRun.create!(
      integration_config: integration,
      triggered_by: triggered_by,
      status: "pending",
      range_type: run_params["range_type"].presence || "cursor",
      from_value: run_params["from_value"].presence,
      to_value: run_params["to_value"].presence,
      params_snapshot: snapshot
    )
  end

  def publish_run(run)
    IntegrationRunPublisher.new(run).call
    run.broadcast_status
    render json: { run: integration_run_payload(run), redirectUrl: integration_run_path(run) }, status: :created
  rescue StandardError => error
    run.update!(status: "failed", error_summary: "Publish failed: #{error.message}", finished_at: Time.current) if run&.persisted?
    run&.broadcast_status
    render json: { error: "Run could not be published.", run: run && integration_run_payload(run) }, status: :service_unavailable
  end

  def integrations_page_payload(rows)
    {
      rows: rows.map { |integration| integration_payload(integration) },
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
    {
      mode: mode,
      integration: integration_payload(integration),
      runs: integration.persisted? ? integration.integration_runs.recent.limit(30).map { |run| integration_run_payload(run) } : [],
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
    last_run = integration.persisted? ? integration.integration_runs.recent.first : nil
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
      last_run: last_run && integration_run_payload(last_run)
    }
  end

  def integration_run_payload(run)
    batches = sync_batches_for(run)
    row_count = batches.sum { |batch| batch.row_count.to_i }
    completed_count = batches.select { |batch| batch.status == "completed" }.sum { |batch| batch.row_count.to_i }

    run.stream_payload.merge(
      integration_name: run.integration_config.name,
      integration_slug: run.integration_config.slug,
      sync_job_id: run.sync_job_id,
      rows_read: row_count,
      rows_written: completed_count,
      rows_errored: batches.count { |batch| batch.status == "failed" },
      batch_count: batches.length,
      show_url: integration_run_path(run)
    )
  end

  def sync_batches_for(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.where(job_id: run.sync_job_id).order(:batch_no).to_a
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    []
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

    nodes = []
    edges = []
    configs.each do |config|
      source_id = "source-#{config.id}"
      stream_id = "stream-#{config.stream_name.presence || config.slug}"
      destination_id = "destination-#{config.id}"
      stats = lineage_stats(config)

      nodes << { id: source_id, label: "#{config.source_type} #{config.stream_name.presence || config.slug}", type: "source", event_count_24h: stats[:event_count_24h], last_seen_at: stats[:last_seen_at] }
      nodes << { id: stream_id, label: config.stream_name.presence || "manual stream", type: "store", row_count: stats[:stream_row_count], last_seen_at: stats[:cursor_updated_at] }
      nodes << { id: destination_id, label: config.destination_type, type: "destination", event_count_24h: stats[:completed_rows_24h], last_seen_at: stats[:last_run_at] }
      edges << { from: source_id, to: stream_id, label: "#{stats[:event_count_24h]} rows/24h", status: stats[:health] }
      edges << { from: stream_id, to: destination_id, label: "#{stats[:completed_rows_24h]} rows/24h", status: stats[:health] }
    end

    { nodes: nodes.uniq { |node| node[:id] }, edges: edges }
  end

  def empty_lineage_payload
    { nodes: [], edges: [] }
  end

  def lineage_stats(config)
    event_scope = SyncScanIngest.where("observed_at >= ?", 24.hours.ago)
    event_scope = event_scope.where(stream_name: config.stream_name) if config.stream_name.present?
    cursor = config.stream_name.present? ? SyncCursor.find_by(stream_name: config.stream_name) : nil
    runs = config.integration_runs.where("created_at >= ?", 24.hours.ago)
    total_runs = runs.count
    failed_runs = runs.failed.count
    failure_rate = total_runs.zero? ? 0 : (failed_runs.to_f / total_runs)

    {
      event_count_24h: event_scope.count,
      stream_row_count: event_scope.count,
      completed_rows_24h: runs.where(status: "completed").count,
      last_seen_at: event_scope.maximum(:observed_at),
      cursor_updated_at: cursor&.updated_at,
      last_run_at: config.integration_runs.maximum(:created_at),
      health: failure_rate > 0.20 ? "error" : (failure_rate >= 0.05 ? "warn" : "ok")
    }
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    {
      event_count_24h: 0,
      stream_row_count: 0,
      completed_rows_24h: 0,
      last_seen_at: nil,
      cursor_updated_at: nil,
      last_run_at: nil,
      health: "warn"
    }
  end
end
