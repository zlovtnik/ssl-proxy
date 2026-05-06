class IntegrationRunsController < ApplicationController
  SORTS = {
    "created_at" => :created_at,
    "status" => :status,
    "triggered_by" => :triggered_by,
    "started_at" => :started_at,
    "finished_at" => :finished_at
  }.freeze

  FILTERS = {
    "status" => :status,
    "triggered_by" => :triggered_by,
    "integration_config_id" => :integration_config_id,
    "created_at" => { column: :created_at, type: :date }
  }.freeze

  def index
    runs = apply_grid_filters(IntegrationRun.includes(:integration_config), FILTERS)
    runs = apply_sort(runs, SORTS, default_sort: :created_at, default_direction: :desc)
    rows = paginate(runs)
    @integration_runs_page_payload = runs_page_payload(rows)

    respond_to do |format|
      format.html
      format.json { render json: @integration_runs_page_payload }
    end
  end

  def show
    run = IntegrationRun.includes(:integration_config).find(params[:id])
    @integration_run_page_payload = run_detail_payload(run)

    respond_to do |format|
      format.html
      format.json { render json: @integration_run_page_payload }
    end
  end

  def cancel
    run = IntegrationRun.find(params[:id])
    run.cancel!
    render json: { run: run_payload(run) }
  end

  private

  def runs_page_payload(rows)
    {
      rows: rows.map { |run| run_payload(run) },
      sortKey: @sort || "created_at",
      sortDirection: @direction || "desc",
      filters: parsed_grid_filters,
      totalCount: @total_count,
      totalPages: @total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      endpoints: {
        index: integration_runs_path
      }
    }
  end

  def run_detail_payload(run)
    {
      run: run_payload(run),
      batches: batch_payloads(run),
      endpoints: {
        index: integration_runs_path,
        cancel: cancel_integration_run_path(run),
        batches: integration_run_batches_path(run)
      }
    }
  end

  def run_payload(run)
    batches = sync_batches_for(run)
    row_count = batches.sum { |batch| batch.row_count.to_i }
    run.stream_payload.merge(
      integration_name: run.integration_config.name,
      integration_slug: run.integration_config.slug,
      integration_url: integration_path(run.integration_config),
      sync_job_id: run.sync_job_id,
      rows_read: row_count,
      rows_written: batches.select { |batch| batch.status == "completed" }.sum { |batch| batch.row_count.to_i },
      rows_errored: batches.count { |batch| batch.status == "failed" },
      batch_count: batches.length,
      batches_completed: batches.count { |batch| batch.status == "completed" },
      batches_failed: batches.count { |batch| batch.status == "failed" },
      show_url: integration_run_path(run),
      cancel_url: run.cancellable? ? cancel_integration_run_path(run) : nil
    )
  end

  def batch_payloads(run)
    sync_batches_for(run).map { |batch| batch_payload(batch) }
  end

  def batch_payload(batch)
    {
      id: batch.batch_id,
      batch_no: batch.batch_no,
      status: batch.status,
      from_value: batch.cursor_start,
      to_value: batch.cursor_end,
      rows_read: batch.row_count.to_i,
      rows_written: batch.status == "completed" ? batch.row_count.to_i : 0,
      rows_errored: batch.status == "failed" ? 1 : 0,
      duration_ms: nil,
      error_detail: batch.last_error.presence || batch.sync_errors.map(&:error_text).join("\n").presence,
      created_at: batch.created_at,
      updated_at: batch.updated_at
    }
  end

  def sync_batches_for(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.includes(:sync_errors).where(job_id: run.sync_job_id).order(:batch_no).to_a
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    []
  end
end
