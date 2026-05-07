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
    @integration_runs_page_payload = runs_page_payload(rows, sync_batches_by_job(rows))

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

  def runs_page_payload(rows, batches_by_job = {})
    {
      rows: rows.map { |run| run_payload(run, batches_by_job: batches_by_job) },
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
    batches = sync_batches_for(run)
    {
      run: run_payload(run, batches_by_job: { run.sync_job_id => batches }),
      batches: batch_payloads(run, batches),
      endpoints: {
        index: integration_runs_path,
        cancel: cancel_integration_run_path(run),
        batches: integration_run_batches_path(run)
      }
    }
  end

  def run_payload(run, batches_by_job: nil)
    batches = batches_by_job ? batches_by_job.fetch(run.sync_job_id, []) : sync_batches_for(run)
    row_count = 0
    rows_written = 0
    rows_errored = 0
    batch_count = 0
    batches_completed = 0
    batches_failed = 0

    batches.each do |batch|
      rows = batch.row_count.to_i
      row_count += rows
      batch_count += 1
      if batch.status == "completed"
        rows_written += rows
        batches_completed += 1
      elsif batch.status == "failed"
        rows_errored += rows
        batches_failed += 1
      end
    end

    run.stream_payload.merge(
      integration_name: run.integration_config.name,
      integration_slug: run.integration_config.slug,
      integration_url: integration_path(run.integration_config),
      sync_job_id: run.sync_job_id,
      rows_read: row_count,
      rows_written: rows_written,
      rows_errored: rows_errored,
      batch_count: batch_count,
      batches_completed: batches_completed,
      batches_failed: batches_failed,
      show_url: integration_run_path(run),
      cancel_url: run.cancellable? ? cancel_integration_run_path(run) : nil
    )
  end

  def batch_payloads(run, batches = nil)
    (batches || sync_batches_for(run)).map { |batch| SyncBatchPayload.call(batch) }
  end

  def sync_batches_for(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.includes(:sync_errors).where(job_id: run.sync_job_id).order(:batch_no).to_a
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished => e
    Rails.logger.error("Failed to fetch sync batches for job #{run.sync_job_id}: #{e.class} - #{e.message}")
    Rails.logger.error(e.backtrace.join("\n")) if e.backtrace.present?
    []
  end

  def sync_batches_by_job(rows)
    job_ids = rows.map(&:sync_job_id).compact
    return {} if job_ids.empty?

    SyncBatch.includes(:sync_errors).where(job_id: job_ids).order(:batch_no).to_a.group_by(&:job_id)
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished => e
    Rails.logger.error("Failed to preload sync batches: #{e.class} - #{e.message}")
    Rails.logger.error(e.backtrace.join("\n")) if e.backtrace.present?
    {}
  end
end
