class BacklogController < ApplicationController
  SORTS = {
    "dedupe_key" => :dedupe_key,
    "stream_name" => :stream_name,
    "status" => :status,
    "attempt_count" => :attempt_count,
    "updated_at" => :updated_at
  }.freeze

  FILTERS = {
    "dedupe_key" => :dedupe_key,
    "stream_name" => :stream_name,
    "status" => :status,
    "attempt_count" => { column: :attempt_count, type: :number },
    "updated_at" => { column: :updated_at, type: :date }
  }.freeze

  def index
    @status = params[:status].presence
    @entries = BacklogStatus.all
    @entries = @entries.where(status: @status) if @status.present?
    @entries = apply_grid_filters(@entries, FILTERS)
    @entries = apply_sort(@entries, SORTS, default_sort: :updated_at, default_direction: :asc)
    @entries = paginate(@entries)

    respond_to do |format|
      format.html { @backlog_payload = backlog_payload }
      format.json { render json: backlog_payload }
    end
  end

  def retry
    result = BacklogRetryService.new(params[:id]).call
    respond_to do |format|
      format.html { redirect_to backlog_index_path, notice: "Retry published to #{result.subject}", status: :see_other }
      format.json { render json: { notice: "Retry published to #{result.subject}" } }
    end
  rescue ActiveRecord::RecordNotFound
    respond_to do |format|
      format.html { redirect_to backlog_index_path, alert: "Backlog row was not found", status: :see_other }
      format.json { render json: { error: "Backlog row was not found" }, status: :not_found }
    end
  rescue StandardError => error
    Rails.logger.error("Backlog retry failed: #{error.class} - #{error.message}")
    respond_to do |format|
      format.html { redirect_to backlog_index_path, alert: "Retry failed. Please try again or contact support.", status: :see_other }
      format.json { render json: { error: "Retry failed. Please try again or contact support." }, status: :service_unavailable }
    end
  end

  private

  def backlog_payload
    {
      rows: @entries.map { |entry| backlog_row(entry) },
      status: @status || "",
      totalCount: @total_count,
      totalPages: @total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      sortKey: @sort,
      sortDirection: @direction,
      filters: parsed_grid_filters,
      endpoints: {
        index: backlog_index_path
      }
    }
  end

  def backlog_row(entry)
    {
      id: entry.dedupe_key,
      dedupe_key: entry.dedupe_key,
      stream_name: entry.stream_name,
      status: entry.status,
      attempt_count: entry.attempt_count,
      updated_at: entry.updated_at&.iso8601,
      retry_url: retry_backlog_path(entry.dedupe_key)
    }
  end
end
