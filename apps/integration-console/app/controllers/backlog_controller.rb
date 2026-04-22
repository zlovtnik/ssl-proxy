class BacklogController < ApplicationController
  SORTS = {
    "dedupe_key" => :dedupe_key,
    "stream_name" => :stream_name,
    "status" => :status,
    "attempt_count" => :attempt_count,
    "updated_at" => :updated_at
  }.freeze

  def index
    @status = params[:status].presence
    @entries = BacklogStatus.all
    @entries = @entries.where(status: @status) if @status.present?
    @entries = apply_sort(@entries, SORTS, default_sort: :updated_at, default_direction: :asc)
    @entries = paginate(@entries)
  end

  def retry
    result = BacklogRetryService.new(params[:id]).call
    redirect_to backlog_index_path, notice: "Retry published to #{result.subject}"
  rescue ActiveRecord::RecordNotFound
    redirect_to backlog_index_path, alert: "Backlog row was not found"
  rescue StandardError => error
    Rails.logger.error("Backlog retry failed: #{error.class} - #{error.message}")
    redirect_to backlog_index_path, alert: "Retry failed. Please try again or contact support."
  end
end
