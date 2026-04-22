class BacklogController < ApplicationController
  def index
    @status = params[:status].presence
    @entries = BacklogStatus.order(updated_at: :asc).limit(200)
    @entries = @entries.where(status: @status) if @status.present?
  end

  def retry
    result = BacklogRetryService.new(params[:id]).call
    redirect_to backlog_index_path, notice: "Retry published to #{result.subject}"
  rescue ActiveRecord::RecordNotFound
    redirect_to backlog_index_path, alert: "Backlog row was not found"
  rescue StandardError => error
    redirect_to backlog_index_path, alert: "Retry failed: #{error.message}"
  end
end
