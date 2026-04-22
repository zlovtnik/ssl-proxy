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
    Rails.logger.error("Backlog retry failed: #{error.class} - #{error.message}")
    redirect_to backlog_index_path, alert: "Retry failed. Please try again or contact support."
  end
end
