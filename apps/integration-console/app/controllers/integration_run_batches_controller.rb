class IntegrationRunBatchesController < ApplicationController
  def index
    run = IntegrationRun.find(params[:integration_run_id])
    render json: {
      run: run.stream_payload,
      batches: batch_payloads(run)
    }
  end

  private

  def batch_payloads(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.includes(:sync_errors).where(job_id: run.sync_job_id).order(:batch_no).map do |batch|
      {
        id: batch.batch_id,
        batch_no: batch.batch_no,
        status: batch.status,
        from_value: batch.cursor_start,
        to_value: batch.cursor_end,
        rows_read: batch.row_count.to_i,
        rows_written: batch.status == "completed" ? batch.row_count.to_i : 0,
        rows_errored: batch.sync_errors&.size.to_i,
        duration_ms: nil,
        error_detail: batch.last_error.presence || batch.sync_errors.map(&:error_text).join("\n").presence,
        created_at: batch.created_at,
        updated_at: batch.updated_at
      }
    end
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    []
  end
end
