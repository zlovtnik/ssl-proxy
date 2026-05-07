class IntegrationRunBatchesController < ApplicationController
  def index
    run = IntegrationRun.find(params[:integration_run_id])
    return head :forbidden unless IntegrationRunChannel.authorized_for_run?(current_user, run)

    render json: {
      run: run.stream_payload,
      batches: batch_payloads(run)
    }
  end

  private

  def batch_payloads(run)
    return [] if run.sync_job_id.blank?

    SyncBatch.includes(:sync_errors).where(job_id: run.sync_job_id).order(:batch_no).map { |batch| SyncBatchPayload.call(batch) }
  rescue ActiveRecord::StatementInvalid, ActiveRecord::ConnectionNotEstablished
    []
  end
end
