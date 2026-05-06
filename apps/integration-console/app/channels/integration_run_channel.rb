class IntegrationRunChannel < ApplicationCable::Channel
  def subscribed
    return reject unless params[:run_id].present?

    run = IntegrationRun.find_by(id: params[:run_id])
    return reject unless run

    stream_from "integration_run:#{run.id}"
  rescue ActiveRecord::StatementInvalid
    reject
  end
end
