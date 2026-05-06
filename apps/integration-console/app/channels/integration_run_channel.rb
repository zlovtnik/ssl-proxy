class IntegrationRunChannel < ApplicationCable::Channel
  def subscribed
    return reject unless params[:run_id].present?

    stream_from "integration_run:#{params[:run_id]}"
  end
end
