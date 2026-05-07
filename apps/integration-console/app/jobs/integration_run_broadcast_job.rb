class IntegrationRunBroadcastJob < ApplicationJob
  queue_as :default

  def perform(run_id, batch = nil)
    run = IntegrationRun.find(run_id)
    ActionCable.server.broadcast("integration_run:#{run.id}", {
      run: run.stream_payload,
      batch: batch
    })
  rescue ActiveRecord::RecordNotFound
    nil
  end
end
