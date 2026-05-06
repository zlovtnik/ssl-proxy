class IntegrationRunChannel < ApplicationCable::Channel
  def subscribed
    return reject unless params[:run_id].present?

    run = IntegrationRun.find_by(id: params[:run_id])
    return reject unless run
    return reject unless authorized_for_run?(run)

    stream_from "integration_run:#{run.id}"
  rescue ActiveRecord::StatementInvalid
    reject
  end

  private

  def authorized_for_run?(run)
    return authorize(run) if respond_to?(:authorize, true)

    user = respond_to?(:current_user, true) ? current_user : nil
    return IntegrationRunPolicy.new(user, run).show? if defined?(IntegrationRunPolicy)
    return run.user == user if user && run.respond_to?(:user)

    true
  end
end
