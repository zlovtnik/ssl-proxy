class IntegrationRunChannel < ApplicationCable::Channel
  def self.authorized_for_run?(user, run)
    return IntegrationRunPolicy.new(user, run).show? if defined?(IntegrationRunPolicy)
    return run.user == user if user && run.respond_to?(:user)

    Rails.logger.warn("IntegrationRunChannel has no authorization mechanism for run #{run.id}")
    false
  rescue StandardError => error
    Rails.logger.warn("IntegrationRunChannel rejected run #{run.id}: #{error.class} - #{error.message}")
    false
  end

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
    if respond_to?(:authorize, true)
      authorize(run)
      return true
    end

    user = respond_to?(:current_user, true) ? current_user : nil
    self.class.authorized_for_run?(user, run)
  rescue StandardError => error
    Rails.logger.warn("IntegrationRunChannel rejected run #{run.id}: #{error.class} - #{error.message}")
    false
  end
end
