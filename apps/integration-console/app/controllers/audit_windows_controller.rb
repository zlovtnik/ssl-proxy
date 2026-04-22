class AuditWindowsController < ApplicationController
  def index
    @audit_windows = AuditWindow.order(:location_id)
  end

  def new
    @audit_window = AuditWindow.new(enabled: true)
  end

  def create
    @audit_window = AuditWindow.new(audit_window_params)
    if save_and_publish(@audit_window)
      redirect_to audit_windows_path, notice: "Audit window saved and published"
    else
      render :new, status: :unprocessable_entity
    end
  rescue StandardError => error
    handle_publish_failure(error)
    render :new, status: :unprocessable_entity
  end

  def edit
    @audit_window = AuditWindow.find(params[:id])
  end

  def update
    @audit_window = AuditWindow.find(params[:id])
    @audit_window.assign_attributes(audit_window_params)
    if save_and_publish(@audit_window)
      redirect_to audit_windows_path, notice: "Audit window updated and published"
    else
      render :edit, status: :unprocessable_entity
    end
  rescue ActiveRecord::RecordNotFound
    raise
  rescue StandardError => error
    handle_publish_failure(error)
    render :edit, status: :unprocessable_entity
  end

  def destroy
    AuditWindow.find(params[:id]).destroy!
    redirect_to audit_windows_path, notice: "Audit window removed"
  end

  private

  def audit_window_params
    params.require(:audit_window).permit(:location_id, :timezone, :days, :start_time, :end_time, :enabled)
  end

  def save_and_publish(audit_window)
    return false unless audit_window.valid?

    ActiveRecord::Base.transaction do
      audit_window.save!
      AuditWindowPublisher.new(audit_window).call
    end
    true
  end

  def handle_publish_failure(error)
    Rails.logger.error("Audit window publish failed: #{error.class} - #{error.message}")
    @audit_window.errors.add(:base, "could not be published")
  end
end
