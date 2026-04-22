class AuditWindowsController < ApplicationController
  def index
    @audit_windows = AuditWindow.order(:location_id)
  end

  def new
    @audit_window = AuditWindow.new(enabled: true)
  end

  def create
    @audit_window = AuditWindow.new(audit_window_params)
    if @audit_window.save
      AuditWindowPublisher.new(@audit_window).call
      redirect_to audit_windows_path, notice: "Audit window saved and published"
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
    @audit_window = AuditWindow.find(params[:id])
  end

  def update
    @audit_window = AuditWindow.find(params[:id])
    if @audit_window.update(audit_window_params)
      AuditWindowPublisher.new(@audit_window).call
      redirect_to audit_windows_path, notice: "Audit window updated and published"
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    AuditWindow.find(params[:id]).destroy!
    redirect_to audit_windows_path, notice: "Audit window removed"
  end

  private

  def audit_window_params
    params.require(:audit_window).permit(:location_id, :timezone, :days, :start_time, :end_time, :enabled)
  end
end
