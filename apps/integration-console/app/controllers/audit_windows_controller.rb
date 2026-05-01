class AuditWindowsController < ApplicationController
  SORTS = {
    "location_id" => :location_id,
    "timezone" => :timezone,
    "days" => :days,
    "start_time" => :start_time,
    "end_time" => :end_time,
    "enabled" => :enabled
  }.freeze

  FILTERS = {
    "location_id" => :location_id,
    "timezone" => :timezone,
    "days" => :days,
    "start_time" => :start_time,
    "end_time" => :end_time,
    "enabled" => { column: :enabled, type: :boolean }
  }.freeze

  def index
    @audit_windows = apply_grid_filters(AuditWindow.all, FILTERS)
    @audit_windows = apply_sort(@audit_windows, SORTS, default_sort: :location_id, default_direction: :asc)
    @audit_windows_page_payload = audit_windows_page_payload(rows: @audit_windows, mode: "index")

    respond_to do |format|
      format.html
      format.json { render json: @audit_windows_page_payload }
    end
  end

  def new
    @audit_window = AuditWindow.new(enabled: true)
    @audit_windows_page_payload = audit_windows_page_payload(rows: [], mode: "form", audit_window: @audit_window)
  end

  def create
    @audit_window = AuditWindow.new(audit_window_params)
    if save_and_publish(@audit_window)
      respond_to do |format|
        format.html { redirect_to audit_windows_path, notice: "Audit window saved and published", status: :see_other }
        format.json { render json: { auditWindow: audit_window_payload(@audit_window), redirectUrl: audit_windows_path }, status: :created }
      end
    else
      render_audit_window_errors(:new)
    end
  rescue StandardError => error
    handle_publish_failure(error)
    render_audit_window_errors(:new)
  end

  def edit
    @audit_window = AuditWindow.find(params[:id])
    @audit_windows_page_payload = audit_windows_page_payload(rows: [], mode: "form", audit_window: @audit_window)
  end

  def update
    @audit_window = AuditWindow.find(params[:id])
    @audit_window.assign_attributes(audit_window_params)
    if save_and_publish(@audit_window)
      respond_to do |format|
        format.html { redirect_to audit_windows_path, notice: "Audit window updated and published", status: :see_other }
        format.json { render json: { auditWindow: audit_window_payload(@audit_window), redirectUrl: audit_windows_path } }
      end
    else
      render_audit_window_errors(:edit)
    end
  rescue ActiveRecord::RecordNotFound
    raise
  rescue StandardError => error
    handle_publish_failure(error)
    render_audit_window_errors(:edit)
  end

  def destroy
    AuditWindow.find(params[:id]).destroy!
    respond_to do |format|
      format.html { redirect_to audit_windows_path, notice: "Audit window removed", status: :see_other }
      format.json { head :no_content }
    end
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

  def render_audit_window_errors(template)
    @audit_windows_page_payload = audit_windows_page_payload(rows: [], mode: "form", audit_window: @audit_window)
    respond_to do |format|
      format.html { render template, status: :unprocessable_entity }
      format.json { render json: { errors: @audit_window.errors.full_messages, auditWindow: audit_window_payload(@audit_window) }, status: :unprocessable_entity }
    end
  end

  def audit_windows_page_payload(rows:, mode:, audit_window: nil)
    {
      mode: mode,
      rows: rows.map { |row| audit_window_payload(row) },
      current: audit_window && audit_window_payload(audit_window),
      errors: audit_window&.errors&.full_messages || [],
      sortKey: @sort || "location_id",
      sortDirection: @direction || "asc",
      filters: parsed_grid_filters,
      endpoints: {
        index: audit_windows_path,
        create: audit_windows_path
      }
    }
  end

  def audit_window_payload(audit_window)
    {
      id: audit_window.id,
      location_id: audit_window.location_id,
      timezone: audit_window.timezone,
      days: audit_window.days,
      start_time: audit_window.start_time&.strftime("%H:%M"),
      end_time: audit_window.end_time&.strftime("%H:%M"),
      enabled: audit_window.enabled,
      edit_url: audit_window.persisted? ? edit_audit_window_path(audit_window) : nil,
      update_url: audit_window.persisted? ? audit_window_path(audit_window) : nil,
      delete_url: audit_window.persisted? ? audit_window_path(audit_window) : nil
    }
  end
end
