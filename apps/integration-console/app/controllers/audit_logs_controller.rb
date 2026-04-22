class AuditLogsController < ApplicationController
  SORTS = {
    "observed_at" => "observed_at",
    "sensor_id" => "payload->>'sensor_id'",
    "location_id" => "payload->>'location_id'",
    "frame_subtype" => "payload->>'frame_subtype'",
    "ssid" => "payload->>'ssid'",
    "source_mac" => "payload->>'source_mac'",
    "signal_dbm" => "CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END"
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @audit_logs = AuditLog.recent
    @audit_logs = @audit_logs.search(@query) if @query.present?
    @audit_logs = apply_sql_sort(@audit_logs, SORTS, default_sort: :observed_at)
    @audit_logs = paginate(@audit_logs)
  end
end
