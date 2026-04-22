class AuditLogsController < ApplicationController
  SORTS = {
    "observed_at" => "observed_at",
    "sensor_id" => "payload->>'sensor_id'",
    "location_id" => "payload->>'location_id'",
    "frame_subtype" => "payload->>'frame_subtype'",
    "ssid" => "ssid",
    "source_mac" => "source_mac",
    "bssid" => "bssid",
    "destination_bssid" => "destination_bssid",
    "signal_dbm" => "signal_dbm",
    "raw_len" => "raw_len",
    "frame_control_flags" => "frame_control_flags",
    "security_flags" => "security_flags",
    "device_fingerprint" => "device_fingerprint",
    "handshake_captured" => "handshake_captured"
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @audit_logs = AuditLog.recent
    @audit_logs = @audit_logs.search(@query) if @query.present?
    @audit_logs = apply_sql_sort(@audit_logs, SORTS, default_sort: :observed_at)
    @audit_logs = paginate(@audit_logs)
    @live_updates = @query.blank? && @current_page == 1 && @sort == "observed_at" && @direction == "desc"
  end

  def show
    @audit_log = AuditLog.recent.find(params[:id])
  end

  def recent
    scope = AuditLog.recent
    if params[:after].present?
      after = Time.zone.parse(params[:after].to_s)
      scope = scope.where("observed_at > ?", after) if after
    end

    limit = params[:limit].to_i
    limit = 20 unless limit.positive?
    limit = [limit, 100].min

    render json: scope.limit(limit).map { |entry| live_payload(entry) }
  rescue ArgumentError
    render json: []
  end

  private

  def live_payload(entry)
    {
      dedupe_key: entry.dedupe_key,
      show_url: audit_log_path(entry),
      observed_at: entry.observed_at&.iso8601,
      sensor_id: entry.sensor_id,
      location_id: entry.location_id,
      frame_subtype: entry.frame_subtype,
      event_type: entry.event_type,
      ssid: entry.ssid,
      source_mac: entry.source_mac,
      source_mac_display: helpers.display_mac(entry.source_mac),
      bssid: entry.bssid,
      bssid_display: helpers.display_mac(entry.bssid),
      destination_bssid: entry.destination_bssid,
      destination_bssid_display: helpers.display_mac(entry.destination_bssid),
      signal_dbm: entry.signal_dbm,
      antenna_id: entry.antenna_id,
      raw_len: entry.raw_len,
      frame_control_flags: entry.frame_control_flags,
      frame_flags_label: entry.frame_flags_label,
      more_data: entry.more_data,
      retry: entry.retry,
      power_save: entry.power_save,
      protected: entry.protected,
      security_flags: entry.security_flags,
      security_label: entry.compact_security_label,
      device_fingerprint: entry.device_fingerprint,
      wps_device_name: entry.wps_device_name,
      handshake_captured: entry.handshake_captured
    }
  end
end
