require "csv"

class AuditLogsController < ApplicationController
  EXPORT_MAX_ROWS = 10_000

  SORTS = {
    "observed_at" => "observed_at",
    "schema_version" => "schema_version",
    "sensor_id" => "payload->>'sensor_id'",
    "location_id" => "payload->>'location_id'",
    "frame_type" => "frame_type",
    "frame_subtype" => "payload->>'frame_subtype'",
    "ssid" => "ssid",
    "source_mac" => "source_mac",
    "bssid" => "bssid",
    "destination_bssid" => "destination_bssid",
    "signal_dbm" => "signal_dbm",
    "channel_number" => "channel_number",
    "app_protocol" => "app_protocol",
    "src_ip" => "src_ip",
    "dst_ip" => "dst_ip",
    "raw_len" => "raw_len",
    "frame_control_flags" => "frame_control_flags",
    "security_flags" => "security_flags",
    "device_fingerprint" => "device_fingerprint",
    "handshake_captured" => "handshake_captured"
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @audit_logs = filtered_scope
    @audit_logs = apply_sql_sort(@audit_logs, SORTS, default_sort: :observed_at)
    @audit_logs = paginate(@audit_logs)
    @live_updates = @query.blank? && @current_page == 1 && @sort == "observed_at" && @direction == "desc"
  end

  def show
    @audit_log = AuditLog.recent.find(params[:id])
  end

  def recent
    scope = AuditLog.recent
    query = params[:q].to_s.strip
    scope = scope.search(query) if query.present?

    if params[:after].present?
      after = Time.zone.parse(params[:after].to_s)
      scope = scope.where("observed_at > ?", after) if after
    else
      # Default to last hour for live-updates endpoint to prevent unbounded scans
      scope = scope.where("observed_at > ?", 1.hour.ago)
    end

    limit = params[:limit].to_i
    limit = 20 unless limit.positive?
    limit = [limit, 100].min

    render json: scope.limit(limit).map { |entry| live_payload(entry) }
  rescue ArgumentError
    render json: []
  end

  def export
    @query = params[:q].to_s.strip
    scope = filtered_scope
    scope = apply_sql_sort(scope, SORTS, default_sort: :observed_at)
    scope = scope.limit(EXPORT_MAX_ROWS)

    csv = CSV.generate(headers: true) do |rows|
      rows << [
        "dedupe_key", "observed_at", "schema_version", "sensor_id", "location_id", "frame_type", "frame_subtype",
        "ssid", "source_mac", "destination_bssid", "channel", "channel_number", "signal_dbm",
        "raw_len", "protected", "payload_visibility", "src_ip", "dst_ip", "src_port", "dst_port",
        "app_protocol", "session_key", "frame_fingerprint", "large_frame"
      ]
      scope.each do |entry|
        rows << [
          entry.dedupe_key,
          entry.observed_at&.iso8601,
          entry.schema_version,
          entry.sensor_id,
          entry.location_id,
          entry.frame_type,
          entry.frame_subtype,
          entry.ssid,
          entry.source_mac,
          entry.destination_bssid,
          entry.channel,
          entry.channel_number,
          entry.signal_dbm,
          entry.raw_len,
          entry.protected,
          entry.payload_visibility,
          entry.src_ip,
          entry.dst_ip,
          entry.src_port,
          entry.dst_port,
          entry.app_protocol,
          entry.session_key,
          entry.frame_fingerprint,
          entry.large_frame
        ]
      end
    end

    send_data csv, filename: "wireless-audit-#{Time.zone.now.strftime("%Y%m%d%H%M%S")}.csv", type: "text/csv"
  end

  private

  def filtered_scope
    scope = AuditLog.recent
    scope = scope.search(@query) if @query.present?
    scope
  end

  def live_payload(entry)
    {
      dedupe_key: entry.dedupe_key,
      show_url: audit_log_path(entry),
      observed_at: entry.observed_at&.iso8601,
      schema_version: entry.schema_version,
      sensor_id: entry.sensor_id,
      location_id: entry.location_id,
      frame_type: entry.frame_type,
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
      channel_number: entry.channel_number,
      antenna_id: entry.antenna_id,
      raw_len: entry.raw_len,
      frame_control_flags: entry.frame_control_flags,
      frame_flags_label: entry.frame_flags_label,
      more_data: entry.more_data,
      retry: entry.retry_flag,
      power_save: entry.power_save,
      protected: entry.protected,
      payload_visibility: entry.payload_visibility,
      src_ip: entry.src_ip,
      dst_ip: entry.dst_ip,
      src_port: entry.src_port,
      dst_port: entry.dst_port,
      app_protocol: entry.app_protocol,
      session_key: entry.session_key,
      frame_fingerprint: entry.frame_fingerprint,
      large_frame: entry.large_frame,
      security_flags: entry.security_flags,
      security_label: entry.compact_security_label,
      device_fingerprint: entry.device_fingerprint,
      wps_device_name: entry.wps_device_name,
      handshake_captured: entry.handshake_captured
    }
  end
end
