require "csv"

class AuditLogsController < ApplicationController
  EXPORT_MAX_ROWS = 10_000
  EXPORT_CACHE_TTL = 5.minutes

  around_action :with_audit_statement_timeout, only: %i[index recent]

  SORTS = {
    "observed_at" => "observed_at",
    "schema_version" => "schema_version",
    "sensor_id" => "sensor_id",
    "location_id" => "location_id",
    "frame_type" => "frame_type",
    "frame_subtype" => "frame_subtype",
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

  FILTERS = {
    "observed_at" => { column: "observed_at", type: :date },
    "sensor_id" => "sensor_id",
    "location_id" => "location_id",
    "frame_type" => "frame_type",
    "frame_subtype" => "frame_subtype",
    "ssid" => "ssid",
    "source_mac" => "source_mac",
    "bssid" => "bssid",
    "destination_bssid" => "destination_bssid",
    "signal_dbm" => { column: "signal_dbm", type: :number },
    "channel_number" => { column: "channel_number", type: :number },
    "app_protocol" => "app_protocol",
    "src_ip" => "src_ip",
    "dst_ip" => "dst_ip",
    "raw_len" => { column: "raw_len", type: :number },
    "frame_control_flags" => { column: "frame_control_flags", type: :number },
    "security_flags" => { column: "security_flags", type: :number },
    "device_fingerprint" => "device_fingerprint",
    "handshake_captured" => { column: "handshake_captured", type: :boolean }
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @location_id = params[:location_id].to_s.strip
    @audit_logs = filtered_scope
    @audit_logs = apply_sql_sort(@audit_logs, SORTS, default_sort: :observed_at)
    @audit_logs = paginate(@audit_logs)
    @live_updates = @query.blank? && @location_id.blank? && @current_page == 1 && @sort == "observed_at" && @direction == "desc"

    respond_to do |format|
      format.html { 
        raw_entries = @audit_logs.to_a
        @audit_logs = raw_entries.map { |entry| AuditLogPresenter.new(entry) }
        @audit_log_payload = audit_logs_payload(raw_entries) 
      }
      format.json { render json: audit_logs_payload(@audit_logs) }
    end
  end

  def show
    entry = AuditLog.wireless.find(params[:id])
    @audit_log = AuditLogPresenter.new(entry)
    if entry.session_key.present?
      @related = AuditLog.wireless
        .where(session_key: entry.session_key, location_id: entry.location_id)
        .where("observed_at > ?", 24.hours.ago)
        .order(observed_at: :asc)
        .limit(50)
    end
  end

  def recent
    query = params[:q].to_s.strip
    limit = params[:limit].to_i
    limit = 20 unless limit.positive?
    limit = [limit, 100].min

    if params[:after].blank? && query.blank?
      render_cached_json([], browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
      return
    end

    data = Rails.cache.fetch(recent_cache_key(query: query, after: params[:after], limit: limit), expires_in: IntegrationConsole::CacheTtl.audit_recent) do
      scope = AuditLog.recent

      if params[:after].present?
        after_value = params[:after].to_s
        after = Time.zone.parse(after_value)
        after = after.change(usec: 999_999) unless after_value.match?(/\.\d+/)
        scope = scope.where("observed_at > ?", after) if after
      elsif query.present?
        scope = scope.search(query)
      end

      scope.limit(limit).map { |entry| live_payload(entry) }
    end

    render_cached_json(data, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  rescue ArgumentError
    render_cached_json([], browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  end

  def export
    @query = params[:q].to_s.strip
    @location_id = params[:location_id].to_s.strip
    scope = filtered_scope
    scope = apply_sql_sort(scope, SORTS, default_sort: :observed_at)
    scope = scope.limit(EXPORT_MAX_ROWS)

    key = ExportStore.key_for(type: "audit", query: export_query_key, sort: @sort, direction: @direction)
    url = ExportStore.fetch_or_generate(key: key, ttl: EXPORT_CACHE_TTL, filename: "audit-logs.csv") do
      audit_logs_csv(scope)
    end

    redirect_to url, allow_other_host: true
  end

  private

  def filtered_scope
    scope = AuditLog.recent
    scope = scope.search(@query) if @query.present?
    scope = scope.where(location_id: @location_id) if @location_id.present?
    scope = apply_grid_filters(scope, FILTERS)
    scope
  end

  def audit_logs_csv(scope)
    csv = CSV.generate(headers: true) do |rows|
      rows << [
        "dedupe_key", "observed_at", "schema_version", "sensor_id", "location_id", "frame_type", "frame_subtype",
        "ssid", "source_mac", "destination_bssid", "channel", "channel_number", "signal_dbm",
        "raw_len", "protected", "payload_visibility", "src_ip", "dst_ip", "src_port", "dst_port",
        "app_protocol", "session_key", "frame_fingerprint", "large_frame"
      ]
      scope.each do |entry|
        rows << [
          csv_safe(entry.dedupe_key),
          entry.observed_at&.iso8601,
          entry.schema_version,
          csv_safe(entry.sensor_id),
          csv_safe(entry.location_id),
          csv_safe(entry.frame_type),
          csv_safe(entry.frame_subtype),
          csv_safe(entry.ssid),
          csv_safe(entry.source_mac),
          csv_safe(entry.destination_bssid),
          entry.channel,
          entry.channel_number,
          entry.signal_dbm,
          entry.raw_len,
          entry.public_send(:protected),
          csv_safe(entry.payload_visibility),
          csv_safe(entry.src_ip),
          csv_safe(entry.dst_ip),
          entry.src_port,
          entry.dst_port,
          csv_safe(entry.app_protocol),
          csv_safe(entry.session_key),
          csv_safe(entry.frame_fingerprint),
          entry.large_frame
        ]
      end
    end
    csv
  end

  def csv_safe(value)
    return value unless value.is_a?(String)
    return value unless value.match?(/\A[=+\-@]/)

    "'#{value}"
  end

  def live_payload(entry)
    presenter = AuditLogPresenter.new(entry)
    {
      dedupe_key: entry.dedupe_key,
      show_url: audit_log_path(entry),
      observed_at: entry.observed_at&.iso8601(6),
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
      frame_flags_label: presenter.frame_flags_label,
      more_data: entry.more_data,
      retry: entry.public_send(:retry),
      power_save: entry.power_save,
      protected: entry.public_send(:protected),
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
      security_label: presenter.compact_security_label,
      device_fingerprint: entry.device_fingerprint,
      wps_device_name: entry.wps_device_name,
      handshake_captured: entry.handshake_captured,
      tags: entry.payload.is_a?(Hash) ? Array(entry.payload["tags"]).select { |t| t.is_a?(String) && t.start_with?("threat:") } : []
    }
  end

  def audit_logs_payload(entries)
    {
      rows: entries.map { |entry| live_payload(entry) },
      totalCount: @total_count,
      totalPages: @total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      sortKey: @sort,
      sortDirection: @direction,
      query: @query,
      filters: parsed_grid_filters,
      locationId: @location_id,
      fullMacs: helpers.full_macs_enabled?,
      endpoints: {
        index: audit_logs_path,
        recent: recent_audit_logs_path(format: :json),
        export: export_audit_logs_path
      },
      macOptions: {
        inventoryUrl: inventory_identities_path(format: :json),
        macSummaryUrl: mac_summary_identities_path(format: :json),
        recentAuditLogsUrl: recent_audit_logs_path(format: :json),
        auditLogsUrl: audit_logs_path,
        identitiesUrl: identities_path,
        shadowItUrl: shadow_it_alerts_path
      }
    }
  end

  def recent_cache_key(query:, after:, limit:)
    source = {
      after: after.to_s,
      full_macs: helpers.full_macs_enabled?,
      limit: limit,
      query: query.to_s.downcase
    }.to_json

    "audit_recent:#{Digest::SHA1.hexdigest(source)}"
  end

  def export_query_key
    { q: @query, location_id: @location_id }.to_json
  end

  def with_audit_statement_timeout
    connection = AuditLog.connection
    previous_timeout = connection.select_value("SHOW statement_timeout")
    connection.execute("SET statement_timeout TO '8000ms'")
    yield
  ensure
    connection&.execute("SET statement_timeout TO #{connection.quote(previous_timeout)}") if previous_timeout
  end
end
