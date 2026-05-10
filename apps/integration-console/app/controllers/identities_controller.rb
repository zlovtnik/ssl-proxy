require "csv"

class IdentitiesController < ApplicationController
  include GridFilterable

  EXPORT_MAX_ROWS = 10_000
  EXPORT_CACHE_TTL = 2.minutes

  SORTS = {
    "source_mac" => :source_mac,
    "destination_bssid" => :destination_bssid,
    "ssid" => :ssid,
    "location_id" => :location_id,
    "registered_username" => :registered_username,
    "display_name" => :display_name,
    "signal_dbm" => :signal_dbm,
    "first_occurred_at" => :first_occurred_at,
    "last_occurred_at" => :last_occurred_at
  }.freeze

  FILTERS = {
    "source_mac" => :source_mac,
    "location_id" => :location_id,
    "ssid" => :ssid,
    "destination_bssid" => :destination_bssid,
    "registered_username" => :registered_username,
    "display_name" => :display_name,
    "ip_addresses" => :ip_addresses,
    "hostnames" => :hostnames,
    "services" => :services,
    "dns_names" => :dns_names,
    "frame_count" => { column: :frame_count, type: :number },
    "protected_frame_count" => { column: :protected_frame_count, type: :number },
    "open_frame_count" => { column: :open_frame_count, type: :number },
    "first_occurred_at" => { column: :first_occurred_at, type: :date },
    "last_occurred_at" => { column: :last_occurred_at, type: :date }
  }.freeze

  def index
    @query = params[:q].to_s.strip
    scope = WirelessDeviceInventory.recent
    scope = scope.search(@query) if @query.present?
    scope = apply_grid_filters(scope, FILTERS)
    scope = apply_sort(scope, SORTS, default_sort: :last_occurred_at)
    @identities = paginate(scope)

    @inventory_query_parameters = @query.present? ? { q: @query } : {}

    respond_to do |format|
      format.html {
        @identities = @identities.to_a
      }
      format.json {
        render json: {
          rows: @identities.as_json(
            only: %i[source_mac bssid destination_bssid ssid signal_dbm location_id username registered_username
                     display_name device_id wps_device_name wps_model_name device_fingerprint
                     first_occurred_at last_occurred_at]
          ),
          totalCount: @total_count,
          currentPage: @current_page,
          perPage: @per_page,
          sortKey: @sort,
          sortDirection: @direction,
          filters: parsed_grid_filters,
          query: @query,
          endpoints: {
            index: identities_path
          }
        }
      }
    end
  end

  def inventory
    @query = params[:q].to_s.strip
    scope = WirelessDeviceInventory.recent
    scope = scope.search(@query) if @query.present?
    scope = apply_grid_filters(scope, FILTERS)

    respond_to do |format|
      format.json do
        inventory_cache_key = inventory_cache_key(@query, parsed_grid_filters)
        data = Rails.cache.fetch(inventory_cache_key, expires_in: IntegrationConsole::CacheTtl.inventory) do
          scope.limit(500).to_a
        end
        render_cached_json(data, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
      end
      format.csv do
        key = ExportStore.key_for(type: "inventory", query: @query, filters: parsed_grid_filters, sort: "last_occurred_at", direction: "desc")
        url = ExportStore.fetch_or_generate(key: key, ttl: EXPORT_CACHE_TTL, filename: "wireless-inventory.csv") do
          inventory_csv(scope.limit(EXPORT_MAX_ROWS))
        end

        redirect_to url, allow_other_host: true
      end
    end
  end

  def mac_summary
    query = params[:q].to_s.strip
    if query.blank?
      render_cached_json({ mac: "", device: nil, inventory: nil, recentAuditLogs: [] }, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
      return
    end

    render_cached_json(mac_summary_payload(query), browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
  end

  def distinct_values
    field = params[:field].to_s
    allowed_fields = FILTERS.keys.map(&:to_s)
    
    if allowed_fields.include?(field)
      values = Rails.cache.fetch("identities:distinct:#{field}", expires_in: 60.seconds) do
        WirelessDeviceInventory.where.not(field => nil).distinct.order(field).limit(100).pluck(field).compact
      end
      render json: values
    else
      render json: [], status: :bad_request
    end
  end

  private

  def mac_summary_payload(query)
    normalized = Device.normalize_mac(query)
    lookup = normalized || query.downcase
    device = device_for_mac(lookup)
    logs = recent_logs_for_mac(lookup).limit(25).to_a

    {
      mac: normalized || query,
      device: device && device_payload(device),
      inventory: inventory_from_logs(logs),
      recentAuditLogs: logs.map { |entry| audit_summary_payload(entry) }
    }
  end

  def device_for_mac(lookup)
    return if lookup.blank?

    if lookup.include?(":") && lookup.split(":").length == 6
      Device.where("lower(mac_hint) = ?", lookup.downcase).first
    else
      Device.where("lower(mac_hint) LIKE ?", "%#{Device.sanitize_sql_like(lookup.downcase)}%").first
    end
  end

  def recent_logs_for_mac(lookup)
    scope = AuditLog.recent
    if lookup.include?(":") && lookup.split(":").length == 6
      scope.where(
        "lower(source_mac) = :mac OR lower(bssid) = :mac OR lower(destination_bssid) = :mac",
        mac: lookup.downcase
      )
    else
      pattern = "%#{AuditLog.sanitize_sql_like(lookup.downcase)}%"
      scope.where(
        "lower(source_mac) LIKE :q OR lower(bssid) LIKE :q OR lower(destination_bssid) LIKE :q",
        q: pattern
      )
    end
  end

  def device_payload(device)
    {
      device_id: device.mac_id,
      mac_id: device.mac_id,
      display_name: device.display_name,
      username: device.username,
      hostname: device.hostname,
      os_hint: device.os_hint,
      mac_hint: device.mac_hint,
      notes: device.notes
    }
  end

  def inventory_from_logs(logs)
    return if logs.blank?

    signals = logs.map(&:signal_dbm).compact
    {
      source_mac: logs.filter_map(&:source_mac).first,
      location_id: logs.filter_map(&:location_id).first,
      first_seen: logs.map(&:observed_at).compact.min&.iso8601(6),
      last_seen: logs.map(&:observed_at).compact.max&.iso8601(6),
      first_occurred_at: logs.map(&:observed_at).compact.min&.iso8601(6),
      last_occurred_at: logs.map(&:observed_at).compact.max&.iso8601(6),
      ssid: logs.filter_map(&:ssid).first,
      destination_bssid: logs.filter_map(&:destination_bssid).first,
      ip_addresses: logs.flat_map { |entry| [entry.src_ip, entry.dst_ip] }.compact.uniq.first(5).join(", "),
      hostnames: logs.filter_map(&:dhcp_hostname).uniq.first(5).join(", "),
      services: logs.filter_map(&:app_protocol).uniq.first(5).join(", "),
      frame_count: logs.length,
      protected_frame_count: logs.count { |entry| entry.public_send(:protected) },
      open_frame_count: logs.count { |entry| !entry.public_send(:protected) },
      signal_min: signals.min,
      signal_max: signals.max
    }
  end

  def audit_summary_payload(entry)
    {
      dedupe_key: entry.dedupe_key,
      observed_at: entry.observed_at&.iso8601(6),
      signal_dbm: entry.signal_dbm,
      session_key: entry.session_key,
      ssid: entry.ssid,
      source_mac: entry.source_mac,
      destination_bssid: entry.destination_bssid,
      app_protocol: entry.app_protocol
    }
  end

  def inventory_cache_key(query, filters)
    filter_hash = Digest::SHA1.hexdigest(filters.to_json)
    "inventory:#{Digest::SHA1.hexdigest(query.to_s.strip.downcase)}:#{filter_hash}"
  end

  def inventory_csv(scope)
    CSV.generate(headers: true) do |rows|
      rows << [
        "source_mac", "location_id", "first_occurred_at", "last_occurred_at", "ssid", "destination_bssid",
        "ip_addresses", "hostnames", "services", "dns_names", "frame_count",
        "protected_frame_count", "open_frame_count"
      ]
      scope.each do |entry|
        rows << [
          csv_safe(entry.source_mac),
          csv_safe(entry.location_id),
          entry.first_occurred_at&.iso8601,
          entry.last_occurred_at&.iso8601,
          csv_safe(entry.ssid),
          csv_safe(entry.destination_bssid),
          csv_safe(entry.ip_addresses),
          csv_safe(entry.hostnames),
          csv_safe(entry.services),
          csv_safe(entry.dns_names),
          entry.frame_count,
          entry.protected_frame_count,
          entry.open_frame_count
        ]
      end
    end
  end

  def csv_safe(value)
    return value unless value.is_a?(String)
    return value unless value.match?(/\A[=+\-@]/)

    "'#{value}"
  end
end