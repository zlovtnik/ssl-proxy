require "csv"

class IdentitiesController < ApplicationController
  EXPORT_MAX_ROWS = 10_000
  EXPORT_CACHE_TTL = 2.minutes

  SORTS = {
    "observed_at" => :observed_at,
    "source_mac" => :source_mac,
    "bssid" => :bssid,
    "destination_bssid" => :destination_bssid,
    "ssid" => :ssid,
    "signal_dbm" => :signal_dbm,
    "username" => :username,
    "registered_username" => :registered_username,
    "display_name" => :display_name,
    "device_fingerprint" => :device_fingerprint,
    "wps_device_name" => :wps_device_name
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @identities = WirelessAuditIdentity.recent
    @identities = @identities.search(@query) if @query.present?
    @identities = apply_sort(@identities, SORTS, default_sort: :observed_at)
    @identities = paginate(@identities)
  end

  def inventory
    @query = params[:q].to_s.strip
    scope = WirelessDeviceInventory.recent
    scope = scope.search(@query) if @query.present?

    respond_to do |format|
      format.json do
        data = Rails.cache.fetch(inventory_cache_key(@query), expires_in: IntegrationConsole::CacheTtl.inventory) do
          scope.limit(500).to_a
        end
        render_cached_json(data, browser_ttl: IntegrationConsole::CacheTtl.audit_recent)
      end
      format.csv do
        key = ExportStore.key_for(type: "inventory", query: @query, sort: "last_seen", direction: "desc")
        url = ExportStore.fetch_or_generate(key: key, ttl: EXPORT_CACHE_TTL) do
          inventory_csv(scope.limit(EXPORT_MAX_ROWS))
        end

        redirect_to url, allow_other_host: true
      end
    end
  end

  private

  def inventory_cache_key(query)
    "inventory:#{Digest::SHA1.hexdigest(query.to_s.strip.downcase)}"
  end

  def inventory_csv(scope)
    CSV.generate(headers: true) do |rows|
      rows << [
        "source_mac", "location_id", "first_seen", "last_seen", "ssid", "destination_bssid",
        "ip_addresses", "hostnames", "services", "dns_names", "frame_count",
        "protected_frame_count", "open_frame_count"
      ]
      scope.each do |entry|
        rows << [
          csv_safe(entry.source_mac),
          csv_safe(entry.location_id),
          entry.first_seen&.iso8601,
          entry.last_seen&.iso8601,
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
