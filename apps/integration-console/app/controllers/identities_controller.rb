require "csv"

class IdentitiesController < ApplicationController
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
      format.json { render json: scope.limit(500) }
      format.csv do
        csv = CSV.generate(headers: true) do |rows|
          rows << [
            "source_mac", "location_id", "first_seen", "last_seen", "ssid", "destination_bssid",
            "ip_addresses", "hostnames", "services", "dns_names", "frame_count",
            "protected_frame_count", "open_frame_count"
          ]
          scope.each do |entry|
            rows << [
              entry.source_mac,
              entry.location_id,
              entry.first_seen&.iso8601,
              entry.last_seen&.iso8601,
              entry.ssid,
              entry.destination_bssid,
              entry.ip_addresses,
              entry.hostnames,
              entry.services,
              entry.dns_names,
              entry.frame_count,
              entry.protected_frame_count,
              entry.open_frame_count
            ]
          end
        end

        send_data csv, filename: "wireless-device-inventory-#{Time.zone.now.strftime("%Y%m%d%H%M%S")}.csv", type: "text/csv"
      end
    end
  end
end
