class IdentitiesController < ApplicationController
  SORTS = {
    "observed_at" => :observed_at,
    "source_mac" => :source_mac,
    "bssid" => :bssid,
    "ssid" => :ssid,
    "username" => :username,
    "registered_username" => :registered_username,
    "display_name" => :display_name
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @identities = WirelessAuditIdentity.recent
    @identities = @identities.search(@query) if @query.present?
    @identities = apply_sort(@identities, SORTS, default_sort: :observed_at)
    @identities = paginate(@identities)
  end
end
