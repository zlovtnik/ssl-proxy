class ShadowItAlertsController < ApplicationController
  SORTS = {
    "observed_at" => :observed_at,
    "source_mac" => :source_mac,
    "destination_bssid" => :destination_bssid,
    "ssid" => :ssid,
    "sensor_id" => :sensor_id,
    "location_id" => :location_id,
    "signal_dbm" => :signal_dbm,
    "reason" => :reason,
    "resolved_at" => :resolved_at
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @shadow_it_alerts = ShadowItAlert.recent
    @shadow_it_alerts = @shadow_it_alerts.search(@query) if @query.present?
    @shadow_it_alerts = apply_sort(@shadow_it_alerts, SORTS, default_sort: :observed_at)
    @shadow_it_alerts = paginate(@shadow_it_alerts)
  end
end
