class ShadowItAlertsController < ApplicationController
  SORTS = {
    "last_occurred_at" => :last_occurred_at,
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
    @shadow_it_alerts = apply_sort(@shadow_it_alerts, SORTS, default_sort: :last_occurred_at)
    @shadow_it_alerts = paginate(@shadow_it_alerts)
  end

  def distinct_values
    field = params[:field].to_s
    allowed_fields = %w[source_mac destination_bssid ssid sensor_id location_id reason]
    
    if allowed_fields.include?(field)
      values = Rails.cache.fetch("shadow_it_alerts:distinct:#{field}", expires_in: 60.seconds) do
        ShadowItAlert.where.not(field => nil).distinct.pluck(field).compact.sort.take(100)
      end
      render json: values
    else
      render json: [], status: :bad_request
    end
  end
end
