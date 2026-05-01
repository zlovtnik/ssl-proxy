class ShadowItAlertsController < ApplicationController
  include GridFilterable

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

  FILTERS = {
    "source_mac" => :source_mac,
    "destination_bssid" => :destination_bssid,
    "ssid" => :ssid,
    "sensor_id" => :sensor_id,
    "location_id" => :location_id,
    "reason" => :reason,
    "signal_dbm" => { column: :signal_dbm, type: :number },
    "last_occurred_at" => { column: :last_occurred_at, type: :date },
    "resolved_at" => { column: :resolved_at, type: :date }
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @shadow_it_alerts = ShadowItAlert.recent
    @shadow_it_alerts = @shadow_it_alerts.search(@query) if @query.present?
    @shadow_it_alerts = apply_grid_filters(@shadow_it_alerts, FILTERS)
    @shadow_it_alerts = apply_sort(@shadow_it_alerts, SORTS, default_sort: :last_occurred_at)
    @shadow_it_alerts = paginate(@shadow_it_alerts)
  end

  def distinct_values
    field = params[:field].to_s
    allowed_fields = %w[source_mac destination_bssid ssid sensor_id location_id reason]
    
    if allowed_fields.include?(field)
      values = Rails.cache.fetch("shadow_it_alerts:distinct:#{field}", expires_in: 60.seconds) do
        ShadowItAlert.where.not(field => nil).distinct.order(field).limit(100).pluck(field)
      end
      render json: values
    else
      render json: [], status: :bad_request
    end
  end
end
