class HeatmapController < ApplicationController
  SORTS = {
    "location_id" => "location_id",
    "event_count" => "event_count",
    "avg_signal_dbm" => "avg_signal_dbm"
  }.freeze

  def index
    @locations = heatmap_scope
    @locations = apply_sql_sort(@locations, SORTS, default_sort: :event_count)
    @locations = paginate(@locations)
  end

  private

  def heatmap_scope
    # Prefer the pre-aggregated materialized view when available
    if materialized_view_available?("mv_wireless_audit_hourly_summary")
      return hourly_summary_scope
    end

    fallback_scope
  end

  def hourly_summary_scope
    WirelessAuditHourlySummary
      .where(hour: 24.hours.ago..)
      .group(:location_id)
      .select(
        "location_id, " \
        "SUM(frame_count) AS event_count, " \
        "ROUND(AVG(avg_signal_dbm))::integer AS avg_signal_dbm"
      )
  end

  def fallback_scope
    AuditLog
      .where("payload ? 'location_id'")
      .where(observed_at: 24.hours.ago..)
      .group("payload->>'location_id'")
      .select(
        "payload->>'location_id' AS location_id, " \
        "count(*) AS event_count, " \
        "avg(CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END) AS avg_signal_dbm"
      )
  end

  def materialized_view_available?(name)
    ActiveRecord::Base.connection.table_exists?(name)
  rescue ActiveRecord::StatementInvalid
    false
  end
end
