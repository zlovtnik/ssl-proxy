class HeatmapController < ApplicationController
  SORTS = {
    "location_id" => "location_id",
    "event_count" => "event_count",
    "avg_signal_dbm" => "avg_signal_dbm"
  }.freeze

  def index
    @locations = AuditLog
      .where("payload ? 'location_id'")
      .group("payload->>'location_id'")
      .select("payload->>'location_id' AS location_id, count(*) AS event_count, avg(CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END) AS avg_signal_dbm")
    @locations = apply_sql_sort(@locations, SORTS, default_sort: :event_count)
    @locations = paginate(@locations)
  end
end
