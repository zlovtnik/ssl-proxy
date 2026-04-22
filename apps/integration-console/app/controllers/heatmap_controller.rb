class HeatmapController < ApplicationController
  def index
    @locations = AuditLog
      .where("payload ? 'location_id'")
      .group("payload->>'location_id'")
      .select("payload->>'location_id' AS location_id, count(*) AS event_count, avg(CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END) AS avg_signal_dbm")
      .order("event_count DESC")
      .limit(50)
  end
end
