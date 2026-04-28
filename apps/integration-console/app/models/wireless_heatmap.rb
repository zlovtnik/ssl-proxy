class WirelessHeatmap < SyncRecord
  self.table_name = "mv_wireless_heatmap"
  self.primary_key = "location_id"

  scope :ordered_by_events, -> { order(event_count: :desc) }

  def self.refresh!
    connection.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_wireless_heatmap")
  end
end
