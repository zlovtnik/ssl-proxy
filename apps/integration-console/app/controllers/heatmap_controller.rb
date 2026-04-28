class HeatmapController < ApplicationController
  SORTS = {
    "location_id" => "location_id",
    "event_count" => "event_count",
    "avg_signal_dbm" => "avg_signal_dbm",
    "unique_devices" => "unique_devices",
    "last_seen_at" => "last_seen_at"
  }.freeze

  def index
    @locations = WirelessHeatmap.all
    @locations = apply_sql_sort(@locations, SORTS, default_sort: :event_count)
    @locations = paginate(@locations)

    respond_to do |format|
      format.html { @heatmap_payload = heatmap_payload(@locations) }
      format.json { render json: heatmap_payload(@locations) }
    end
  end

  private

  def heatmap_payload(locations)
    {
      rows: locations.map { |location| serialize_location(location) },
      visualLocations: WirelessHeatmap.ordered_by_events.limit(200).map { |location| serialize_location(location) },
      totalCount: @total_count,
      totalPages: @total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      sortKey: @sort,
      sortDirection: @direction,
      endpoints: {
        index: heatmap_index_path
      }
    }
  end

  def serialize_location(location)
    {
      location_id: location.location_id,
      event_count: location.event_count.to_i,
      avg_signal_dbm: location.avg_signal_dbm&.to_f,
      unique_devices: location.unique_devices.to_i,
      last_seen_at: location.last_seen_at&.iso8601
    }
  end
end
