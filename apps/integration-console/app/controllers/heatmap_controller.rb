class HeatmapController < ApplicationController
  LocationView = Struct.new(:location_id, :event_count, :avg_signal_dbm, :unique_devices, :last_seen_at, keyword_init: true)

  SORTS = {
    "location_id" => "location_id",
    "event_count" => "event_count",
    "avg_signal_dbm" => "avg_signal_dbm",
    "unique_devices" => "unique_devices",
    "last_seen_at" => "last_seen_at"
  }.freeze

  def index
    @heatmap_payload = Rails.cache.fetch(heatmap_cache_key, expires_in: IntegrationConsole::CacheTtl.heatmap) do
      heatmap_payload
    end
    apply_pagination_state(@heatmap_payload)
    @locations = location_views(@heatmap_payload[:rows])

    respond_to do |format|
      format.html
      format.json do
        response.headers["Cache-Control"] = "public, s-maxage=300"
        if @heatmap_payload[:lastRefreshedAt].present?
          response.headers["Last-Modified"] = Time.zone.parse(@heatmap_payload[:lastRefreshedAt]).httpdate
        end
        render json: @heatmap_payload
      end
    end
  end

  private

  def heatmap_payload
    rows = heatmap_rows
    total_count = rows.first&.fetch("total_count", 0).to_i
    total_pages = [(total_count.to_f / @per_page).ceil, 1].max
    page_rows = rows.select { |row| row["payload_kind"] == "row" }.map { |row| serialize_result(row) }
    visual_rows = rows.select { |row| row["payload_kind"] == "visual" }.map { |row| serialize_result(row) }
    last_refreshed_at = rows.first&.fetch("last_refreshed_at", nil)

    {
      rows: page_rows,
      visualLocations: visual_rows,
      totalCount: total_count,
      totalPages: total_pages,
      currentPage: @current_page,
      perPage: @per_page,
      sortKey: @sort,
      sortDirection: @direction,
      lastRefreshedAt: iso8601(last_refreshed_at),
      endpoints: {
        index: heatmap_index_path
      }
    }
  end

  def heatmap_rows
    configure_pagination
    configure_sort
    offset = (@current_page - 1) * @per_page
    first_rank = offset + 1
    last_rank = offset + @per_page

    sql = <<~SQL
      WITH ranked AS (
        SELECT
          location_id,
          event_count,
          avg_signal_dbm,
          unique_devices,
          last_seen_at,
          row_number() OVER (ORDER BY #{@sort_expression} #{@direction.upcase}) AS page_rank,
          row_number() OVER (ORDER BY event_count DESC) AS visual_rank,
          count(*) OVER () AS total_count,
          max(last_seen_at) OVER () AS last_refreshed_at
        FROM mv_wireless_heatmap
      )
      SELECT *
      FROM (
        SELECT 0 AS sort_bucket, 'row' AS payload_kind, page_rank AS result_rank, *
        FROM ranked
        WHERE page_rank BETWEEN #{first_rank} AND #{last_rank}
        UNION ALL
        SELECT 1 AS sort_bucket, 'visual' AS payload_kind, visual_rank AS result_rank, *
        FROM ranked
        WHERE visual_rank <= 200
      ) payload
      ORDER BY sort_bucket ASC, result_rank ASC
    SQL

    WirelessHeatmap.connection.exec_query(sql).to_a
  end

  def serialize_result(row)
    {
      location_id: row["location_id"],
      event_count: row["event_count"].to_i,
      avg_signal_dbm: row["avg_signal_dbm"]&.to_f,
      unique_devices: row["unique_devices"].to_i,
      last_seen_at: iso8601(row["last_seen_at"])
    }
  end

  def configure_pagination
    requested_per_page = params[:per_page].to_i
    @per_page = requested_per_page.positive? ? [requested_per_page, Paginatable::MAX_PER_PAGE].min : 50
    @current_page = params[:page].to_i
    @current_page = 1 if @current_page < 1
  end

  def configure_sort
    sort_key = params[:sort].to_s
    @sort_expression = SORTS.fetch(sort_key, SORTS.fetch("event_count"))
    @sort = SORTS.key?(sort_key) ? sort_key : "event_count"
    @direction = sort_direction(:desc)
  end

  def heatmap_cache_key
    source = {
      direction: params[:direction].to_s,
      page: params[:page].to_i,
      per_page: params[:per_page].to_i,
      sort: params[:sort].to_s
    }.to_json

    "heatmap:payload:#{Digest::SHA1.hexdigest(source)}"
  end

  def location_views(rows)
    rows.map do |row|
      LocationView.new(
        location_id: row[:location_id],
        event_count: row[:event_count],
        avg_signal_dbm: row[:avg_signal_dbm],
        unique_devices: row[:unique_devices],
        last_seen_at: row[:last_seen_at]
      )
    end
  end

  def apply_pagination_state(payload)
    @total_count = payload[:totalCount]
    @total_pages = payload[:totalPages]
    @current_page = payload[:currentPage]
    @per_page = payload[:perPage]
    @sort = payload[:sortKey]
    @direction = payload[:sortDirection]
  end

  def iso8601(value)
    return if value.blank?
    return value.iso8601 if value.respond_to?(:iso8601)

    Time.zone.parse(value.to_s)&.iso8601
  rescue ArgumentError
    value.to_s
  end
end
