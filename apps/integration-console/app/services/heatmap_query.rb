class HeatmapQuery
  include GridFilterable

  FILTERS = {
    "location_id" => "location_id",
    "event_count" => { column: "event_count", type: :number },
    "avg_signal_dbm" => { column: "avg_signal_dbm", type: :number },
    "unique_devices" => { column: "unique_devices", type: :number },
    "last_seen_at" => { column: "last_seen_at", type: :date }
  }.freeze

  def initialize(sort_expression:, direction:, first_rank:, last_rank:, filters:)
    @sort_expression = sort_expression
    @direction = direction
    @first_rank = first_rank
    @last_rank = last_rank
    @filters = filters
  end

  def execute
    WirelessHeatmap.connection.exec_query(sql).to_a
  end

  private

  attr_reader :sort_expression, :direction, :first_rank, :last_rank, :filters

  def sql
    <<~SQL
      WITH ranked AS (
        SELECT
          location_id,
          event_count,
          avg_signal_dbm,
          unique_devices,
          last_seen_at,
          row_number() OVER (ORDER BY #{sort_expression} #{direction.upcase}) AS page_rank,
          row_number() OVER (ORDER BY event_count DESC) AS visual_rank,
          count(*) OVER () AS total_count,
          max(last_seen_at) OVER () AS last_refreshed_at
        FROM mv_wireless_heatmap
        #{where_clause}
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
  end

  def where_clause
    return "" if filters.blank?

    clauses = []
    binds = []

    filters.first(MAX_FILTERS).each do |filter|
      field = filter["field"].to_s
      config = FILTERS[field]
      next unless config

      column = filter_column_sql(config)
      type = filter_type(config)
      clause, values = grid_filter_clause(column, type, filter["operator"].to_s, filter["value"])
      next if clause.blank?

      conjunction = filter["conjunction"].to_s == "OR" ? "OR" : "AND"
      clauses << { sql: clause, conjunction: conjunction }
      binds.concat(values)
    end

    return "" if clauses.blank?

    sql = clauses.each_with_index.map do |clause, index|
      prefix = index.zero? ? "" : "#{clause[:conjunction]} "
      "#{prefix}(#{clause[:sql]})"
    end.join(" ")

    sanitized = WirelessHeatmap.sanitize_sql_array([sql, *binds])
    "WHERE #{sanitized}"
  end

  def params
    { filters: filters.to_json }
  end
end
