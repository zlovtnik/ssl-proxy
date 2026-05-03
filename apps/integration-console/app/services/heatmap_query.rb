class HeatmapQuery
  MAX_FILTERS = 10

  FILTERS = {
    "location_id" => "location_id",
    "event_count" => { column: "event_count", type: :number },
    "avg_signal_dbm" => { column: "avg_signal_dbm", type: :number },
    "unique_devices" => { column: "unique_devices", type: :number },
    "last_seen_at" => { column: "last_seen_at", type: :date }
  }.freeze

  ALLOWED_SORT_COLUMNS = %w[location_id event_count avg_signal_dbm unique_devices last_seen_at].freeze

  def initialize(sort_expression:, direction:, first_rank:, last_rank:, filters:)
    @sort_expression = validate_sort_column(sort_expression)
    @direction = validate_direction(direction)
    @first_rank = validate_rank(first_rank)
    @last_rank = validate_rank(last_rank)
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

  def validate_sort_column(column)
    ALLOWED_SORT_COLUMNS.include?(column.to_s) ? column.to_s : "event_count"
  end

  def validate_direction(dir)
    dir.to_s.upcase == "ASC" ? "ASC" : "DESC"
  end

  def validate_rank(rank)
    [[rank.to_i, 1].max, 100_000].min
  end

  def filter_column_sql(config)
    column = config.is_a?(Hash) ? config.fetch(:column) : config
    column.to_s
  end

  def filter_type(config)
    return :text unless config.is_a?(Hash)
    (config[:type] || :text).to_sym
  end

  def grid_filter_clause(column, type, operator, value)
    return empty_clause(column, false) if operator == "is_empty"
    return empty_clause(column, true) if operator == "is_not_empty"

    case type
    when :number
      numeric_clause(column, operator, value)
    when :date
      date_clause(column, operator, value)
    else
      text_clause(column, operator, value)
    end
  end

  def text_clause(column, operator, value)
    text_value = value.to_s
    return [nil, []] if text_value.blank?

    normalized = text_value.downcase
    expression = "LOWER(CAST(#{column} AS TEXT))"

    case operator
    when "equals"
      ["#{expression} = ?", [normalized]]
    when "starts_with"
      ["#{expression} LIKE ?", ["#{sanitize_like(normalized)}%"]]
    when "not_equals"
      ["#{expression} != ?", [normalized]]
    else
      ["#{expression} LIKE ?", ["%#{sanitize_like(normalized)}%"]]
    end
  end

  def numeric_clause(column, operator, value)
    number = Float(value.to_s.strip)
    case operator
    when "greater_than"
      ["#{column} > ?", [number]]
    when "less_than"
      ["#{column} < ?", [number]]
    else
      ["#{column} = ?", [number]]
    end
  rescue ArgumentError, TypeError
    [nil, []]
  end

  def date_clause(column, operator, value)
    date = Date.iso8601(value.to_s)
    expression = "DATE(#{column})"

    case operator
    when "after"
      ["#{expression} > ?", [date]]
    when "before"
      ["#{expression} < ?", [date]]
    else
      ["#{expression} = ?", [date]]
    end
  rescue ArgumentError, TypeError
    [nil, []]
  end

  def empty_clause(column, negate)
    clause = "(#{column} IS NULL OR CAST(#{column} AS TEXT) = '')"
    negate ? ["NOT #{clause}", []] : [clause, []]
  end

  def sanitize_like(value)
    ActiveRecord::Base.sanitize_sql_like(value)
  end
end
