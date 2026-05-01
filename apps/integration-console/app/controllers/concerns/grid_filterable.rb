module GridFilterable
  extend ActiveSupport::Concern

  included do
    helper_method :parsed_grid_filters
  end

  MAX_FILTERS = 10

  private

  def apply_grid_filters(scope, allowed_filters)
    filters = parsed_grid_filters
    return scope if filters.blank?

    clauses = []
    binds = []

    filters.first(MAX_FILTERS).each do |filter|
      field = filter["field"].to_s
      config = allowed_filters[field] || allowed_filters[field.to_sym]
      next unless config

      column = filter_column_sql(config)
      type = filter_type(config)
      clause, values = grid_filter_clause(column, type, filter["operator"].to_s, filter["value"])
      next if clause.blank?

      conjunction = filter["conjunction"].to_s == "OR" ? "OR" : "AND"
      clauses << { sql: clause, conjunction: conjunction }
      binds.concat(values)
    end

    return scope if clauses.blank?

    sql = clauses.each_with_index.map do |clause, index|
      prefix = index.zero? ? "" : "#{clause[:conjunction]} "
      "#{prefix}(#{clause[:sql]})"
    end.join(" ")

    scope.where(sql, *binds)
  end

  def parsed_grid_filters
    raw = params[:filters].to_s
    return [] if raw.blank?

    parsed = JSON.parse(raw)
    parsed.is_a?(Array) ? parsed : []
  rescue JSON::ParserError
    []
  end

  def filter_column_sql(config)
    column = config.is_a?(Hash) ? config.fetch(:column) : config
    column = column.to_s
    return column if column.match?(/\A[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?\z/i)

    raise ArgumentError, "Unsafe filter column"
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
    when :boolean
      boolean_clause(column, operator, value)
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
    number = normalized_number_filter_value(value)
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

  def normalized_number_filter_value(value)
    text = value.to_s.strip
    Float(text)
    text.match?(/\A-?\d+\z/) ? text.to_i : text.to_f
  end

  def boolean_clause(column, _operator, value)
    return ["#{column} = ?", [true]] if value.to_s == "true"
    return ["#{column} = ?", [false]] if value.to_s == "false"

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
