module Sortable
  extend ActiveSupport::Concern

  private

  def apply_sort(scope, allowed_sorts, default_sort:, default_direction: :desc)
    sort_key = params[:sort].to_s
    sort_column = allowed_sorts.fetch(sort_key, allowed_sorts.fetch(default_sort.to_s))
    direction = sort_direction(default_direction)

    @sort = allowed_sorts.key?(sort_key) ? sort_key : default_sort.to_s
    @direction = direction

    scope.reorder(sort_column => direction)
  end

  def apply_sql_sort(scope, allowed_sorts, default_sort:, default_direction: :desc)
    sort_key = params[:sort].to_s
    sort_expression = allowed_sorts.fetch(sort_key, allowed_sorts.fetch(default_sort.to_s))
    direction = sort_direction(default_direction)

    @sort = allowed_sorts.key?(sort_key) ? sort_key : default_sort.to_s
    @direction = direction

    scope.reorder(Arel.sql("#{sort_expression} #{direction.upcase}"))
  end

  def sort_direction(default_direction)
    return "asc" if params[:direction].to_s == "asc"
    return "desc" if params[:direction].to_s == "desc"

    default_direction.to_s == "asc" ? "asc" : "desc"
  end
end
