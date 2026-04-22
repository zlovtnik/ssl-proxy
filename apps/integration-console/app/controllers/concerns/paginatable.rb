module Paginatable
  extend ActiveSupport::Concern

  MAX_PER_PAGE = 200

  private

  def paginate(scope, per_page: 50)
    requested_per_page = params[:per_page].to_i
    @per_page = requested_per_page.positive? ? [requested_per_page, MAX_PER_PAGE].min : per_page

    count_scope = scope.except(:order)
    count_scope = count_scope.except(:select) if count_scope.group_values.any?
    count_result = count_scope.count
    @total_count = count_result.is_a?(Hash) ? count_result.length : count_result
    @total_pages = [(@total_count.to_f / @per_page).ceil, 1].max
    @current_page = params[:page].to_i
    @current_page = 1 if @current_page < 1
    @current_page = @total_pages if @current_page > @total_pages

    scope.offset((@current_page - 1) * @per_page).limit(@per_page)
  end
end
