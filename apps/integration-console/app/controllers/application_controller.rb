class ApplicationController < ActionController::Base
  include Paginatable
  include Sortable

  rescue_from ActiveRecord::StatementInvalid, with: :render_query_error

  private

  def render_query_error(error)
    raise error unless error.cause.is_a?(PG::QueryCanceled)

    respond_to do |format|
      format.json { render json: { error: "Query timed out. Narrow the search and try again." }, status: :service_unavailable }
      format.any { render plain: "Query timed out. Narrow the search and try again.", status: :service_unavailable }
    end
  end
end
