require "digest/sha1"

class ApplicationController < ActionController::Base
  include Paginatable
  include Sortable
  include GridFilterable

  rescue_from ActiveRecord::StatementInvalid, with: :render_query_error
  rescue_from ExportStore::Error, with: :render_export_store_error
  rescue_from IntegrationRun::InvalidTransitionError, with: :render_invalid_transition

  private

  def render_query_error(error)
    raise error unless error.cause.is_a?(PG::QueryCanceled)

    respond_to do |format|
      format.json { render json: { error: "Query timed out. Narrow the search and try again." }, status: :service_unavailable }
      format.any { render plain: "Query timed out. Narrow the search and try again.", status: :service_unavailable }
    end
  end

  def render_export_store_error(error)
    Rails.logger.error("Export storage unavailable: #{error.class} - #{error.message}")

    respond_to do |format|
      format.json { render json: { error: "Export storage is unavailable. Try again later." }, status: :service_unavailable }
      format.any { render plain: "Export storage is unavailable. Try again later.", status: :service_unavailable }
    end
  end

  def render_invalid_transition(error)
    respond_to do |format|
      format.json { render json: { error: error.message }, status: :unprocessable_entity }
      format.any { redirect_back fallback_location: integration_runs_path, alert: error.message, status: :see_other }
    end
  end

  def render_cached_json(payload, browser_ttl:)
    expires_in browser_ttl, public: true
    etag = Digest::SHA1.hexdigest(payload.to_json)
    render json: payload if stale?(etag: etag, public: true)
  end

  def cache_bucket_time(seconds)
    Time.at((Time.current.to_i / seconds) * seconds).utc
  end
end
