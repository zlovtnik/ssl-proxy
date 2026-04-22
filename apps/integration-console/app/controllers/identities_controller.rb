class IdentitiesController < ApplicationController
  def index
    @query = params[:q].to_s.strip
    @identities = WirelessAuditIdentity.recent
    @identities = @identities.search(@query) if @query.present?
    @identities = @identities.limit(100)
  end
end
