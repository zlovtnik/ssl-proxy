class AuditLogsController < ApplicationController
  def index
    @query = params[:q].to_s.strip
    @audit_logs = AuditLog.recent
    @audit_logs = @audit_logs.search(@query) if @query.present?
    @audit_logs = @audit_logs.limit(100)
  end
end
