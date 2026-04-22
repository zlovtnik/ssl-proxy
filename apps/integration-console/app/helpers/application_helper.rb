module ApplicationHelper
  def status_class(status)
    case status.to_s
    when "online", "synced" then "status-ok"
    when "stale", "pending" then "status-warn"
    else "status-alert"
    end
  end
end
