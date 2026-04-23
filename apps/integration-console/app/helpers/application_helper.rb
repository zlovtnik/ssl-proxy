module ApplicationHelper
  def page_title
    [content_for(:title).presence, "Integration Console"].compact.join(" | ")
  end

  def status_class(status)
    case status.to_s
    when "online", "synced" then "status-ok"
    when "stale", "pending" then "status-warn"
    else "status-alert"
    end
  end

  def display_mac(mac)
    return if mac.blank?
    return mac if ENV.fetch("INTEGRATION_CONSOLE_FULL_MACS", "false") == "true"

    octets = mac.to_s.split(":")
    return "XX:XX:XX:XX:#{octets[-2]}:#{octets[-1]}" if octets.length == 6

    "masked"
  end

  def sort_link_to(label, key)
    active = params[:sort].to_s == key.to_s
    next_direction = active && params[:direction].to_s == "asc" ? "desc" : "asc"
    css_class = active ? "sort-link active" : "sort-link"
    indicator = active ? (params[:direction].to_s == "asc" ? " up" : " down") : ""

    link_to "#{label}#{indicator}", url_for(sort_params(key, next_direction)), class: css_class
  end

  private

  def sort_params(key, direction)
    request.query_parameters.merge(sort: key, direction: direction, page: nil).compact
  end
end
