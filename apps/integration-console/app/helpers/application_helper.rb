module ApplicationHelper
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
end
