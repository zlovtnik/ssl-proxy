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
    return mac if full_macs_enabled?

    octets = mac.to_s.split(":")
    return "XX:XX:XX:XX:#{octets[-2]}:#{octets[-1]}" if octets.length == 6

    "masked"
  end

  def full_macs_enabled?
    ENV.fetch("INTEGRATION_CONSOLE_FULL_MACS", "false") == "true"
  end

  def svelte_props_tag(root_id, props)
    content_tag(
      :script,
      json_escape(props.to_json).html_safe,
      type: "application/json",
      id: "#{root_id}-props"
    )
  end

  def svelte_bundle_tags(entrypoint)
    safe_join([
      optional_vite_stylesheet_tag(entrypoint),
      vite_javascript_tag(entrypoint.to_s, "data-turbo-track": "reload")
    ].compact, "\n")
  end

  def optional_vite_stylesheet_tag(entrypoint)
    vite_stylesheet_tag(entrypoint.to_s, "data-turbo-track": "reload")
  rescue ViteRuby::MissingEntrypointError
    nil
  end

  def metric_card_status_class(status)
    {
      "ok" => "metric-card-ok",
      "warn" => "metric-card-warn",
      "alert" => "metric-card-alert",
      "neutral" => "metric-card-neutral"
    }.fetch(status.to_s, "metric-card-neutral")
  end

  def metric_card_trend_class(trend)
    {
      "up" => "status-ok",
      "down" => "status-alert",
      "flat" => "muted"
    }.fetch(trend.to_s, "muted")
  end

  def metric_card_trend_symbol(trend)
    {
      "up" => "\u2191",
      "down" => "\u2193",
      "flat" => "\u2192"
    }.fetch(trend.to_s, "\u2192")
  end

  def metric_card_sparkline_path(points)
    numbers = Array(points).filter_map { |point| Float(point, exception: false) }
    return if numbers.empty?

    numbers << numbers.first if numbers.one?
    min = numbers.min
    max = numbers.max
    span = max - min
    span = 1 if span.zero?
    step = 100.0 / (numbers.length - 1)

    numbers.each_with_index.map do |point, index|
      x = index * step
      y = 28 - ((point - min) / span) * 24
      "#{index.zero? ? "M" : "L"}#{format("%.1f", x)} #{format("%.1f", y)}"
    end.join(" ")
  end

  def sort_link_to(label, key)
    active = params[:sort].to_s == key.to_s
    next_direction = active && params[:direction].to_s == "asc" ? "desc" : "asc"
    css_class = active ? "sort-link active" : "sort-link"
    indicator = active ? (params[:direction].to_s == "asc" ? " up" : " down") : ""

    params = sort_params(key, next_direction)
    link_to "#{label}#{indicator}", url_for(params), class: css_class
  rescue ActionController::UrlGenerationError
    link_to "#{label}#{indicator}", "?#{params.to_query}", class: css_class
  end

  private

  def sort_params(key, direction)
    request.query_parameters.merge(sort: key, direction: direction, page: nil).compact
  end
end
