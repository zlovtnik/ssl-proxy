module NavHelper
  ICONS = {
    health: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h4l2-6 4 12 2-6h4"/></svg>',
    audit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5h14M5 12h14M5 19h9"/></svg>',
    backlog: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 7h12v4H6zM6 13h12v4H6z"/></svg>',
    windows: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5h14v14H5zM5 10h14"/></svg>',
    identities: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM5 20c1-4 13-4 14 0"/></svg>',
    heatmap: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 19V9M12 19V5M19 19v-7"/></svg>',
    alerts: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4 3 20h18zM12 9v5M12 17h.01"/></svg>'
  }.freeze

  def nav_link_to(label, path, icon:)
    classes = ["nav-link"]
    classes << "active" if current_page?(path)

    link_to path, class: classes.join(" ") do
      safe_join([
        tag.span(ICONS.fetch(icon).html_safe, class: "nav-icon"),
        tag.span(label, class: "nav-label")
      ])
    end
  end
end
