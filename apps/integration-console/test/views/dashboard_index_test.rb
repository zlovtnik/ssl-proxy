require "test_helper"

class DashboardIndexTest < ActionView::TestCase
  test "renders when optional dashboard collections are nil" do
    @active_sensors = 0
    @stale_sensors = 0
    @pending_backlog = 0
    @failed_backlog = 0
    @recent_samples = nil
    @recent_alerts = nil
    @sensors = nil

    render template: "dashboard/index"

    assert_includes rendered, "Integration Console"
  end

  test "renders health cards without dashboard svelte bundle" do
    @dashboard_cards_payload = {
      cards: [
        {
          label: "Active Sensors",
          value: 2,
          status: "ok",
          trend: "flat",
          trendLabel: "current",
          sparkline: [2]
        }
      ]
    }
    @recent_samples = nil
    @recent_alerts = nil
    @sensors = nil

    render template: "dashboard/index"

    assert_includes rendered, "Active Sensors"
    assert_includes rendered, 'data-controller="live-feed"'
    refute_includes rendered, "dashboard_cards"
    refute_includes rendered, 'data-controller="svelte"'
  end
end
