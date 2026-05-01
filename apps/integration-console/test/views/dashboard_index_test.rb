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
    assert_includes rendered, "dashboard-cards-svelte-root"
  end

  test "renders health panel svelte mount targets" do
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

    assert_includes rendered, "dashboard-cards-svelte-root"
    assert_includes rendered, "live-feed-panel-svelte-root"
    assert_includes rendered, "sync-health-svelte-root"
    assert_includes rendered, "sensors-panel-svelte-root"
    assert_includes rendered, "dashboard_cards"
    refute_includes rendered, 'data-controller="live-feed"'
  end
end
