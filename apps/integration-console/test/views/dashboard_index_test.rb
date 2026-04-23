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
end
