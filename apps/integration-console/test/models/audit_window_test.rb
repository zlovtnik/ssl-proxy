require "test_helper"

class AuditWindowTest < ActiveSupport::TestCase
  test "builds sensor config payload" do
    window = AuditWindow.new(
      location_id: "lab",
      timezone: "America/New_York",
      days: "mon,fri",
      start_time: "09:00",
      end_time: "17:00",
      enabled: true
    )

    assert window.valid?
    assert_equal "lab", window.payload[:location_id]
    assert_equal "mon,fri", window.payload[:days]
  end

  test "rejects unsupported days" do
    window = AuditWindow.new(location_id: "lab", timezone: "UTC", days: "weekday")

    assert_not window.valid?
  end
end
