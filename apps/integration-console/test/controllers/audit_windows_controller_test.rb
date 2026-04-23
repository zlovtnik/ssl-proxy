require "test_helper"

class AuditWindowsControllerTest < ActionDispatch::IntegrationTest
  test "create rolls back when publishing fails" do
    publisher = Object.new
    def publisher.call = raise "nats down"

    assert_no_difference -> { AuditWindow.count } do
      AuditWindowPublisher.stub(:new, publisher) do
        post audit_windows_url, params: {
          audit_window: {
            location_id: "lab",
            timezone: "UTC",
            days: "mon",
            start_time: "09:00",
            end_time: "17:00",
            enabled: true
          }
        }
      end
    end

    assert_response :unprocessable_entity
    assert_includes response.body, "could not be published"
  end

  test "update rolls back when publishing fails" do
    audit_window = AuditWindow.create!(location_id: "lab", timezone: "UTC", enabled: true)
    publisher = Object.new
    def publisher.call = raise "nats down"

    AuditWindowPublisher.stub(:new, publisher) do
      patch audit_window_url(audit_window), params: {
        audit_window: {
          location_id: "branch",
          timezone: "UTC",
          enabled: true
        }
      }
    end

    assert_response :unprocessable_entity
    assert_equal "lab", audit_window.reload.location_id
    assert_includes response.body, "could not be published"
  end
end
