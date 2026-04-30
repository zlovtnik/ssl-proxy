require "test_helper"

class AuditWindowsControllerTest < ActionDispatch::IntegrationTest
  setup do
    AuditWindow.delete_all
  end

  test "index renders svelte root and json payload" do
    AuditWindow.create!(location_id: "lab", timezone: "America/New_York", enabled: true)

    get audit_windows_url

    assert_response :success
    assert_includes response.body, "audit-windows-svelte-root"
    assert_includes response.body, "lab"

    get audit_windows_url(format: :json)

    assert_response :success
    assert_equal ["lab"], JSON.parse(response.body).fetch("rows").map { |row| row["location_id"] }
  end

  test "create redirects with see other when publishing succeeds" do
    publisher = Object.new
    def publisher.call = true

    AuditWindowPublisher.stub(:new, ->(_audit_window) { publisher }) do
      post audit_windows_url, params: {
        audit_window: {
          location_id: "lab",
          timezone: "America/New_York",
          days: "mon",
          start_time: "09:00",
          end_time: "17:00",
          enabled: true
        }
      }
    end

    assert_redirected_to audit_windows_path
    assert_response :see_other
  end

  test "create rolls back when publishing fails" do
    publisher = Object.new
    def publisher.call = raise "nats down"

    assert_no_difference -> { AuditWindow.count } do
      AuditWindowPublisher.stub(:new, ->(_audit_window) { publisher }) do
        post audit_windows_url, params: {
          audit_window: {
            location_id: "lab",
            timezone: "America/New_York",
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
    audit_window = AuditWindow.create!(location_id: "lab", timezone: "America/New_York", enabled: true)
    publisher = Object.new
    def publisher.call = raise "nats down"

    AuditWindowPublisher.stub(:new, ->(_audit_window) { publisher }) do
      patch audit_window_url(audit_window), params: {
        audit_window: {
          location_id: "branch",
          timezone: "America/New_York",
          enabled: true
        }
      }
    end

    assert_response :unprocessable_entity
    assert_equal "lab", audit_window.reload.location_id
    assert_includes response.body, "could not be published"
  end
end
