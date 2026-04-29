require "application_system_test_case"

class AuditLogsTurboTest < ApplicationSystemTestCase
  setup do
    clear_sync_tables("sync_scan_ingest")

    insert_sync_ingest(
      dedupe_key: "audit-turbo-remount",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-turbo-remount",
        "location_id" => "lab",
        "frame_subtype" => "beacon",
        "source_mac" => "00:11:22:33:44:55"
      }
    )
  end

  test "audit logs remount after a Turbo return visit" do
    visit root_path

    click_link "Audit Logs"
    assert_current_path audit_logs_path
    assert_text "sensor-turbo-remount"

    click_link "Health"
    assert_current_path root_path

    click_link "Audit Logs"
    assert_current_path audit_logs_path
    assert_text "sensor-turbo-remount"
  end
end
