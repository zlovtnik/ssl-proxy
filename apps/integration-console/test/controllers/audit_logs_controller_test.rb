require "test_helper"

class AuditLogsControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
  end

  test "index returns requested audit log page slice" do
    55.times do |index|
      insert_sync_ingest(
        dedupe_key: "audit-#{index}",
        observed_at: index.minutes.ago,
        payload: {
          "sensor_id" => format("sensor-%02d", index),
          "location_id" => "lab",
          "frame_subtype" => "probe",
          "source_mac" => "00:11:22:33:44:#{format("%02d", index)}"
        }
      )
    end

    get audit_logs_url(page: 2)

    assert_response :success
    assert_includes response.body, "sensor-50"
    assert_no_match(/sensor-04/, response.body)
    assert_includes response.body, "Page 2 of 2"
  end
end
