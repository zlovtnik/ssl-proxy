require "test_helper"
require "base64"
require "json"

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

  test "index links rows to audit log detail" do
    insert_sync_ingest(
      dedupe_key: "audit-link",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "frame_subtype" => "beacon"
      }
    )

    get audit_logs_url

    assert_response :success
    assert_includes response.body, audit_log_path("audit-link")
    assert_includes response.body, "Antenna"
  end

  test "show renders rf metadata when present" do
    insert_sync_ingest(
      dedupe_key: "audit-rf",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "location_id" => "lab",
        "frame_subtype" => "beacon",
        "tsft" => 72_623_859_790_382_856,
        "signal_dbm" => -42,
        "frequency_mhz" => 2437,
        "channel_flags" => 160,
        "data_rate_kbps" => 6000,
        "antenna_id" => 3
      }
    )

    get audit_log_url("audit-rf")

    assert_response :success
    assert_includes response.body, "RF Metadata"
    assert_includes response.body, "Frequency MHz"
    assert_includes response.body, "2437"
    assert_includes response.body, "Antenna ID"
    assert_includes response.body, "3"
    assert_includes response.body, "TSFT"
    assert_includes response.body, "72623859790382856"
  end

  test "show renders raw frame base64 and hex dump" do
    raw_frame = Base64.strict_encode64([0x00, 0x01, 0x41, 0xff].pack("C*"))
    insert_sync_ingest(
      dedupe_key: "audit-raw",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "location_id" => "lab",
        "frame_subtype" => "beacon",
        "raw_frame" => raw_frame
      }
    )

    get audit_log_url("audit-raw")

    assert_response :success
    assert_includes response.body, "Raw Frame"
    assert_includes response.body, raw_frame
    assert_includes response.body, "0000"
    assert_includes response.body, "00 01 41 ff"
  end

  test "show handles legacy audit logs without raw frame" do
    insert_sync_ingest(
      dedupe_key: "audit-legacy",
      observed_at: Time.current,
      payload: { "sensor_id" => "sensor-1" }
    )

    get audit_log_url("audit-legacy")

    assert_response :success
    assert_includes response.body, "Raw frame not available"
  end

  test "show handles invalid raw frame payloads" do
    insert_sync_ingest(
      dedupe_key: "audit-invalid",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "raw_frame" => "not base64"
      }
    )

    get audit_log_url("audit-invalid")

    assert_response :success
    assert_includes response.body, "Raw frame could not be decoded"
  end

  test "recent returns newest persisted audit rows after cursor" do
    older = 2.minutes.ago
    newer = 1.minute.ago
    insert_sync_ingest(
      dedupe_key: "audit-old",
      observed_at: older,
      payload: { "sensor_id" => "sensor-old", "source_mac" => "00:11:22:33:44:55" }
    )
    insert_sync_ingest(
      dedupe_key: "audit-new",
      observed_at: newer,
      payload: { "sensor_id" => "sensor-new", "source_mac" => "00:11:22:33:44:66", "antenna_id" => 3 }
    )

    get recent_audit_logs_url(after: older.iso8601)

    assert_response :success
    rows = JSON.parse(response.body)
    assert_equal ["audit-new"], rows.map { |row| row["dedupe_key"] }
    assert_equal "sensor-new", rows.first["sensor_id"]
    assert_equal "XX:XX:XX:XX:44:66", rows.first["source_mac_display"]
    assert_equal 3, rows.first["antenna_id"]
    assert_equal audit_log_path("audit-new"), rows.first["show_url"]
  end
end
