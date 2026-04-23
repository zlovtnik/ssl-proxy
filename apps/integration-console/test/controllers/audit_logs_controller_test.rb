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
    assert_includes response.body, "Dest BSSID"
    assert_includes response.body, "Flags"
    assert_includes response.body, "Security"
    assert_includes response.body, "Fingerprint"
  end

  test "show renders rf metadata when present" do
    insert_sync_ingest(
      dedupe_key: "audit-rf",
      observed_at: Time.current,
      payload: {
        "schema_version" => 2,
        "frame_type" => "management",
        "sensor_id" => "sensor-1",
        "location_id" => "lab",
        "frame_subtype" => "beacon",
        "tsft" => 72_623_859_790_382_856,
        "signal_dbm" => -42,
        "frequency_mhz" => 2437,
        "channel_number" => 6,
        "signal_status" => "present",
        "channel_flags" => 160,
        "data_rate_kbps" => 6000,
        "antenna_id" => 3
      }
    )

    get audit_log_url("audit-rf")

    assert_response :success
    assert_includes response.body, "RF Metadata"
    assert_includes response.body, "Schema version"
    assert_includes response.body, "management"
    assert_includes response.body, "Frequency MHz"
    assert_includes response.body, "2437"
    assert_includes response.body, "Channel number"
    assert_includes response.body, "present"
    assert_includes response.body, "Antenna ID"
    assert_includes response.body, "3"
    assert_includes response.body, "TSFT"
    assert_includes response.body, "72623859790382856"
  end

  test "show renders protocol and correlation metadata when present" do
    insert_sync_ingest(
      dedupe_key: "audit-protocol",
      observed_at: Time.current,
      payload: {
        "schema_version" => 2,
        "sensor_id" => "sensor-1",
        "location_id" => "lab",
        "frame_type" => "data",
        "frame_subtype" => "qos_data",
        "source_mac" => "00:11:22:33:44:55",
        "destination_bssid" => "10:20:30:40:50:60",
        "src_ip" => "192.168.1.10",
        "dst_ip" => "239.255.255.250",
        "src_port" => 49_152,
        "dst_port" => 1900,
        "app_protocol" => "ssdp",
        "ssdp_message_type" => "M-SEARCH",
        "ssdp_st" => "upnp:rootdevice",
        "session_key" => "00:11:22:33:44:55|10:20:30:40:50:60",
        "frame_fingerprint" => "abc123",
        "payload_visibility" => "plaintext",
        "large_frame" => true,
        "anomaly_reasons" => ["large_frame"]
      }
    )

    get audit_log_url("audit-protocol")

    assert_response :success
    assert_includes response.body, "Protocol Metadata"
    assert_includes response.body, "192.168.1.10"
    assert_includes response.body, "239.255.255.250"
    assert_includes response.body, "ssdp"
    assert_includes response.body, "M-SEARCH"
    assert_includes response.body, "Correlation"
    assert_includes response.body, "abc123"
    assert_includes response.body, "plaintext"
    assert_includes response.body, "large_frame"
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
      payload: {
        "sensor_id" => "sensor-new",
        "source_mac" => "00:11:22:33:44:66",
        "destination_bssid" => "10:20:30:40:50:60",
        "schema_version" => 2,
        "frame_type" => "data",
        "channel_number" => 6,
        "app_protocol" => "dns",
        "src_ip" => "10.0.0.2",
        "dst_ip" => "8.8.8.8",
        "raw_len" => 1440,
        "more_data" => true,
        "retry" => true,
        "protected" => true,
        "antenna_id" => 3,
        "security_flags" => 10,
        "device_fingerprint" => "0123456789abcdef",
        "handshake_captured" => true
      }
    )

    get recent_audit_logs_url(after: older.iso8601)

    assert_response :success
    rows = JSON.parse(response.body)
    assert_equal ["audit-new"], rows.map { |row| row["dedupe_key"] }
    assert_equal 2, rows.first["schema_version"]
    assert_equal "data", rows.first["frame_type"]
    assert_equal "sensor-new", rows.first["sensor_id"]
    assert_equal "XX:XX:XX:XX:44:66", rows.first["source_mac_display"]
    assert_equal "XX:XX:XX:XX:50:60", rows.first["destination_bssid_display"]
    assert_equal 6, rows.first["channel_number"]
    assert_equal "dns", rows.first["app_protocol"]
    assert_equal "10.0.0.2", rows.first["src_ip"]
    assert_equal "8.8.8.8", rows.first["dst_ip"]
    assert_equal 1440, rows.first["raw_len"]
    assert_equal "more data, retry, protected", rows.first["frame_flags_label"]
    assert_equal 3, rows.first["antenna_id"]
    assert_equal 10, rows.first["security_flags"]
    assert_equal "RSN/WPA2, WPS", rows.first["security_label"]
    assert_equal "0123456789abcdef", rows.first["device_fingerprint"]
    assert_equal true, rows.first["handshake_captured"]
    assert_equal audit_log_path("audit-new"), rows.first["show_url"]
  end

  test "export returns csv summary" do
    insert_sync_ingest(
      dedupe_key: "audit-export",
      observed_at: Time.current,
      payload: {
        "schema_version" => 2,
        "sensor_id" => "sensor-1",
        "location_id" => "lab",
        "frame_type" => "data",
        "frame_subtype" => "qos_data",
        "source_mac" => "00:11:22:33:44:55",
        "destination_bssid" => "10:20:30:40:50:60",
        "channel_number" => 6,
        "src_ip" => "192.168.1.10",
        "dst_ip" => "239.255.255.250",
        "src_port" => 49_152,
        "dst_port" => 1900,
        "app_protocol" => "ssdp",
        "session_key" => "00:11:22:33:44:55|10:20:30:40:50:60",
        "frame_fingerprint" => "abc123",
        "payload_visibility" => "plaintext",
        "large_frame" => true,
        "raw_len" => 1200
      }
    )

    get export_audit_logs_url(format: :csv)

    assert_response :success
    assert_includes response.media_type, "text/csv"
    assert_includes response.body, "schema_version"
    assert_includes response.body, "audit-export"
    assert_includes response.body, "ssdp"
    assert_includes response.body, "abc123"
  end
end
