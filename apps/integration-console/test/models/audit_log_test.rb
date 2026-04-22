require "test_helper"
require "base64"

class AuditLogTest < ActiveSupport::TestCase
  setup do
    clear_sync_tables("sync_scan_ingest")
  end

  test "raw_frame returns payload value" do
    raw_frame = Base64.strict_encode64([0x00, 0x01, 0x41, 0xff].pack("C*"))
    insert_sync_ingest(
      dedupe_key: "audit-raw",
      observed_at: Time.current,
      payload: { "sensor_id" => "sensor-1", "raw_frame" => raw_frame }
    )

    entry = AuditLog.find("audit-raw")

    assert_equal raw_frame, entry.raw_frame
  end

  test "rf metadata accessors return payload values" do
    insert_sync_ingest(
      dedupe_key: "audit-rf",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "tsft" => 72_623_859_790_382_856,
        "signal_dbm" => -42,
        "frequency_mhz" => 2437,
        "channel_flags" => 160,
        "data_rate_kbps" => 6000,
        "antenna_id" => 3
      }
    )

    entry = AuditLog.find("audit-rf")

    assert_equal 72_623_859_790_382_856, entry.tsft
    assert_equal(-42, entry.signal_dbm)
    assert_equal 2437, entry.frequency_mhz
    assert_equal 160, entry.channel_flags
    assert_equal 6000, entry.data_rate_kbps
    assert_equal 3, entry.antenna_id
  end

  test "wireless security fields prefer physical columns" do
    insert_sync_ingest(
      dedupe_key: "audit-security",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "security_flags" => 0,
        "wps_device_name" => "payload name",
        "device_fingerprint" => "payload-fp",
        "handshake_captured" => false
      }
    )
    sync_connection.execute(<<~SQL.squish)
      UPDATE sync_scan_ingest
      SET security_flags = 26,
          wps_device_name = 'Lobby AP',
          wps_manufacturer = 'Acme',
          wps_model_name = 'Model 7',
          device_fingerprint = '0123456789abcdef',
          handshake_captured = TRUE
      WHERE dedupe_key = 'audit-security'
    SQL

    entry = AuditLog.find("audit-security")

    assert_equal 26, entry.security_flags
    assert_equal ["RSN/WPA2", "WPS", "PMF required"], entry.security_labels
    assert_equal "Lobby AP", entry.wps_device_name
    assert_equal "Acme", entry.wps_manufacturer
    assert_equal "Model 7", entry.wps_model_name
    assert_equal "0123456789abcdef", entry.device_fingerprint
    assert entry.handshake_captured
  end

  test "raw_frame_hex_dump renders decoded bytes" do
    raw_frame = Base64.strict_encode64([0x00, 0x01, 0x41, 0xff].pack("C*"))
    insert_sync_ingest(
      dedupe_key: "audit-raw",
      observed_at: Time.current,
      payload: { "sensor_id" => "sensor-1", "raw_frame" => raw_frame }
    )

    dump = AuditLog.find("audit-raw").raw_frame_hex_dump

    assert_includes dump, "0000"
    assert_includes dump, "00 01 41 ff"
    assert_includes dump, "|..A.|"
  end

  test "raw_frame_hex_dump is nil for missing or invalid raw frame" do
    insert_sync_ingest(
      dedupe_key: "audit-missing",
      observed_at: Time.current,
      payload: { "sensor_id" => "sensor-1" }
    )
    insert_sync_ingest(
      dedupe_key: "audit-invalid",
      observed_at: Time.current,
      payload: { "sensor_id" => "sensor-2", "raw_frame" => "not base64" }
    )

    assert_nil AuditLog.find("audit-missing").raw_frame_hex_dump
    assert_nil AuditLog.find("audit-invalid").raw_frame_hex_dump
  end
end
