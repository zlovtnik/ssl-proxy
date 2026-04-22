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
