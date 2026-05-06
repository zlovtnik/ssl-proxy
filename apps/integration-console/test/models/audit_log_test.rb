require "test_helper"
require "base64"

class AuditLogTest < ActiveSupport::TestCase
  setup do
    clear_sync_tables("sync_scan_ingest")
    ensure_wireless_audit_search_vector
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
        "schema_version" => 2,
        "frame_type" => "management",
        "sensor_id" => "sensor-1",
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

    entry = AuditLog.find("audit-rf")

    assert_equal 2, entry.schema_version
    assert_equal "management", entry.frame_type
    assert_equal 72_623_859_790_382_856, entry.tsft
    assert_equal(-42, entry.signal_dbm)
    assert_equal 2437, entry.frequency_mhz
    assert_equal 6, entry.channel_number
    assert_equal "present", entry.signal_status
    assert_equal 160, entry.channel_flags
    assert_equal 6000, entry.data_rate_kbps
    assert_equal 3, entry.antenna_id
  end

  test "protocol and correlation accessors return payload values" do
    insert_sync_ingest(
      dedupe_key: "audit-protocol",
      observed_at: Time.current,
      payload: {
        "schema_version" => 2,
        "sensor_id" => "sensor-1",
        "frame_type" => "data",
        "frame_subtype" => "qos_data",
        "llc_oui" => "00:00:00",
        "ethertype" => 2048,
        "ethertype_name" => "ipv4",
        "src_ip" => "192.168.1.10",
        "dst_ip" => "239.255.255.250",
        "src_port" => 49_152,
        "dst_port" => 1900,
        "transport_protocol" => "udp",
        "transport_length" => 180,
        "transport_checksum" => 0,
        "app_protocol" => "ssdp",
        "ssdp_message_type" => "M-SEARCH",
        "ssdp_st" => "upnp:rootdevice",
        "dhcp_hostname" => "sensor",
        "dns_query_name" => "printer.local",
        "mdns_name" => "_airplay._tcp.local",
        "session_key" => "aa|bb",
        "retransmit_key" => "tx|rx|1|0",
        "frame_fingerprint" => "abc123",
        "payload_visibility" => "plaintext",
        "large_frame" => true,
        "mixed_encryption" => false,
        "dedupe_or_replay_suspect" => false,
        "anomaly_reasons" => ["large_frame"]
      }
    )

    entry = AuditLog.find("audit-protocol")

    assert_equal "00:00:00", entry.llc_oui
    assert_equal 2048, entry.ethertype
    assert_equal "ipv4", entry.ethertype_name
    assert_equal "192.168.1.10", entry.src_ip
    assert_equal "239.255.255.250", entry.dst_ip
    assert_equal 49_152, entry.src_port
    assert_equal 1900, entry.dst_port
    assert_equal "udp", entry.transport_protocol
    assert_equal 180, entry.transport_length
    assert_equal "ssdp", entry.app_protocol
    assert_equal "M-SEARCH", entry.ssdp_message_type
    assert_equal "aa|bb", entry.session_key
    assert_equal "abc123", entry.frame_fingerprint
    assert_equal "plaintext", entry.payload_visibility
    assert entry.large_frame
    assert_equal ["large_frame"], entry.anomaly_reasons
  end

  test "promoted accessors fall back to payload when column is unavailable" do
    entry = AuditLog.new(payload: {
      "ethertype_name" => "ipv4",
      "ssdp_message_type" => "M-SEARCH",
      "retransmit_key" => "tx|rx|1|0"
    })

    entry.stub(:has_attribute?, false) do
      assert_equal "ipv4", entry.ethertype_name
      assert_equal "M-SEARCH", entry.ssdp_message_type
      assert_equal "tx|rx|1|0", entry.retransmit_key
    end
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

  test "wireless frame columns prefer physical columns and expose flag labels" do
    insert_sync_ingest(
      dedupe_key: "audit-frame",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "source_mac" => "payload-source",
        "destination_bssid" => "payload-bssid",
        "raw_len" => 1,
        "more_data" => false,
        "retry" => false
      }
    )
    sync_connection.execute(<<~SQL.squish)
      UPDATE sync_scan_ingest
      SET source_mac = 'aa:bb:cc:dd:ee:01',
          bssid = '10:20:30:40:50:60',
          destination_bssid = '10:20:30:40:50:60',
          ssid = 'CorpWiFi',
          signal_dbm = -42,
          raw_len = 1440,
          frame_control_flags = 30984,
          more_data = TRUE,
          retry = TRUE,
          power_save = FALSE,
          protected = TRUE
      WHERE dedupe_key = 'audit-frame'
    SQL

    entry = AuditLog.find("audit-frame")

    assert_equal "aa:bb:cc:dd:ee:01", entry.source_mac
    assert_equal "10:20:30:40:50:60", entry.destination_bssid
    assert_equal "CorpWiFi", entry.ssid
    assert_equal(-42, entry.signal_dbm)
    assert_equal 1440, entry.raw_len
    assert_equal 30984, entry.frame_control_flags
    assert_equal "more data, retry, protected", entry.frame_flags_label
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

  test "wireless audit cleanup function truncates minutes and removes duplicates" do
    ensure_wireless_audit_cleanup_function
    base = Time.utc(2026, 4, 29, 10, 15, 12)
    payload = {
      "source_mac" => "00:11:22:33:44:55",
      "bssid" => "10:20:30:40:50:60",
      "ssid" => "CorpWiFi",
      "sensor_id" => "sensor-1",
      "location_id" => "lab",
      "frame_subtype" => "probe",
      "app_protocol" => "mdns",
      "session_key" => "session-1",
      "frame_fingerprint" => "fingerprint-1"
    }

    insert_sync_ingest(dedupe_key: "cleanup-old", observed_at: base, payload: payload)
    insert_sync_ingest(dedupe_key: "cleanup-new", observed_at: base + 20.seconds, payload: payload)
    sync_connection.execute(<<~SQL.squish)
      UPDATE sync_scan_ingest
      SET created_at = CASE dedupe_key
            WHEN 'cleanup-old' THEN '2026-04-29 10:15:00+00'::timestamptz
            ELSE '2026-04-29 10:16:00+00'::timestamptz
          END,
          updated_at = CASE dedupe_key
            WHEN 'cleanup-old' THEN '2026-04-29 10:15:00+00'::timestamptz
            ELSE '2026-04-29 10:16:00+00'::timestamptz
          END
      WHERE dedupe_key IN ('cleanup-old', 'cleanup-new')
    SQL

    result = sync_connection.select_one(<<~SQL.squish)
      SELECT * FROM normalize_wireless_audit_minutes('2026-04-29 10:15:10+00', '2026-04-29 11:00:00+00')
    SQL
    rows = sync_connection.select_all("SELECT dedupe_key, observed_at FROM sync_scan_ingest ORDER BY dedupe_key").to_a

    assert_equal 2, result.fetch("normalized_count")
    assert_equal 1, result.fetch("deleted_count")
    assert_equal(["cleanup-new"], rows.map { |row| row.fetch("dedupe_key") })
    assert_equal Time.utc(2026, 4, 29, 10, 15), rows.first.fetch("observed_at")
  end

  test "search uses wireless generated text vector" do
    insert_sync_ingest(
      dedupe_key: "audit-search",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-vector",
        "ssid" => "engineering"
      }
    )

    assert_equal ["audit-search"], AuditLog.recent.search("sensor-vector").pluck(:dedupe_key)
  end

  test "recent scope defaults to last 24 hours but wireless can find older rows" do
    insert_sync_ingest(
      dedupe_key: "audit-old-window",
      observed_at: 25.hours.ago,
      payload: { "sensor_id" => "sensor-old" }
    )

    assert_empty AuditLog.recent.where(dedupe_key: "audit-old-window")
    assert_equal "audit-old-window", AuditLog.wireless.find("audit-old-window").dedupe_key
  end
end
