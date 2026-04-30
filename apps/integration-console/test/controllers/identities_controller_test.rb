require "test_helper"

class IdentitiesControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
    Device.delete_all
    ensure_wireless_audit_views
  end

  test "index paginates identities" do
    51.times do |index|
      insert_sync_ingest(
        dedupe_key: "identity-#{index}",
        observed_at: index.minutes.ago,
        payload: {
          "source_mac" => "00:11:22:33:44:#{format("%02d", index)}",
          "bssid" => "aa:bb:cc:dd:ee:ff",
          "ssid" => "lab",
          "username" => format("user-%02d", index)
        }
      )
    end

    get identities_url(page: 2)

    assert_response :success
    assert_includes response.body, "user-50"
    assert_no_match(/user-00/, response.body)
    assert_includes response.body, "Page 2"
    assert_not_includes response.body, "Page 2 of"
  end

  test "index ignores unsafe sort parameters" do
    older = 10.minutes.ago
    newer = Time.current

    insert_sync_ingest(
      dedupe_key: "identity-old",
      observed_at: older,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "bssid" => "aa:bb:cc:dd:ee:ff",
        "ssid" => "old-lab",
        "signal_dbm" => -20
      }
    )
    insert_sync_ingest(
      dedupe_key: "identity-new",
      observed_at: newer,
      payload: {
        "source_mac" => "00:11:22:33:44:66",
        "bssid" => "aa:bb:cc:dd:ee:ff",
        "ssid" => "new-lab",
        "signal_dbm" => -90
      }
    )

    get identities_url(sort: "ssid", direction: "asc")

    assert_response :success
    assert_operator response.body.index("new-lab"), :<, response.body.index("old-lab")
    assert_no_match(/sort=signal_dbm/, response.body)
    assert_no_match(/sort=ssid/, response.body)
    assert_no_match(/sort=observed_at/, response.body)
  end

  test "inventory exports json summaries and redirects cached csv exports" do
    insert_sync_ingest(
      dedupe_key: "inventory-1",
      observed_at: Time.current,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "destination_bssid" => "10:20:30:40:50:60",
        "ssid" => "lab",
        "location_id" => "lab",
        "src_ip" => "192.168.1.10",
        "dhcp_hostname" => "sensor",
        "app_protocol" => "ssdp",
        "dns_query_name" => "printer.local",
        "protected" => false
      }
    )

    get inventory_identities_url(format: :json)

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "00:11:22:33:44:55", json.first["source_mac"]
    assert_equal json.first["last_seen"], json.first["last_occurred_at"]
    assert_includes json.first["services"], "ssdp"

    captured_csv = nil
    ExportStore.stub(:fetch_or_generate, ->(key:, ttl:, filename: nil, &block) {
      captured_csv = block.call
      assert_equal "wireless-inventory.csv", filename
      "http://minio.test/inventory.csv"
    }) do
      get inventory_identities_url(format: :csv)
    end

    assert_redirected_to "http://minio.test/inventory.csv"
    assert_includes captured_csv, "last_occurred_at"
    assert_includes captured_csv, "00:11:22:33:44:55"
    assert_includes captured_csv, "printer.local"
  end

  test "inventory json returns one row per mac with max occurrence time" do
    older = 10.minutes.ago
    newer = Time.current

    insert_sync_ingest(
      dedupe_key: "inventory-mac-old",
      observed_at: older,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "ssid" => "old-lab",
        "location_id" => "first-floor"
      }
    )
    insert_sync_ingest(
      dedupe_key: "inventory-mac-new",
      observed_at: newer,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "ssid" => "new-lab",
        "location_id" => "second-floor"
      }
    )

    get inventory_identities_url(format: :json)

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal ["00:11:22:33:44:55"], json.map { |row| row["source_mac"] }
    assert_equal "new-lab", json.first["ssid"]
    assert_equal 2, json.first["occurrence_count"]
    assert_in_delta newer.to_f, Time.zone.parse(json.first["last_occurred_at"]).to_f, 0.01
  end

  test "inventory json uses cache until ttl expires" do
    insert_sync_ingest(
      dedupe_key: "inventory-cache-1",
      observed_at: 2.minutes.ago,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "ssid" => "cached-lab"
      }
    )

    get inventory_identities_url(format: :json, q: "cached-lab")
    assert_response :success
    assert_equal ["00:11:22:33:44:55"], JSON.parse(response.body).map { |row| row["source_mac"] }

    insert_sync_ingest(
      dedupe_key: "inventory-cache-2",
      observed_at: Time.current,
      payload: {
        "source_mac" => "00:11:22:33:44:66",
        "ssid" => "cached-lab"
      }
    )

    get inventory_identities_url(format: :json, q: "cached-lab")
    assert_response :success
    assert_equal ["00:11:22:33:44:55"], JSON.parse(response.body).map { |row| row["source_mac"] }

    travel 61.seconds

    get inventory_identities_url(format: :json, q: "cached-lab")
    assert_response :success
    assert_equal ["00:11:22:33:44:66", "00:11:22:33:44:55"], JSON.parse(response.body).map { |row| row["source_mac"] }
  end

  test "mac summary returns registry labels and recent audit rows" do
    Device.create!(
      display_name: "Lobby Printer",
      username: "facilities",
      mac_hint: "00:11:22:33:44:55",
      hostname: "printer-lobby"
    )
    insert_sync_ingest(
      dedupe_key: "mac-summary-1",
      observed_at: Time.current,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "ssid" => "CorpWiFi",
        "location_id" => "lobby",
        "signal_dbm" => -40,
        "app_protocol" => "mdns",
        "session_key" => "session-1",
        "protected" => true
      }
    )

    get mac_summary_identities_url(format: :json, q: "00:11:22:33:44:55")

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "Lobby Printer", json.dig("device", "display_name")
    assert_equal "facilities", json.dig("device", "username")
    assert_equal "CorpWiFi", json.dig("inventory", "ssid")
    assert_equal(["mac-summary-1"], json.fetch("recentAuditLogs").map { |row| row["dedupe_key"] })

    get mac_summary_identities_url(format: :json, q: "11:22")

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "Lobby Printer", json.dig("device", "display_name")
    assert_equal(["mac-summary-1"], json.fetch("recentAuditLogs").map { |row| row["dedupe_key"] })
  end
end
