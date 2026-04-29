require "test_helper"

class IdentitiesControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
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
    assert_includes response.body, "Page 2 of 2"
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
    assert_includes json.first["services"], "ssdp"

    captured_csv = nil
    ExportStore.stub(:fetch_or_generate, ->(key:, ttl:, &block) {
      captured_csv = block.call
      "http://minio.test/inventory.csv"
    }) do
      get inventory_identities_url(format: :csv)
    end

    assert_redirected_to "http://minio.test/inventory.csv"
    assert_includes captured_csv, "source_mac"
    assert_includes captured_csv, "00:11:22:33:44:55"
    assert_includes captured_csv, "printer.local"
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
end
