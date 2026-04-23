require "test_helper"

class IdentitiesControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
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

  test "inventory exports csv and json summaries" do
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

    get inventory_identities_url(format: :csv)

    assert_response :success
    assert_includes response.body, "source_mac"
    assert_includes response.body, "00:11:22:33:44:55"
    assert_includes response.body, "printer.local"
  end
end
