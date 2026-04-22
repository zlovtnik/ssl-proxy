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
end
