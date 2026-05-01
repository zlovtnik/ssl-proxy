require "test_helper"

class AuthorizedWirelessNetworksControllerTest < ActionDispatch::IntegrationTest
  setup do
    AuthorizedWirelessNetwork.delete_all
  end

  test "index renders configured networks" do
    AuthorizedWirelessNetwork.create!(ssid: "CorpWiFi", bssid: "10:20:30:40:50:60", location_id: "lab")

    get authorized_wireless_networks_url

    assert_response :success
    assert_includes response.body, "CorpWiFi"
    assert_includes response.body, "10:20:30:40:50:60"
    assert_includes response.body, "authorized-wireless-svelte-root"
  end

  test "index returns json payload for svelte page" do
    AuthorizedWirelessNetwork.create!(ssid: "CorpWiFi", bssid: "10:20:30:40:50:60", location_id: "lab")

    get authorized_wireless_networks_url(format: :json)

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal ["CorpWiFi"], json.fetch("rows").map { |row| row["ssid"] }
  end

  test "create saves authorized network" do
    assert_difference("AuthorizedWirelessNetwork.count", 1) do
      post authorized_wireless_networks_url, params: {
        authorized_wireless_network: {
          ssid: "CorpWiFi",
          bssid: "10:20:30:40:50:60",
          location_id: "lab",
          enabled: "1"
        }
      }
    end

    assert_redirected_to authorized_wireless_networks_path
    assert_response :see_other
  end
end
