require "test_helper"

class AuthorizedWirelessNetworkTest < ActiveSupport::TestCase
  setup do
    AuthorizedWirelessNetwork.delete_all
  end

  test "requires an ssid or bssid" do
    network = AuthorizedWirelessNetwork.new

    assert_not network.valid?
    assert_includes network.errors[:ssid], "can't be blank"
    assert_includes network.errors[:bssid], "can't be blank"
  end

  test "normalizes bssid" do
    network = AuthorizedWirelessNetwork.create!(ssid: "CorpWiFi", bssid: "AA:BB:CC:DD:EE:FF")

    assert_equal "aa:bb:cc:dd:ee:ff", network.bssid
  end
end
