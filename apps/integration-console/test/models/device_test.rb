require "test_helper"

class DeviceTest < ActiveSupport::TestCase
  setup do
    Device.delete_all
  end

  test "normalizes mac hints" do
    device = Device.create!(display_name: "Phone", mac_hint: "AA-BB-CC-DD-EE-FF")

    assert_equal "aa:bb:cc:dd:ee:ff", device.mac_hint
    assert device.device_id.present?
  end

  test "rejects malformed mac hints" do
    device = Device.new(display_name: "Bad", mac_hint: "not-a-mac")

    assert_not device.valid?
  end

  test "search normalizes mac-like queries" do
    device = Device.create!(display_name: "Phone", mac_hint: "AA-BB-CC-DD-EE-FF")

    assert_equal [device], Device.search("aabbccddeeff").to_a
    assert_equal [device], Device.search("aa-bb-cc-dd-ee-ff").to_a
  end
end
