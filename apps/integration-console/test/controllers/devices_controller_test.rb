require "test_helper"

class DevicesControllerTest < ActionDispatch::IntegrationTest
  setup do
    Device.delete_all
  end

  test "index renders configured mac identifiers" do
    Device.create!(display_name: "Lobby Printer", username: "facilities", mac_hint: "00:11:22:33:44:55")

    get devices_url

    assert_response :success
    assert_includes response.body, "devices-svelte-root"
    assert_includes response.body, "Lobby Printer"
    assert_includes response.body, "00:11:22:33:44:55"
  end

  test "index returns json payload" do
    Device.create!(display_name: "Lobby Printer", username: "facilities", mac_hint: "00:11:22:33:44:55")

    get devices_url(format: :json, q: "printer")

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal(["Lobby Printer"], json.fetch("rows").map { |row| row["display_name"] })
  end

  test "create saves mac identifier" do
    assert_difference("Device.count", 1) do
      post devices_url, params: {
        device: {
          display_name: "Lobby Printer",
          username: "facilities",
          mac_hint: "00:11:22:33:44:55"
        }
      }
    end

    assert_redirected_to devices_path
    assert_equal "00:11:22:33:44:55", Device.last.mac_hint
    assert_equal "00:11:22:33:44:55", Device.last.mac_id
  end

  test "create rejects duplicate mac identifier" do
    Device.create!(display_name: "Lobby Printer", username: "facilities", mac_hint: "00:11:22:33:44:55")

    assert_no_difference("Device.count") do
      post devices_url(format: :json), params: {
        device: {
          display_name: "Duplicate",
          mac_hint: "0011.2233.4455"
        }
      }
    end

    assert_response :unprocessable_entity
    assert_includes JSON.parse(response.body).fetch("errors").join(" "), "already been taken"
  end

  test "json create reports validation errors" do
    post devices_url(format: :json), params: {
      device: {
        display_name: "Bad",
        mac_hint: "not-a-mac"
      }
    }

    assert_response :unprocessable_entity
    assert_includes JSON.parse(response.body).fetch("errors").join(" "), "Mac hint"
  end
end
