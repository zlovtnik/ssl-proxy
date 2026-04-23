require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  setup do
    Sensor.delete_all
  end

  test "index paginates sensors table with default page size" do
    26.times do |index|
      Sensor.create!(
        sensor_id: format("sensor-%02d", index),
        location_id: "lab",
        last_seen_at: index.minutes.ago,
        status: "online"
      )
    end

    get root_url(page: 2)

    assert_response :success
    assert_includes response.body, "sensor-25"
    assert_includes response.body, "Page 2 of 2"
  end
end
