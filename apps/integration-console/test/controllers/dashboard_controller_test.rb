require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  setup do
    Sensor.delete_all
    SensorAlert.delete_all
    NatsTrafficSample.delete_all
    clear_sync_tables("audit_backlog")
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

  test "json cards use conditional response and combined backlog counts" do
    Sensor.create!(sensor_id: "sensor-online", location_id: "lab", last_seen_at: Time.current, status: "online")
    insert_backlog(dedupe_key: "pending-1", status: "pending")
    insert_backlog(dedupe_key: "failed-1", status: "failed")
    insert_backlog(dedupe_key: "sync-failed-1", status: "sync_failed")

    get root_url(format: :json)

    assert_response :success
    payload = JSON.parse(response.body)
    backlog = payload.fetch("counts")
    assert_equal 1, backlog.fetch("pending_backlog")
    assert_equal 2, backlog.fetch("failed_backlog")
    etag = response.headers.fetch("ETag")

    get root_url(format: :json), headers: { "If-None-Match" => etag }

    assert_response :not_modified
    assert_empty response.body
  end
end
