require "test_helper"

class HeatmapControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
    ensure_wireless_heatmap_materialized_view
  end

  test "index paginates grouped heatmap rows" do
    51.times do |index|
      insert_sync_ingest(
        dedupe_key: "heatmap-#{index}",
        observed_at: index.minutes.ago,
        payload: {
          "location_id" => format("location-%02d", index),
          "signal_dbm" => "-40"
        }
      )
    end
    refresh_wireless_heatmap_materialized_view

    get heatmap_index_url(page: 2, sort: "location_id", direction: "asc")

    assert_response :success
    assert_includes response.body, "location-50"
    assert_includes response.body, "Page 2 of 2"
  end

  test "json payload includes visual locations and refresh staleness" do
    insert_sync_ingest(
      dedupe_key: "heatmap-json",
      observed_at: Time.current,
      payload: {
        "location_id" => "lab",
        "signal_dbm" => "-42"
      }
    )
    refresh_wireless_heatmap_materialized_view

    get heatmap_index_url(format: :json)

    assert_response :success
    assert_equal "public, s-maxage=300", response.headers["Cache-Control"]
    payload = JSON.parse(response.body)
    assert_equal "lab", payload.fetch("rows").first.fetch("location_id")
    assert_equal "lab", payload.fetch("visualLocations").first.fetch("location_id")
    assert payload.fetch("lastRefreshedAt").present?
    assert response.headers["Last-Modified"].present?
  end
end
