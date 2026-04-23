require "test_helper"

class HeatmapControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("sync_scan_ingest")
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

    get heatmap_index_url(page: 2, sort: "location_id", direction: "asc")

    assert_response :success
    assert_includes response.body, "location-50"
    assert_includes response.body, "Page 2 of 2"
  end
end
