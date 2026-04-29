require "test_helper"

class WirelessHeatmapTest < ActiveSupport::TestCase
  class LockedRedis
    def set(*) = false
    def get(*) = nil
    def del(*) = true
  end

  setup do
    clear_sync_tables("sync_scan_ingest")
    ensure_wireless_heatmap_materialized_view
  end

  test "refresh skips when redis mutex is already held" do
    assert_equal false, WirelessHeatmap.refresh!(redis: LockedRedis.new)
  end
end
