require "test_helper"

class SyncRecordTest < ActiveSupport::TestCase
  setup do
    clear_sync_tables("sync_scan_ingest")
  end

  test "sync models are read only" do
    record = AuditLog.allocate

    assert record.readonly?
  end

  test "sync models reject callback bypass mutators" do
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.allocate.delete }
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.delete("dedupe-key") }
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.delete_all }
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.update_all(status: "pending") }
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.insert_all([{ dedupe_key: "dedupe-key" }]) }
    assert_raises(ActiveRecord::ReadOnlyRecord) { AuditLog.upsert_all([{ dedupe_key: "dedupe-key" }]) }
  end

  test "insert_sync_ingest persists promoted payload keys without helper updates" do
    insert_sync_ingest(
      dedupe_key: "promoted-columns",
      observed_at: Time.current,
      payload: {
        "sensor_id" => "sensor-1",
        "adjacent_mac_hint" => "aa:bb:cc:dd:ee:ff",
        "tsft_delta_us" => 1234,
        "wall_clock_delta_ms" => 56
      }
    )

    entry = AuditLog.find("promoted-columns")

    assert_equal "aa:bb:cc:dd:ee:ff", entry.read_attribute(:adjacent_mac_hint)
    assert_equal 1234, entry.tsft_delta_us
    assert_equal 56, entry.wall_clock_delta_ms
  end
end
