require "test_helper"

class SyncRecordTest < ActiveSupport::TestCase
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
end
