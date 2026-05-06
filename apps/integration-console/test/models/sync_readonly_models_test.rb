require "test_helper"

class SyncReadonlyModelsTest < ActiveSupport::TestCase
  test "sync models reject writes" do
    assert_raises(ActiveRecord::ReadOnlyRecord) { SyncCursor.delete_all }
    assert_raises(ActiveRecord::ReadOnlyRecord) { SyncBatch.delete_all }
    assert_raises(ActiveRecord::ReadOnlyRecord) { SyncJob.delete_all }
    assert_raises(ActiveRecord::ReadOnlyRecord) { SyncError.delete_all }
  end
end
