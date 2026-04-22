require "test_helper"

class SyncRecordTest < ActiveSupport::TestCase
  test "sync models are read only" do
    record = AuditLog.allocate

    assert record.readonly?
  end
end
