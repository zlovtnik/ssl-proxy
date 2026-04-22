require "test_helper"

class BacklogStatusTest < ActiveSupport::TestCase
  setup do
    clear_sync_tables("audit_backlog")
  end

  test "failed scope includes sync failed and failed statuses" do
    insert_backlog(dedupe_key: "pending", status: "pending")
    insert_backlog(dedupe_key: "sync-failed", status: "sync_failed")
    insert_backlog(dedupe_key: "failed", status: "failed")

    assert_equal ["failed", "sync-failed"], BacklogStatus.failed.order(:dedupe_key).pluck(:dedupe_key)
  end
end
