require "test_helper"

class BacklogControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("audit_backlog")
  end

  test "index paginates backlog entries and preserves status filter" do
    52.times do |index|
      insert_backlog(dedupe_key: "pending-#{index}", status: "pending", updated_at: index.minutes.ago)
    end
    insert_backlog(dedupe_key: "failed-1", status: "sync_failed")

    get backlog_index_url(status: "pending", page: 2)

    assert_response :success
    assert_includes response.body, "pending-1"
    assert_no_match(/failed-1/, response.body)
    assert_includes response.body, "status=pending"
  end
end
