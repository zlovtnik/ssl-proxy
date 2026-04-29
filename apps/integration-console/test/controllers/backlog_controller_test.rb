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
    assert_includes response.body, "backlog-svelte-root"
  end

  test "index returns json payload for svelte page" do
    insert_backlog(dedupe_key: "pending-json", status: "pending")

    get backlog_index_url(format: :json, status: "pending")

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal ["pending-json"], json.fetch("rows").map { |row| row["dedupe_key"] }
    assert_equal "pending", json.fetch("status")
  end

  test "retry redirects with see other when backlog row is missing" do
    post retry_backlog_url("missing-row")

    assert_redirected_to backlog_index_path
    assert_response :see_other
  end
end
