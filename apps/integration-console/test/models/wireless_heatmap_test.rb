require "test_helper"

class WirelessHeatmapTest < ActiveSupport::TestCase
  class LockedRedis
    def set(*) = false
    def get(*) = nil
    def del(*) = true
  end

  class UnlockedRedis
    attr_reader :token

    def set(_key, token, **_options)
      @token = token
      true
    end

    def get(*) = token
    def del(*) = true
  end

  class MissingConcurrentIndexConnection
    attr_reader :statements

    def initialize
      @statements = []
    end

    def execute(statement)
      statements << statement
      return true unless statement == "REFRESH MATERIALIZED VIEW CONCURRENTLY \"mv_wireless_heatmap\""

      raise ActiveRecord::StatementInvalid, <<~MSG.squish
        PG::ObjectNotInPrerequisiteState: ERROR: cannot refresh materialized view "public.mv_wireless_heatmap" concurrently
        HINT: Create a unique index with no WHERE clause on one or more columns of the materialized view.
      MSG
    end

    def quote_table_name(name)
      %("#{name}")
    end
  end

  class FakeConnectionPool
    def initialize(connection)
      @connection = connection
    end

    def with_connection
      yield @connection
    end
  end

  setup do
    clear_sync_tables("sync_scan_ingest")
    ensure_wireless_heatmap_materialized_view
  end

  test "refresh skips when redis mutex is already held" do
    assert_equal false, WirelessHeatmap.refresh!(redis: LockedRedis.new)
  end

  test "refresh falls back when concurrent index is missing" do
    fake_connection = MissingConcurrentIndexConnection.new

    WirelessHeatmap.stub(:connection_pool, FakeConnectionPool.new(fake_connection)) do
      assert_equal true, WirelessHeatmap.refresh!(redis: UnlockedRedis.new)
    end

    assert_equal [
      "REFRESH MATERIALIZED VIEW CONCURRENTLY \"mv_wireless_heatmap\"",
      "REFRESH MATERIALIZED VIEW \"mv_wireless_heatmap\""
    ], fake_connection.statements
  end
end
