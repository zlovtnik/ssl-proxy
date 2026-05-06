require "redis"
require "securerandom"

class WirelessHeatmap < SyncRecord
  self.table_name = "mv_wireless_heatmap"
  self.primary_key = "location_id"

  scope :ordered_by_events, -> { order(event_count: :desc) }

  def self.refresh!(redis: nil)
    owns_redis = redis.nil?
    redis ||= Redis.new(url: ENV.fetch("INTEGRATION_CONSOLE_REDIS_URL", "redis://127.0.0.1:6379/1"))
    lock_key = "heatmap:refresh:lock"
    token = SecureRandom.uuid
    lock_ttl = IntegrationConsole::CacheTtl.heatmap.to_i + 10
    acquired = redis.set(lock_key, token, nx: true, ex: lock_ttl)
    return false unless acquired

    refresh_materialized_view
    Rails.cache.delete_matched("heatmap:payload:*")
    true
  ensure
    redis.del(lock_key) if acquired && redis.get(lock_key) == token
    redis.close if owns_redis && redis.respond_to?(:close)
  end

  def self.last_refreshed_at
    maximum(:last_seen_at)
  end

  def self.refresh_materialized_view
    connection_pool.with_connection do |conn|
      conn.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY #{conn.quote_table_name(table_name)}")
    end
  rescue ActiveRecord::StatementInvalid => error
    raise unless missing_concurrent_refresh_index?(error)

    Rails.logger.warn(
      "Falling back to non-concurrent wireless heatmap refresh because the materialized view is missing its unique index"
    )
    connection_pool.with_connection do |conn|
      conn.execute("REFRESH MATERIALIZED VIEW #{conn.quote_table_name(table_name)}")
    end
  end

  def self.missing_concurrent_refresh_index?(error)
    message = error.message
    message.include?("cannot refresh materialized view") &&
      message.include?("concurrently") &&
      message.include?("unique index")
  end
end
