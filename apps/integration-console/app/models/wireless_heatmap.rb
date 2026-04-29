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

    connection.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_wireless_heatmap")
    Rails.cache.delete_matched("heatmap:payload:*")
    true
  ensure
    redis.del(lock_key) if acquired && redis.get(lock_key) == token
    redis.close if owns_redis && redis.respond_to?(:close)
  end

  def self.last_refreshed_at
    maximum(:last_seen_at)
  end
end
