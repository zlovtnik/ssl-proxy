require "digest/sha1"

class DashboardCache
  KEY_PREFIX = "dashboard:cards"

  def self.fetch(&block)
    Rails.cache.fetch("#{KEY_PREFIX}:#{version_digest}", expires_in: IntegrationConsole::CacheTtl.dashboard, &block)
  end

  def self.expire!
    Rails.cache.delete_matched("#{KEY_PREFIX}:*")
  end

  def self.version_digest
    Digest::SHA1.hexdigest(
      [
        Sensor.maximum(:updated_at)&.to_i,
        SensorAlert.maximum(:updated_at)&.to_i,
        NatsTrafficSample.maximum(:updated_at)&.to_i,
        BacklogStatus.maximum(:updated_at)&.to_i
      ].join(":")
    )
  end
end
