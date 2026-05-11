require "json"
require "nats/client"

module Nats
  class Subscriber
    INTEGRATION_CACHE_TTL = 30.seconds

    def self.configured_subjects
      IntegrationConfig.enabled
        .where(source_type: "nats")
        .order(:slug)
        .filter_map { |config| config.params.to_h["subject"].to_s.strip.presence }
        .uniq
    end

    def initialize(url: ENV.fetch("SYNC_NATS_URL", "nats://127.0.0.1:4222"), client: nil, subjects: nil, run_wireless_worker: true)
      @url = url
      @client = client
      @subjects = subjects
      @integration_by_subject = nil
      @integration_by_subject_expires_at = nil
      @run_wireless_worker = run_wireless_worker
      @wireless_worker = nil
    end

    def run_forever
      owns_client = @client.nil?
      @client ||= NATS.connect(servers: [@url])
      subscribe_configured
      start_wireless_worker if @run_wireless_worker
      sleep
    ensure
      @wireless_worker&.stop
      @client&.close if owns_client
      @client = nil if owns_client
    end

    def subscribe_configured
      raise ArgumentError, "NATS client is required" unless @client

      subjects.each do |subject|
        @client.subscribe(subject) { |message| handle(subject, message) }
      end
    end

    def reset_integration_cache!
      @integration_by_subject = nil
      @integration_by_subject_expires_at = nil
    end

    def handle(subject, message)
      payload = decode(message)
      sensor_id = payload["sensor_id"]
      NatsTrafficSample.increment!(subject: subject, sensor_id: sensor_id)

      if subject == "wireless.audit"
        update_sensor(payload)
        ActionCable.server.broadcast("live_audit", payload)
      elsif subject == "wifi.alert.handshake"
        record_handshake_alert(payload)
      elsif subject == "audit.threat.shadow_device"
        ActionCable.server.broadcast("sensor_alerts", { alert_type: "shadow_device", payload: payload })
      else
        broadcast_unhandled_subject(subject, payload, sensor_id)
      end
    end

    private

    def subjects
      (@subjects || self.class.configured_subjects).filter_map { |subject| subject.to_s.strip.presence }.uniq
    end

    def decode(message)
      JSON.parse(message.respond_to?(:data) ? message.data : message.to_s)
    rescue JSON::ParserError
      { "raw" => message.to_s }
    end

    def broadcast_unhandled_subject(subject, payload, sensor_id)
      integration = integration_for_subject(subject)
      unless integration
        Rails.logger.info("Unhandled NATS subject #{subject} for sensor #{sensor_id.presence || "unknown"}")
        return
      end

      Rails.logger.info("Forwarding unhandled NATS subject #{subject} for integration #{integration.slug}")
      ActionCable.server.broadcast("integration:#{integration.slug}", { subject: subject, payload: payload })
    end

    def integration_for_subject(subject)
      integration_by_subject[subject]
    end

    def integration_by_subject
      now = Time.current
      if @integration_by_subject && @integration_by_subject_expires_at && @integration_by_subject_expires_at > now
        return @integration_by_subject
      end

      @integration_by_subject = IntegrationConfig.enabled.where(source_type: "nats").each_with_object({}) do |config, memo|
        subject = config.params.to_h["subject"].to_s.strip
        memo[subject] = config if subject.present?
      end
      @integration_by_subject_expires_at = now + INTEGRATION_CACHE_TTL
      @integration_by_subject
    end

    def update_sensor(payload)
      sensor_id = payload["sensor_id"].presence
      return unless sensor_id

      sensor = Sensor.find_or_create_by!(sensor_id: sensor_id) do |record|
        record.location_id = payload["location_id"].presence || "unknown"
      end
      sensor.with_lock do
        sensor.location_id ||= payload["location_id"].presence || "unknown"
        sensor.mark_seen!(payload)
      end
      ActionCable.server.broadcast(
        "sensor_health",
        {
          sensor_id: sensor.sensor_id,
          location_id: sensor.location_id,
          last_seen_at: sensor.last_seen_at,
          status: sensor.status
        }
      )
    end

    def record_handshake_alert(payload)
      sensor_id = payload["sensor_id"].presence || "unknown"
      bssid = payload["bssid"].presence || "unknown"
      client_mac = payload["client_mac"].presence || "unknown"
      alert = SensorAlert.open.find_or_initialize_by(
        sensor_id: sensor_id,
        alert_type: "handshake_captured"
      )
      alert.severity = "critical"
      alert.message = "4-way handshake captured for BSSID #{bssid} client #{client_mac}"
      alert.payload = SensorAlert.sanitize_payload(payload)
      alert.save!
      ActionCable.server.broadcast("sensor_alerts", alert.as_json)
    end

    def start_wireless_worker
      return if @wireless_worker
      return unless @client

      @wireless_worker = WirelessWorker.new(client: @client)
      Thread.new { @wireless_worker.run_forever }
      Rails.logger.info("[Subscriber] Wireless worker thread started")
    end
  end
end
