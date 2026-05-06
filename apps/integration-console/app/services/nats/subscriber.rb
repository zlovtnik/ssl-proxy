require "json"
require "nats/client"

module Nats
  class Subscriber
    def self.configured_subjects
      IntegrationConfig.enabled
        .where(source_type: "nats")
        .order(:slug)
        .filter_map { |config| config.params.to_h["subject"].to_s.strip.presence }
        .uniq
    end

    def initialize(url: ENV.fetch("SYNC_NATS_URL", "nats://127.0.0.1:4222"), client: nil, subjects: nil)
      @url = url
      @client = client
      @subjects = subjects
    end

    def run_forever
      client = @client || NATS.connect(servers: [@url])
      subscribe_configured(client)
      sleep
    ensure
      client&.close unless @client
    end

    def subscribe_configured(client)
      subjects.each do |subject|
        client.subscribe(subject) { |message| handle(subject, message) }
      end
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
        ActionCable.server.broadcast("sensor_health", { subject: subject, payload: payload })
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
  end
end
