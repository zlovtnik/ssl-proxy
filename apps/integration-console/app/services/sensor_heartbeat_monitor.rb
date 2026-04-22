class SensorHeartbeatMonitor
  THRESHOLD = 5.minutes

  def call(now: Time.current)
    Sensor.where("last_seen_at IS NULL OR last_seen_at < ?", now - THRESHOLD).find_each do |sensor|
      alert = SensorAlert.open.find_or_initialize_by(sensor_id: sensor.sensor_id, alert_type: "missing_heartbeat")
      alert.severity = "critical"
      alert.message = "Sensor #{sensor.sensor_id} has not reported for more than 5 minutes"
      alert.save!
      sensor.update!(status: "stale")
      ActionCable.server.broadcast("sensor_alerts", alert.as_json)
    end
  end
end
