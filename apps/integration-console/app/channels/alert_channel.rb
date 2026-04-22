class AlertChannel < ApplicationCable::Channel
  def subscribed
    stream_from "sensor_alerts"
  end
end
