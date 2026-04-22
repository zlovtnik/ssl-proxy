class SensorHealthChannel < ApplicationCable::Channel
  def subscribed
    stream_from "sensor_health"
  end
end
