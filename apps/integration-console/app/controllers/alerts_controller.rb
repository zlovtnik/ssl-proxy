class AlertsController < ApplicationController
  def index
    SensorHeartbeatMonitor.new.call
    @alerts = SensorAlert.order(created_at: :desc).limit(200)
  end
end
