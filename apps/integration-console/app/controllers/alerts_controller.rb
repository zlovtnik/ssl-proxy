class AlertsController < ApplicationController
  def index
    @alerts = SensorAlert.order(created_at: :desc).limit(200)
  end
end
