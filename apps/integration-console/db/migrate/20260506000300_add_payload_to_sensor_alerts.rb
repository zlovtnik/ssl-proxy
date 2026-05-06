class AddPayloadToSensorAlerts < ActiveRecord::Migration[7.2]
  def change
    add_column :sensor_alerts, :payload, :jsonb, null: false, default: {}
  end
end
