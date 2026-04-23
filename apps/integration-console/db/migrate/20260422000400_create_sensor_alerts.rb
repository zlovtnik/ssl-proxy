class CreateSensorAlerts < ActiveRecord::Migration[7.2]
  def change
    create_table :sensor_alerts do |t|
      t.string :sensor_id, null: false
      t.string :alert_type, null: false
      t.string :severity, null: false
      t.text :message, null: false
      t.datetime :resolved_at

      t.timestamps
    end

    add_index :sensor_alerts, [:sensor_id, :alert_type, :resolved_at], name: "idx_sensor_alerts_sensor_type_open"
  end
end
