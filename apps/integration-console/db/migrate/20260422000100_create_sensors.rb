class CreateSensors < ActiveRecord::Migration[7.2]
  def change
    create_table :sensors do |t|
      t.string :sensor_id, null: false
      t.string :location_id, null: false
      t.string :interface
      t.integer :channel
      t.integer :last_signal_dbm
      t.datetime :last_seen_at
      t.string :status, null: false, default: "unknown"

      t.timestamps
    end

    add_index :sensors, :sensor_id, unique: true
    add_index :sensors, [:status, :last_seen_at]
  end
end
