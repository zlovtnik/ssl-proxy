class CreateNatsTrafficSamples < ActiveRecord::Migration[7.2]
  def change
    create_table :nats_traffic_samples do |t|
      t.string :subject, null: false
      t.string :sensor_id
      t.datetime :sampled_at, null: false
      t.integer :event_count, null: false, default: 0

      t.timestamps
    end

    add_index :nats_traffic_samples, [:subject, :sensor_id, :sampled_at], unique: true, name: "idx_nats_samples_subject_sensor_time"
    add_index :nats_traffic_samples, :sampled_at
  end
end
