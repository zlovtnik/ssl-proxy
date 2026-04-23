class CreateAuditWindows < ActiveRecord::Migration[7.2]
  def change
    create_table :audit_windows do |t|
      t.string :location_id, null: false
      t.string :timezone, null: false, default: "UTC"
      t.string :days
      t.time :start_time
      t.time :end_time
      t.boolean :enabled, null: false, default: true

      t.timestamps
    end

    add_index :audit_windows, :location_id, unique: true
  end
end
