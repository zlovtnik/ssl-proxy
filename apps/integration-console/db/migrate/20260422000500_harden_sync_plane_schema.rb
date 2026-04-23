class HardenSyncPlaneSchema < ActiveRecord::Migration[7.2]
  def change
    add_column :sync_batch, :created_at, :timestamptz, null: false, default: -> { "now()" }, if_not_exists: true
    add_column :sync_batch, :updated_at, :timestamptz, null: false, default: -> { "now()" }, if_not_exists: true

    add_check_constraint :sync_job,
      "status IN ('pending','running','completed','failed')",
      name: "chk_sync_job_status",
      if_not_exists: true

    add_check_constraint :sync_batch,
      "status IN ('pending','processing','dispatched','completed','failed')",
      name: "chk_sync_batch_status",
      if_not_exists: true

    add_check_constraint :audit_backlog,
      "status IN ('pending','synced','sync_failed','failed')",
      name: "chk_audit_backlog_status",
      if_not_exists: true

    add_foreign_key :sync_job,
      :sync_cursor,
      column: :stream_name,
      primary_key: :stream_name,
      name: "fk_sync_job_stream_name",
      if_not_exists: true,
      deferrable: :deferred

    add_foreign_key :sync_batch,
      :sync_job,
      column: :job_id,
      primary_key: :job_id,
      name: "fk_sync_batch_job_id",
      if_not_exists: true

    add_foreign_key :sync_error,
      :sync_job,
      column: :job_id,
      primary_key: :job_id,
      name: "fk_sync_error_job_id",
      if_not_exists: true

    add_foreign_key :sync_error,
      :sync_batch,
      column: :batch_id,
      primary_key: :batch_id,
      name: "fk_sync_error_batch_id",
      if_not_exists: true

    add_index :sync_job, :stream_name, name: "idx_sync_job_stream_name", if_not_exists: true
    add_index :sync_job, [:status, :created_at], name: "idx_sync_job_status_created_at", if_not_exists: true
    add_index :sync_batch, [:job_id, :batch_no], name: "idx_sync_batch_job_batch_no", if_not_exists: true
    add_index :sync_batch, :status, name: "idx_sync_batch_status", if_not_exists: true
    add_index :sync_error, :job_id, name: "idx_sync_error_job_id", if_not_exists: true
    add_index :sync_error, :batch_id, name: "idx_sync_error_batch_id", if_not_exists: true
    add_index :sensors, :location_id, name: "idx_sensors_location_id", if_not_exists: true
    add_index :sensor_alerts, [:severity, :resolved_at], name: "idx_sensor_alerts_severity_resolved_at", if_not_exists: true
    add_index :nats_traffic_samples, [:sensor_id, :sampled_at], name: "idx_nats_traffic_samples_sensor_sampled_at", if_not_exists: true

    reversible do |dir|
      dir.up { raise_on_duplicate_open_alerts! }
    end

    add_index :sensor_alerts,
      [:sensor_id, :alert_type],
      unique: true,
      where: "resolved_at IS NULL",
      name: "idx_sensor_alerts_open_unique",
      if_not_exists: true
  end

  private

  def raise_on_duplicate_open_alerts!
    duplicate = select_one(<<~SQL.squish)
      SELECT sensor_id, alert_type, COUNT(*) AS duplicate_count
      FROM sensor_alerts
      WHERE resolved_at IS NULL
      GROUP BY sensor_id, alert_type
      HAVING COUNT(*) > 1
      LIMIT 1
    SQL

    return if duplicate.blank?

    raise ActiveRecord::IrreversibleMigration,
      "Cannot add open alert uniqueness constraint: sensor_id=#{duplicate["sensor_id"]} alert_type=#{duplicate["alert_type"]} has #{duplicate["duplicate_count"]} open rows"
  end
end
