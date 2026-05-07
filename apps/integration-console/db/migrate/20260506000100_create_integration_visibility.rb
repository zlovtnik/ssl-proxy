class CreateIntegrationVisibility < ActiveRecord::Migration[7.2]
  def change
    create_table :integration_configs, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.text :name, null: false
      t.text :slug, null: false
      t.text :source_type, null: false
      t.text :destination_type, null: false
      t.text :stream_name
      t.boolean :enabled, null: false, default: true
      t.text :schedule_cron
      t.jsonb :params, null: false
      t.jsonb :param_schema, null: false
      t.text :cursor_field

      t.timestamps
    end

    add_index :integration_configs, :slug, unique: true
    add_index :integration_configs, :enabled
    add_check_constraint :integration_configs,
      "slug ~ '^[a-z0-9-]+$'",
      name: "chk_integration_configs_slug_format"

    create_table :integration_runs, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.references :integration_config, null: false, type: :uuid, foreign_key: true
      t.uuid :sync_job_id
      t.text :triggered_by, null: false, default: "schedule"
      t.text :status, null: false, default: "pending"
      t.text :range_type, null: false, default: "cursor"
      t.text :from_value
      t.text :to_value
      t.jsonb :params_snapshot, null: false, default: {}
      t.text :error_summary
      t.timestamptz :started_at
      t.timestamptz :finished_at

      t.timestamps
    end

    add_index :integration_runs, [:integration_config_id, :created_at]
    add_index :integration_runs, [:integration_config_id, :triggered_by, :created_at],
      name: "idx_on_integration_config_id_triggered_by_created_at",
      order: { created_at: :desc }
    add_index :integration_runs, [:integration_config_id, :status, :created_at],
      name: "idx_on_integration_config_id_status_created_at",
      order: { created_at: :desc }
    add_index :integration_runs, [:status, :created_at]
    add_index :integration_runs, :sync_job_id
    add_check_constraint :integration_runs,
      "triggered_by = ANY (ARRAY['schedule'::text, 'manual'::text, 'replay'::text])",
      name: "chk_integration_runs_triggered_by"
    add_check_constraint :integration_runs,
      "status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])",
      name: "chk_integration_runs_status"
    add_check_constraint :integration_runs,
      "range_type = ANY (ARRAY['cursor'::text, 'datetime'::text])",
      name: "chk_integration_runs_range_type"
  end
end
