# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.2].define(version: 2026_04_22_000600) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "plpgsql"

  create_table "audit_backlog", primary_key: "dedupe_key", id: :text, force: :cascade do |t|
    t.text "stream_name", null: false
    t.text "payload", null: false
    t.text "status", default: "pending", null: false
    t.integer "attempt_count", default: 0, null: false
    t.text "last_error"
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
    t.index ["status", "updated_at"], name: "audit_backlog_status_idx"
  end

  create_table "audit_windows", force: :cascade do |t|
    t.string "location_id", null: false
    t.string "timezone", default: "UTC", null: false
    t.string "days"
    t.time "start_time"
    t.time "end_time"
    t.boolean "enabled", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["location_id"], name: "index_audit_windows_on_location_id", unique: true
  end

  create_table "devices", primary_key: "device_id", id: :text, force: :cascade do |t|
    t.text "wg_pubkey"
    t.text "claim_token_hash"
    t.text "display_name"
    t.text "username"
    t.text "hostname"
    t.text "os_hint"
    t.text "mac_hint"
    t.timestamptz "first_seen", default: -> { "now()" }, null: false
    t.timestamptz "last_seen", default: -> { "now()" }, null: false
    t.text "notes"
    t.index "lower(mac_hint)", name: "devices_mac_hint_idx"
    t.index ["username", "last_seen"], name: "devices_username_idx", order: { last_seen: :desc }
    t.index ["wg_pubkey"], name: "devices_wg_pubkey_idx"
  end

  create_table "nats_traffic_samples", force: :cascade do |t|
    t.string "subject", null: false
    t.string "sensor_id"
    t.datetime "sampled_at", null: false
    t.integer "event_count", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["sensor_id", "sampled_at"], name: "idx_nats_traffic_samples_sensor_sampled_at"
    t.index ["sampled_at"], name: "index_nats_traffic_samples_on_sampled_at"
    t.index ["subject", "sensor_id", "sampled_at"], name: "idx_nats_samples_subject_sensor_time", unique: true
  end

  create_table "sensor_alerts", force: :cascade do |t|
    t.string "sensor_id", null: false
    t.string "alert_type", null: false
    t.string "severity", null: false
    t.text "message", null: false
    t.datetime "resolved_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["sensor_id", "alert_type"], name: "idx_sensor_alerts_open_unique", unique: true, where: "(resolved_at IS NULL)"
    t.index ["sensor_id", "alert_type", "resolved_at"], name: "idx_sensor_alerts_sensor_type_open"
    t.index ["severity", "resolved_at"], name: "idx_sensor_alerts_severity_resolved_at"
  end

  create_table "sensors", force: :cascade do |t|
    t.string "sensor_id", null: false
    t.string "location_id", null: false
    t.string "interface"
    t.integer "channel"
    t.integer "last_signal_dbm"
    t.datetime "last_seen_at"
    t.string "status", default: "unknown", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["location_id"], name: "idx_sensors_location_id"
    t.index ["sensor_id"], name: "index_sensors_on_sensor_id", unique: true
    t.index ["status", "last_seen_at"], name: "index_sensors_on_status_and_last_seen_at"
  end

  create_table "sync_batch", primary_key: "batch_id", id: :uuid, default: nil, force: :cascade do |t|
    t.uuid "job_id", null: false
    t.integer "batch_no", null: false
    t.text "payload_ref", null: false
    t.text "status", null: false
    t.integer "row_count"
    t.text "checksum"
    t.integer "attempt_count", default: 0, null: false
    t.text "last_error"
    t.text "dedupe_key", null: false
    t.text "cursor_start", null: false
    t.text "cursor_end", null: false
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
    t.index ["dedupe_key"], name: "sync_batch_dedupe_idx", unique: true
    t.index ["job_id", "batch_no"], name: "idx_sync_batch_job_batch_no"
    t.index ["status"], name: "idx_sync_batch_status"
  end

  create_table "sync_cursor", primary_key: "stream_name", id: :text, force: :cascade do |t|
    t.text "cursor_value", null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
  end

  create_table "sync_error", force: :cascade do |t|
    t.uuid "job_id"
    t.uuid "batch_id"
    t.text "error_class", null: false
    t.text "error_text", null: false
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.index ["batch_id"], name: "idx_sync_error_batch_id"
    t.index ["job_id"], name: "idx_sync_error_job_id"
  end

  create_table "sync_job", primary_key: "job_id", id: :uuid, default: nil, force: :cascade do |t|
    t.text "stream_name", null: false
    t.text "status", null: false
    t.integer "attempt_count", default: 0, null: false
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "started_at"
    t.timestamptz "finished_at"
    t.index ["status", "created_at"], name: "idx_sync_job_status_created_at"
    t.index ["stream_name"], name: "idx_sync_job_stream_name"
  end

  create_table "sync_scan_ingest", primary_key: "dedupe_key", id: :text, force: :cascade do |t|
    t.text "stream_name", null: false
    t.timestamptz "observed_at", null: false
    t.text "payload_ref", null: false
    t.jsonb "payload"
    t.text "payload_sha256"
    t.text "status", default: "pending", null: false
    t.integer "attempt_count", default: 0, null: false
    t.text "last_error"
    t.text "producer", default: "unknown", null: false
    t.text "event_kind"
    t.integer "security_flags", default: 0, null: false
    t.text "wps_device_name"
    t.text "wps_manufacturer"
    t.text "wps_model_name"
    t.text "device_fingerprint"
    t.boolean "handshake_captured", default: false, null: false
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
    t.index "((payload -> 'tags'::text))", name: "ssi_wireless_threat_tags_idx", where: "(stream_name = 'wireless.audit'::text)", using: :gin
    t.index "((payload ->> 'source_mac'::text))", name: "ssi_wireless_source_mac_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "((payload ->> 'ssid'::text)), observed_at DESC", name: "ssi_wireless_ssid_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "device_fingerprint, observed_at DESC", name: "ssi_wireless_device_fingerprint_idx", where: "((stream_name = 'wireless.audit'::text) AND (device_fingerprint IS NOT NULL))"
    t.index "observed_at DESC", name: "ssi_wireless_handshake_captured_idx", where: "((stream_name = 'wireless.audit'::text) AND handshake_captured)"
    t.index "security_flags, observed_at DESC", name: "ssi_wireless_security_flags_idx", where: "((stream_name = 'wireless.audit'::text) AND (security_flags <> 0))"
    t.index ["observed_at"], name: "ssi_pending_observed_idx", where: "(status = ANY (ARRAY['pending'::text, 'failed'::text]))"
    t.index ["status", "observed_at"], name: "sync_scan_ingest_status_idx"
    t.index ["stream_name", "observed_at"], name: "sync_scan_ingest_stream_idx"
  end

  add_check_constraint "audit_backlog", "status = ANY (ARRAY['pending'::text, 'synced'::text, 'sync_failed'::text, 'failed'::text])", name: "chk_audit_backlog_status"
  add_check_constraint "sync_batch", "status = ANY (ARRAY['pending'::text, 'processing'::text, 'dispatched'::text, 'completed'::text, 'failed'::text])", name: "chk_sync_batch_status"
  add_check_constraint "sync_job", "status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])", name: "chk_sync_job_status"
  add_foreign_key "sync_batch", "sync_job", column: "job_id", primary_key: "job_id", name: "fk_sync_batch_job_id"
  add_foreign_key "sync_error", "sync_batch", column: "batch_id", primary_key: "batch_id", name: "fk_sync_error_batch_id"
  add_foreign_key "sync_error", "sync_job", column: "job_id", primary_key: "job_id", name: "fk_sync_error_job_id"
  add_foreign_key "sync_job", "sync_cursor", column: "stream_name", primary_key: "stream_name", name: "fk_sync_job_stream_name", deferrable: :deferred
end
