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

ActiveRecord::Schema[7.2].define(version: 2026_04_29_000100) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_trgm"
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

  create_table "authorized_wireless_networks", force: :cascade do |t|
    t.text "ssid"
    t.text "bssid"
    t.text "location_id"
    t.text "label"
    t.boolean "enabled", default: true, null: false
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index "COALESCE(lower(ssid), ''::text), COALESCE(lower(bssid), ''::text), COALESCE(location_id, ''::text)", name: "authorized_wireless_networks_match_idx", unique: true
    t.index ["enabled", "location_id"], name: "authorized_wireless_networks_enabled_idx"
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

  create_table "shadow_it_alerts", primary_key: "alert_id", force: :cascade do |t|
    t.text "dedupe_key", null: false
    t.timestamptz "observed_at", null: false
    t.text "source_mac", null: false
    t.text "destination_bssid"
    t.text "ssid"
    t.text "sensor_id"
    t.text "location_id"
    t.integer "signal_dbm"
    t.text "reason", null: false
    t.jsonb "evidence", default: {}, null: false
    t.timestamptz "resolved_at"
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
    t.index ["dedupe_key"], name: "index_shadow_it_alerts_on_dedupe_key", unique: true
    t.index "lower(source_mac), observed_at DESC", name: "shadow_it_alerts_source_idx"
    t.index ["observed_at"], name: "shadow_it_alerts_open_idx", order: :desc, where: "(resolved_at IS NULL)"
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
    t.text "sensor_id"
    t.text "location_id"
    t.text "frame_subtype"
    t.text "username"
    t.integer "schema_version", default: 1, null: false
    t.text "frame_type"
    t.text "source_mac"
    t.text "bssid"
    t.text "destination_bssid"
    t.text "ssid"
    t.integer "signal_dbm"
    t.integer "fragment_number"
    t.integer "channel_number"
    t.text "signal_status"
    t.text "adjacent_mac_hint"
    t.integer "qos_tid"
    t.boolean "qos_eosp"
    t.integer "qos_ack_policy"
    t.text "qos_ack_policy_label"
    t.boolean "qos_amsdu"
    t.text "llc_oui"
    t.integer "ethertype"
    t.text "ethertype_name"
    t.text "src_ip"
    t.text "dst_ip"
    t.integer "ip_ttl"
    t.integer "ip_protocol"
    t.text "ip_protocol_name"
    t.integer "src_port"
    t.integer "dst_port"
    t.text "transport_protocol"
    t.integer "transport_length"
    t.integer "transport_checksum"
    t.text "app_protocol"
    t.text "ssdp_message_type"
    t.text "ssdp_st"
    t.text "ssdp_mx"
    t.text "ssdp_usn"
    t.text "dhcp_requested_ip"
    t.text "dhcp_hostname"
    t.text "dhcp_vendor_class"
    t.text "dns_query_name"
    t.text "mdns_name"
    t.text "session_key"
    t.text "retransmit_key"
    t.text "frame_fingerprint"
    t.text "payload_visibility"
    t.bigint "tsft_delta_us"
    t.bigint "wall_clock_delta_ms"
    t.boolean "large_frame", default: false, null: false
    t.boolean "mixed_encryption"
    t.boolean "dedupe_or_replay_suspect", default: false, null: false
    t.integer "raw_len", default: 0, null: false
    t.integer "frame_control_flags", default: 0, null: false
    t.boolean "more_data", default: false, null: false
    t.boolean "retry", default: false, null: false
    t.boolean "power_save", default: false, null: false
    t.boolean "protected", default: false, null: false
    t.integer "security_flags", default: 0, null: false
    t.text "wps_device_name"
    t.text "wps_manufacturer"
    t.text "wps_model_name"
    t.text "device_fingerprint"
    t.boolean "handshake_captured", default: false, null: false
    t.virtual "wireless_search_tsv", type: :tsvector, as: "to_tsvector('simple'::regconfig, lower((((((((((((((((((((((((COALESCE(sensor_id, ''::text) || ' '::text) || COALESCE(source_mac, ''::text)) || ' '::text) || COALESCE(bssid, ''::text)) || ' '::text) || COALESCE(destination_bssid, ''::text)) || ' '::text) || COALESCE(ssid, ''::text)) || ' '::text) || COALESCE(wps_device_name, ''::text)) || ' '::text) || COALESCE(wps_manufacturer, ''::text)) || ' '::text) || COALESCE(wps_model_name, ''::text)) || ' '::text) || COALESCE(device_fingerprint, ''::text)) || ' '::text) || COALESCE(app_protocol, ''::text)) || ' '::text) || COALESCE(src_ip, ''::text)) || ' '::text) || COALESCE(dst_ip, ''::text)) || ' '::text) || COALESCE(username, ''::text))))", stored: true
    t.timestamptz "created_at", default: -> { "now()" }, null: false
    t.timestamptz "updated_at", default: -> { "now()" }, null: false
    t.index "((payload -> 'tags'::text))", name: "ssi_wireless_threat_tags_idx", where: "(stream_name = 'wireless.audit'::text)", using: :gin
    t.index "lower(app_protocol) gin_trgm_ops", name: "ssi_wireless_app_protocol_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (app_protocol IS NOT NULL))", using: :gin
    t.index "lower(bssid)", name: "ssi_wireless_bssid_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "lower(bssid) gin_trgm_ops", name: "ssi_wireless_bssid_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (bssid IS NOT NULL))", using: :gin
    t.index ["observed_at"], name: "ssi_wireless_audit_cover_idx", order: { observed_at: :desc }, where: "(stream_name = 'wireless.audit'::text)", include: ["dedupe_key", "sensor_id", "location_id", "frame_subtype", "source_mac", "bssid", "destination_bssid", "ssid", "signal_dbm", "raw_len", "frame_control_flags", "security_flags", "device_fingerprint", "handshake_captured", "frame_type", "wps_device_name"]
    t.index "(((lower(COALESCE(sensor_id, ''::text)) || ' '::text) || lower(COALESCE(source_mac, ''::text))) || ' '::text) || lower(COALESCE(ssid, ''::text)) gin_trgm_ops", name: "ssi_wireless_common_search_idx", where: "(stream_name = 'wireless.audit'::text)", using: :gin
    t.index "lower(destination_bssid)", name: "ssi_wireless_destination_bssid_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "lower(destination_bssid) gin_trgm_ops", name: "ssi_wireless_destination_bssid_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (destination_bssid IS NOT NULL))", using: :gin
    t.index "frame_fingerprint", name: "ssi_wireless_frame_fingerprint_idx", where: "((stream_name = 'wireless.audit'::text) AND (frame_fingerprint IS NOT NULL))"
    t.index "lower(device_fingerprint) gin_trgm_ops", name: "ssi_wireless_device_fingerprint_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (device_fingerprint IS NOT NULL))", using: :gin
    t.index "lower(dst_ip) gin_trgm_ops", name: "ssi_wireless_dst_ip_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (dst_ip IS NOT NULL))", using: :gin
    t.index "lower(source_mac)", name: "ssi_wireless_source_mac_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "lower(source_mac) gin_trgm_ops", name: "ssi_wireless_source_mac_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (source_mac IS NOT NULL))", using: :gin
    t.index "lower(sensor_id) gin_trgm_ops", name: "ssi_wireless_sensor_id_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (sensor_id IS NOT NULL))", using: :gin
    t.index ["app_protocol", "observed_at"], name: "ssi_wireless_app_protocol_idx", where: "((stream_name = 'wireless.audit'::text) AND (app_protocol IS NOT NULL))"
    t.index "signal_dbm, observed_at DESC", name: "ssi_wireless_signal_idx", where: "((stream_name = 'wireless.audit'::text) AND (signal_dbm IS NOT NULL))"
    t.index ["schema_version", "observed_at"], name: "ssi_wireless_schema_version_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index ["session_key", "observed_at"], name: "ssi_wireless_session_key_idx", where: "((stream_name = 'wireless.audit'::text) AND (session_key IS NOT NULL))"
    t.index "ssid, observed_at DESC", name: "ssi_wireless_ssid_idx", where: "(stream_name = 'wireless.audit'::text)"
    t.index "lower(ssid) gin_trgm_ops", name: "ssi_wireless_ssid_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (ssid IS NOT NULL))", using: :gin
    t.index ["src_ip"], name: "ssi_wireless_src_ip_idx", where: "((stream_name = 'wireless.audit'::text) AND (src_ip IS NOT NULL))"
    t.index "lower(src_ip) gin_trgm_ops", name: "ssi_wireless_src_ip_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (src_ip IS NOT NULL))", using: :gin
    t.index ["dst_ip"], name: "ssi_wireless_dst_ip_idx", where: "((stream_name = 'wireless.audit'::text) AND (dst_ip IS NOT NULL))"
    t.index "device_fingerprint, observed_at DESC", name: "ssi_wireless_device_fingerprint_idx", where: "((stream_name = 'wireless.audit'::text) AND (device_fingerprint IS NOT NULL))"
    t.index "observed_at DESC", name: "ssi_wireless_handshake_captured_idx", where: "((stream_name = 'wireless.audit'::text) AND handshake_captured)"
    t.index "security_flags, observed_at DESC", name: "ssi_wireless_security_flags_idx", where: "((stream_name = 'wireless.audit'::text) AND (security_flags <> 0))"
    t.index "wireless_search_tsv", name: "ssi_wireless_search_tsv_idx", where: "(stream_name = 'wireless.audit'::text)", using: :gin
    t.index "lower(username) gin_trgm_ops", name: "ssi_wireless_username_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (username IS NOT NULL))", using: :gin
    t.index "lower(wps_device_name) gin_trgm_ops", name: "ssi_wireless_wps_device_name_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (wps_device_name IS NOT NULL))", using: :gin
    t.index "lower(wps_manufacturer) gin_trgm_ops", name: "ssi_wireless_wps_manufacturer_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (wps_manufacturer IS NOT NULL))", using: :gin
    t.index "lower(wps_model_name) gin_trgm_ops", name: "ssi_wireless_wps_model_name_trgm_idx", where: "((stream_name = 'wireless.audit'::text) AND (wps_model_name IS NOT NULL))", using: :gin
    t.index ["observed_at"], name: "ssi_pending_observed_idx", where: "(status = ANY (ARRAY['pending'::text, 'failed'::text]))"
    t.index ["status", "observed_at"], name: "sync_scan_ingest_status_idx"
    t.index ["stream_name", "observed_at"], name: "sync_scan_ingest_stream_idx"
  end

  execute <<~SQL
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wireless_heatmap AS
    SELECT
      COALESCE(location_id, payload->>'location_id') AS location_id,
      count(*) AS event_count,
      avg(COALESCE(signal_dbm, CASE WHEN payload->>'signal_dbm' ~ '^-?[0-9]+$' THEN (payload->>'signal_dbm')::integer END)) AS avg_signal_dbm,
      count(DISTINCT lower(COALESCE(source_mac, payload->>'source_mac'))) AS unique_devices,
      max(observed_at) AS last_seen_at
    FROM sync_scan_ingest
    WHERE stream_name = 'wireless.audit'
      AND COALESCE(location_id, payload->>'location_id') IS NOT NULL
    GROUP BY COALESCE(location_id, payload->>'location_id')
    WITH NO DATA
  SQL

  execute "REFRESH MATERIALIZED VIEW mv_wireless_heatmap"

  execute <<~SQL
    CREATE UNIQUE INDEX IF NOT EXISTS mv_wireless_heatmap_location_idx
      ON mv_wireless_heatmap (location_id)
  SQL

  execute <<~SQL
    CREATE OR REPLACE VIEW v_wireless_audit_with_devices AS
    SELECT
      ssi.dedupe_key,
      ssi.observed_at,
      ssi.stream_name,
      ssi.status,
      ssi.producer,
      ssi.event_kind,
      COALESCE(
        ssi.schema_version,
        CASE WHEN ssi.payload->>'schema_version' ~ '^[0-9]+$' THEN (ssi.payload->>'schema_version')::integer END,
        1
      ) AS schema_version,
      COALESCE(ssi.frame_type, ssi.payload->>'frame_type') AS frame_type,
      COALESCE(ssi.source_mac, ssi.payload->>'source_mac') AS source_mac,
      ssi.payload->>'transmitter_mac' AS transmitter_mac,
      ssi.payload->>'receiver_mac' AS receiver_mac,
      COALESCE(ssi.bssid, ssi.payload->>'bssid') AS bssid,
      COALESCE(ssi.destination_bssid, ssi.bssid, ssi.payload->>'destination_bssid', ssi.payload->>'bssid') AS destination_bssid,
      COALESCE(ssi.ssid, ssi.payload->>'ssid') AS ssid,
      COALESCE(ssi.frame_subtype, ssi.payload->>'frame_subtype') AS frame_subtype,
      COALESCE(ssi.signal_dbm::text, ssi.payload->>'signal_dbm') AS signal_dbm,
      ssi.payload->>'noise_dbm' AS noise_dbm,
      ssi.payload->>'frequency_mhz' AS frequency_mhz,
      COALESCE(ssi.channel_number::text, ssi.payload->>'channel_number') AS channel_number,
      COALESCE(ssi.signal_status, ssi.payload->>'signal_status') AS signal_status,
      COALESCE(ssi.qos_tid::text, ssi.payload->>'qos_tid') AS qos_tid,
      COALESCE(ssi.ethertype::text, ssi.payload->>'ethertype') AS ethertype,
      COALESCE(ssi.src_ip, ssi.payload->>'src_ip') AS src_ip,
      COALESCE(ssi.dst_ip, ssi.payload->>'dst_ip') AS dst_ip,
      COALESCE(ssi.src_port::text, ssi.payload->>'src_port') AS src_port,
      COALESCE(ssi.dst_port::text, ssi.payload->>'dst_port') AS dst_port,
      COALESCE(ssi.app_protocol, ssi.payload->>'app_protocol') AS app_protocol,
      COALESCE(ssi.session_key, ssi.payload->>'session_key') AS session_key,
      COALESCE(ssi.retransmit_key, ssi.payload->>'retransmit_key') AS retransmit_key,
      COALESCE(ssi.frame_fingerprint, ssi.payload->>'frame_fingerprint') AS frame_fingerprint,
      COALESCE(ssi.payload_visibility, ssi.payload->>'payload_visibility') AS payload_visibility,
      COALESCE(ssi.large_frame::text, ssi.payload->>'large_frame') AS large_frame,
      COALESCE(ssi.mixed_encryption::text, ssi.payload->>'mixed_encryption') AS mixed_encryption,
      COALESCE(ssi.dedupe_or_replay_suspect::text, ssi.payload->>'dedupe_or_replay_suspect') AS dedupe_or_replay_suspect,
      COALESCE(ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS dhcp_hostname,
      COALESCE(ssi.dns_query_name, ssi.payload->>'dns_query_name') AS dns_query_name,
      COALESCE(ssi.mdns_name, ssi.payload->>'mdns_name') AS mdns_name,
      COALESCE(ssi.raw_len::text, ssi.payload->>'raw_len') AS raw_len,
      COALESCE(ssi.frame_control_flags::text, ssi.payload->>'frame_control_flags') AS frame_control_flags,
      COALESCE(ssi.more_data::text, ssi.payload->>'more_data') AS more_data,
      COALESCE(ssi.retry::text, ssi.payload->>'retry') AS retry,
      COALESCE(ssi.power_save::text, ssi.payload->>'power_save') AS power_save,
      COALESCE(ssi.protected::text, ssi.payload->>'protected') AS protected,
      COALESCE(ssi.location_id, ssi.payload->>'location_id') AS location_id,
      COALESCE(ssi.sensor_id, ssi.payload->>'sensor_id') AS sensor_id,
      ssi.payload->>'identity_source' AS identity_source,
      COALESCE(ssi.username, ssi.payload->>'username') AS username,
      ssi.payload->'tags' AS tags,
      ssi.security_flags,
      ssi.wps_device_name,
      ssi.wps_manufacturer,
      ssi.wps_model_name,
      ssi.device_fingerprint,
      ssi.handshake_captured,
      COALESCE(d_src.device_id, d_bssid.device_id) AS device_id,
      COALESCE(d_src.display_name, d_bssid.display_name) AS display_name,
      COALESCE(d_src.username, d_bssid.username) AS registered_username,
      COALESCE(d_src.os_hint, d_bssid.os_hint) AS os_hint,
      COALESCE(d_src.hostname, d_bssid.hostname, ssi.dhcp_hostname, ssi.payload->>'dhcp_hostname') AS hostname
    FROM sync_scan_ingest ssi
    LEFT JOIN devices d_src
      ON lower(d_src.mac_hint) = lower(COALESCE(ssi.source_mac, ssi.payload->>'source_mac'))
    LEFT JOIN devices d_bssid
      ON lower(d_bssid.mac_hint) = lower(COALESCE(ssi.bssid, ssi.payload->>'bssid'))
    WHERE ssi.stream_name = 'wireless.audit'
  SQL

  execute <<~SQL
    CREATE OR REPLACE VIEW v_wireless_device_inventory AS
    SELECT
      md5(COALESCE(lower(source_mac), '') || '|' || COALESCE(location_id, '')) AS inventory_key,
      lower(source_mac) AS source_mac,
      max(location_id) AS location_id,
      min(observed_at) AS first_seen,
      max(observed_at) AS last_seen,
      max(ssid) AS ssid,
      max(destination_bssid) AS destination_bssid,
      string_agg(DISTINCT src_ip, ', ') FILTER (WHERE src_ip IS NOT NULL) AS ip_addresses,
      string_agg(DISTINCT hostname, ', ') FILTER (WHERE hostname IS NOT NULL) AS hostnames,
      string_agg(DISTINCT app_protocol, ', ') FILTER (WHERE app_protocol IS NOT NULL) AS services,
      string_agg(DISTINCT dns_query_name, ', ') FILTER (WHERE dns_query_name IS NOT NULL) AS dns_names,
      count(*) AS frame_count,
      sum(CASE WHEN protected THEN 1 ELSE 0 END) AS protected_frame_count,
      sum(CASE WHEN NOT protected THEN 1 ELSE 0 END) AS open_frame_count
    FROM (
      SELECT
        observed_at,
        COALESCE(source_mac, payload->>'source_mac') AS source_mac,
        COALESCE(location_id, payload->>'location_id') AS location_id,
        COALESCE(ssid, payload->>'ssid') AS ssid,
        COALESCE(destination_bssid, bssid, payload->>'destination_bssid', payload->>'bssid') AS destination_bssid,
        COALESCE(src_ip, payload->>'src_ip') AS src_ip,
        COALESCE(dhcp_hostname, mdns_name, payload->>'dhcp_hostname', payload->>'mdns_name') AS hostname,
        COALESCE(app_protocol, payload->>'app_protocol') AS app_protocol,
        COALESCE(dns_query_name, payload->>'dns_query_name') AS dns_query_name,
        COALESCE(protected, FALSE) AS protected
      FROM sync_scan_ingest
      WHERE stream_name = 'wireless.audit'
    ) inventory
    WHERE source_mac IS NOT NULL
    GROUP BY lower(source_mac), location_id
  SQL

  execute <<~SQL
    CREATE OR REPLACE VIEW v_shadow_it_alerts AS
    SELECT
      alert_id,
      dedupe_key,
      observed_at,
      source_mac,
      destination_bssid,
      ssid,
      sensor_id,
      location_id,
      signal_dbm,
      reason,
      evidence,
      resolved_at,
      created_at,
      updated_at
    FROM shadow_it_alerts
    ORDER BY observed_at DESC
  SQL

  add_check_constraint "audit_backlog", "status = ANY (ARRAY['pending'::text, 'synced'::text, 'sync_failed'::text, 'failed'::text])", name: "chk_audit_backlog_status"
  add_check_constraint "authorized_wireless_networks", "NULLIF(TRIM(BOTH FROM COALESCE(ssid, ''::text)), ''::text) IS NOT NULL OR NULLIF(TRIM(BOTH FROM COALESCE(bssid, ''::text)), ''::text) IS NOT NULL", name: "authorized_wireless_network_identity_chk"
  add_check_constraint "sync_batch", "status = ANY (ARRAY['pending'::text, 'processing'::text, 'dispatched'::text, 'completed'::text, 'failed'::text])", name: "chk_sync_batch_status"
  add_check_constraint "sync_job", "status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])", name: "chk_sync_job_status"
  add_foreign_key "sync_batch", "sync_job", column: "job_id", primary_key: "job_id", name: "fk_sync_batch_job_id"
  add_foreign_key "sync_error", "sync_batch", column: "batch_id", primary_key: "batch_id", name: "fk_sync_error_batch_id"
  add_foreign_key "sync_error", "sync_job", column: "job_id", primary_key: "job_id", name: "fk_sync_error_job_id"
  add_foreign_key "sync_job", "sync_cursor", column: "stream_name", primary_key: "stream_name", name: "fk_sync_job_stream_name", deferrable: :deferred
end
