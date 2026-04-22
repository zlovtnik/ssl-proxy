ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "minitest/mock"
require "securerandom"

class ActiveSupport::TestCase
  parallelize(workers: 1)

  def sync_connection
    SyncRecord.connection
  end

  def clear_sync_tables(*tables)
    tables.each do |table|
      sync_connection.execute("DELETE FROM #{table}")
    end
  end

  def insert_sync_ingest(dedupe_key:, observed_at:, payload:, stream_name: "wireless.audit", status: "pending")
    quoted_payload = sync_connection.quote(payload.to_json)
    security_flags = payload.fetch("security_flags", 0).to_i
    wps_device_name = payload["wps_device_name"]
    wps_manufacturer = payload["wps_manufacturer"]
    wps_model_name = payload["wps_model_name"]
    device_fingerprint = payload["device_fingerprint"]
    handshake_captured = payload.fetch("handshake_captured", false) ? "TRUE" : "FALSE"
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_scan_ingest
        (dedupe_key, stream_name, observed_at, payload_ref, payload, payload_sha256, status, producer, event_kind, security_flags, wps_device_name, wps_manufacturer, wps_model_name, device_fingerprint, handshake_captured, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, #{sync_connection.quote(stream_name)}, #{sync_connection.quote(observed_at)}, #{sync_connection.quote("payload://#{dedupe_key}")}, #{quoted_payload}::jsonb, #{sync_connection.quote(SecureRandom.hex(16))}, #{sync_connection.quote(status)}, 'test', 'test', #{security_flags}, #{sync_connection.quote(wps_device_name)}, #{sync_connection.quote(wps_manufacturer)}, #{sync_connection.quote(wps_model_name)}, #{sync_connection.quote(device_fingerprint)}, #{handshake_captured}, now(), now())
    SQL
  end

  def insert_backlog(dedupe_key:, status:, updated_at: Time.current)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO audit_backlog
        (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, 'sync.scan.request', '{}', #{sync_connection.quote(status)}, 0, now(), #{sync_connection.quote(updated_at)})
    SQL
  end
end
