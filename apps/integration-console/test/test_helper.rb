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
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_scan_ingest
        (dedupe_key, stream_name, observed_at, payload_ref, payload, payload_sha256, status, producer, event_kind, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, #{sync_connection.quote(stream_name)}, #{sync_connection.quote(observed_at)}, #{sync_connection.quote("payload://#{dedupe_key}")}, #{quoted_payload}::jsonb, #{sync_connection.quote(SecureRandom.hex(16))}, #{sync_connection.quote(status)}, 'test', 'test', now(), now())
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
