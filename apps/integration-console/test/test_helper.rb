ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "minitest/mock"
require "securerandom"

class ActiveSupport::TestCase
  SYNC_SCAN_INGEST_MANAGED_COLUMNS = %w[
    dedupe_key
    stream_name
    observed_at
    payload_ref
    payload
    payload_sha256
    status
    attempt_count
    last_error
    producer
    event_kind
    created_at
    updated_at
  ].freeze

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
    attributes = {
      "dedupe_key" => dedupe_key,
      "stream_name" => stream_name,
      "observed_at" => observed_at,
      "payload_ref" => "payload://#{dedupe_key}",
      "payload" => payload,
      "payload_sha256" => SecureRandom.hex(16),
      "status" => status,
      "producer" => "test",
      "event_kind" => "test",
      "destination_bssid" => payload["destination_bssid"] || payload["bssid"]
    }.compact

    sync_scan_ingest_promoted_columns.each_value do |column|
      next if attributes.key?(column.name)
      next unless payload.key?(column.name)

      attributes[column.name] = cast_sync_scan_ingest_value(column, payload[column.name])
    end

    columns_sql = attributes.keys.map { |name| sync_connection.quote_column_name(name) }.join(", ")
    values_sql = attributes.map { |name, value| quote_sync_scan_ingest_value(name, value) }.join(", ")

    sync_connection.execute("INSERT INTO sync_scan_ingest (#{columns_sql}) VALUES (#{values_sql})")
  end

  def insert_backlog(dedupe_key:, status:, updated_at: Time.current)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO audit_backlog
        (dedupe_key, stream_name, payload, status, attempt_count, created_at, updated_at)
      VALUES
        (#{sync_connection.quote(dedupe_key)}, 'sync.scan.request', '{}', #{sync_connection.quote(status)}, 0, now(), #{sync_connection.quote(updated_at)})
    SQL
  end

  private

  def sync_scan_ingest_promoted_columns
    @sync_scan_ingest_promoted_columns ||= sync_connection.columns("sync_scan_ingest").each_with_object({}) do |column, memo|
      next if SYNC_SCAN_INGEST_MANAGED_COLUMNS.include?(column.name)

      memo[column.name] = column
    end.freeze
  end

  def cast_sync_scan_ingest_value(column, value)
    return if value.nil?

    case column.type
    when :boolean
      ActiveModel::Type::Boolean.new.cast(value)
    when :integer, :bigint
      value.to_i
    when :float
      value.to_f
    else
      value
    end
  end

  def quote_sync_scan_ingest_value(column_name, value)
    return "#{sync_connection.quote(value.to_json)}::jsonb" if column_name == "payload"

    sync_connection.quote(value)
  end
end
