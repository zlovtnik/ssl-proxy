class SyncPlaneHealth < SyncRecord
  self.table_name = "v_sync_plane_health"
  self.primary_key = nil

  IMPORTANT_RELATIONS = {
    "sync_scan_ingest" => "Wireless audit events",
    "sync_job" => "Coordinator jobs",
    "sync_batch" => "Oracle load batches",
    "audit_backlog" => "Sensor publish backlog",
    "shadow_it_alerts" => "Shadow IT alerts",
    "sync_cursor" => "Stream cursors",
    "sync_error" => "Sync errors",
    "devices" => "Registered MAC identifiers",
    "authorized_wireless_networks" => "Allowed wireless networks"
  }.freeze

  DEFAULT_ATTRIBUTES = {
    "measured_at" => nil,
    "wireless_last_observed_at" => nil,
    "last_shadow_it_alert_at" => nil,
    "wireless_cursor_value" => nil,
    "wireless_cursor_updated_at" => nil,
    "wireless_events_24h_count" => 0,
    "wireless_ingest_pending_count" => 0,
    "wireless_ingest_processing_count" => 0,
    "wireless_ingest_batched_count" => 0,
    "wireless_ingest_failed_count" => 0,
    "wireless_ingest_total_count" => 0,
    "ingest_pending_count" => 0,
    "ingest_processing_count" => 0,
    "ingest_batched_count" => 0,
    "ingest_failed_count" => 0,
    "ingest_total_count" => 0,
    "batch_pending_count" => 0,
    "batch_processing_count" => 0,
    "batch_dispatched_count" => 0,
    "batch_completed_count" => 0,
    "batch_failed_count" => 0,
    "batch_total_count" => 0,
    "job_stored_pending_count" => 0,
    "job_stored_running_count" => 0,
    "job_stored_completed_count" => 0,
    "job_stored_failed_count" => 0,
    "job_total_count" => 0,
    "job_effective_pending_count" => 0,
    "job_effective_running_count" => 0,
    "job_effective_completed_count" => 0,
    "job_effective_failed_count" => 0,
    "job_orphaned_count" => 0,
    "backlog_pending_count" => 0,
    "backlog_failed_count" => 0,
    "open_shadow_it_alert_count" => 0
  }.freeze

  Snapshot = Struct.new(*DEFAULT_ATTRIBUTES.keys.map(&:to_sym), keyword_init: true) do
    def attributes
      to_h.stringify_keys
    end
  end

  def self.snapshot
    from_attributes(first&.attributes)
  rescue ActiveRecord::StatementInvalid => error
    raise unless missing_health_view?(error)

    default_snapshot
  end

  def self.from_attributes(attributes)
    normalized = DEFAULT_ATTRIBUTES.merge((attributes || {}).stringify_keys)
    Snapshot.new(**normalized.symbolize_keys)
  end

  def self.important_relations
    quoted_names = IMPORTANT_RELATIONS.keys.map { |name| connection.quote(name) }.join(", ")
    rows = connection.exec_query(<<~SQL.squish)
      SELECT
        class.relname AS name,
        CASE class.relkind
          WHEN 'r' THEN 'table'
          WHEN 'v' THEN 'view'
          WHEN 'm' THEN 'materialized view'
          ELSE class.relkind::text
        END AS kind,
        COALESCE(stats.n_live_tup, 0)::bigint AS estimated_rows,
        pg_total_relation_size(class.oid)::bigint AS total_bytes
      FROM pg_class class
      JOIN pg_namespace namespace ON namespace.oid = class.relnamespace
      LEFT JOIN pg_stat_user_tables stats ON stats.relid = class.oid
      WHERE namespace.nspname = current_schema()
        AND class.relname IN (#{quoted_names})
        AND class.relkind IN ('r', 'v', 'm')
      ORDER BY array_position(ARRAY[#{quoted_names}]::text[], class.relname::text)
    SQL

    rows.map do |row|
      row.symbolize_keys.merge(
        role: IMPORTANT_RELATIONS.fetch(row.fetch("name")),
        total_size: format_bytes(row.fetch("total_bytes").to_i)
      )
    end
  end

  def self.default_snapshot
    from_attributes(DEFAULT_ATTRIBUTES)
  end

  def self.missing_health_view?(error)
    error.message.include?(table_name)
  end
  private_class_method :default_snapshot, :missing_health_view?

  def self.format_bytes(bytes)
    units = %w[B KB MB GB TB]
    value = bytes.to_f
    unit_index = 0

    while value >= 1024 && unit_index < units.length - 1
      value /= 1024
      unit_index += 1
    end

    unit_index.zero? ? "#{bytes} B" : "#{value.round(1)} #{units[unit_index]}"
  end
  private_class_method :format_bytes
end
