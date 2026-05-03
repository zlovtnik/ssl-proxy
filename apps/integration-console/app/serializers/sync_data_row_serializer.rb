class SyncDataRowSerializer
  def self.serialize(sync_health)
    [
      {
        label: "Wireless ingest",
        source: "sync_scan_ingest",
        value: sync_health.wireless_ingest_total_count.to_i,
        detail: "#{sync_health.wireless_ingest_pending_count.to_i} pending, #{sync_health.wireless_ingest_processing_count.to_i} processing, #{sync_health.wireless_ingest_failed_count.to_i} failed",
        lastSeen: sync_health.wireless_last_observed_at&.to_fs(:db)
      },
      {
        label: "Oracle batches",
        source: "sync_batch",
        value: sync_health.batch_total_count.to_i,
        detail: "#{sync_health.batch_pending_count.to_i} pending, #{sync_health.batch_dispatched_count.to_i} dispatched, #{sync_health.batch_failed_count.to_i} failed",
        lastSeen: nil
      },
      {
        label: "Coordinator jobs",
        source: "sync_job + sync_batch",
        value: sync_health.job_total_count.to_i,
        detail: "#{sync_health.job_effective_running_count.to_i} running, #{sync_health.job_effective_completed_count.to_i} completed, #{sync_health.job_orphaned_count.to_i} orphaned",
        lastSeen: nil
      },
      {
        label: "Sensor backlog",
        source: "audit_backlog",
        value: sync_health.backlog_pending_count.to_i,
        detail: "#{sync_health.backlog_failed_count.to_i} failed",
        lastSeen: nil
      },
      {
        label: "Shadow IT",
        source: "shadow_it_alerts",
        value: sync_health.open_shadow_it_alert_count.to_i,
        detail: "open alerts",
        lastSeen: sync_health.last_shadow_it_alert_at&.to_fs(:db)
      },
      {
        label: "Wireless cursor",
        source: "sync_cursor",
        value: sync_health.wireless_cursor_value.presence || "unset",
        detail: "stream wireless.audit",
        lastSeen: sync_health.wireless_cursor_updated_at&.to_fs(:db)
      }
    ]
  end
end
