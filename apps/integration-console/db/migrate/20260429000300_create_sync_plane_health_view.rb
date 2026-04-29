class CreateSyncPlaneHealthView < ActiveRecord::Migration[7.2]
  def up
    execute <<~SQL
      DROP VIEW IF EXISTS v_sync_plane_health;

      CREATE OR REPLACE VIEW v_sync_plane_health AS
      WITH ingest_status AS (
        SELECT
          status,
          count(*)::bigint AS row_count
        FROM sync_scan_ingest
        GROUP BY status
      ),
      wireless_ingest_status AS (
        SELECT
          status,
          count(*)::bigint AS row_count
        FROM sync_scan_ingest
        WHERE stream_name = 'wireless.audit'
        GROUP BY status
      ),
      ingest_time AS (
        SELECT
          count(*) FILTER (WHERE stream_name = 'wireless.audit' AND observed_at >= now() - interval '24 hours')::bigint AS wireless_events_24h_count,
          max(observed_at) FILTER (WHERE stream_name = 'wireless.audit') AS wireless_last_observed_at
        FROM sync_scan_ingest
      ),
      batch_status AS (
        SELECT
          status,
          count(*)::bigint AS row_count
        FROM sync_batch
        GROUP BY status
      ),
      job_batch_rollup AS (
        SELECT
          job.job_id,
          job.status AS stored_status,
          job.created_at,
          count(batch.batch_id)::bigint AS batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status IN ('pending', 'processing', 'dispatched'))::bigint AS open_batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status = 'failed')::bigint AS failed_batch_count,
          count(batch.batch_id) FILTER (WHERE batch.status = 'completed')::bigint AS completed_batch_count
        FROM sync_job job
        LEFT JOIN sync_batch batch ON batch.job_id = job.job_id
        GROUP BY job.job_id, job.status, job.created_at
      ),
      job_effective_status AS (
        SELECT
          CASE
            WHEN open_batch_count > 0 THEN stored_status
            WHEN failed_batch_count > 0 THEN 'failed'
            WHEN completed_batch_count > 0 THEN 'completed'
            WHEN stored_status IN ('pending', 'running') AND created_at < now() - interval '5 minutes' THEN 'orphaned'
            ELSE stored_status
          END AS effective_status,
          stored_status,
          count(*)::bigint AS row_count
        FROM job_batch_rollup
        GROUP BY
          CASE
            WHEN open_batch_count > 0 THEN stored_status
            WHEN failed_batch_count > 0 THEN 'failed'
            WHEN completed_batch_count > 0 THEN 'completed'
            WHEN stored_status IN ('pending', 'running') AND created_at < now() - interval '5 minutes' THEN 'orphaned'
            ELSE stored_status
          END,
          stored_status
      ),
      backlog_status AS (
        SELECT
          status,
          count(*)::bigint AS row_count
        FROM audit_backlog
        GROUP BY status
      ),
      shadow_status AS (
        SELECT
          count(*) FILTER (WHERE resolved_at IS NULL)::bigint AS open_alert_count,
          max(observed_at) FILTER (WHERE resolved_at IS NULL) AS last_open_alert_at
        FROM shadow_it_alerts
      )
      SELECT
        now() AS measured_at,
        coalesce((SELECT wireless_events_24h_count FROM ingest_time), 0)::bigint AS wireless_events_24h_count,
        (SELECT wireless_last_observed_at FROM ingest_time) AS wireless_last_observed_at,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'pending'), 0)::bigint AS wireless_ingest_pending_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'processing'), 0)::bigint AS wireless_ingest_processing_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'batched'), 0)::bigint AS wireless_ingest_batched_count,
        coalesce((SELECT row_count FROM wireless_ingest_status WHERE status = 'failed'), 0)::bigint AS wireless_ingest_failed_count,
        coalesce((SELECT sum(row_count) FROM wireless_ingest_status), 0)::bigint AS wireless_ingest_total_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'pending'), 0)::bigint AS ingest_pending_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'processing'), 0)::bigint AS ingest_processing_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'batched'), 0)::bigint AS ingest_batched_count,
        coalesce((SELECT row_count FROM ingest_status WHERE status = 'failed'), 0)::bigint AS ingest_failed_count,
        coalesce((SELECT sum(row_count) FROM ingest_status), 0)::bigint AS ingest_total_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'pending'), 0)::bigint AS batch_pending_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'processing'), 0)::bigint AS batch_processing_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'dispatched'), 0)::bigint AS batch_dispatched_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'completed'), 0)::bigint AS batch_completed_count,
        coalesce((SELECT row_count FROM batch_status WHERE status = 'failed'), 0)::bigint AS batch_failed_count,
        coalesce((SELECT sum(row_count) FROM batch_status), 0)::bigint AS batch_total_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'pending'), 0)::bigint AS job_stored_pending_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'running'), 0)::bigint AS job_stored_running_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'completed'), 0)::bigint AS job_stored_completed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE stored_status = 'failed'), 0)::bigint AS job_stored_failed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status), 0)::bigint AS job_total_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'pending'), 0)::bigint AS job_effective_pending_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'running'), 0)::bigint AS job_effective_running_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'completed'), 0)::bigint AS job_effective_completed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'failed'), 0)::bigint AS job_effective_failed_count,
        coalesce((SELECT sum(row_count) FROM job_effective_status WHERE effective_status = 'orphaned'), 0)::bigint AS job_orphaned_count,
        coalesce((SELECT row_count FROM backlog_status WHERE status = 'pending'), 0)::bigint AS backlog_pending_count,
        coalesce((SELECT sum(row_count) FROM backlog_status WHERE status IN ('sync_failed', 'failed')), 0)::bigint AS backlog_failed_count,
        coalesce((SELECT open_alert_count FROM shadow_status), 0)::bigint AS open_shadow_it_alert_count,
        (SELECT last_open_alert_at FROM shadow_status) AS last_shadow_it_alert_at,
        (SELECT cursor_value FROM sync_cursor WHERE stream_name = 'wireless.audit') AS wireless_cursor_value,
        (SELECT updated_at FROM sync_cursor WHERE stream_name = 'wireless.audit') AS wireless_cursor_updated_at
    SQL
  end

  def down
    execute "DROP VIEW IF EXISTS v_sync_plane_health"
  end
end
